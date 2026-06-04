using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hosting;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;
using DataProtectionKeyManagementOptions = Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions;

// ReSharper disable once CheckNamespace — extensions for IDataProtectionBuilder live in the
// host's namespace by .NET convention so they appear without an extra `using`.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// <see cref="IDataProtectionBuilder"/> extensions that wire a post-quantum / hybrid XML
/// encryptor into ASP.NET Core Data Protection.
/// </summary>
public static class PostQuantumDataProtectionBuilderExtensions
{
    /// <summary>
    /// Protects every persisted Data Protection key with an ML-KEM-768 + AES-256-GCM hybrid
    /// envelope. Requires <see cref="IContentKeyProvider"/> to already be registered (call
    /// <c>AddPostQuantumKeyManagement(...)</c> from
    /// <c>PostQuantum.KeyManagement.Extensions.DependencyInjection</c> first).
    /// </summary>
    /// <param name="builder">The data protection builder.</param>
    /// <param name="configure">Callback to set <see cref="PostQuantumDataProtectionOptions"/> (key store path, mode).</param>
    public static IDataProtectionBuilder ProtectKeysWithPostQuantum(
        this IDataProtectionBuilder builder,
        Action<PostQuantumDataProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var snapshot = new PostQuantumDataProtectionOptions();
        configure(snapshot);

        if (string.IsNullOrWhiteSpace(snapshot.KeyStorePath))
        {
            throw new InvalidOperationException(
                "PostQuantumDataProtectionOptions.KeyStorePath is required but was empty. " +
                "Set it to a writable file path; the long-lived ML-KEM-768 keypair will be persisted there " +
                "(e.g. \"keys/pq-keystore.txt\"). " +
                "If you are running in a container, make sure the path lives on a mounted, durable volume — " +
                "container-local disk is lost on every restart, which is equivalent to losing every Data Protection key. " +
                "See docs/deployment.md §2 (pre-deployment checklist) for the production posture.");
        }

        builder.Services.AddOptions<PostQuantumDataProtectionOptions>().Configure(configure);
        builder.Services.TryAddSingleton<IPostQuantumKeyStore>(_ => new FilePostQuantumKeyStore(snapshot.KeyStorePath!));
        builder.Services.TryAddSingleton<PostQuantumKeyManager>(static sp =>
        {
            IContentKeyProvider contentKeys = sp.GetRequiredService<IContentKeyProvider>();
            IPostQuantumKeyStore store = sp.GetRequiredService<IPostQuantumKeyStore>();
            ILogger<PostQuantumKeyManager>? logger = sp.GetService<ILogger<PostQuantumKeyManager>>();
            PostQuantumDataProtectionOptions opts = sp.GetRequiredService<IOptions<PostQuantumDataProtectionOptions>>().Value;
            return new PostQuantumKeyManager(contentKeys, store, opts.ParameterSet, logger);
        });

        // Data Protection's IActivator activates PostQuantumXmlDecryptor via
        // ActivatorUtilities.CreateInstance(serviceProvider, typeof(PostQuantumXmlDecryptor)). The
        // [ActivatorUtilitiesConstructor] on its (IServiceProvider) ctor disambiguates from the
        // explicit-dependency ctor used by tests. We deliberately do NOT register the decryptor
        // as a DI service — that would force ASP.NET Core's strict-DI validator to inspect both
        // constructors and fail on "ambiguous". The activator pattern does not need it.

        // Register the scheduled-rotation hosted service when an interval is set. The service
        // self-disables at runtime if RotationInterval == TimeSpan.Zero, so the registration is
        // always safe regardless of config.
        builder.Services.AddHostedService<PostQuantumRotationHostedService>();

        // Wire the encryptor onto Data Protection's key-management options. The XmlEncryptor
        // setter is the official seam Data Protection exposes for at-rest key wrapping.
        builder.Services.AddOptions<DataProtectionKeyManagementOptions>().Configure<PostQuantumKeyManager, IContentKeyProvider, ILoggerFactory>(
            (keyManagementOptions, pqKeys, contentKeys, loggerFactory) =>
            {
                HybridKemMode mode = snapshot.Mode;
                ILogger<PostQuantumXmlEncryptor> logger = loggerFactory.CreateLogger<PostQuantumXmlEncryptor>();
                keyManagementOptions.XmlEncryptor = new PostQuantumXmlEncryptor(pqKeys, contentKeys, mode, logger);
            });

        return builder;
    }

    /// <summary>
    /// Convenience overload for callers who do not need to tune anything beyond the file path.
    /// </summary>
    public static IDataProtectionBuilder ProtectKeysWithPostQuantum(this IDataProtectionBuilder builder, string keyStorePath)
        => builder.ProtectKeysWithPostQuantum(o => o.KeyStorePath = keyStorePath);

    /// <summary>
    /// Binds <see cref="PostQuantumDataProtectionOptions"/> from a configuration section and registers
    /// the chain. The section's keys map directly to the option property names — typical
    /// <c>appsettings.json</c>:
    /// <code>
    /// "PostQuantumDataProtection": {
    ///   "KeyStorePath": "keys/pq-keystore.txt",
    ///   "Mode": "Hybrid"
    /// }
    /// </code>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode(
        "Binding a strongly-typed options object from IConfigurationSection uses reflection over " +
        "PostQuantumDataProtectionOptions and is not trim-safe. Use the Action<PostQuantumDataProtectionOptions> " +
        "overload instead, or call this method from a non-trimmed host.")]
    [System.Diagnostics.CodeAnalysis.RequiresDynamicCode(
        "Binding a strongly-typed options object from IConfigurationSection requires dynamic code at runtime " +
        "and is not AOT-safe. Use the Action<PostQuantumDataProtectionOptions> overload instead.")]
    public static IDataProtectionBuilder ProtectKeysWithPostQuantum(this IDataProtectionBuilder builder, IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(section);
        if (!section.Exists())
        {
            throw new InvalidOperationException(
                $"Configuration section '{section.Path}' is missing or empty. " +
                "Add a PostQuantumDataProtection section to appsettings.json (or your secret store) with at least KeyStorePath set. " +
                "See README.md § \"Configure from appsettings.json\" for the full schema.");
        }

        return builder.ProtectKeysWithPostQuantum(section.Bind);
    }
}

/// <summary>
/// <see cref="IHealthChecksBuilder"/> extensions for the PQ data-protection chain.
/// </summary>
public static class PostQuantumDataProtectionHealthChecksBuilderExtensions
{
    /// <summary>
    /// Registers a health check that exercises a real PQ envelope roundtrip on every probe — the
    /// PQ key manager, the host <see cref="IContentKeyProvider"/>, ML-KEM encapsulation, the
    /// hybrid combiner, AES-256-GCM, and decapsulation all run against tiny test data. A
    /// regression in any of those surfaces as Unhealthy.
    /// </summary>
    public static IHealthChecksBuilder AddPostQuantumDataProtection(
        this IHealthChecksBuilder builder,
        string name = "post-quantum-data-protection",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddCheck<PostQuantumDataProtectionHealthCheck>(name, failureStatus, tags ?? []);
    }
}
