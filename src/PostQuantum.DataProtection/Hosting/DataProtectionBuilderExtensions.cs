using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
                "PostQuantumDataProtectionOptions.KeyStorePath is required. " +
                "Point it at a writable file location; the long-lived ML-KEM keypair will live there.");
        }

        builder.Services.AddOptions<PostQuantumDataProtectionOptions>().Configure(configure);
        builder.Services.TryAddSingleton<IPostQuantumKeyStore>(_ => new FilePostQuantumKeyStore(snapshot.KeyStorePath!));
        builder.Services.TryAddSingleton<PostQuantumKeyManager>(static sp =>
        {
            IContentKeyProvider contentKeys = sp.GetRequiredService<IContentKeyProvider>();
            IPostQuantumKeyStore store = sp.GetRequiredService<IPostQuantumKeyStore>();
            return new PostQuantumKeyManager(contentKeys, store);
        });

        // Data Protection's IActivator activates PostQuantumXmlDecryptor via
        // ActivatorUtilities.CreateInstance(serviceProvider, typeof(PostQuantumXmlDecryptor)). The
        // [ActivatorUtilitiesConstructor] on its (IServiceProvider) ctor disambiguates from the
        // explicit-dependency ctor used by tests. We deliberately do NOT register the decryptor
        // as a DI service — that would force ASP.NET Core's strict-DI validator to inspect both
        // constructors and fail on "ambiguous". The activator pattern does not need it.

        // Wire the encryptor onto Data Protection's key-management options. The XmlEncryptor
        // setter is the official seam Data Protection exposes for at-rest key wrapping.
        builder.Services.AddOptions<DataProtectionKeyManagementOptions>().Configure<PostQuantumKeyManager, IContentKeyProvider>(
            (keyManagementOptions, pqKeys, contentKeys) =>
            {
                HybridKemMode mode = snapshot.Mode;
                keyManagementOptions.XmlEncryptor = new PostQuantumXmlEncryptor(pqKeys, contentKeys, mode);
            });

        return builder;
    }

    /// <summary>
    /// Convenience overload for callers who do not need to tune anything beyond the file path.
    /// </summary>
    public static IDataProtectionBuilder ProtectKeysWithPostQuantum(this IDataProtectionBuilder builder, string keyStorePath)
        => builder.ProtectKeysWithPostQuantum(o => o.KeyStorePath = keyStorePath);
}
