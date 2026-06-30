using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.DataProtection.Testing;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

// ReSharper disable once CheckNamespace — extensions live in the host namespace by .NET convention.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods that wire a fully-in-memory PQ data-protection chain into a
/// <see cref="IServiceCollection"/>. Intended for consumer unit tests.
/// </summary>
public static class PostQuantumDataProtectionTestingServiceCollectionExtensions
{
    private const string DefaultTestPassphrase = "post-quantum-dataprotection-testing-passphrase-do-not-use-in-production";

    /// <summary>
    /// Registers a complete in-memory PQ data-protection stack:
    /// <list type="bullet">
    ///   <item><description>A <see cref="LocalContentKeyProvider"/> backed by
    ///   <see cref="DefaultTestPassphrase"/> at the smallest Argon2id work factor.</description></item>
    ///   <item><description>A <see cref="FakePostQuantumKeyStore"/>.</description></item>
    ///   <item><description>A <see cref="PostQuantumKeyManager"/> bound to both.</description></item>
    ///   <item><description>An <c>AddDataProtection()</c> chain wired with the PQ encryptor in
    ///   <see cref="HybridKemMode.Hybrid"/> mode.</description></item>
    /// </list>
    /// Suitable for any test that just needs an <see cref="IDataProtectionProvider"/> to call
    /// <c>Protect</c> / <c>Unprotect</c> against, without a real keystore on disk.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionTesting(this IServiceCollection services)
        => services.AddPostQuantumDataProtectionTesting(HybridKemMode.XWingHybrid);

    /// <summary>
    /// Registers the same in-memory PQ data-protection stack as
    /// <see cref="AddPostQuantumDataProtectionTesting(IServiceCollection)"/>, but lets the test pick
    /// the <see cref="HybridKemMode"/> so mode-agnostic consumer code can be exercised under
    /// <see cref="HybridKemMode.MlKemOnly"/>, <see cref="HybridKemMode.Hybrid"/>, and
    /// <see cref="HybridKemMode.XWingHybrid"/>.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionTesting(this IServiceCollection services, HybridKemMode mode)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Host KEK provider — tiny Argon2id cost so the inaugural ML-KEM keypair generation is fast.
        services.TryAddSingleton<IContentKeyProvider>(_ => LocalContentKeyProvider.Create(
            DefaultTestPassphrase,
            new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 }));

        // In-memory PQ keystore + manager.
        services.TryAddSingleton<IPostQuantumKeyStore>(_ => new FakePostQuantumKeyStore());
        services.TryAddSingleton<PostQuantumKeyManager>(static sp =>
            new PostQuantumKeyManager(
                sp.GetRequiredService<IContentKeyProvider>(),
                sp.GetRequiredService<IPostQuantumKeyStore>()));

        // Data Protection chain. We do not call PersistKeysToFileSystem — DataProtection's default
        // in-memory key storage is exactly what we want in tests. The PQ wrap still applies to the
        // in-memory representation.
        services
            .AddDataProtection()
            .Services
            .AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>()
            .Configure<PostQuantumKeyManager, IContentKeyProvider>(
                (options, pqKeys, contentKeys) =>
                {
                    options.XmlEncryptor = new PostQuantumXmlEncryptor(pqKeys, contentKeys, mode);
                });

        return services;
    }
}
