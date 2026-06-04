using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using PostQuantum.DataProtection.AzureKeyVault;
using PostQuantum.DataProtection.Keys;

// ReSharper disable once CheckNamespace — extensions for IServiceCollection live in the host's
// namespace by .NET convention.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI extensions that swap the bundled file store for the Azure Key Vault-backed
/// <see cref="AzureKeyVaultPostQuantumKeyStore"/>.
/// </summary>
public static class AzureKeyVaultPostQuantumServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="IPostQuantumKeyStore"/> backed by Azure Key Vault. Call after
    /// <c>AddDataProtection().ProtectKeysWithPostQuantum(...)</c> to replace the default file
    /// store.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionAzureKeyVault(
        this IServiceCollection services,
        Action<AzureKeyVaultDataProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var snapshot = new AzureKeyVaultDataProtectionOptions();
        configure(snapshot);

        if (snapshot.VaultUri is null)
        {
            throw new InvalidOperationException(
                "AzureKeyVaultDataProtectionOptions.VaultUri is required (e.g. new Uri(\"https://my-vault.vault.azure.net/\")).");
        }

        services.AddOptions<AzureKeyVaultDataProtectionOptions>().Configure(configure);

        // Replace any previously registered IPostQuantumKeyStore (e.g. the default FilePostQuantumKeyStore).
        services.RemoveAll<IPostQuantumKeyStore>();
        services.AddSingleton<IPostQuantumKeyStore>(static sp =>
        {
            AzureKeyVaultDataProtectionOptions o = sp.GetRequiredService<IOptions<AzureKeyVaultDataProtectionOptions>>().Value;
            var credential = o.Credential ?? new DefaultAzureCredential();
            var client = new SecretClient(o.VaultUri!, credential);
            IKeyVaultSecretClient adapter = new KeyVaultSecretClientAdapter(client);
            return new AzureKeyVaultPostQuantumKeyStore(adapter, o.SecretPrefix);
        });

        return services;
    }

    /// <summary>
    /// Convenience overload that only takes the vault URI; uses <c>DefaultAzureCredential</c> and
    /// the default secret prefix.
    /// </summary>
    public static IServiceCollection AddPostQuantumDataProtectionAzureKeyVault(this IServiceCollection services, Uri vaultUri)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        return services.AddPostQuantumDataProtectionAzureKeyVault(o => o.VaultUri = vaultUri);
    }
}
