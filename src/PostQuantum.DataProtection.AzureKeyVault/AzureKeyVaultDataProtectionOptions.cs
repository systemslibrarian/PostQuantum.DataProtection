using Azure.Core;

namespace PostQuantum.DataProtection.AzureKeyVault;

/// <summary>
/// Configuration for the Azure Key Vault-backed PQ key store.
/// </summary>
public sealed class AzureKeyVaultDataProtectionOptions
{
    /// <summary>The vault URI, e.g. <c>https://my-vault.vault.azure.net/</c>. Required.</summary>
    public Uri? VaultUri { get; set; }

    /// <summary>
    /// Token credential to authenticate with. When null, the registration extension supplies a
    /// <c>DefaultAzureCredential</c> with no special options — the standard cloud-native discovery
    /// chain (managed identity, environment variables, Azure CLI, etc.).
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>
    /// Secret-name prefix to use inside the vault. Defaults to
    /// <see cref="AzureKeyVaultPostQuantumKeyStore.DefaultSecretPrefix"/>. Override only if you
    /// share one vault across multiple PQ key rings.
    /// </summary>
    public string SecretPrefix { get; set; } = AzureKeyVaultPostQuantumKeyStore.DefaultSecretPrefix;
}
