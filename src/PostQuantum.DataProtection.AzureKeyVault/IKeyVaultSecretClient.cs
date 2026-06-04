namespace PostQuantum.DataProtection.AzureKeyVault;

/// <summary>
/// Narrow seam over the bits of <c>Azure.Security.KeyVault.Secrets.SecretClient</c> that
/// <see cref="AzureKeyVaultPostQuantumKeyStore"/> needs. Lets the store be unit-tested against an
/// in-memory implementation without standing up a real vault.
/// </summary>
public interface IKeyVaultSecretClient
{
    /// <summary>Fetches the value of the secret with the given name. Returns <see langword="null"/> if the secret does not exist.</summary>
    ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken);

    /// <summary>Lists the names of every secret in the vault.</summary>
    IAsyncEnumerable<string> ListSecretNamesAsync(CancellationToken cancellationToken);

    /// <summary>Sets the value of a secret, creating it if necessary. Returns the new version identifier.</summary>
    ValueTask<string> SetSecretValueAsync(string name, string value, CancellationToken cancellationToken);
}
