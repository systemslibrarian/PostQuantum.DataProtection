namespace PostQuantum.DataProtection.Aws;

/// <summary>
/// Narrow seam over the bits of <c>Amazon.SecretsManager.IAmazonSecretsManager</c> that
/// <see cref="AwsSecretsManagerPostQuantumKeyStore"/> needs. Lets the store be unit-tested against
/// an in-memory implementation without standing up a real AWS account.
/// </summary>
public interface IAwsSecretsManagerClient
{
    /// <summary>Fetches the value of the secret with the given name. Returns <see langword="null"/> if the secret does not exist.</summary>
    ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken);

    /// <summary>Lists the names of every secret accessible from this client.</summary>
    IAsyncEnumerable<string> ListSecretNamesAsync(CancellationToken cancellationToken);

    /// <summary>Sets the value of a secret, creating it if necessary.</summary>
    ValueTask SetSecretValueAsync(string name, string value, CancellationToken cancellationToken);

    /// <summary>Deletes a secret. Returns <see langword="true"/> if a deletion was performed.</summary>
    ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken);
}
