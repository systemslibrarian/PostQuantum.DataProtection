using Azure;
using Azure.Security.KeyVault.Secrets;

namespace PostQuantum.DataProtection.AzureKeyVault;

/// <summary>
/// Default <see cref="IKeyVaultSecretClient"/> implementation that wraps the real Azure SDK
/// <see cref="SecretClient"/>. The wrapper is intentionally thin — every call delegates to
/// <see cref="SecretClient"/> and translates between its types and the narrow seam.
/// </summary>
internal sealed class KeyVaultSecretClientAdapter : IKeyVaultSecretClient
{
    private readonly SecretClient _inner;

    public KeyVaultSecretClientAdapter(SecretClient inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
    }

    public async ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            Response<KeyVaultSecret> response = await _inner.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
            return response.Value?.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async IAsyncEnumerable<string> ListSecretNamesAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (SecretProperties properties in _inner.GetPropertiesOfSecretsAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return properties.Name;
        }
    }

    public async ValueTask<string> SetSecretValueAsync(string name, string value, CancellationToken cancellationToken)
    {
        Response<KeyVaultSecret> response = await _inner.SetSecretAsync(new KeyVaultSecret(name, value), cancellationToken).ConfigureAwait(false);
        return response.Value.Properties.Version;
    }

    public async ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            // Initiate the delete and return immediately — Key Vault soft-delete handles the rest.
            await _inner.StartDeleteSecretAsync(name, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return false;
        }
    }
}
