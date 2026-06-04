using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

namespace PostQuantum.DataProtection.Aws;

/// <summary>
/// Default <see cref="IAwsSecretsManagerClient"/> implementation that wraps the real AWS SDK
/// <see cref="IAmazonSecretsManager"/> client.
/// </summary>
internal sealed class AwsSecretsManagerClientAdapter : IAwsSecretsManagerClient
{
    private readonly IAmazonSecretsManager _inner;

    public AwsSecretsManagerClientAdapter(IAmazonSecretsManager inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
    }

    public async ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            GetSecretValueResponse response = await _inner.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = name },
                cancellationToken).ConfigureAwait(false);
            return response.SecretString;
        }
        catch (ResourceNotFoundException)
        {
            return null;
        }
    }

    public async IAsyncEnumerable<string> ListSecretNamesAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? nextToken = null;
        do
        {
            ListSecretsResponse response = await _inner.ListSecretsAsync(
                new ListSecretsRequest { MaxResults = 100, NextToken = nextToken },
                cancellationToken).ConfigureAwait(false);

            if (response.SecretList is not null)
            {
                foreach (SecretListEntry entry in response.SecretList)
                {
                    if (!string.IsNullOrEmpty(entry.Name))
                    {
                        yield return entry.Name;
                    }
                }
            }

            nextToken = response.NextToken;
        }
        while (!string.IsNullOrEmpty(nextToken));
    }

    public async ValueTask SetSecretValueAsync(string name, string value, CancellationToken cancellationToken)
    {
        try
        {
            await _inner.PutSecretValueAsync(
                new PutSecretValueRequest { SecretId = name, SecretString = value },
                cancellationToken).ConfigureAwait(false);
        }
        catch (ResourceNotFoundException)
        {
            await _inner.CreateSecretAsync(
                new CreateSecretRequest { Name = name, SecretString = value },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            await _inner.DeleteSecretAsync(
                new DeleteSecretRequest { SecretId = name, ForceDeleteWithoutRecovery = false },
                cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (ResourceNotFoundException)
        {
            return false;
        }
    }
}
