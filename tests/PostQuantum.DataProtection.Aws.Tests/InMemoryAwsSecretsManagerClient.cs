using System.Collections.Concurrent;
using PostQuantum.DataProtection.Aws;

namespace PostQuantum.DataProtection.Aws.Tests;

public sealed class InMemoryAwsSecretsManagerClient : IAwsSecretsManagerClient
{
    private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, string> Snapshot => _values;

    public int SetCount { get; private set; }

    public ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken) =>
        new(_values.TryGetValue(name, out string? v) ? v : null);

#pragma warning disable CS1998
    public async IAsyncEnumerable<string> ListSecretNamesAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
#pragma warning restore CS1998
    {
        foreach (string name in _values.Keys.OrderBy(n => n, StringComparer.Ordinal))
        {
            yield return name;
        }
    }

    public ValueTask SetSecretValueAsync(string name, string value, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _SetCountField);
        _values[name] = value;
        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken)
        => new(_values.TryRemove(name, out _));

    private int _SetCountField;

    int SetCountInternal => _SetCountField;
}
