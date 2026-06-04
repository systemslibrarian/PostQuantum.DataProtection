using System.Collections.Concurrent;
using PostQuantum.DataProtection.AzureKeyVault;

namespace PostQuantum.DataProtection.AzureKeyVault.Tests;

/// <summary>
/// In-memory <see cref="IKeyVaultSecretClient"/> that lets the keystore tests exercise the full
/// load/save/race flow without standing up a real Key Vault. The implementation is intentionally
/// simple — concurrent reads + writes are serialised through a <see cref="ConcurrentDictionary{TKey, TValue}"/>,
/// which matches Key Vault's "last writer wins" per-secret semantics closely enough for unit tests.
/// </summary>
public sealed class InMemoryKeyVaultSecretClient : IKeyVaultSecretClient
{
    private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);
    private int _setCount;
    private int _getCount;
    private int _listCount;

    public int SetCount => _setCount;
    public int GetCount => _getCount;
    public int ListCount => _listCount;

    public IReadOnlyDictionary<string, string> Snapshot => _values;

    public ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _getCount);
        return new ValueTask<string?>(_values.TryGetValue(name, out string? v) ? v : null);
    }

#pragma warning disable CS1998 // async method lacks await — we want an IAsyncEnumerable seam, not a hot async loop
    public async IAsyncEnumerable<string> ListSecretNamesAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
#pragma warning restore CS1998
    {
        Interlocked.Increment(ref _listCount);
        foreach (string name in _values.Keys.OrderBy(n => n, StringComparer.Ordinal))
        {
            yield return name;
        }
    }

    public ValueTask<string> SetSecretValueAsync(string name, string value, CancellationToken cancellationToken)
    {
        int versionId = Interlocked.Increment(ref _setCount);
        _values[name] = value;
        return new ValueTask<string>(versionId.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    public ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken)
        => new(_values.TryRemove(name, out _));
}
