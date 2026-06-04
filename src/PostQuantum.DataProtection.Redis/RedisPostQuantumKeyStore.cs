using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Redis;

/// <summary>
/// Redis-backed <see cref="IPostQuantumKeyStore"/>. Stores keypair tokens as fields inside a hash
/// keyed by <c>{prefix}:pairs</c> and the active key id as a string at <c>{prefix}:active</c>.
/// </summary>
public sealed class RedisPostQuantumKeyStore : IPostQuantumKeyStore, IDisposable
{
    /// <summary>Default key prefix. Override to namespace within a shared Redis database.</summary>
    public const string DefaultPrefix = "pq-dataprotection";

    private readonly IRedisKeyStoreClient _client;
    private readonly string _prefix;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly object _stateLock = new();
    private bool _loaded;
    private Dictionary<string, PostQuantumKeyPair> _byId = new(StringComparer.Ordinal);
    private string? _activeKeyId;

    /// <summary>Creates the store.</summary>
    public RedisPostQuantumKeyStore(IRedisKeyStoreClient client, string prefix = DefaultPrefix)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        _client = client;
        _prefix = prefix;
    }

    private string PairsKey => _prefix + ":pairs";
    private string ActiveKey => _prefix + ":active";

    /// <inheritdoc />
    public string? ActiveKeyId
    {
        get
        {
            EnsureLoadedSync();
            lock (_stateLock)
            {
                return _activeKeyId;
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<PostQuantumKeyPair>> LoadAllAsync(CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        lock (_stateLock)
        {
            return _byId.Values.OrderBy(p => p.CreatedAtUnixMs).ToArray();
        }
    }

    /// <inheritdoc />
    public async ValueTask SaveAsync(PostQuantumKeyPair newActive, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newActive);
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);

        await _client.HashSetAsync(PairsKey, newActive.KeyId, newActive.Encode(), cancellationToken).ConfigureAwait(false);
        await _client.StringSetAsync(ActiveKey, newActive.KeyId, cancellationToken).ConfigureAwait(false);

        lock (_stateLock)
        {
            _byId[newActive.KeyId] = newActive;
            _activeKeyId = newActive.KeyId;
        }
    }

    /// <inheritdoc />
    public async ValueTask<bool> DeleteAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);

        string? activeId;
        lock (_stateLock)
        {
            activeId = _activeKeyId;
        }

        if (string.Equals(keyId, activeId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Refusing to delete the active PQ keypair '{keyId}'. Rotate first.");
        }

        bool removed = await _client.HashDeleteAsync(PairsKey, keyId, cancellationToken).ConfigureAwait(false);
        if (removed)
        {
            lock (_stateLock)
            {
                _byId.Remove(keyId);
            }
        }

        return removed;
    }

    private void EnsureLoadedSync()
    {
        if (Volatile.Read(ref _loaded))
        {
            return;
        }

        EnsureLoadedAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    private async ValueTask EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _loaded))
        {
            return;
        }

        await _loadLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _loaded))
            {
                return;
            }

            IReadOnlyDictionary<string, string> entries = await _client.HashGetAllAsync(PairsKey, cancellationToken).ConfigureAwait(false);
            string? activeId = await _client.StringGetAsync(ActiveKey, cancellationToken).ConfigureAwait(false);

            var byId = new Dictionary<string, PostQuantumKeyPair>(entries.Count, StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> entry in entries)
            {
                if (PostQuantumKeyPair.TryDecode(entry.Value, out PostQuantumKeyPair? pair))
                {
                    byId[pair.KeyId] = pair;
                }
            }

            lock (_stateLock)
            {
                _byId = byId;
                _activeKeyId = string.IsNullOrEmpty(activeId) ? null : activeId;
            }

            Volatile.Write(ref _loaded, true);
        }
        finally
        {
            _loadLock.Release();
        }
    }

    /// <summary>Releases the load-coordination primitive.</summary>
    public void Dispose() => _loadLock.Dispose();
}
