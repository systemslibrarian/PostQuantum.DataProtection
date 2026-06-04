using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.AzureKeyVault;

/// <summary>
/// Azure Key Vault-backed <see cref="IPostQuantumKeyStore"/>. Stores each
/// <see cref="PostQuantumKeyPair"/> as a Key Vault Secret named <c>{prefix}-{keyId}</c>, with the
/// active key id pinned in a separate <c>{prefix}-active</c> secret.
/// </summary>
/// <remarks>
/// <para>
/// The PQ secret key inside each keypair token is already envelope-encrypted by the host
/// <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/> before it reaches this store. Key
/// Vault sees an opaque blob; it is a durable persistence target, not a new trust boundary.
/// </para>
/// <para>
/// <b>Concurrency.</b> The store caches the loaded keypairs in memory on first read and updates
/// the cache on every <see cref="SaveAsync"/>. The <c>{prefix}-active</c> secret is updated last
/// so that a partial save (key written, active pointer not yet written) leaves the prior active
/// pointer in place — readers never see a "ghost active" pointing at a key that does not exist
/// in the cache. Concurrent rotations from two replicas race for the active pointer; Key Vault's
/// per-secret versioning guarantees the last writer's value persists.
/// </para>
/// <para>
/// <b>Cost.</b> Each rotation = 2 Key Vault writes (the keypair + the active pointer); each
/// host startup = 1 list + N reads, where N is the number of keypairs ever generated. Plan for
/// the Key Vault transaction cost accordingly.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultPostQuantumKeyStore : IPostQuantumKeyStore, IDisposable
{
    /// <summary>Default secret-name prefix. Override via the options if you share a vault across hosts.</summary>
    public const string DefaultSecretPrefix = "pq-dataprotection";

    /// <summary>Suffix of the secret that stores the active keypair id.</summary>
    public const string ActivePointerSuffix = "active";

    private readonly IKeyVaultSecretClient _client;
    private readonly string _prefix;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly object _stateLock = new();
    private bool _loaded;
    private Dictionary<string, PostQuantumKeyPair> _byId = new(StringComparer.Ordinal);
    private string? _activeKeyId;

    /// <summary>
    /// Creates the store. Production callers go through
    /// <c>AddPostQuantumDataProtectionAzureKeyVault(...)</c>; this ctor is exposed for tests and
    /// for hand-wired hosts.
    /// </summary>
    public AzureKeyVaultPostQuantumKeyStore(IKeyVaultSecretClient client, string secretPrefix = DefaultSecretPrefix)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretPrefix);
        _client = client;
        _prefix = secretPrefix;
    }

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

        // Write the keypair first, then the active pointer. A crash between the two leaves the
        // prior active pointer intact and the new keypair as an "orphan" that is reachable by id
        // but not active — perfectly recoverable on a retry.
        string keypairSecretName = KeypairSecretName(newActive.KeyId);
        await _client.SetSecretValueAsync(keypairSecretName, newActive.Encode(), cancellationToken).ConfigureAwait(false);
        await _client.SetSecretValueAsync(ActivePointerSecretName(), newActive.KeyId, cancellationToken).ConfigureAwait(false);

        lock (_stateLock)
        {
            _byId[newActive.KeyId] = newActive;
            _activeKeyId = newActive.KeyId;
        }
    }

    private string KeypairSecretName(string keyId) => $"{_prefix}-{keyId}";

    private string ActivePointerSecretName() => $"{_prefix}-{ActivePointerSuffix}";

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

            string activePointer = ActivePointerSecretName();
            string keypairPrefix = $"{_prefix}-";

            var byId = new Dictionary<string, PostQuantumKeyPair>(StringComparer.Ordinal);
            await foreach (string secretName in _client.ListSecretNamesAsync(cancellationToken).ConfigureAwait(false))
            {
                if (string.Equals(secretName, activePointer, StringComparison.Ordinal))
                {
                    continue;
                }

                if (!secretName.StartsWith(keypairPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                string? value = await _client.GetSecretValueAsync(secretName, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                if (PostQuantumKeyPair.TryDecode(value, out PostQuantumKeyPair? pair))
                {
                    byId[pair.KeyId] = pair;
                }
            }

            string? activeId = await _client.GetSecretValueAsync(activePointer, cancellationToken).ConfigureAwait(false);

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
