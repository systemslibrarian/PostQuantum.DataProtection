using System.Security.Cryptography;
using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Redis;

/// <summary>
/// Redis-backed <see cref="IRotationLock"/>. Uses a single short-lived lease key
/// (<c>{prefix}:rotation-lock</c>) taken with <c>SET key value NX PX</c> so that, across many
/// application replicas sharing one Redis, at most one replica performs a given scheduled rotation.
/// </summary>
/// <remarks>
/// The lease auto-expires after the requested duration, so a replica that crashes mid-rotation does
/// not block rotation forever. Release is value-checked: a replica only deletes the lease if it
/// still owns it, so an expired-and-retaken lease is never clobbered.
/// </remarks>
public sealed class RedisRotationLock : IRotationLock
{
    private readonly IRedisKeyStoreClient _client;
    private readonly string _lockKey;

    /// <summary>Creates the lock against the given client, namespaced by <paramref name="prefix"/>.</summary>
    public RedisRotationLock(IRedisKeyStoreClient client, string prefix = RedisPostQuantumKeyStore.DefaultPrefix)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        _client = client;
        _lockKey = prefix + ":rotation-lock";
    }

    /// <inheritdoc />
    public async ValueTask<IAsyncDisposable?> TryAcquireAsync(TimeSpan leaseDuration, CancellationToken cancellationToken = default)
    {
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        bool taken = await _client.LockTakeAsync(_lockKey, token, leaseDuration, cancellationToken).ConfigureAwait(false);
        return taken ? new Lease(_client, _lockKey, token) : null;
    }

    private sealed class Lease : IAsyncDisposable
    {
        private readonly IRedisKeyStoreClient _client;
        private readonly string _lockKey;
        private readonly string _token;

        public Lease(IRedisKeyStoreClient client, string lockKey, string token)
        {
            _client = client;
            _lockKey = lockKey;
            _token = token;
        }

        public async ValueTask DisposeAsync() =>
            await _client.LockReleaseAsync(_lockKey, _token, CancellationToken.None).ConfigureAwait(false);
    }
}
