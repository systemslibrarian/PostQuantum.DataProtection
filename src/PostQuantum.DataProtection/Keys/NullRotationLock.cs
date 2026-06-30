namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// The default <see cref="IRotationLock"/>: a no-op that always grants the lease. Use this — it is
/// registered automatically — when the deployment rotates from a single writer (one replica, a
/// leader-elected pod, a cron job, or manual operator action). Replace it with a distributed lock
/// (for example the Redis package's <c>RedisRotationLock</c>) when more than one replica runs the
/// scheduled rotation against a shared keystore.
/// </summary>
public sealed class NullRotationLock : IRotationLock
{
    /// <summary>The shared instance.</summary>
    public static readonly NullRotationLock Instance = new();

    /// <inheritdoc />
    public ValueTask<IAsyncDisposable?> TryAcquireAsync(TimeSpan leaseDuration, CancellationToken cancellationToken = default)
        => new((IAsyncDisposable?)NoopLease.Instance);

    private sealed class NoopLease : IAsyncDisposable
    {
        public static readonly NoopLease Instance = new();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
