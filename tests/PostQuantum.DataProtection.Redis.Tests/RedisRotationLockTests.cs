using PostQuantum.DataProtection.Keys;
using PostQuantum.DataProtection.Redis;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Redis.Tests;

/// <summary>
/// Proves the multi-replica rotation-concurrency contract: when many replicas share one Redis and
/// each gates its scheduled rotation on <see cref="RedisRotationLock"/>, at most one replica rotates
/// per window. This is the evidence that backs the "single-leader scheduled rotation" claim short of
/// a live multi-pod deployment.
/// </summary>
public sealed class RedisRotationLockTests
{
    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(5);

    private static LocalContentKeyProvider CreateKeys() =>
        LocalContentKeyProvider.Create(
            "redis-rotation-lock-test-passphrase",
            new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });

    [Fact]
    public async Task Only_one_of_many_concurrent_acquirers_wins_the_lease()
    {
        var redis = new InMemoryRedisClient();
        var rotationLock = new RedisRotationLock(redis);

        const int contenders = 32;
        var leases = await Task.WhenAll(
            Enumerable.Range(0, contenders).Select(_ => Task.Run(async () =>
                await rotationLock.TryAcquireAsync(Lease))));

        Assert.Equal(1, leases.Count(l => l is not null));
    }

    [Fact]
    public async Task Lease_can_be_reacquired_after_release()
    {
        var redis = new InMemoryRedisClient();
        var rotationLock = new RedisRotationLock(redis);

        IAsyncDisposable? first = await rotationLock.TryAcquireAsync(Lease);
        Assert.NotNull(first);

        // Held — a second acquire fails.
        Assert.Null(await rotationLock.TryAcquireAsync(Lease));

        await first!.DisposeAsync();

        // Released — a fresh acquire succeeds.
        IAsyncDisposable? second = await rotationLock.TryAcquireAsync(Lease);
        Assert.NotNull(second);
        await second!.DisposeAsync();
    }

    [Fact]
    public async Task Concurrent_replicas_produce_exactly_one_new_keypair_per_window()
    {
        // One shared Redis and KEK across all replicas — the real multi-replica topology.
        var redis = new InMemoryRedisClient();
        using LocalContentKeyProvider keys = CreateKeys();

        // Establish the inaugural keypair once, before the contended window.
        using (var seedStore = new RedisPostQuantumKeyStore(redis))
        using (var seedManager = new PostQuantumKeyManager(keys, seedStore))
        {
            await seedManager.GetActiveKeyIdAsync();
        }

        int countBefore = (await new RedisPostQuantumKeyStore(redis).LoadAllAsync()).Count;
        Assert.Equal(1, countBefore);

        // Each replica runs the hosted-service rotation step: take the lease, rotate if won, else skip.
        const int replicas = 8;
        int rotationsPerformed = 0;

        await Task.WhenAll(Enumerable.Range(0, replicas).Select(_ => Task.Run(async () =>
        {
            var rotationLock = new RedisRotationLock(redis);
            using var store = new RedisPostQuantumKeyStore(redis);
            using var manager = new PostQuantumKeyManager(keys, store);
            await manager.GetActiveKeyIdAsync();

            await using IAsyncDisposable? lease = await rotationLock.TryAcquireAsync(Lease);
            if (lease is null)
            {
                return; // another replica owns this window — skip, exactly like the hosted service
            }

            await manager.RotateAsync();
            Interlocked.Increment(ref rotationsPerformed);
        })));

        Assert.Equal(1, rotationsPerformed);

        // The store grew by exactly one keypair (inaugural + one rotation), not by one-per-replica.
        IReadOnlyList<PostQuantumKeyPair> after = await new RedisPostQuantumKeyStore(redis).LoadAllAsync();
        Assert.Equal(2, after.Count);
    }
}
