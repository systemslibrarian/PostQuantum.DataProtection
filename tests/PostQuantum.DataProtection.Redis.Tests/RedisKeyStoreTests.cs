using PostQuantum.DataProtection.Keys;
using PostQuantum.DataProtection.Redis;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Redis.Tests;

public sealed class RedisKeyStoreTests
{
    private static LocalContentKeyProvider CreateKeys() =>
        LocalContentKeyProvider.Create(
            "redis-test-passphrase",
            new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });

    [Fact]
    public async Task First_run_writes_keypair_hash_field_and_active_pointer()
    {
        var redis = new InMemoryRedisClient();
        using var store = new RedisPostQuantumKeyStore(redis);
        using LocalContentKeyProvider keys = CreateKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();

        Assert.Equal(activeId, await redis.StringGetAsync("pq-dataprotection:active", CancellationToken.None));
        Assert.NotNull(await redis.HashGetAsync("pq-dataprotection:pairs", activeId, CancellationToken.None));
    }

    [Fact]
    public async Task Reload_restores_the_same_active_keypair()
    {
        var redis = new InMemoryRedisClient();
        using LocalContentKeyProvider keys = CreateKeys();

        string original;
        using (var s1 = new RedisPostQuantumKeyStore(redis))
        using (var m1 = new PostQuantumKeyManager(keys, s1))
        {
            original = await m1.GetActiveKeyIdAsync();
        }

        using (var s2 = new RedisPostQuantumKeyStore(redis))
        using (var m2 = new PostQuantumKeyManager(keys, s2))
        {
            Assert.Equal(original, await m2.GetActiveKeyIdAsync());
            Assert.Single(await m2.ListKeysAsync());
        }
    }

    [Fact]
    public async Task Rotation_then_prune_removes_old_keypair_entry()
    {
        var redis = new InMemoryRedisClient();
        using var store = new RedisPostQuantumKeyStore(redis);
        using LocalContentKeyProvider keys = CreateKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string oldId = await manager.GetActiveKeyIdAsync();
        _ = await manager.RotateAsync();
        int removed = await manager.PruneOlderThanAsync(DateTimeOffset.UtcNow.AddSeconds(5));

        Assert.Equal(1, removed);
        Assert.Null(await redis.HashGetAsync("pq-dataprotection:pairs", oldId, CancellationToken.None));
    }
}
