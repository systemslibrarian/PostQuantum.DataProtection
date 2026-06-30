using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.DataProtection.Keys;
using Xunit;

namespace PostQuantum.DataProtection.Testing.Tests;

public sealed class TestingServiceCollectionExtensionsTests
{
    [Fact]
    public void AddPostQuantumDataProtectionTesting_supports_protect_unprotect_roundtrip()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPostQuantumDataProtectionTesting();

        using ServiceProvider sp = services.BuildServiceProvider();
        IDataProtectionProvider dp = sp.GetRequiredService<IDataProtectionProvider>();
        IDataProtector protector = dp.CreateProtector("testing.purpose");

        string protectedToken = protector.Protect("hello, fake world");
        string roundtripped = protector.Unprotect(protectedToken);

        Assert.Equal("hello, fake world", roundtripped);
    }

    [Fact]
    public async Task FakePostQuantumKeyStore_keeps_old_keypairs_after_rotation()
    {
        var store = new FakePostQuantumKeyStore();
        using var keys = PostQuantum.KeyManagement.Local.LocalContentKeyProvider.Create(
            "test-passphrase",
            new PostQuantum.KeyManagement.Local.LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });
        using var manager = new PostQuantumKeyManager(keys, store);

        string oldId = await manager.GetActiveKeyIdAsync();
        string newId = await manager.RotateAsync();

        IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();
        Assert.Equal(2, descriptors.Count);
        Assert.Equal(newId, descriptors.Single(d => d.IsActive).KeyId);
        Assert.Contains(descriptors, d => d.KeyId == oldId && !d.IsActive);
    }

    [Theory]
    [InlineData(PostQuantum.DataProtection.Hybrid.HybridKemMode.MlKemOnly)]
    [InlineData(PostQuantum.DataProtection.Hybrid.HybridKemMode.Hybrid)]
    [InlineData(PostQuantum.DataProtection.Hybrid.HybridKemMode.XWingHybrid)]
    public void AddPostQuantumDataProtectionTesting_roundtrips_under_every_mode(PostQuantum.DataProtection.Hybrid.HybridKemMode mode)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPostQuantumDataProtectionTesting(mode);

        using ServiceProvider sp = services.BuildServiceProvider();
        IDataProtector protector = sp.GetRequiredService<IDataProtectionProvider>().CreateProtector("p");

        Assert.Equal("payload", protector.Unprotect(protector.Protect("payload")));
    }

    [Fact]
    public async Task CorruptSecretKey_makes_decapsulation_fail_closed()
    {
        var store = new FakePostQuantumKeyStore();
        using var keys = PostQuantum.KeyManagement.Local.LocalContentKeyProvider.Create(
            "test-passphrase",
            new PostQuantum.KeyManagement.Local.LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();
        Assert.True(store.CorruptSecretKey(activeId));

        // Reload from the corrupted store so the manager picks up the mangled wrapped secret key.
        using var reloaded = new PostQuantumKeyManager(keys, store);
        // The secret-key unwrap fails (AEAD tag) before the ciphertext is ever used, so its length is irrelevant.
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(
            async () => await reloaded.DecapsulateAsync(activeId, new byte[1088]));
    }

    [Fact]
    public async Task FakePostQuantumKeyStore_supports_pruning_non_active_keys()
    {
        var store = new FakePostQuantumKeyStore();
        using var keys = PostQuantum.KeyManagement.Local.LocalContentKeyProvider.Create(
            "test-passphrase",
            new PostQuantum.KeyManagement.Local.LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });
        using var manager = new PostQuantumKeyManager(keys, store);

        string oldId = await manager.GetActiveKeyIdAsync();
        _ = await manager.RotateAsync();
        Assert.Equal(2, store.Count);

        // Pruning everything older than "now" removes the non-active old key, never the active one.
        int removed = await manager.PruneOlderThanAsync(DateTimeOffset.UtcNow.AddDays(1));
        Assert.Equal(1, removed);
        Assert.Equal(1, store.Count);
        Assert.DoesNotContain(oldId, store.KeyIds);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.DeleteAsync(store.ActiveKeyId!));
    }
}
