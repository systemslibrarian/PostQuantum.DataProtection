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
}
