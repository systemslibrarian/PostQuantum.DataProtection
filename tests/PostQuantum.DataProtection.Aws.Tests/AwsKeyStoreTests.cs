using PostQuantum.DataProtection.Aws;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Aws.Tests;

public sealed class AwsKeyStoreTests
{
    private static LocalContentKeyProvider CreateContentKeys() =>
        LocalContentKeyProvider.Create(
            "aws-test-passphrase",
            new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });

    [Fact]
    public async Task First_save_writes_keypair_and_active_pointer_secrets()
    {
        var fake = new InMemoryAwsSecretsManagerClient();
        using var store = new AwsSecretsManagerPostQuantumKeyStore(fake);
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();

        Assert.True(fake.Snapshot.ContainsKey($"pq-dataprotection-{activeId}"));
        Assert.Equal(activeId, fake.Snapshot["pq-dataprotection-active"]);
    }

    [Fact]
    public async Task Reload_restores_the_same_active_keypair()
    {
        var fake = new InMemoryAwsSecretsManagerClient();
        using LocalContentKeyProvider keys = CreateContentKeys();

        string activeOriginal;
        using (var firstStore = new AwsSecretsManagerPostQuantumKeyStore(fake))
        using (var manager = new PostQuantumKeyManager(keys, firstStore))
        {
            activeOriginal = await manager.GetActiveKeyIdAsync();
        }

        using (var secondStore = new AwsSecretsManagerPostQuantumKeyStore(fake))
        using (var manager = new PostQuantumKeyManager(keys, secondStore))
        {
            string activeRestored = await manager.GetActiveKeyIdAsync();
            Assert.Equal(activeOriginal, activeRestored);

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();
            Assert.Single(descriptors);
        }
    }

    [Fact]
    public async Task Rotation_writes_second_keypair_and_advances_active_pointer()
    {
        var fake = new InMemoryAwsSecretsManagerClient();
        using var store = new AwsSecretsManagerPostQuantumKeyStore(fake);
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string oldId = await manager.GetActiveKeyIdAsync();
        string newId = await manager.RotateAsync();

        Assert.NotEqual(oldId, newId);
        Assert.True(fake.Snapshot.ContainsKey($"pq-dataprotection-{oldId}"));
        Assert.True(fake.Snapshot.ContainsKey($"pq-dataprotection-{newId}"));
        Assert.Equal(newId, fake.Snapshot["pq-dataprotection-active"]);
    }

    [Fact]
    public async Task Custom_prefix_is_honoured()
    {
        var fake = new InMemoryAwsSecretsManagerClient();
        using var store = new AwsSecretsManagerPostQuantumKeyStore(fake, secretPrefix: "tenant-z-pq");
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();
        Assert.True(fake.Snapshot.ContainsKey($"tenant-z-pq-{activeId}"));
        Assert.Equal(activeId, fake.Snapshot["tenant-z-pq-active"]);
    }
}
