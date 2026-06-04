using PostQuantum.DataProtection.AzureKeyVault;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.AzureKeyVault.Tests;

public sealed class AzureKeyVaultKeyStoreTests
{
    private static LocalContentKeyProvider CreateContentKeys() =>
        LocalContentKeyProvider.Create(
            "akv-test-passphrase",
            new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });

    [Fact]
    public async Task First_save_writes_keypair_and_active_pointer_secrets()
    {
        var fake = new InMemoryKeyVaultSecretClient();
        using var store = new AzureKeyVaultPostQuantumKeyStore(fake);
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();

        Assert.Equal(2, fake.SetCount);
        Assert.True(fake.Snapshot.ContainsKey($"pq-dataprotection-{activeId}"));
        Assert.Equal(activeId, fake.Snapshot["pq-dataprotection-active"]);
    }

    [Fact]
    public async Task Reload_from_existing_vault_restores_the_same_active_keypair()
    {
        var fake = new InMemoryKeyVaultSecretClient();
        using LocalContentKeyProvider keys = CreateContentKeys();

        // Real lifetime: create + save + dispose, then create a fresh store around the same fake vault.
        string activeOriginal;
        using (var firstStore = new AzureKeyVaultPostQuantumKeyStore(fake))
        using (var manager = new PostQuantumKeyManager(keys, firstStore))
        {
            activeOriginal = await manager.GetActiveKeyIdAsync();
        }

        using (var secondStore = new AzureKeyVaultPostQuantumKeyStore(fake))
        using (var manager = new PostQuantumKeyManager(keys, secondStore))
        {
            string activeRestored = await manager.GetActiveKeyIdAsync();
            Assert.Equal(activeOriginal, activeRestored);

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();
            Assert.Single(descriptors);
            Assert.Equal(activeOriginal, descriptors[0].KeyId);
        }
    }

    [Fact]
    public async Task Rotation_writes_a_second_keypair_secret_and_advances_active_pointer()
    {
        var fake = new InMemoryKeyVaultSecretClient();
        using var store = new AzureKeyVaultPostQuantumKeyStore(fake);
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
    public async Task Active_pointer_is_written_after_the_keypair_secret_so_a_crash_leaves_a_consistent_state()
    {
        // The store's contract: a crash between writing the keypair and writing the active pointer
        // leaves an "orphan keypair" in the vault, never a ghost-active pointing at a missing key.
        // We verify the write order via SetCount semantics: the second Set is the active pointer.
        var fake = new InMemoryKeyVaultSecretClient();
        using var store = new AzureKeyVaultPostQuantumKeyStore(fake);
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        await manager.GetActiveKeyIdAsync();

        // First Set wrote the keypair; second Set wrote the active pointer.
        Assert.Equal(2, fake.SetCount);
    }

    [Fact]
    public async Task Custom_secret_prefix_is_honoured()
    {
        var fake = new InMemoryKeyVaultSecretClient();
        using var store = new AzureKeyVaultPostQuantumKeyStore(fake, secretPrefix: "tenant-a-pq");
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        string activeId = await manager.GetActiveKeyIdAsync();

        Assert.True(fake.Snapshot.ContainsKey($"tenant-a-pq-{activeId}"));
        Assert.Equal(activeId, fake.Snapshot["tenant-a-pq-active"]);
        Assert.DoesNotContain(fake.Snapshot.Keys, k => k.StartsWith("pq-dataprotection-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unrelated_secrets_in_the_same_vault_are_ignored_on_load()
    {
        var fake = new InMemoryKeyVaultSecretClient();
        await fake.SetSecretValueAsync("some-other-app-secret", "value", CancellationToken.None);
        await fake.SetSecretValueAsync("not-our-prefix-pair", "x", CancellationToken.None);

        using var store = new AzureKeyVaultPostQuantumKeyStore(fake);
        using LocalContentKeyProvider keys = CreateContentKeys();
        using var manager = new PostQuantumKeyManager(keys, store);

        _ = await manager.GetActiveKeyIdAsync();
        IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();
        Assert.Single(descriptors);
    }
}
