using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class PruneTests
{
    [Fact]
    public async Task PruneOlderThanAsync_removes_old_inactive_keypairs_only()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            _ = await pq.GetActiveKeyIdAsync();
            _ = await pq.RotateAsync();
            string activeId = await pq.GetActiveKeyIdAsync();

            // Two keypairs exist; the older one is inactive.
            IReadOnlyList<PostQuantumKeyDescriptor> before = await pq.ListKeysAsync();
            Assert.Equal(2, before.Count);

            // Prune everything older than now+1s — only the inactive old keypair qualifies.
            int removed = await pq.PruneOlderThanAsync(DateTimeOffset.UtcNow.AddSeconds(1));
            Assert.Equal(1, removed);

            IReadOnlyList<PostQuantumKeyDescriptor> after = await pq.ListKeysAsync();
            Assert.Single(after);
            Assert.Equal(activeId, after[0].KeyId);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task DeleteAsync_on_active_keypair_throws_clear_error()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            string activeId = await pq.GetActiveKeyIdAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.DeleteAsync(activeId));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
