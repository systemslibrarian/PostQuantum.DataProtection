using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class KeyDescriptorTests
{
    [Fact]
    public async Task ListKeysAsync_returns_one_active_keypair_after_first_run()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await pq.ListKeysAsync();

            Assert.Single(descriptors);
            PostQuantumKeyDescriptor only = descriptors[0];
            Assert.StartsWith("pq-mlkem768-", only.KeyId, StringComparison.Ordinal);
            Assert.Equal("ML-KEM-768", only.Algorithm);
            Assert.True(only.IsActive);
            Assert.InRange(only.CreatedAt, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(5));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task ListKeysAsync_after_rotation_returns_old_and_new_with_only_new_active()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            string oldId = await pq.GetActiveKeyIdAsync();
            string newId = await pq.RotateAsync();

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await pq.ListKeysAsync();

            Assert.Equal(2, descriptors.Count);
            Assert.Single(descriptors, d => d.IsActive);

            PostQuantumKeyDescriptor active = descriptors.Single(d => d.IsActive);
            Assert.Equal(newId, active.KeyId);

            PostQuantumKeyDescriptor inactive = descriptors.Single(d => !d.IsActive);
            Assert.Equal(oldId, inactive.KeyId);

            // Ordering is by creation time ascending: old keypair created first.
            Assert.True(descriptors[0].CreatedAt <= descriptors[1].CreatedAt);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
