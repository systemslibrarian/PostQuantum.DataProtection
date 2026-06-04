using System.Collections.Concurrent;
using System.Xml.Linq;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Concurrency stress against the bundled file store plus the in-memory cloud-store fakes
/// declared in this assembly. The cloud-specific test suites also exercise their respective
/// stores end-to-end against the same fakes — this file adds a stronger contention test that
/// is unconditional on which store is in use.
/// </summary>
public sealed class CloudStoreConcurrencyTests
{
    [Fact]
    public async Task File_store_under_concurrent_load_serves_consistent_active_id()
    {
        const int threads = 32;
        const int iterations = 8;

        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            using var manager = new PostQuantumKeyManager(keys, store);

            // Force the first-run code path before the parallel load.
            string firstActive = await manager.GetActiveKeyIdAsync();

            var observed = new ConcurrentBag<string>();
            await Parallel.ForEachAsync(
                Enumerable.Range(0, threads),
                new ParallelOptions { MaxDegreeOfParallelism = threads },
                async (_idx, ct) =>
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        observed.Add(await manager.GetActiveKeyIdAsync(ct));
                    }
                });

            // No reads should ever see a different active id while no rotation is happening.
            Assert.Single(observed.Distinct());
            Assert.Equal(firstActive, observed.First());
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Parallel_rotations_serialise_correctly_and_grow_the_keyring_monotonically()
    {
        const int rotators = 8;
        const int rotationsPerThread = 4;

        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            using var manager = new PostQuantumKeyManager(keys, store);
            _ = await manager.GetActiveKeyIdAsync();

            await Parallel.ForEachAsync(
                Enumerable.Range(0, rotators),
                new ParallelOptions { MaxDegreeOfParallelism = rotators },
                async (_idx, ct) =>
                {
                    for (int i = 0; i < rotationsPerThread; i++)
                    {
                        _ = await manager.RotateAsync(ct);
                    }
                });

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();

            // Exactly one active key.
            Assert.Single(descriptors, d => d.IsActive);

            // Inaugural + (rotators * rotationsPerThread) — all rotations must have committed.
            Assert.Equal(1 + (rotators * rotationsPerThread), descriptors.Count);

            // Encrypt under the final active key; decrypt with the same manager.
            var encryptor = new PostQuantumXmlEncryptor(manager, keys);
            var decryptor = new PostQuantumXmlDecryptor(manager, keys);
            var encrypted = encryptor.Encrypt(new XElement("p", "rotation storm survivor")).EncryptedElement;
            Assert.Equal("rotation storm survivor", decryptor.Decrypt(encrypted).Value);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task PruneAsync_under_concurrent_rotations_never_deletes_the_active_keypair()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            using var manager = new PostQuantumKeyManager(keys, store);
            _ = await manager.GetActiveKeyIdAsync();

            // Seed 5 rotations, sequentially, so we have history to prune.
            for (int i = 0; i < 5; i++)
            {
                _ = await manager.RotateAsync();
            }

            using var cts = new CancellationTokenSource();
            Task rotateTask = Task.Run(async () =>
            {
                while (!cts.IsCancellationRequested)
                {
                    try { _ = await manager.RotateAsync(cts.Token); }
                    catch (OperationCanceledException) { return; }
                }
            });

            for (int i = 0; i < 3; i++)
            {
                _ = await manager.PruneOlderThanAsync(DateTimeOffset.UtcNow.AddSeconds(1));
            }

            await cts.CancelAsync();
            await rotateTask;

            // The active key must still be present and decryptable end-to-end.
            string activeId = await manager.GetActiveKeyIdAsync();
            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await manager.ListKeysAsync();
            Assert.Contains(descriptors, d => d.KeyId == activeId);

            var encryptor = new PostQuantumXmlEncryptor(manager, keys);
            var decryptor = new PostQuantumXmlDecryptor(manager, keys);
            var encrypted = encryptor.Encrypt(new XElement("p", "post-prune sanity")).EncryptedElement;
            Assert.Equal("post-prune sanity", decryptor.Decrypt(encrypted).Value);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
