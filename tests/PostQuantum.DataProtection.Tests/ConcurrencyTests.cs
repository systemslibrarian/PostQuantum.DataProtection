using System.Collections.Concurrent;
using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Stress tests that exercise <see cref="PostQuantumKeyManager"/>, the file-backed key store, and
/// the encryptor / decryptor pair under genuine multi-thread contention. They turn the
/// "documented as thread-safe" claim into "tested as thread-safe."
/// </summary>
public sealed class ConcurrencyTests
{
    [Fact]
    public async Task Many_threads_can_encrypt_and_decrypt_against_one_key_manager()
    {
        const int threadCount = 16;
        const int iterationsPerThread = 12;

        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var failures = new ConcurrentBag<Exception>();
            var results = new ConcurrentBag<string>();

            await Parallel.ForEachAsync(
                Enumerable.Range(0, threadCount),
                new ParallelOptions { MaxDegreeOfParallelism = threadCount },
                async (threadId, ct) =>
                {
                    try
                    {
                        for (int i = 0; i < iterationsPerThread; i++)
                        {
                            string payload = $"thread-{threadId}-iter-{i}";
                            var element = new XElement("payload", payload);

                            var encrypted = encryptor.Encrypt(element).EncryptedElement;
                            var roundtripped = decryptor.Decrypt(encrypted);

                            string actual = roundtripped.Value;
                            results.Add(actual);

                            if (!string.Equals(actual, payload, StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException(
                                    $"Mismatch for thread {threadId} iter {i}: expected '{payload}', got '{actual}'.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        failures.Add(ex);
                    }

                    await Task.CompletedTask;
                });

            Assert.Empty(failures);
            Assert.Equal(threadCount * iterationsPerThread, results.Count);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Encryptions_concurrent_with_rotations_all_succeed_and_remain_decryptable()
    {
        // Tests the load-bearing claim: a rotation in flight does not break or corrupt an
        // encryption issued concurrently on another thread. Encryptions issued under the old
        // active key must still decrypt after the active key changes, because the old keypair
        // stays in the loaded set.
        const int encryptThreads = 8;
        const int iterationsPerThread = 8;
        const int rotationCount = 4;

        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var encryptedPayloads = new ConcurrentBag<(string Plaintext, XElement Encrypted)>();
            var failures = new ConcurrentBag<Exception>();

            using var cts = new CancellationTokenSource();

            Task rotationTask = Task.Run(async () =>
            {
                try
                {
                    for (int i = 0; i < rotationCount; i++)
                    {
                        await Task.Delay(20, cts.Token);
                        _ = await pq.RotateAsync(cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // intended: encrypt loop completed first
                }
                catch (Exception ex)
                {
                    failures.Add(ex);
                }
            });

            await Parallel.ForEachAsync(
                Enumerable.Range(0, encryptThreads),
                new ParallelOptions { MaxDegreeOfParallelism = encryptThreads },
                async (threadId, ct) =>
                {
                    try
                    {
                        for (int i = 0; i < iterationsPerThread; i++)
                        {
                            string payload = $"rotation-stress-{threadId}-{i}";
                            var element = new XElement("payload", payload);
                            var encrypted = encryptor.Encrypt(element).EncryptedElement;
                            encryptedPayloads.Add((payload, encrypted));
                        }
                    }
                    catch (Exception ex)
                    {
                        failures.Add(ex);
                    }

                    await Task.CompletedTask;
                });

            await cts.CancelAsync();
            await rotationTask;

            Assert.Empty(failures);

            // Every payload encrypted during the storm must still decrypt cleanly, regardless of
            // which keypair was active at the time. This is the invariant rotation is supposed to
            // preserve.
            foreach ((string plaintext, XElement encrypted) in encryptedPayloads)
            {
                var roundtripped = decryptor.Decrypt(encrypted);
                Assert.Equal(plaintext, roundtripped.Value);
            }
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task First_run_under_concurrent_load_creates_exactly_one_keypair()
    {
        // The first GetActiveKeyIdAsync triggers EnsureLoadedAsync -> RotateCoreAsync. If multiple
        // threads race that path, the SemaphoreSlim must ensure exactly one inaugural keypair is
        // generated.
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            var ids = new ConcurrentBag<string>();
            await Parallel.ForEachAsync(
                Enumerable.Range(0, 16),
                async (_, ct) => ids.Add(await pq.GetActiveKeyIdAsync(ct)));

            Assert.Single(ids.Distinct());

            IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await pq.ListKeysAsync();
            Assert.Single(descriptors);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
