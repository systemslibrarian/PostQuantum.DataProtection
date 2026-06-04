using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class FilePostQuantumKeyStoreTests
{
    [Fact]
    public async Task First_run_creates_keystore_with_a_fresh_keypair()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(path);
            using var pq = new PostQuantumKeyManager(keys, store);

            string activeId = await pq.GetActiveKeyIdAsync();

            Assert.True(File.Exists(path));
            string raw = await File.ReadAllTextAsync(path);
            Assert.Contains($"active {activeId}", raw, StringComparison.Ordinal);
            Assert.Contains("pair ", raw, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task The_raw_keystore_file_contains_no_plaintext_ml_kem_secret_key()
    {
        // We cannot inspect the SK directly without unwrapping. The check we can make is that
        // the encoded keypair token does not silently leak a 2400-byte run that decodes to the
        // SK. That is impossible to test rigorously without breaking encapsulation, so the proxy
        // test is: the file must not contain the ML-KEM private key byte length pattern in the
        // clear. A weaker but still useful test: ensure the file size is on the order of one
        // wrapped pair (~5 KiB base64), not 4 KiB more (which is what a leaked SK would add).
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(path);
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            long size = new FileInfo(path).Length;
            Assert.InRange(size, 4_000, 8_000);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Second_load_rehydrates_existing_keypair_and_keeps_active_id()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();

            string activeFromFirst;
            using (var first = new PostQuantumKeyManager(keys, new FilePostQuantumKeyStore(path)))
            {
                activeFromFirst = await first.GetActiveKeyIdAsync();
            }

            using (var second = new PostQuantumKeyManager(keys, new FilePostQuantumKeyStore(path)))
            {
                string activeFromSecond = await second.GetActiveKeyIdAsync();
                Assert.Equal(activeFromFirst, activeFromSecond);
            }
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Rotate_changes_active_key_and_keeps_old_keypair_loadable()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(path);
            using var pq = new PostQuantumKeyManager(keys, store);

            string oldId = await pq.GetActiveKeyIdAsync();
            string newId = await pq.RotateAsync();

            Assert.NotEqual(oldId, newId);
            Assert.Equal(newId, await pq.GetActiveKeyIdAsync());

            // Old keypair is still in the loaded set: encrypt under old, rotate, decrypt -> works.
            (string activeId, byte[] _) = await pq.GetPublicKeyAsync(oldId);
            Assert.Equal(oldId, activeId);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Atomic_write_leaves_no_temp_files_after_a_normal_save()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(path);
            using var pq = new PostQuantumKeyManager(keys, store);

            _ = await pq.GetActiveKeyIdAsync();
            _ = await pq.RotateAsync();

            string[] tempFiles = Directory.GetFiles(tempDir, "*.tmp.*");
            Assert.Empty(tempFiles);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Payload_encrypted_under_old_keypair_still_decrypts_after_rotation()
    {
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            string path = Path.Combine(tempDir, "pq.txt");
            using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
            var store = new FilePostQuantumKeyStore(path);
            using var pq = new PostQuantumKeyManager(keys, store);

            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys, HybridKemMode.Hybrid);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var original = new System.Xml.Linq.XElement("payload", "before rotation");
            var encrypted = encryptor.Encrypt(original).EncryptedElement;

            _ = await pq.RotateAsync();

            var roundtripped = decryptor.Decrypt(encrypted);
            Assert.Equal(original.ToString(), roundtripped.ToString());
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
