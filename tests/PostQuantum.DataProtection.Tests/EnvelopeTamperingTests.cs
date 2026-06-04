using System.Security.Cryptography;
using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class EnvelopeTamperingTests
{
    [Fact]
    public async Task Tampered_ciphertext_byte_fails_authentication()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var original = new XElement("payload", "something to encrypt");
            var encrypted = encryptor.Encrypt(original).EncryptedElement;

            string original_token = encrypted.Value.Trim();
            HybridKemEnvelope envelope = HybridKemEnvelope.Decode(original_token);
            envelope.Ciphertext[0] ^= 0xFF;

            var tampered = new XElement(
                encrypted.Name,
                encrypted.Attributes(),
                envelope.Encode());

            Assert.ThrowsAny<CryptographicException>(() => decryptor.Decrypt(tampered));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Tampered_tag_fails_authentication()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var encrypted = encryptor.Encrypt(new XElement("payload", "x")).EncryptedElement;
            HybridKemEnvelope envelope = HybridKemEnvelope.Decode(encrypted.Value.Trim());
            envelope.Tag[5] ^= 0x01;

            var tampered = new XElement(encrypted.Name, encrypted.Attributes(), envelope.Encode());
            Assert.ThrowsAny<CryptographicException>(() => decryptor.Decrypt(tampered));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Tampered_kem_ciphertext_fails_decapsulation()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var encrypted = encryptor.Encrypt(new XElement("payload", "x")).EncryptedElement;
            HybridKemEnvelope envelope = HybridKemEnvelope.Decode(encrypted.Value.Trim());

            // ML-KEM is IND-CCA2: an invalid ciphertext yields a different (implicit) shared secret,
            // which causes the downstream AES-GCM verify to fail. We must not get plaintext.
            envelope.KemCiphertext[10] ^= 0xFF;

            var tampered = new XElement(encrypted.Name, encrypted.Attributes(), envelope.Encode());
            Assert.ThrowsAny<CryptographicException>(() => decryptor.Decrypt(tampered));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Truncated_envelope_throws_FormatException_on_decode()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);

            var encrypted = encryptor.Encrypt(new XElement("payload", "x")).EncryptedElement;
            string token = encrypted.Value.Trim();
            string truncated = token[..(token.Length / 2)];

            Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(truncated));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void TryDecode_returns_false_on_malformed_input_without_throwing()
    {
        Assert.False(HybridKemEnvelope.TryDecode(null, out _));
        Assert.False(HybridKemEnvelope.TryDecode(string.Empty, out _));
        Assert.False(HybridKemEnvelope.TryDecode("not-base64url-!!!", out _));
        Assert.False(HybridKemEnvelope.TryDecode("AAAA", out _));
    }
}
