using System.Security.Cryptography;
using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// The decryptor's fail-closed contract: every unreadable input — malformed token, truncated
/// envelope, or a structurally valid envelope carrying invalid material (e.g. a wrong-sized KEM
/// ciphertext) — must surface as <see cref="CryptographicException"/>, not as a leaked
/// <see cref="FormatException"/> / <see cref="ArgumentException"/>. ASP.NET Core Data Protection's
/// key-ring loader relies on that exception type to isolate one corrupt element and keep loading.
/// </summary>
public sealed class DecryptorFailClosedTests
{
    private static XElement Wrap(string payload) =>
        new(XName.Get(PostQuantumXmlEncryptor.XmlElementName, PostQuantumXmlEncryptor.XmlNamespace), payload);

    [Theory]
    [InlineData("!!! not base64url !!!")]
    [InlineData("AAAA")] // decodes to bytes but is a truncated/invalid envelope
    public async Task Malformed_token_fails_closed_as_CryptographicException(string garbage)
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            // Not FormatException — the contract is fail-closed as CryptographicException.
            Assert.ThrowsAny<CryptographicException>(() => decryptor.Decrypt(Wrap(garbage)));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Wrong_sized_kem_ciphertext_fails_closed_as_CryptographicException()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            string activeId = await pq.GetActiveKeyIdAsync();

            // Structurally valid envelope addressed to the real active keypair, but the KEM
            // ciphertext is one byte short — decapsulation throws ArgumentException internally.
            var bad = new HybridKemEnvelope
            {
                Mode = HybridKemMode.MlKemOnly,
                KemAlgorithm = MlKem.AlgorithmName,
                PublicKeyId = activeId,
                KemCiphertext = new byte[MlKem.EncapsulationLength - 1],
                ClassicalWrappedKeyToken = string.Empty,
                Nonce = new byte[HybridKemEnvelope.NonceLength],
                Tag = new byte[HybridKemEnvelope.TagLength],
                Ciphertext = [1, 2, 3],
            };

            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            Assert.ThrowsAny<CryptographicException>(() => decryptor.Decrypt(Wrap(bad.Encode())));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
