using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class ParameterSetTests
{
    [Theory]
    [InlineData(MlKemParameterSet.Kem512)]
    [InlineData(MlKemParameterSet.Kem768)]
    [InlineData(MlKemParameterSet.Kem1024)]
    public async Task Each_parameter_set_produces_envelopes_that_roundtrip(MlKemParameterSet set)
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store, set);

            string activeId = await pq.GetActiveKeyIdAsync();
            Assert.StartsWith(MlKem.KeyIdPrefixFor(set), activeId, StringComparison.Ordinal);

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var element = new XElement("payload", $"hello {set}");
            var encrypted = encryptor.Encrypt(element).EncryptedElement;
            var roundtripped = decryptor.Decrypt(encrypted);

            Assert.Equal(element.ToString(SaveOptions.DisableFormatting), roundtripped.ToString(SaveOptions.DisableFormatting));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task A_keypair_minted_under_kem512_still_decrypts_after_switching_to_kem1024()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));

            // Replica A — minted under Kem512.
            XElement? encrypted;
            using (var pqA = new PostQuantumKeyManager(keys, store, MlKemParameterSet.Kem512))
            {
                _ = await pqA.GetActiveKeyIdAsync();
                var encryptor = new PostQuantumXmlEncryptor(pqA, keys);
                encrypted = encryptor.Encrypt(new XElement("p", "mixed parameter sets")).EncryptedElement;
            }

            // Replica B — newly configured for Kem1024. Rotation produces a Kem1024 keypair.
            using (var pqB = new PostQuantumKeyManager(keys, store, MlKemParameterSet.Kem1024))
            {
                string activeId = await pqB.GetActiveKeyIdAsync();
                Assert.StartsWith("pq-mlkem512-", activeId, StringComparison.Ordinal);
                _ = await pqB.RotateAsync();
                string newActive = await pqB.GetActiveKeyIdAsync();
                Assert.StartsWith("pq-mlkem1024-", newActive, StringComparison.Ordinal);

                // The Kem512 envelope still decrypts because the Kem512 keypair stayed loaded.
                var decryptor = new PostQuantumXmlDecryptor(pqB, keys);
                var roundtripped = decryptor.Decrypt(encrypted);
                Assert.Equal("mixed parameter sets", roundtripped.Value);
            }
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Theory]
    [InlineData(MlKemParameterSet.Kem512, 800, 1632, 768)]
    [InlineData(MlKemParameterSet.Kem768, 1184, 2400, 1088)]
    [InlineData(MlKemParameterSet.Kem1024, 1568, 3168, 1568)]
    public void Per_set_size_constants_match_FIPS_203(MlKemParameterSet set, int expectedPk, int expectedSk, int expectedCt)
    {
        Assert.Equal(expectedPk, MlKem.PublicKeyLengthFor(set));
        Assert.Equal(expectedSk, MlKem.PrivateKeyLengthFor(set));
        Assert.Equal(expectedCt, MlKem.EncapsulationLengthFor(set));
    }
}
