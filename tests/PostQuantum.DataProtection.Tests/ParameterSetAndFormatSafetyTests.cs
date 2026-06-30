using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// End-to-end agility coverage across all three ML-KEM parameter sets, plus the format-safety
/// guarantees that let the wire format be frozen at 1.0: a decoder must reject a future format
/// version cleanly (via both <see cref="HybridKemEnvelope.Decode"/> throwing and
/// <see cref="HybridKemEnvelope.TryDecode"/> returning false) rather than mis-parsing it.
/// </summary>
public sealed class ParameterSetAndFormatSafetyTests
{
    [Theory]
    [InlineData(MlKemParameterSet.Kem512, "pq-mlkem512-")]
    [InlineData(MlKemParameterSet.Kem768, "pq-mlkem768-")]
    [InlineData(MlKemParameterSet.Kem1024, "pq-mlkem1024-")]
    public async Task Every_parameter_set_roundtrips_under_the_default_mode(MlKemParameterSet set, string expectedIdPrefix)
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store, set);

            string activeId = await pq.GetActiveKeyIdAsync();
            Assert.StartsWith(expectedIdPrefix, activeId, StringComparison.Ordinal);

            var encryptor = new PostQuantumXmlEncryptor(pq, keys); // default mode = XWingHybrid
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var original = new XElement("payload", new XAttribute("kind", "data-protection-key"), "secret-bytes-here");
            var encrypted = encryptor.Encrypt(original);

            // The envelope records the parameter set as its algorithm label.
            HybridKemEnvelope envelope = HybridKemEnvelope.Decode(encrypted.EncryptedElement.Value);
            Assert.Equal(MlKem.AlgorithmLabel(set), envelope.KemAlgorithm);

            var roundtripped = decryptor.Decrypt(encrypted.EncryptedElement);
            Assert.Equal(
                original.ToString(SaveOptions.DisableFormatting),
                roundtripped.ToString(SaveOptions.DisableFormatting));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void TryDecode_returns_false_for_a_future_format_version()
    {
        byte futureVersion = (byte)(HybridKemEnvelope.CurrentFormatVersion + 1);
        byte[] bytes = [futureVersion, (byte)HybridKemMode.XWingHybrid, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        string token = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

        Assert.False(HybridKemEnvelope.TryDecode(token, out HybridKemEnvelope? result));
        Assert.Null(result);
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(token));
    }
}
