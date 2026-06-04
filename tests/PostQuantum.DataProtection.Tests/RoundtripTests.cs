using System.Xml.Linq;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class RoundtripTests
{
    [Theory]
    [InlineData(HybridKemMode.Hybrid)]
    [InlineData(HybridKemMode.MlKemOnly)]
    [InlineData(HybridKemMode.XWingHybrid)]
    public async Task Encrypt_then_Decrypt_yields_the_original_element(HybridKemMode mode)
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);

            // Force a load + initial keypair generation.
            string activeId = await pq.GetActiveKeyIdAsync();
            Assert.StartsWith("pq-mlkem768-", activeId, StringComparison.Ordinal);

            var encryptor = new PostQuantumXmlEncryptor(pq, keys, mode);
            var decryptor = new PostQuantumXmlDecryptor(pq, keys);

            var original = new XElement("payload", new XAttribute("kind", "data-protection-key"), "secret-bytes-here");
            var encrypted = encryptor.Encrypt(original);
            var roundtripped = decryptor.Decrypt(encrypted.EncryptedElement);

            Assert.Equal(original.ToString(SaveOptions.DisableFormatting), roundtripped.ToString(SaveOptions.DisableFormatting));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Two_encryptions_of_the_same_input_produce_different_envelopes()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var payload = new XElement("payload", "same-bytes-twice");

            var a = encryptor.Encrypt(payload).EncryptedElement.Value;
            var b = encryptor.Encrypt(payload).EncryptedElement.Value;

            Assert.NotEqual(a, b);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task EncryptedElement_uses_pinned_xml_namespace_and_element_name()
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

            Assert.Equal(PostQuantumXmlEncryptor.XmlElementName, encrypted.Name.LocalName);
            Assert.Equal(PostQuantumXmlEncryptor.XmlNamespace, encrypted.Name.NamespaceName);
            Assert.Equal(HybridKemEnvelope.CurrentFormatVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), encrypted.Attribute("version")?.Value);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task EncryptedXmlInfo_names_the_PostQuantumXmlDecryptor_type()
    {
        using LocalContentKeyProvider keys = TestDefaults.CreateContentKeyProvider();
        string tempDir = TestDefaults.CreateTempDirectory();
        try
        {
            var store = new FilePostQuantumKeyStore(Path.Combine(tempDir, "pq.txt"));
            using var pq = new PostQuantumKeyManager(keys, store);
            _ = await pq.GetActiveKeyIdAsync();

            var encryptor = new PostQuantumXmlEncryptor(pq, keys);
            var info = encryptor.Encrypt(new XElement("payload", "x"));

            Assert.Equal(typeof(PostQuantumXmlDecryptor), info.DecryptorType);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
