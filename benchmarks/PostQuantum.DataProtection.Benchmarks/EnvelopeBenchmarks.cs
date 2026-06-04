using System.Xml.Linq;
using BenchmarkDotNet.Attributes;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement.Local;

namespace PostQuantum.DataProtection.Benchmarks;

/// <summary>
/// End-to-end envelope micro-benchmarks. Numbers here are what an ASP.NET Core Data Protection
/// key persist / load actually costs in production: ML-KEM + the classical wrap + AES-GCM +
/// XML wrapping.
/// </summary>
[MemoryDiagnoser]
public class EnvelopeBenchmarks : IDisposable
{
    private LocalContentKeyProvider _keys = null!;
    private PostQuantumKeyManager _pq = null!;
    private PostQuantumXmlEncryptor _hybridEncryptor = null!;
    private PostQuantumXmlEncryptor _mlKemOnlyEncryptor = null!;
    private PostQuantumXmlDecryptor _decryptor = null!;
    private XElement _payload = null!;
    private XElement _hybridEncrypted = null!;
    private XElement _mlKemOnlyEncrypted = null!;
    private string _tempDir = null!;

    [GlobalSetup]
    public void Setup()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "pq-dp-bench-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);

        _keys = LocalContentKeyProvider.Create(
            "benchmark-passphrase-not-secret",
            new LocalKekOptions
            {
                DegreeOfParallelism = 1,
                MemorySizeInKib = 8 * 1024,
                Iterations = 1,
            });

        var store = new FilePostQuantumKeyStore(Path.Combine(_tempDir, "pq.txt"));
        _pq = new PostQuantumKeyManager(_keys, store);
        _ = _pq.GetActiveKeyIdAsync().AsTask().GetAwaiter().GetResult();

        _hybridEncryptor = new PostQuantumXmlEncryptor(_pq, _keys, HybridKemMode.Hybrid);
        _mlKemOnlyEncryptor = new PostQuantumXmlEncryptor(_pq, _keys, HybridKemMode.MlKemOnly);
        _decryptor = new PostQuantumXmlDecryptor(_pq, _keys);

        // ~250-byte payload, comparable to a real ASP.NET Core Data Protection key XML payload.
        _payload = new XElement("descriptor",
            new XElement("encryption", new XAttribute("algorithm", "AES_256_CBC")),
            new XElement("validation", new XAttribute("algorithm", "HMACSHA256")),
            new XElement("masterKey",
                new XAttribute("requiresEncryption", "true"),
                new string('a', 128)));

        _hybridEncrypted = _hybridEncryptor.Encrypt(_payload).EncryptedElement;
        _mlKemOnlyEncrypted = _mlKemOnlyEncryptor.Encrypt(_payload).EncryptedElement;
    }

    [GlobalCleanup]
    public void Cleanup() => Dispose();

    public void Dispose()
    {
        _pq?.Dispose();
        _keys?.Dispose();
        if (_tempDir is not null && Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "Envelope Encrypt (Hybrid)")]
    public XElement EncryptHybrid() => _hybridEncryptor.Encrypt(_payload).EncryptedElement;

    [Benchmark(Description = "Envelope Encrypt (MlKemOnly)")]
    public XElement EncryptMlKemOnly() => _mlKemOnlyEncryptor.Encrypt(_payload).EncryptedElement;

    [Benchmark(Description = "Envelope Decrypt (Hybrid)")]
    public XElement DecryptHybrid() => _decryptor.Decrypt(_hybridEncrypted);

    [Benchmark(Description = "Envelope Decrypt (MlKemOnly)")]
    public XElement DecryptMlKemOnly() => _decryptor.Decrypt(_mlKemOnlyEncrypted);
}
