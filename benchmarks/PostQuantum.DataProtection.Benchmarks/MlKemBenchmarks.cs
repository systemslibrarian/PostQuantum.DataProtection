using BenchmarkDotNet.Attributes;
using PostQuantum.DataProtection.Hybrid;

namespace PostQuantum.DataProtection.Benchmarks;

/// <summary>
/// Pure ML-KEM-768 micro-benchmarks. Numbers here pin the cost of the post-quantum step alone,
/// independent of the AES-GCM envelope or the classical wrap layer.
/// </summary>
[MemoryDiagnoser]
public class MlKemBenchmarks
{
    private byte[] _publicKey = null!;
    private byte[] _privateKey = null!;
    private byte[] _ciphertext = null!;

    [GlobalSetup]
    public void Setup()
    {
        (_publicKey, _privateKey) = MlKem.GenerateKeyPair();
        (_ciphertext, _) = MlKem.Encapsulate(_publicKey);
    }

    [Benchmark(Description = "ML-KEM-768 GenerateKeyPair")]
    public (byte[], byte[]) GenerateKeyPair() => MlKem.GenerateKeyPair();

    [Benchmark(Description = "ML-KEM-768 Encapsulate")]
    public (byte[], byte[]) Encapsulate() => MlKem.Encapsulate(_publicKey);

    [Benchmark(Description = "ML-KEM-768 Decapsulate")]
    public byte[] Decapsulate() => MlKem.Decapsulate(_privateKey, _ciphertext);
}
