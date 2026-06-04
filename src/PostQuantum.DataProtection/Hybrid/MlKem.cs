using System.Security.Cryptography;

namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// FIPS 203 ML-KEM operations. Internally this class is a thin facade — on <c>net10.0</c> the
/// implementation lives behind <c>System.Security.Cryptography.MLKem</c> (BCL); on
/// <c>net8.0</c> and <c>net9.0</c> it lives behind BouncyCastle. Both produce byte-for-byte the
/// same FIPS 203 outputs, so envelopes written under one path decode under the other.
/// </summary>
/// <remarks>
/// <para>
/// The shared file (<c>MlKem.cs</c>) holds algorithm metadata and the public surface. Per-platform
/// implementations live in <c>MlKem.Bcl.cs</c> and <c>MlKem.BouncyCastle.cs</c> and are selected at
/// compile time by the <c>NET10_0_OR_GREATER</c> symbol. The BCL path is AOT-compatible; the
/// BouncyCastle path is not. See <c>docs/aot.md</c> for the rationale.
/// </para>
/// <para>
/// Stateless and thread-safe; per-call objects are short-lived. Randomness comes from
/// <see cref="RandomNumberGenerator"/> on both paths.
/// </para>
/// </remarks>
internal static partial class MlKem
{
    /// <summary>The shared-secret length is 32 bytes for every ML-KEM parameter set.</summary>
    public const int SharedSecretLength = 32;

    /// <summary>The FIPS 203 keygen seed length (d || z) is 64 bytes for every parameter set.</summary>
    public const int SeedLength = 64;

    // === ML-KEM-768 (default) — historical names kept for the existing tests and benchmarks ====
    public const string AlgorithmName = "ML-KEM-768";
    public const int PublicKeyLength = 1184;
    public const int PrivateKeyLength = 2400;
    public const int EncapsulationLength = 1088;

    /// <summary>FIPS 203 algorithm label for the given parameter set.</summary>
    public static string AlgorithmLabel(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => "ML-KEM-512",
        MlKemParameterSet.Kem768 => "ML-KEM-768",
        MlKemParameterSet.Kem1024 => "ML-KEM-1024",
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    /// <summary>Public-key length in bytes for the given parameter set (FIPS 203 §8).</summary>
    public static int PublicKeyLengthFor(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => 800,
        MlKemParameterSet.Kem768 => 1184,
        MlKemParameterSet.Kem1024 => 1568,
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    /// <summary>Private-key length in bytes for the given parameter set (FIPS 203 §8).</summary>
    public static int PrivateKeyLengthFor(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => 1632,
        MlKemParameterSet.Kem768 => 2400,
        MlKemParameterSet.Kem1024 => 3168,
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    /// <summary>Ciphertext (encapsulation) length in bytes for the given parameter set (FIPS 203 §8).</summary>
    public static int EncapsulationLengthFor(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => 768,
        MlKemParameterSet.Kem768 => 1088,
        MlKemParameterSet.Kem1024 => 1568,
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    /// <summary>Keypair-id prefix recorded on the <c>PostQuantumKeyPair.ComputeKeyId</c> output.</summary>
    public static string KeyIdPrefixFor(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => "pq-mlkem512-",
        MlKemParameterSet.Kem768 => "pq-mlkem768-",
        MlKemParameterSet.Kem1024 => "pq-mlkem1024-",
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    /// <summary>Parses an algorithm label back to a parameter set; throws on unknown values.</summary>
    public static MlKemParameterSet ParseAlgorithmLabel(string label) => label switch
    {
        "ML-KEM-512" => MlKemParameterSet.Kem512,
        "ML-KEM-768" => MlKemParameterSet.Kem768,
        "ML-KEM-1024" => MlKemParameterSet.Kem1024,
        _ => throw new CryptographicException($"Unknown ML-KEM algorithm label '{label}'."),
    };

    // === Default-parameter-set overloads ====================================

    /// <summary>Default-parameter-set keypair generation. Equivalent to <c>GenerateKeyPair(Kem768)</c>.</summary>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair() => GenerateKeyPair(MlKemParameterSet.Kem768);

    /// <summary>Default-parameter-set encapsulation. Equivalent to <c>Encapsulate(publicKey, Kem768)</c>.</summary>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey)
        => Encapsulate(publicKey, MlKemParameterSet.Kem768);

    /// <summary>Default-parameter-set decapsulation. Equivalent to <c>Decapsulate(privateKey, ciphertext, Kem768)</c>.</summary>
    public static byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext)
        => Decapsulate(privateKey, ciphertext, MlKemParameterSet.Kem768);

    // === Platform-specific surface (implemented in MlKem.Bcl.cs / MlKem.BouncyCastle.cs) ====

    /// <summary>Generates a fresh ML-KEM keypair for the chosen parameter set using the platform CSPRNG.</summary>
    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair(MlKemParameterSet set);

    /// <summary>
    /// Generates an ML-KEM keypair deterministically from a 64-byte FIPS 203 seed (<c>d || z</c>).
    /// Used by KAT tests and any caller that needs reproducible keys.
    /// </summary>
    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPairFromSeed(MlKemParameterSet set, ReadOnlySpan<byte> seed);

    /// <summary>Encapsulates a fresh shared secret against <paramref name="publicKey"/>.</summary>
    public static partial (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey, MlKemParameterSet set);

    /// <summary>Decapsulates <paramref name="ciphertext"/> with <paramref name="privateKey"/> for the chosen parameter set.</summary>
    public static partial byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext, MlKemParameterSet set);

    private static void ValidateLengths(MlKemParameterSet set, ReadOnlySpan<byte> pk, int expectedPk, string field)
    {
        if (pk.Length != expectedPk)
        {
            throw new ArgumentException(
                $"{AlgorithmLabel(set)} {field} must be exactly {expectedPk} bytes; got {pk.Length}.",
                field);
        }
    }
}
