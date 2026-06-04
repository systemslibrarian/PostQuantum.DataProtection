using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Thin wrapper over BouncyCastle's FIPS 203 ML-KEM implementation, supporting all three NIST
/// parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024). The library defaults to
/// <see cref="MlKemParameterSet.Kem768"/> but every operation accepts any set, and the keypair id
/// prefix reflects the set used so envelopes route correctly across mixed-set deployments.
/// </summary>
/// <remarks>
/// <para>
/// Size constants are hard-coded per FIPS 203 §8 so a wire-format reviewer can read them from the
/// source. The BouncyCastle-reported sizes are asserted against the hard-coded values at
/// encapsulate time — a BC version that disagreed would fail loudly rather than produce a
/// malformed envelope.
/// </para>
/// <para>
/// Stateless and thread-safe; the BouncyCastle classes are short-lived per call. Randomness comes
/// from <see cref="SecureRandom"/>, which delegates to <see cref="RandomNumberGenerator"/> on .NET.
/// </para>
/// </remarks>
internal static class MlKem
{
    /// <summary>The shared-secret length is 32 bytes for every ML-KEM parameter set.</summary>
    public const int SharedSecretLength = 32;

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

    private static MLKemParameters BcParameters(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => MLKemParameters.ml_kem_512,
        MlKemParameterSet.Kem768 => MLKemParameters.ml_kem_768,
        MlKemParameterSet.Kem1024 => MLKemParameters.ml_kem_1024,
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

    // === Generation, encapsulation, decapsulation ============================================

    /// <summary>Default-parameter-set keypair generation. Equivalent to <c>GenerateKeyPair(Kem768)</c>.</summary>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair() => GenerateKeyPair(MlKemParameterSet.Kem768);

    /// <summary>Generates a fresh ML-KEM keypair for the chosen parameter set using the platform CSPRNG.</summary>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair(MlKemParameterSet set)
    {
        MLKemParameters parameters = BcParameters(set);
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, parameters));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

        byte[] pk = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        byte[] sk = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();

        int expectedPk = PublicKeyLengthFor(set);
        int expectedSk = PrivateKeyLengthFor(set);
        if (pk.Length != expectedPk || sk.Length != expectedSk)
        {
            CryptographicOperations.ZeroMemory(sk);
            throw new CryptographicException(
                $"BouncyCastle produced an {AlgorithmLabel(set)} keypair with unexpected sizes (pk={pk.Length}, sk={sk.Length}). " +
                "This is a library / BouncyCastle version mismatch, not a runtime input problem.");
        }

        return (pk, sk);
    }

    /// <summary>Default-parameter-set encapsulation. Equivalent to <c>Encapsulate(publicKey, Kem768)</c>.</summary>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey)
        => Encapsulate(publicKey, MlKemParameterSet.Kem768);

    /// <summary>Encapsulates a fresh shared secret against <paramref name="publicKey"/>.</summary>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey, MlKemParameterSet set)
    {
        int expectedPk = PublicKeyLengthFor(set);
        if (publicKey.Length != expectedPk)
        {
            throw new ArgumentException(
                $"{AlgorithmLabel(set)} public key must be exactly {expectedPk} bytes; got {publicKey.Length}.",
                nameof(publicKey));
        }

        MLKemParameters parameters = BcParameters(set);
        int expectedCt = EncapsulationLengthFor(set);

        MLKemPublicKeyParameters pk = MLKemPublicKeyParameters.FromEncoding(parameters, publicKey.ToArray());
        var encapsulator = new MLKemEncapsulator(parameters);
        encapsulator.Init(new ParametersWithRandom(pk, new SecureRandom()));

        if (encapsulator.EncapsulationLength != expectedCt || encapsulator.SecretLength != SharedSecretLength)
        {
            throw new CryptographicException(
                $"BouncyCastle reports unexpected {AlgorithmLabel(set)} size constants. Aborting before producing a malformed envelope.");
        }

        byte[] ciphertext = new byte[expectedCt];
        byte[] sharedSecret = new byte[SharedSecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
        return (ciphertext, sharedSecret);
    }

    /// <summary>Default-parameter-set decapsulation. Equivalent to <c>Decapsulate(privateKey, ciphertext, Kem768)</c>.</summary>
    public static byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext)
        => Decapsulate(privateKey, ciphertext, MlKemParameterSet.Kem768);

    /// <summary>Decapsulates <paramref name="ciphertext"/> with <paramref name="privateKey"/> for the chosen parameter set.</summary>
    public static byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext, MlKemParameterSet set)
    {
        int expectedSk = PrivateKeyLengthFor(set);
        int expectedCt = EncapsulationLengthFor(set);

        if (privateKey.Length != expectedSk)
        {
            throw new ArgumentException(
                $"{AlgorithmLabel(set)} private key must be exactly {expectedSk} bytes; got {privateKey.Length}.",
                nameof(privateKey));
        }

        if (ciphertext.Length != expectedCt)
        {
            throw new ArgumentException(
                $"{AlgorithmLabel(set)} ciphertext must be exactly {expectedCt} bytes; got {ciphertext.Length}.",
                nameof(ciphertext));
        }

        MLKemParameters parameters = BcParameters(set);
        MLKemPrivateKeyParameters sk = MLKemPrivateKeyParameters.FromEncoding(parameters, privateKey.ToArray());
        var decapsulator = new MLKemDecapsulator(parameters);
        decapsulator.Init(sk);

        byte[] sharedSecret = new byte[SharedSecretLength];
        decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
        return sharedSecret;
    }
}
