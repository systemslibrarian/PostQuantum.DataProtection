using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Thin wrapper over BouncyCastle's FIPS 203 ML-KEM-768 implementation, expressed in the .NET
/// style the rest of this library uses: <see cref="ReadOnlySpan{T}"/> in, exact-length output
/// arrays, no in-band parameter shuffling.
/// </summary>
/// <remarks>
/// <para>
/// ML-KEM-768 was chosen because it sits at the "general-purpose" security level
/// (NIST category 3, ≈ 192-bit classical strength) — comfortable margin without the wire-size cost
/// of ML-KEM-1024. The size constants below come from FIPS 203 §8 and match the values BouncyCastle
/// reports at run time; we hard-code them so a wire-format reviewer can read the envelope sizes
/// from the source without running code. <see cref="EncapsulationLength"/> and
/// <see cref="SharedSecretLength"/> are asserted against the BouncyCastle-reported values on first
/// use so a future BC version that disagreed would fail loudly instead of producing a malformed
/// envelope.
/// </para>
/// <para>
/// This class is stateless and thread-safe; the BouncyCastle classes it instantiates are short-lived
/// per call. Randomness comes from <see cref="SecureRandom"/>, which delegates to
/// <see cref="RandomNumberGenerator"/> on .NET.
/// </para>
/// </remarks>
internal static class MlKem
{
    /// <summary>Human-readable algorithm label recorded inside the envelope.</summary>
    public const string AlgorithmName = "ML-KEM-768";

    /// <summary>Length of an ML-KEM-768 public key in bytes (FIPS 203 §8).</summary>
    public const int PublicKeyLength = 1184;

    /// <summary>Length of an ML-KEM-768 private (decapsulation) key in bytes (FIPS 203 §8).</summary>
    public const int PrivateKeyLength = 2400;

    /// <summary>Length of an ML-KEM-768 ciphertext (encapsulation output) in bytes (FIPS 203 §8).</summary>
    public const int EncapsulationLength = 1088;

    /// <summary>Length of the ML-KEM shared secret in bytes (always 32 across ML-KEM-512/768/1024).</summary>
    public const int SharedSecretLength = 32;

    /// <summary>
    /// Generates a fresh ML-KEM-768 keypair using the platform CSPRNG.
    /// </summary>
    /// <returns>
    /// A tuple <c>(publicKey, privateKey)</c>. Both arrays are owned by the caller; the private key
    /// is sensitive and must be zeroed when it is no longer needed (the wrapping store does this).
    /// </returns>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

        byte[] pk = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        byte[] sk = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();

        if (pk.Length != PublicKeyLength || sk.Length != PrivateKeyLength)
        {
            CryptographicOperations.ZeroMemory(sk);
            throw new CryptographicException(
                $"BouncyCastle produced an ML-KEM-768 keypair with unexpected sizes (pk={pk.Length}, sk={sk.Length}). " +
                "This is a library / BouncyCastle version mismatch, not a runtime input problem.");
        }

        return (pk, sk);
    }

    /// <summary>
    /// Encapsulates a fresh shared secret against <paramref name="publicKey"/>.
    /// </summary>
    /// <param name="publicKey">A 1184-byte ML-KEM-768 public key.</param>
    /// <returns>
    /// A tuple <c>(ciphertext, sharedSecret)</c>. The ciphertext is 1088 bytes and is sent in the
    /// envelope; the shared secret is 32 bytes and is consumed by <see cref="HybridCombiner"/>
    /// (then zeroed by the caller).
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="publicKey"/> is not the right length.</exception>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PublicKeyLength)
        {
            throw new ArgumentException(
                $"ML-KEM-768 public key must be exactly {PublicKeyLength} bytes; got {publicKey.Length}.",
                nameof(publicKey));
        }

        MLKemPublicKeyParameters pk = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey.ToArray());
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(pk, new SecureRandom()));

        if (encapsulator.EncapsulationLength != EncapsulationLength
            || encapsulator.SecretLength != SharedSecretLength)
        {
            throw new CryptographicException(
                "BouncyCastle reports unexpected ML-KEM-768 size constants. Aborting before producing a malformed envelope.");
        }

        byte[] ciphertext = new byte[EncapsulationLength];
        byte[] sharedSecret = new byte[SharedSecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
        return (ciphertext, sharedSecret);
    }

    /// <summary>
    /// Decapsulates <paramref name="ciphertext"/> with <paramref name="privateKey"/>, recovering the
    /// shared secret that the encapsulator produced.
    /// </summary>
    /// <param name="privateKey">A 2400-byte ML-KEM-768 private key. Sensitive; caller owns its lifetime.</param>
    /// <param name="ciphertext">A 1088-byte ML-KEM-768 ciphertext from the envelope.</param>
    /// <returns>The 32-byte shared secret. Caller must zero it after consumption.</returns>
    /// <exception cref="ArgumentException">Either input is the wrong length.</exception>
    public static byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentException(
                $"ML-KEM-768 private key must be exactly {PrivateKeyLength} bytes; got {privateKey.Length}.",
                nameof(privateKey));
        }

        if (ciphertext.Length != EncapsulationLength)
        {
            throw new ArgumentException(
                $"ML-KEM-768 ciphertext must be exactly {EncapsulationLength} bytes; got {ciphertext.Length}.",
                nameof(ciphertext));
        }

        MLKemPrivateKeyParameters sk = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, privateKey.ToArray());
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(sk);

        byte[] sharedSecret = new byte[SharedSecretLength];
        decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
        return sharedSecret;
    }
}
