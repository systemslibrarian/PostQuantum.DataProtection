#if !NET10_0_OR_GREATER
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.DataProtection.Hybrid;

internal static partial class MlKem
{
    private static MLKemParameters BcParameters(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => MLKemParameters.ml_kem_512,
        MlKemParameterSet.Kem768 => MLKemParameters.ml_kem_768,
        MlKemParameterSet.Kem1024 => MLKemParameters.ml_kem_1024,
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair(MlKemParameterSet set)
    {
        MLKemParameters parameters = BcParameters(set);
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, parameters));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

        byte[] pk = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        byte[] sk = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();
        AssertKeySizes(set, pk, sk);
        return (pk, sk);
    }

    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPairFromSeed(MlKemParameterSet set, ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedLength)
        {
            throw new ArgumentException($"FIPS 203 seed must be exactly {SeedLength} bytes (d || z); got {seed.Length}.", nameof(seed));
        }

        MLKemParameters parameters = BcParameters(set);
        MLKemPrivateKeyParameters sk = MLKemPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
        byte[] pk = sk.GetPublicKey().GetEncoded();
        byte[] skBytes = sk.GetEncoded();
        AssertKeySizes(set, pk, skBytes);
        return (pk, skBytes);
    }

    public static partial (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey, MlKemParameterSet set)
    {
        ValidateLengths(set, publicKey, PublicKeyLengthFor(set), nameof(publicKey));

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

    public static partial byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext, MlKemParameterSet set)
    {
        ValidateLengths(set, privateKey, PrivateKeyLengthFor(set), nameof(privateKey));
        ValidateLengths(set, ciphertext, EncapsulationLengthFor(set), nameof(ciphertext));

        MLKemParameters parameters = BcParameters(set);
        MLKemPrivateKeyParameters sk = MLKemPrivateKeyParameters.FromEncoding(parameters, privateKey.ToArray());
        var decapsulator = new MLKemDecapsulator(parameters);
        decapsulator.Init(sk);

        byte[] sharedSecret = new byte[SharedSecretLength];
        decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
        return sharedSecret;
    }

    private static void AssertKeySizes(MlKemParameterSet set, byte[] pk, byte[] sk)
    {
        int expectedPk = PublicKeyLengthFor(set);
        int expectedSk = PrivateKeyLengthFor(set);
        if (pk.Length != expectedPk || sk.Length != expectedSk)
        {
            CryptographicOperations.ZeroMemory(sk);
            throw new CryptographicException(
                $"BouncyCastle produced an {AlgorithmLabel(set)} keypair with unexpected sizes (pk={pk.Length}, sk={sk.Length}). " +
                "This is a library / BouncyCastle version mismatch, not a runtime input problem.");
        }
    }
}
#endif
