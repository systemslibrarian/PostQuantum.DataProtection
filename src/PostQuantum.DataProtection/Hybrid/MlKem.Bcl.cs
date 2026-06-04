#if NET10_0_OR_GREATER
using System.Security.Cryptography;

namespace PostQuantum.DataProtection.Hybrid;

internal static partial class MlKem
{
    private static MLKemAlgorithm BclAlgorithm(MlKemParameterSet set) => set switch
    {
        MlKemParameterSet.Kem512 => MLKemAlgorithm.MLKem512,
        MlKemParameterSet.Kem768 => MLKemAlgorithm.MLKem768,
        MlKemParameterSet.Kem1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair(MlKemParameterSet set)
    {
        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "The .NET 10 ML-KEM implementation is not available on this platform. Update to a build that includes System.Security.Cryptography.MLKem support, or run on net8.0/net9.0 to fall back to the BouncyCastle implementation.");
        }

        using MLKem kem = MLKem.GenerateKey(BclAlgorithm(set));
        byte[] pk = kem.ExportEncapsulationKey();
        byte[] sk = kem.ExportDecapsulationKey();
        AssertKeySizes(set, pk, sk);
        return (pk, sk);
    }

    public static partial (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPairFromSeed(MlKemParameterSet set, ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedLength)
        {
            throw new ArgumentException($"FIPS 203 seed must be exactly {SeedLength} bytes (d || z); got {seed.Length}.", nameof(seed));
        }

        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException("System.Security.Cryptography.MLKem is not available on this platform.");
        }

        using MLKem kem = MLKem.ImportPrivateSeed(BclAlgorithm(set), seed);
        byte[] pk = kem.ExportEncapsulationKey();
        byte[] sk = kem.ExportDecapsulationKey();
        AssertKeySizes(set, pk, sk);
        return (pk, sk);
    }

    public static partial (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey, MlKemParameterSet set)
    {
        ValidateLengths(set, publicKey, PublicKeyLengthFor(set), nameof(publicKey));

        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException("System.Security.Cryptography.MLKem is not available on this platform.");
        }

        using MLKem kem = MLKem.ImportEncapsulationKey(BclAlgorithm(set), publicKey);
        byte[] ciphertext = new byte[EncapsulationLengthFor(set)];
        byte[] sharedSecret = new byte[SharedSecretLength];
        kem.Encapsulate(ciphertext, sharedSecret);
        return (ciphertext, sharedSecret);
    }

    public static partial byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext, MlKemParameterSet set)
    {
        ValidateLengths(set, privateKey, PrivateKeyLengthFor(set), nameof(privateKey));
        ValidateLengths(set, ciphertext, EncapsulationLengthFor(set), nameof(ciphertext));

        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException("System.Security.Cryptography.MLKem is not available on this platform.");
        }

        using MLKem kem = MLKem.ImportDecapsulationKey(BclAlgorithm(set), privateKey);
        byte[] sharedSecret = new byte[SharedSecretLength];
        kem.Decapsulate(ciphertext, sharedSecret);
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
                $"BCL produced an {AlgorithmLabel(set)} keypair with unexpected sizes (pk={pk.Length}, sk={sk.Length}). " +
                "This is a library / .NET runtime version mismatch.");
        }
    }
}
#endif
