using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Derives the 256-bit AES-GCM content key from one or two shared secrets using HKDF-SHA-256.
/// </summary>
/// <remarks>
/// <para>
/// The combiner mirrors the IRTF / NIST-recommended pattern for hybrid KEMs: concatenate the
/// component secrets in a fixed order and feed them to HKDF with a domain-separation label. The
/// label pins the <em>mode</em> and the v1 wire-format version, so the three modes derive distinct
/// keys from identical secrets and a derived key cannot be reused in another protocol. The label is
/// a fixed string (it always reads <c>"ML-KEM-768"</c>) and does <b>not</b> encode the runtime ML-KEM
/// parameter set — that would be a wire-format change, and the format is frozen at v1. Distinctness
/// across parameter sets instead comes from the parameter-set-specific ML-KEM shared secret, and in
/// <see cref="HybridKemMode.XWingHybrid"/> additionally from the bound ML-KEM ciphertext. A future
/// wire-format version would change the label and thus the derived key for otherwise-identical inputs.
/// </para>
/// <para>
/// The HKDF salt is the per-envelope nonce (12 random bytes), so even when the same KEM keypair
/// and the same classical KEK encrypt many payloads, every payload gets a fresh derived key.
/// </para>
/// </remarks>
internal static class HybridCombiner
{
    /// <summary>Length of the derived AES-GCM key (AES-256).</summary>
    public const int DerivedKeyLength = 32;

    private const string HybridLabel = "PostQuantum.DataProtection v1 hybrid ML-KEM-768 + AES-256-GCM";
    private const string MlKemOnlyLabel = "PostQuantum.DataProtection v1 ML-KEM-768 + AES-256-GCM";
    private const string XWingLabel = "PostQuantum.DataProtection v1 XWing-hybrid ML-KEM-768 + AES-256-GCM";

    /// <summary>
    /// HKDF-SHA-256(salt = <paramref name="salt"/>, ikm = <paramref name="mlKemSharedSecret"/>,
    /// info = the ML-KEM-only domain label) → 32-byte AES-256 key.
    /// </summary>
    public static byte[] DeriveMlKemOnly(ReadOnlySpan<byte> mlKemSharedSecret, ReadOnlySpan<byte> salt)
    {
        if (mlKemSharedSecret.Length != MlKem.SharedSecretLength)
        {
            throw new ArgumentException(
                $"ML-KEM shared secret must be exactly {MlKem.SharedSecretLength} bytes.",
                nameof(mlKemSharedSecret));
        }

        byte[] output = new byte[DerivedKeyLength];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, mlKemSharedSecret, output, salt, Encoding.UTF8.GetBytes(MlKemOnlyLabel));
        return output;
    }

    /// <summary>
    /// HKDF-SHA-256(salt = <paramref name="salt"/>, ikm = <paramref name="mlKemSharedSecret"/> ||
    /// <paramref name="classicalSharedSecret"/>, info = the hybrid domain label) → 32-byte AES-256 key.
    /// </summary>
    /// <remarks>
    /// Concatenation order is fixed (ML-KEM first, classical second). Both inputs are zeroed by the
    /// caller after this method returns; the temporary concatenated buffer used here is zeroed on
    /// the way out.
    /// </remarks>
    public static byte[] DeriveHybrid(
        ReadOnlySpan<byte> mlKemSharedSecret,
        ReadOnlySpan<byte> classicalSharedSecret,
        ReadOnlySpan<byte> salt)
    {
        if (mlKemSharedSecret.Length != MlKem.SharedSecretLength)
        {
            throw new ArgumentException(
                $"ML-KEM shared secret must be exactly {MlKem.SharedSecretLength} bytes.",
                nameof(mlKemSharedSecret));
        }

        if (classicalSharedSecret.IsEmpty)
        {
            throw new ArgumentException("Classical shared secret must not be empty in hybrid mode.", nameof(classicalSharedSecret));
        }

        byte[] ikm = new byte[mlKemSharedSecret.Length + classicalSharedSecret.Length];
        try
        {
            mlKemSharedSecret.CopyTo(ikm.AsSpan(0, mlKemSharedSecret.Length));
            classicalSharedSecret.CopyTo(ikm.AsSpan(mlKemSharedSecret.Length));

            byte[] output = new byte[DerivedKeyLength];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, Encoding.UTF8.GetBytes(HybridLabel));
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>
    /// X-Wing-style combiner adapted to our (no classical KEM ciphertext) setting.
    /// SHA3-256(label || ml_kem_ss || classical_ss || ml_kem_ct || salt) → 32-byte AES-256 key.
    /// Single-shot hash; no HKDF needed because every input is fixed-length and the hash output is
    /// already the target key length.
    /// </summary>
    public static byte[] DeriveXWingHybrid(
        ReadOnlySpan<byte> mlKemSharedSecret,
        ReadOnlySpan<byte> classicalSharedSecret,
        ReadOnlySpan<byte> mlKemCiphertext,
        ReadOnlySpan<byte> salt)
    {
        if (mlKemSharedSecret.Length != MlKem.SharedSecretLength)
        {
            throw new ArgumentException(
                $"ML-KEM shared secret must be exactly {MlKem.SharedSecretLength} bytes.",
                nameof(mlKemSharedSecret));
        }

        if (classicalSharedSecret.IsEmpty)
        {
            throw new ArgumentException("Classical shared secret must not be empty in XWingHybrid mode.", nameof(classicalSharedSecret));
        }

        if (mlKemCiphertext.IsEmpty)
        {
            throw new ArgumentException("ML-KEM ciphertext must not be empty in XWingHybrid mode.", nameof(mlKemCiphertext));
        }

        byte[] label = Encoding.UTF8.GetBytes(XWingLabel);
        int totalLength = label.Length + mlKemSharedSecret.Length + classicalSharedSecret.Length + mlKemCiphertext.Length + salt.Length;

        byte[] buffer = new byte[totalLength];
        try
        {
            int offset = 0;
            label.AsSpan().CopyTo(buffer.AsSpan(offset)); offset += label.Length;
            mlKemSharedSecret.CopyTo(buffer.AsSpan(offset)); offset += mlKemSharedSecret.Length;
            classicalSharedSecret.CopyTo(buffer.AsSpan(offset)); offset += classicalSharedSecret.Length;
            mlKemCiphertext.CopyTo(buffer.AsSpan(offset)); offset += mlKemCiphertext.Length;
            salt.CopyTo(buffer.AsSpan(offset));

            return SHA3_256.HashData(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
