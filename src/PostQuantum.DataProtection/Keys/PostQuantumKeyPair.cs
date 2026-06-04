using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.DataProtection.Internal;

namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// A persistable post-quantum keypair: the public key in the clear, the secret key
/// envelope-encrypted into an opaque blob by <see cref="PostQuantumKeyManager"/>.
/// </summary>
/// <remarks>
/// <para>
/// The public key is non-secret — it goes into every encryption envelope. The secret key never
/// appears here in plaintext; <see cref="WrappedSecretKey"/> is a self-contained blob whose layout
/// is defined and parsed only by <see cref="PostQuantumKeyManager"/>. Outside callers should treat
/// it as opaque.
/// </para>
/// <para>
/// <b>Wire layout (version 1).</b>
/// </para>
/// <code>
/// [FormatVersion : byte = 1]
/// [KeyId         : length-prefixed utf8]
/// [Algorithm     : length-prefixed utf8]   // "ML-KEM-768"
/// [PublicKey     : length-prefixed bytes]
/// [WrappedSecret : length-prefixed bytes]  // opaque, defined by PostQuantumKeyManager
/// [CreatedAtUtc  : int64 big-endian]       // Unix milliseconds
/// </code>
/// </remarks>
public sealed record PostQuantumKeyPair
{
    private const byte CurrentFormatVersion = 1;

    /// <summary>A stable, human-readable identifier for this keypair, used to route at decrypt time.</summary>
    public required string KeyId { get; init; }

    /// <summary>The KEM algorithm label. Currently always <c>"ML-KEM-768"</c>.</summary>
    public required string Algorithm { get; init; }

    /// <summary>The ML-KEM public key bytes (1184 bytes for ML-KEM-768).</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The envelope-encrypted secret key as an opaque blob. Its layout is defined by
    /// <see cref="PostQuantumKeyManager"/>; callers outside the library should not parse it.
    /// </summary>
    public required byte[] WrappedSecretKey { get; init; }

    /// <summary>When this keypair was generated (Unix milliseconds, UTC). Informational only.</summary>
    public required long CreatedAtUnixMs { get; init; }

    /// <summary>Encodes this keypair into a compact, URL-safe Base64 token suitable for at-rest storage.</summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        PortableEncoding.WriteByte(buffer, CurrentFormatVersion);
        PortableEncoding.WriteString(buffer, KeyId);
        PortableEncoding.WriteString(buffer, Algorithm);
        PortableEncoding.WriteBytes(buffer, PublicKey);
        PortableEncoding.WriteBytes(buffer, WrappedSecretKey);

        Span<byte> ts = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(ts, CreatedAtUnixMs);
        PortableEncoding.WriteRaw(buffer, ts);

        return PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="token"/> is null or empty.</exception>
    /// <exception cref="FormatException">The token is malformed or uses an unsupported format version.</exception>
    public static PostQuantumKeyPair Decode(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return DecodeCore(token);
    }

    /// <summary>Tries to decode without throwing on malformed input. Suitable for untrusted sources.</summary>
    public static bool TryDecode([NotNullWhen(true)] string? token, [NotNullWhen(true)] out PostQuantumKeyPair? result)
    {
        if (string.IsNullOrEmpty(token))
        {
            result = null;
            return false;
        }

        try
        {
            result = DecodeCore(token);
            return true;
        }
        catch (FormatException)
        {
            result = null;
            return false;
        }
    }

    /// <summary>Safe diagnostic — redacts the public key bytes (length only) and never names the wrapped SK contents.</summary>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Append("KeyId = ").Append(KeyId);
        builder.Append(", Algorithm = ").Append(Algorithm);
        builder.Append(", PublicKey = <").Append(PublicKey.Length).Append(" bytes>");
        builder.Append(", WrappedSecretKey = <").Append(WrappedSecretKey.Length).Append(" bytes>");
        builder.Append(", CreatedAtUnixMs = ").Append(CreatedAtUnixMs);
        return true;
    }

    /// <summary>
    /// Derives a stable, human-readable id from the public key bytes:
    /// <c>"pq-mlkem768-" + hex(SHA-256(pk)[..6])</c>.
    /// </summary>
    public static string ComputeKeyId(ReadOnlySpan<byte> publicKey)
    {
        byte[] hash = SHA256.HashData(publicKey);
        return "pq-mlkem768-" + Convert.ToHexString(hash, 0, 6).ToLowerInvariant();
    }

    private static PostQuantumKeyPair DecodeCore(string token)
    {
        byte[] data = PortableEncoding.FromBase64Url(token);
        int offset = 0;

        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version != CurrentFormatVersion)
        {
            throw new FormatException($"Unsupported PostQuantumKeyPair format version: {version}.");
        }

        string keyId = PortableEncoding.ReadString(data, ref offset);
        string algorithm = PortableEncoding.ReadString(data, ref offset);
        byte[] publicKey = PortableEncoding.ReadBytes(data, ref offset);
        byte[] wrappedSk = PortableEncoding.ReadBytes(data, ref offset);
        byte[] tsBytes = PortableEncoding.ReadRaw(data, ref offset, 8);
        long createdAt = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(tsBytes);

        if (offset != data.Length)
        {
            throw new FormatException("PostQuantumKeyPair token contains trailing bytes.");
        }

        return new PostQuantumKeyPair
        {
            KeyId = keyId,
            Algorithm = algorithm,
            PublicKey = publicKey,
            WrappedSecretKey = wrappedSk,
            CreatedAtUnixMs = createdAt,
        };
    }
}
