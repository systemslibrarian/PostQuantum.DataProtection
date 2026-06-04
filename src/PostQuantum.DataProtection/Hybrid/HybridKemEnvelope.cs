using System.Diagnostics.CodeAnalysis;
using System.Text;
using PostQuantum.DataProtection.Internal;

namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// The versioned binary envelope persisted inside each protected XML element. Carries the routing
/// metadata, both KEM outputs, and the AES-256-GCM ciphertext that holds the original element's
/// bytes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire layout (version 1).</b> All integers are big-endian; byte fields are 4-byte
/// length-prefixed:
/// </para>
/// <code>
/// [FormatVersion : byte = 1]
/// [Mode          : byte]                     // 0 = MlKemOnly, 1 = Hybrid
/// [KemAlgorithm  : length-prefixed utf8]     // "ML-KEM-768"
/// [PublicKeyId   : length-prefixed utf8]     // id of the long-lived PQ keypair this was encrypted to
/// [KemCiphertext : length-prefixed bytes]    // ML-KEM-768 encapsulation output (1088 bytes)
/// [ClassicalWrap : length-prefixed utf8]     // WrappedContentKey.Encode() token; empty in MlKemOnly
/// [Nonce         : 12 raw bytes]             // AES-GCM nonce
/// [Tag           : 16 raw bytes]             // AES-GCM authentication tag
/// [Ciphertext    : length-prefixed bytes]    // AES-256-GCM ciphertext of the original XML payload
/// </code>
/// <para>
/// The encoded envelope is then Base64Url-wrapped and placed inside a single XML element. The
/// decoder caps every length-prefixed field at <see cref="PortableEncoding.MaxFieldLength"/> and
/// uses overflow-safe bounds arithmetic so a malformed payload cannot trigger huge allocations or
/// out-of-bounds reads. <see cref="TryDecode"/> reports failure without throwing for inputs from
/// untrusted sources.
/// </para>
/// </remarks>
public sealed record HybridKemEnvelope
{
    /// <summary>Current wire-format version. Bumped whenever the binary layout changes.</summary>
    public const byte CurrentFormatVersion = 1;

    /// <summary>Length of the AES-GCM nonce (96 bits, the standard random-nonce size).</summary>
    public const int NonceLength = 12;

    /// <summary>Length of the AES-GCM authentication tag (128 bits).</summary>
    public const int TagLength = 16;

    /// <summary>The envelope format version this instance was decoded from (or will encode as).</summary>
    public byte FormatVersion { get; init; } = CurrentFormatVersion;

    /// <summary>The KEM derivation mode (<see cref="HybridKemMode.Hybrid"/> or <see cref="HybridKemMode.MlKemOnly"/>).</summary>
    public required HybridKemMode Mode { get; init; }

    /// <summary>The KEM algorithm label recorded on the envelope (currently always <c>"ML-KEM-768"</c>).</summary>
    public required string KemAlgorithm { get; init; }

    /// <summary>The identifier of the long-lived PQ keypair this envelope was encrypted to.</summary>
    public required string PublicKeyId { get; init; }

    /// <summary>The ML-KEM-768 encapsulation output (1088 bytes).</summary>
    public required byte[] KemCiphertext { get; init; }

    /// <summary>
    /// The classical layer's <see cref="PostQuantum.KeyManagement.WrappedContentKey"/> as an Encode() token.
    /// Empty string when <see cref="Mode"/> is <see cref="HybridKemMode.MlKemOnly"/>.
    /// </summary>
    public required string ClassicalWrappedKeyToken { get; init; }

    /// <summary>The AES-GCM nonce (12 bytes).</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>The AES-GCM authentication tag (16 bytes).</summary>
    public required byte[] Tag { get; init; }

    /// <summary>The AES-256-GCM ciphertext of the original XML payload.</summary>
    public required byte[] Ciphertext { get; init; }

    /// <summary>Encodes this envelope as a compact, URL-safe Base64 token.</summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        PortableEncoding.WriteByte(buffer, FormatVersion);
        PortableEncoding.WriteByte(buffer, (byte)Mode);
        PortableEncoding.WriteString(buffer, KemAlgorithm);
        PortableEncoding.WriteString(buffer, PublicKeyId);
        PortableEncoding.WriteBytes(buffer, KemCiphertext);
        PortableEncoding.WriteString(buffer, ClassicalWrappedKeyToken);

        if (Nonce.Length != NonceLength)
        {
            throw new InvalidOperationException($"Envelope nonce must be exactly {NonceLength} bytes.");
        }

        if (Tag.Length != TagLength)
        {
            throw new InvalidOperationException($"Envelope tag must be exactly {TagLength} bytes.");
        }

        PortableEncoding.WriteRaw(buffer, Nonce);
        PortableEncoding.WriteRaw(buffer, Tag);
        PortableEncoding.WriteBytes(buffer, Ciphertext);
        return PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="token"/> is null or empty.</exception>
    /// <exception cref="FormatException">The token is malformed or uses an unsupported format version.</exception>
    public static HybridKemEnvelope Decode(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return DecodeCore(token);
    }

    /// <summary>
    /// Attempts to decode a token without throwing for malformed inputs. Returns <see langword="true"/>
    /// on success and assigns <paramref name="result"/>; returns <see langword="false"/> otherwise.
    /// </summary>
    public static bool TryDecode([NotNullWhen(true)] string? token, [NotNullWhen(true)] out HybridKemEnvelope? result)
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

    /// <summary>
    /// Diagnostic-friendly representation that names the routing fields but never the ciphertext or
    /// the classical wrapped-key token. Safe to log.
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Append("FormatVersion = ").Append(FormatVersion);
        builder.Append(", Mode = ").Append(Mode);
        builder.Append(", KemAlgorithm = ").Append(KemAlgorithm);
        builder.Append(", PublicKeyId = ").Append(PublicKeyId);
        builder.Append(", KemCiphertext = <").Append(KemCiphertext.Length).Append(" bytes>");
        builder.Append(", ClassicalWrappedKeyToken = <").Append(ClassicalWrappedKeyToken.Length).Append(" chars>");
        builder.Append(", Nonce = <").Append(Nonce.Length).Append(" bytes>");
        builder.Append(", Tag = <").Append(Tag.Length).Append(" bytes>");
        builder.Append(", Ciphertext = <").Append(Ciphertext.Length).Append(" bytes>");
        return true;
    }

    private static HybridKemEnvelope DecodeCore(string token)
    {
        byte[] data = PortableEncoding.FromBase64Url(token);
        int offset = 0;

        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version != CurrentFormatVersion)
        {
            throw new FormatException($"Unsupported envelope format version: {version}.");
        }

        byte modeByte = PortableEncoding.ReadByte(data, ref offset);
        if (modeByte > (byte)HybridKemMode.Hybrid)
        {
            throw new FormatException($"Unknown KEM mode: {modeByte}.");
        }

        var mode = (HybridKemMode)modeByte;
        string kemAlgorithm = PortableEncoding.ReadString(data, ref offset);
        string publicKeyId = PortableEncoding.ReadString(data, ref offset);
        byte[] kemCiphertext = PortableEncoding.ReadBytes(data, ref offset);
        string classicalWrappedKey = PortableEncoding.ReadString(data, ref offset);

        if (mode == HybridKemMode.Hybrid && classicalWrappedKey.Length == 0)
        {
            throw new FormatException("Hybrid envelope is missing the classical wrapped-key token.");
        }

        if (mode == HybridKemMode.MlKemOnly && classicalWrappedKey.Length != 0)
        {
            throw new FormatException("MlKemOnly envelope must not carry a classical wrapped-key token.");
        }

        byte[] nonce = PortableEncoding.ReadRaw(data, ref offset, NonceLength);
        byte[] tag = PortableEncoding.ReadRaw(data, ref offset, TagLength);
        byte[] ciphertext = PortableEncoding.ReadBytes(data, ref offset);

        if (offset != data.Length)
        {
            throw new FormatException("Envelope contains trailing bytes after the ciphertext.");
        }

        return new HybridKemEnvelope
        {
            FormatVersion = version,
            Mode = mode,
            KemAlgorithm = kemAlgorithm,
            PublicKeyId = publicKeyId,
            KemCiphertext = kemCiphertext,
            ClassicalWrappedKeyToken = classicalWrappedKey,
            Nonce = nonce,
            Tag = tag,
            Ciphertext = ciphertext,
        };
    }
}
