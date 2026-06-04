using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.DataProtection.Internal;

/// <summary>
/// Shared primitives for the library's compact, versioned, URL-safe token format: big-endian,
/// length-prefixed fields written to a stream and read back from a byte array with a moving cursor.
/// Mirrors the format conventions of <c>PostQuantum.KeyManagement</c> so wire-format reviewers see
/// one shape across the family.
/// </summary>
/// <remarks>
/// All <c>Read*</c> overloads validate bounds against the buffer length using subtraction rather
/// than addition so that an attacker-supplied length prefix cannot overflow <see cref="int"/>
/// arithmetic and bypass the bounds check. The <c>Capped</c> overloads additionally reject lengths
/// above a caller-specified ceiling so a malformed envelope cannot force a giant allocation.
/// </remarks>
internal static class PortableEncoding
{
    /// <summary>Hard upper bound on any single length-prefixed field. Far above any sane value.</summary>
    public const int MaxFieldLength = 1 << 20; // 1 MiB

    public static void WriteByte(Stream stream, byte value) => stream.WriteByte(value);

    public static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    public static void WriteRaw(Stream stream, ReadOnlySpan<byte> value) => stream.Write(value);

    public static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    public static void WriteString(Stream stream, string value)
        => WriteBytes(stream, Encoding.UTF8.GetBytes(value));

    public static byte ReadByte(byte[] data, ref int offset)
    {
        if (offset >= data.Length)
        {
            throw new FormatException("Truncated envelope.");
        }

        return data[offset++];
    }

    public static int ReadInt32(byte[] data, ref int offset)
    {
        if (offset > data.Length - 4)
        {
            throw new FormatException("Truncated envelope.");
        }

        int value = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    /// <summary>Reads exactly <paramref name="count"/> raw bytes; throws on truncation.</summary>
    public static byte[] ReadRaw(byte[] data, ref int offset, int count)
    {
        if (count < 0 || count > data.Length - offset)
        {
            throw new FormatException("Truncated envelope.");
        }

        byte[] value = data.AsSpan(offset, count).ToArray();
        offset += count;
        return value;
    }

    /// <summary>Reads a length-prefixed byte field with the default <see cref="MaxFieldLength"/> ceiling.</summary>
    public static byte[] ReadBytes(byte[] data, ref int offset)
        => ReadBytesCapped(data, ref offset, MaxFieldLength);

    /// <summary>
    /// Reads a length-prefixed byte field, rejecting negative lengths, lengths that would read past
    /// the end of the buffer, and lengths that exceed <paramref name="maxLength"/>. The subtraction
    /// form <c>length &gt; data.Length - offset</c> is overflow-safe — <c>offset + length</c> is not.
    /// </summary>
    public static byte[] ReadBytesCapped(byte[] data, ref int offset, int maxLength)
    {
        int length = ReadInt32(data, ref offset);
        if (length < 0 || length > maxLength || length > data.Length - offset)
        {
            throw new FormatException("Corrupt or oversized length prefix in envelope.");
        }

        byte[] value = data.AsSpan(offset, length).ToArray();
        offset += length;
        return value;
    }

    public static string ReadString(byte[] data, ref int offset)
        => Encoding.UTF8.GetString(ReadBytesCapped(data, ref offset, MaxFieldLength));

    public static string ToBase64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string token)
    {
        string padded = token.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            0 => padded,
            _ => throw new FormatException("Invalid Base64Url length."),
        };

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Envelope is not valid Base64Url.", ex);
        }
    }
}
