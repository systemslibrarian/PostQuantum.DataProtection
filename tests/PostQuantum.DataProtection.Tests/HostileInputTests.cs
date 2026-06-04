using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class HostileInputTests
{
    [Fact]
    public void Envelope_decoder_rejects_oversized_length_prefix()
    {
        // Build a token whose first length-prefixed field claims 2 GiB. The decoder must reject
        // before allocating.
        using var buffer = new MemoryStream();
        buffer.WriteByte(HybridKemEnvelope.CurrentFormatVersion);
        buffer.WriteByte((byte)HybridKemMode.Hybrid);

        // big-endian int32 = 0x7FFFFFFF (2 GiB minus 1)
        buffer.Write([0x7F, 0xFF, 0xFF, 0xFF]);

        // ... no actual payload follows; the decoder should fail at the length check.
        string token = ToBase64Url(buffer.ToArray());
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(token));
    }

    [Fact]
    public void Keypair_decoder_rejects_oversized_length_prefix()
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(1); // FormatVersion
        buffer.Write([0x7F, 0xFF, 0xFF, 0xFF]); // ridiculous KeyId length

        string token = ToBase64Url(buffer.ToArray());
        Assert.Throws<FormatException>(() => PostQuantumKeyPair.Decode(token));
    }

    [Fact]
    public void Envelope_decoder_rejects_negative_length_prefix()
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(HybridKemEnvelope.CurrentFormatVersion);
        buffer.WriteByte((byte)HybridKemMode.Hybrid);
        buffer.Write([0xFF, 0xFF, 0xFF, 0xFF]); // -1 as signed int32

        string token = ToBase64Url(buffer.ToArray());
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(token));
    }

    [Fact]
    public void Envelope_TryDecode_swallows_format_errors()
    {
        Assert.False(HybridKemEnvelope.TryDecode("not-base64url-!!!", out _));
        Assert.False(HybridKemEnvelope.TryDecode("AAAA", out _));
        Assert.False(HybridKemEnvelope.TryDecode("", out _));
    }

    [Fact]
    public void Keypair_TryDecode_swallows_format_errors()
    {
        Assert.False(PostQuantumKeyPair.TryDecode(null, out _));
        Assert.False(PostQuantumKeyPair.TryDecode("not-base64url-!!!", out _));
        Assert.False(PostQuantumKeyPair.TryDecode("AAAA", out _));
    }

    [Fact]
    public void Bad_base64url_padding_is_rejected_at_decode()
    {
        // String length 4n+1 is not valid Base64Url.
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode("A"));
    }

    private static string ToBase64Url(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
