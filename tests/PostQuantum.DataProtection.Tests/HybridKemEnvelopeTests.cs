using PostQuantum.DataProtection.Hybrid;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class HybridKemEnvelopeTests
{
    private static HybridKemEnvelope MakeHybrid() => new()
    {
        Mode = HybridKemMode.Hybrid,
        KemAlgorithm = MlKem.AlgorithmName,
        PublicKeyId = "pq-mlkem768-abcdef",
        KemCiphertext = new byte[MlKem.EncapsulationLength],
        ClassicalWrappedKeyToken = "AQVsb2NhbAALcWV5LWlkLWFiYwAJYW55LWFsZw==",
        Nonce = new byte[HybridKemEnvelope.NonceLength],
        Tag = new byte[HybridKemEnvelope.TagLength],
        Ciphertext = [1, 2, 3, 4, 5],
    };

    [Fact]
    public void Encode_then_Decode_round_trips_all_fields()
    {
        HybridKemEnvelope a = MakeHybrid();
        string token = a.Encode();
        HybridKemEnvelope b = HybridKemEnvelope.Decode(token);

        Assert.Equal(a.Mode, b.Mode);
        Assert.Equal(a.KemAlgorithm, b.KemAlgorithm);
        Assert.Equal(a.PublicKeyId, b.PublicKeyId);
        Assert.Equal(a.KemCiphertext, b.KemCiphertext);
        Assert.Equal(a.ClassicalWrappedKeyToken, b.ClassicalWrappedKeyToken);
        Assert.Equal(a.Nonce, b.Nonce);
        Assert.Equal(a.Tag, b.Tag);
        Assert.Equal(a.Ciphertext, b.Ciphertext);
    }

    [Fact]
    public void Encode_rejects_wrong_size_nonce()
    {
        HybridKemEnvelope bad = MakeHybrid() with { Nonce = new byte[10] };
        Assert.Throws<InvalidOperationException>(() => bad.Encode());
    }

    [Fact]
    public void Encode_rejects_wrong_size_tag()
    {
        HybridKemEnvelope bad = MakeHybrid() with { Tag = new byte[10] };
        Assert.Throws<InvalidOperationException>(() => bad.Encode());
    }

    [Fact]
    public void Decode_rejects_hybrid_envelope_with_empty_classical_token()
    {
        HybridKemEnvelope bad = MakeHybrid() with { ClassicalWrappedKeyToken = string.Empty };
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(bad.Encode()));
    }

    [Fact]
    public void Decode_rejects_ml_kem_only_envelope_carrying_classical_token()
    {
        HybridKemEnvelope bad = MakeHybrid() with { Mode = HybridKemMode.MlKemOnly };
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(bad.Encode()));
    }

    [Fact]
    public void Decode_rejects_unknown_format_version_byte()
    {
        // Build a hand-rolled token with FormatVersion = 99
        byte[] bytes = [99, (byte)HybridKemMode.Hybrid, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        string token = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(token));
    }

    [Fact]
    public void Decode_rejects_unknown_mode_byte()
    {
        byte[] bytes = [HybridKemEnvelope.CurrentFormatVersion, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        string token = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(token));
    }

    [Fact]
    public void ToString_redacts_byte_payloads()
    {
        string text = MakeHybrid().ToString();
        Assert.Contains("KemCiphertext = <1088 bytes>", text, StringComparison.Ordinal);
        Assert.Contains("Tag = <16 bytes>", text, StringComparison.Ordinal);
        Assert.Contains("Nonce = <12 bytes>", text, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Byte[]", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_rejects_trailing_bytes()
    {
        HybridKemEnvelope ok = MakeHybrid();
        byte[] encoded = Internal_FromBase64Url(ok.Encode());
        byte[] longer = [.. encoded, 0xFF, 0xFF];
        string trailing = Convert.ToBase64String(longer).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.Throws<FormatException>(() => HybridKemEnvelope.Decode(trailing));
    }

    private static byte[] Internal_FromBase64Url(string token)
    {
        string padded = token.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            _ => padded,
        };

        return Convert.FromBase64String(padded);
    }
}
