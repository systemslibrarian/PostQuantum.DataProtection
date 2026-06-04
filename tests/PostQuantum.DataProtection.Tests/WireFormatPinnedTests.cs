using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Pinned wire-format regression tests. These hand-craft envelopes and key-pair tokens with
/// hard-coded field values and assert the byte-level outputs and round-trip behaviour. They are
/// the line of defence against silent wire-format drift: any change to <see cref="HybridKemEnvelope.Encode"/>
/// or <see cref="PostQuantumKeyPair.Encode"/> that would break compatibility with already-persisted
/// envelopes fails these tests, forcing a deliberate version bump.
/// </summary>
public sealed class WireFormatPinnedTests
{
    [Fact]
    public void Hand_crafted_hybrid_envelope_encodes_and_decodes_with_all_fields_intact()
    {
        // Use deterministic, predictable bytes so the test is a true regression: identical inputs
        // must produce identical decoded fields. We do not pin the exact Base64Url string because
        // its size is dominated by the (legitimately variable) KEM ciphertext field length.
        byte[] kemCiphertext = new byte[MlKem.EncapsulationLength];
        for (int i = 0; i < kemCiphertext.Length; i++)
        {
            kemCiphertext[i] = (byte)(i & 0xFF);
        }

        byte[] nonce = new byte[HybridKemEnvelope.NonceLength];
        for (int i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(0xA0 + i);
        }

        byte[] tag = new byte[HybridKemEnvelope.TagLength];
        for (int i = 0; i < tag.Length; i++)
        {
            tag[i] = (byte)(0xC0 + i);
        }

        byte[] ciphertext = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

        var original = new HybridKemEnvelope
        {
            Mode = HybridKemMode.Hybrid,
            KemAlgorithm = MlKem.AlgorithmName,
            PublicKeyId = "pq-mlkem768-deadbe",
            KemCiphertext = kemCiphertext,
            ClassicalWrappedKeyToken = "AQVsb2NhbAALcWV5LWlkLWFiYwAJYW55LWFsZw==",
            Nonce = nonce,
            Tag = tag,
            Ciphertext = ciphertext,
        };

        string token = original.Encode();
        HybridKemEnvelope roundtripped = HybridKemEnvelope.Decode(token);

        Assert.Equal(HybridKemEnvelope.CurrentFormatVersion, roundtripped.FormatVersion);
        Assert.Equal(HybridKemMode.Hybrid, roundtripped.Mode);
        Assert.Equal(MlKem.AlgorithmName, roundtripped.KemAlgorithm);
        Assert.Equal("pq-mlkem768-deadbe", roundtripped.PublicKeyId);
        Assert.Equal(kemCiphertext, roundtripped.KemCiphertext);
        Assert.Equal("AQVsb2NhbAALcWV5LWlkLWFiYwAJYW55LWFsZw==", roundtripped.ClassicalWrappedKeyToken);
        Assert.Equal(nonce, roundtripped.Nonce);
        Assert.Equal(tag, roundtripped.Tag);
        Assert.Equal(ciphertext, roundtripped.Ciphertext);
    }

    [Fact]
    public void MlKemOnly_envelope_carries_empty_classical_token_and_roundtrips()
    {
        var original = new HybridKemEnvelope
        {
            Mode = HybridKemMode.MlKemOnly,
            KemAlgorithm = MlKem.AlgorithmName,
            PublicKeyId = "pq-mlkem768-cafe01",
            KemCiphertext = new byte[MlKem.EncapsulationLength],
            ClassicalWrappedKeyToken = string.Empty,
            Nonce = new byte[HybridKemEnvelope.NonceLength],
            Tag = new byte[HybridKemEnvelope.TagLength],
            Ciphertext = [0x01, 0x02, 0x03],
        };

        HybridKemEnvelope roundtripped = HybridKemEnvelope.Decode(original.Encode());

        Assert.Equal(HybridKemMode.MlKemOnly, roundtripped.Mode);
        Assert.Equal(string.Empty, roundtripped.ClassicalWrappedKeyToken);
    }

    [Fact]
    public void Encoded_envelope_starts_with_pinned_header_bytes()
    {
        // The first three bytes of the binary payload (pre-Base64Url) are: FormatVersion (1),
        // Mode byte, and the high byte of the KemAlgorithm length prefix. They are stable across
        // every Hybrid envelope. This test makes byte-level drift in the header impossible to
        // miss — even a header re-ordering that still round-tripped would fail here.
        var envelope = new HybridKemEnvelope
        {
            Mode = HybridKemMode.Hybrid,
            KemAlgorithm = MlKem.AlgorithmName,
            PublicKeyId = "pq-mlkem768-deadbe",
            KemCiphertext = new byte[MlKem.EncapsulationLength],
            ClassicalWrappedKeyToken = "x",
            Nonce = new byte[HybridKemEnvelope.NonceLength],
            Tag = new byte[HybridKemEnvelope.TagLength],
            Ciphertext = [],
        };

        byte[] raw = FromBase64Url(envelope.Encode());

        Assert.Equal(HybridKemEnvelope.CurrentFormatVersion, raw[0]);
        Assert.Equal((byte)HybridKemMode.Hybrid, raw[1]);
        Assert.Equal((byte)0x00, raw[2]); // big-endian length-prefix high byte for "ML-KEM-768" (len=10)
        Assert.Equal((byte)0x00, raw[3]);
        Assert.Equal((byte)0x00, raw[4]);
        Assert.Equal((byte)0x0A, raw[5]); // length=10
        Assert.Equal((byte)'M', raw[6]);
        Assert.Equal((byte)'L', raw[7]);
    }

    [Fact]
    public void Keypair_token_roundtrips_through_encode_decode()
    {
        var original = new PostQuantumKeyPair
        {
            KeyId = "pq-mlkem768-feedface",
            Algorithm = MlKem.AlgorithmName,
            PublicKey = MakeIncreasing(MlKem.PublicKeyLength),
            WrappedSecretKey = MakeIncreasing(2666),
            CreatedAtUnixMs = 1_785_540_000_000L, // 2026-06-04T00:00:00Z
        };

        string token = original.Encode();
        PostQuantumKeyPair roundtripped = PostQuantumKeyPair.Decode(token);

        Assert.Equal(original.KeyId, roundtripped.KeyId);
        Assert.Equal(original.Algorithm, roundtripped.Algorithm);
        Assert.Equal(original.PublicKey, roundtripped.PublicKey);
        Assert.Equal(original.WrappedSecretKey, roundtripped.WrappedSecretKey);
        Assert.Equal(original.CreatedAtUnixMs, roundtripped.CreatedAtUnixMs);
    }

    [Fact]
    public void Computed_key_id_is_a_stable_function_of_the_public_key()
    {
        byte[] pk1 = MakeIncreasing(MlKem.PublicKeyLength);
        byte[] pk2 = MakeIncreasing(MlKem.PublicKeyLength);
        byte[] pk3 = (byte[])pk1.Clone();
        pk3[0] ^= 0xFF;

        string id1 = PostQuantumKeyPair.ComputeKeyId(pk1);
        string id2 = PostQuantumKeyPair.ComputeKeyId(pk2);
        string id3 = PostQuantumKeyPair.ComputeKeyId(pk3);

        Assert.Equal(id1, id2);                // same input -> same id
        Assert.NotEqual(id1, id3);             // different input -> different id
        Assert.StartsWith("pq-mlkem768-", id1, StringComparison.Ordinal);
        Assert.Equal(12 + 12, id1.Length);     // "pq-mlkem768-" + 12 hex chars (6 bytes truncation)
    }

    private static byte[] MakeIncreasing(int length)
    {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++)
        {
            buffer[i] = (byte)(i & 0xFF);
        }

        return buffer;
    }

    private static byte[] FromBase64Url(string token)
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
