using System.Security.Cryptography;
using PostQuantum.DataProtection.Hybrid;
using Xunit;
using Xunit.Abstractions;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Known-answer-style integration tests for the BouncyCastle ML-KEM-768 path. These pin our
/// integration: a future BC version that changed the FIPS 203 byte encoding, the seed-derivation
/// path, or any of the size constants would fail loudly instead of silently producing envelopes
/// that downstream readers cannot decode.
/// </summary>
public sealed class MlKemKatTests
{
    private readonly ITestOutputHelper _output;

    public MlKemKatTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// A 64-byte FIPS 203 keygen seed (<c>d || z</c>) pinned for this KAT. Not secret; it is in
    /// source so the derived pk / sk are reproducible across CI runs. The choice is arbitrary —
    /// what matters is that it stays constant. Changing this value invalidates every
    /// <see cref="ExpectedHash"/> constant in this file.
    /// </summary>
    private static readonly byte[] PinnedSeed =
    [
        // d (32 bytes)
        0x50, 0x6f, 0x73, 0x74, 0x51, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x2e, 0x44, 0x61, 0x74, 0x61,
        0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b, 0x41, 0x54, 0x20, 0x31,
        // z (32 bytes)
        0x50, 0x6f, 0x73, 0x74, 0x51, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x2e, 0x44, 0x61, 0x74, 0x61,
        0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b, 0x41, 0x54, 0x20, 0x32,
    ];

    [Fact]
    public void Same_seed_yields_the_same_private_key_bytes()
    {
        (byte[] _, byte[] a) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);
        (byte[] _, byte[] b) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);

        Assert.Equal(MlKem.PrivateKeyLength, a.Length);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Same_seed_yields_the_same_public_key_bytes()
    {
        (byte[] aPk, byte[] _) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);
        (byte[] bPk, byte[] _) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);

        Assert.Equal(MlKem.PublicKeyLength, aPk.Length);
        Assert.Equal(aPk, bPk);
    }

    [Fact]
    public void Seeded_keypair_supports_encapsulate_decapsulate_roundtrip()
    {
        (byte[] pk, byte[] sk) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);

        (byte[] ciphertext, byte[] sentSecret) = MlKem.Encapsulate(pk);
        byte[] recovered = MlKem.Decapsulate(sk, ciphertext);

        Assert.Equal(MlKem.EncapsulationLength, ciphertext.Length);
        Assert.Equal(MlKem.SharedSecretLength, sentSecret.Length);
        Assert.Equal(sentSecret, recovered);
    }

    [Fact]
    public void Seeded_keypair_public_key_hash_is_pinned()
    {
        // Pins the public-key byte encoding via its SHA-256. Same value across BC (net8/9) and BCL
        // (net10) because both implement FIPS 203 byte-for-byte. A future implementation change
        // that produced different bytes for the same seed fails CI rather than silently shipping
        // wire-format-incompatible envelopes.
        (byte[] pk, byte[] _) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);
        string actual = Convert.ToHexString(SHA256.HashData(pk)).ToLowerInvariant();

        _output.WriteLine("PublicKeySha256 = " + actual);
        Assert.Equal(ExpectedHash.PublicKeySha256, actual);
    }

    [Fact]
    public void Seeded_keypair_private_key_hash_is_pinned()
    {
        (byte[] _, byte[] sk) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);
        string actual = Convert.ToHexString(SHA256.HashData(sk)).ToLowerInvariant();

        _output.WriteLine("PrivateKeySha256 = " + actual);
        Assert.Equal(ExpectedHash.PrivateKeySha256, actual);
    }

    [Fact]
    public void Two_different_seeds_yield_different_public_keys()
    {
        byte[] otherSeed = (byte[])PinnedSeed.Clone();
        otherSeed[0] ^= 0xFF;

        (byte[] aPk, byte[] _) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, PinnedSeed);
        (byte[] bPk, byte[] _) = MlKem.GenerateKeyPairFromSeed(MlKemParameterSet.Kem768, otherSeed);

        Assert.NotEqual(aPk, bPk);
    }

    /// <summary>
    /// Pinned SHA-256 hex strings of the (pk, sk) encoded byte arrays for
    /// <see cref="PinnedSeed"/>, recorded once from a known-good BouncyCastle 2.6.2 run on
    /// 2026-06-04. Treat as gold values — only change them with a deliberate commit explaining the
    /// upstream BC version bump that motivated it.
    /// </summary>
    private static class ExpectedHash
    {
        public const string PublicKeySha256 = "32a9b71e9fd8ffe8e478d8a7b1736f37498253c2ae4bf1e765c9cb0d6bbaed27";
        public const string PrivateKeySha256 = "a9b936d602c2a93394b1bb4f84eae45ead2bed6279c9925797ee713dbfe0449a";
    }
}
