using System.Security.Cryptography;
using PostQuantum.DataProtection.Hybrid;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class HybridCombinerTests
{
    private static byte[] Random(int length) => RandomNumberGenerator.GetBytes(length);

    [Fact]
    public void DeriveMlKemOnly_returns_32_bytes()
    {
        byte[] derived = HybridCombiner.DeriveMlKemOnly(Random(32), Random(12));
        Assert.Equal(HybridCombiner.DerivedKeyLength, derived.Length);
        Assert.Equal(32, derived.Length);
    }

    [Fact]
    public void DeriveHybrid_returns_32_bytes()
    {
        byte[] derived = HybridCombiner.DeriveHybrid(Random(32), Random(32), Random(12));
        Assert.Equal(HybridCombiner.DerivedKeyLength, derived.Length);
    }

    [Fact]
    public void DeriveMlKemOnly_is_deterministic_for_identical_inputs()
    {
        byte[] mlKem = Random(32);
        byte[] salt = Random(12);

        byte[] a = HybridCombiner.DeriveMlKemOnly(mlKem, salt);
        byte[] b = HybridCombiner.DeriveMlKemOnly(mlKem, salt);

        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveHybrid_is_deterministic_for_identical_inputs()
    {
        byte[] mlKem = Random(32);
        byte[] classical = Random(32);
        byte[] salt = Random(12);

        byte[] a = HybridCombiner.DeriveHybrid(mlKem, classical, salt);
        byte[] b = HybridCombiner.DeriveHybrid(mlKem, classical, salt);

        Assert.Equal(a, b);
    }

    [Fact]
    public void Hybrid_and_MlKemOnly_modes_produce_different_keys_for_the_same_ml_kem_secret()
    {
        // The domain-separation label in HKDF.info must change the output even when the IKM
        // overlaps. (Hybrid mode IKM = mlKem || classical, MlKemOnly mode IKM = mlKem.) Test both
        // facets: even when the classical secret is 32 zero bytes, the two modes differ.
        byte[] mlKem = Random(32);
        byte[] classicalZero = new byte[32];
        byte[] salt = Random(12);

        byte[] hybrid = HybridCombiner.DeriveHybrid(mlKem, classicalZero, salt);
        byte[] mlKemOnly = HybridCombiner.DeriveMlKemOnly(mlKem, salt);

        Assert.NotEqual(hybrid, mlKemOnly);
    }

    [Fact]
    public void Changing_the_classical_secret_changes_the_hybrid_derived_key()
    {
        byte[] mlKem = Random(32);
        byte[] salt = Random(12);

        byte[] a = HybridCombiner.DeriveHybrid(mlKem, Random(32), salt);
        byte[] b = HybridCombiner.DeriveHybrid(mlKem, Random(32), salt);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_the_salt_changes_the_derived_key()
    {
        byte[] mlKem = Random(32);
        byte[] classical = Random(32);

        byte[] a = HybridCombiner.DeriveHybrid(mlKem, classical, Random(12));
        byte[] b = HybridCombiner.DeriveHybrid(mlKem, classical, Random(12));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Wrong_size_ml_kem_secret_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => HybridCombiner.DeriveMlKemOnly(new byte[16], new byte[12]));
        Assert.Throws<ArgumentException>(() => HybridCombiner.DeriveHybrid(new byte[16], new byte[32], new byte[12]));
    }

    [Fact]
    public void Empty_classical_secret_is_rejected_in_hybrid_mode()
    {
        Assert.Throws<ArgumentException>(() => HybridCombiner.DeriveHybrid(new byte[32], [], new byte[12]));
    }
}
