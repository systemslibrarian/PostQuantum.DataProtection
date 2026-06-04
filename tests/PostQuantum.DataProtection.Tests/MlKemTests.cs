using System.Security.Cryptography;
using PostQuantum.DataProtection.Hybrid;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

public sealed class MlKemTests
{
    [Fact]
    public void GenerateKeyPair_produces_keys_with_FIPS_203_sizes()
    {
        (byte[] pk, byte[] sk) = MlKem.GenerateKeyPair();

        Assert.Equal(MlKem.PublicKeyLength, pk.Length);
        Assert.Equal(MlKem.PrivateKeyLength, sk.Length);
        Assert.Equal(1184, pk.Length);
        Assert.Equal(2400, sk.Length);
    }

    [Fact]
    public void Encapsulate_and_Decapsulate_recover_the_same_shared_secret()
    {
        (byte[] pk, byte[] sk) = MlKem.GenerateKeyPair();

        (byte[] ciphertext, byte[] sharedSecret) = MlKem.Encapsulate(pk);

        Assert.Equal(MlKem.EncapsulationLength, ciphertext.Length);
        Assert.Equal(MlKem.SharedSecretLength, sharedSecret.Length);

        byte[] recovered = MlKem.Decapsulate(sk, ciphertext);
        Assert.Equal(sharedSecret, recovered);
    }

    [Fact]
    public void Decapsulate_with_a_different_secret_key_yields_a_different_shared_secret()
    {
        // ML-KEM is IND-CCA2: decapsulating against the "wrong" SK does not throw, it just yields
        // an implicit-rejection shared secret. The downstream AES-GCM verify is what surfaces the
        // failure to the caller — but the shared secret itself is observably different.
        (byte[] pkA, byte[] _) = MlKem.GenerateKeyPair();
        (byte[] _, byte[] skB) = MlKem.GenerateKeyPair();

        (byte[] ct, byte[] ssA) = MlKem.Encapsulate(pkA);
        byte[] ssWrong = MlKem.Decapsulate(skB, ct);

        Assert.Equal(MlKem.SharedSecretLength, ssWrong.Length);
        Assert.NotEqual(ssA, ssWrong);
    }

    [Fact]
    public void Encapsulate_rejects_wrong_size_public_key()
    {
        byte[] tooShort = new byte[10];
        Assert.Throws<ArgumentException>(() => MlKem.Encapsulate(tooShort));
    }

    [Fact]
    public void Decapsulate_rejects_wrong_size_private_key_and_ciphertext()
    {
        (byte[] pk, byte[] sk) = MlKem.GenerateKeyPair();
        (byte[] ct, byte[] _) = MlKem.Encapsulate(pk);

        Assert.Throws<ArgumentException>(() => MlKem.Decapsulate(new byte[10], ct));
        Assert.Throws<ArgumentException>(() => MlKem.Decapsulate(sk, new byte[10]));
    }

    [Fact]
    public void Two_encapsulations_against_the_same_public_key_produce_different_outputs()
    {
        (byte[] pk, byte[] _) = MlKem.GenerateKeyPair();
        (byte[] ct1, byte[] ss1) = MlKem.Encapsulate(pk);
        (byte[] ct2, byte[] ss2) = MlKem.Encapsulate(pk);

        Assert.NotEqual(ct1, ct2);
        Assert.NotEqual(ss1, ss2);
    }
}
