namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Which FIPS 203 ML-KEM parameter set to use.
/// </summary>
/// <remarks>
/// <para>
/// All three are FIPS 203 standard parameter sets and produce envelopes that the same decoder
/// understands — the wire format records the algorithm label as a string, so a host that rolls
/// from one set to another keeps decrypting prior envelopes correctly. New encryptions target
/// the currently configured set.
/// </para>
/// <para>
/// The keypair id prefix reflects the parameter set: <c>pq-mlkem512-…</c>, <c>pq-mlkem768-…</c>,
/// or <c>pq-mlkem1024-…</c>.
/// </para>
/// </remarks>
public enum MlKemParameterSet : byte
{
    /// <summary>
    /// NIST category 1 (≈ 128-bit classical strength). Smallest envelope: pk = 800 B, sk = 1632 B,
    /// ciphertext = 768 B. Pick when envelope size is the binding constraint.
    /// </summary>
    Kem512 = 0,

    /// <summary>
    /// NIST category 3 (≈ 192-bit classical strength). The general-purpose choice and the default.
    /// pk = 1184 B, sk = 2400 B, ciphertext = 1088 B.
    /// </summary>
    Kem768 = 1,

    /// <summary>
    /// NIST category 5 (≈ 256-bit classical strength). Largest envelope: pk = 1568 B, sk = 3168 B,
    /// ciphertext = 1568 B. Pick when conservatism beats wire-size.
    /// </summary>
    Kem1024 = 2,
}
