namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Selects how the AES-256-GCM content key is derived inside the envelope.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="XWingHybrid"/> is the recommended default for new deployments. Like <see cref="Hybrid"/>
/// it derives the content key from <em>both</em> the ML-KEM shared secret and the symmetric secret
/// carried by <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/>, so an attacker must defeat
/// <em>both</em> layers to recover plaintext — but it additionally binds the ML-KEM ciphertext into
/// the derivation, matching the security argument of the X-Wing combiner draft. The extra SHA3 cost
/// is single-digit microseconds.
/// </para>
/// <para>
/// <see cref="Hybrid"/> is the original combiner and remains fully supported: HKDF-SHA-256 over the
/// concatenation of the ML-KEM and classical shared secrets, salted by the per-envelope nonce. It is
/// safe (break either layer and confidentiality holds) but does not bind the ML-KEM ciphertext into
/// the KDF the way <see cref="XWingHybrid"/> does. Envelopes written under either mode keep decrypting
/// regardless of the current default — the mode is recorded per envelope.
/// </para>
/// <para>
/// <see cref="MlKemOnly"/> drops the classical layer and uses only the ML-KEM shared secret. It is
/// intended for tests, KATs, and callers who explicitly do not have a classical KEK available. Do
/// not pick it lightly — the only way <see cref="MlKemOnly"/> beats the hybrid modes on a production
/// system is space (about 90 bytes per envelope) and the cost of one extra AES-GCM unwrap on the
/// host KEK.
/// </para>
/// </remarks>
public enum HybridKemMode : byte
{
    /// <summary>
    /// ML-KEM-768 alone. Tests, KATs, and callers without a classical KEK. Not the production
    /// default.
    /// </summary>
    MlKemOnly = 0,

    /// <summary>
    /// ML-KEM combined with the symmetric KEK from
    /// <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/> via HKDF-SHA-256. Fully supported;
    /// <see cref="XWingHybrid"/> is the recommended default for new deployments.
    /// </summary>
    Hybrid = 1,

    /// <summary>
    /// ML-KEM combined with the symmetric KEK via an X-Wing-style combiner
    /// (SHA3-256 over the ML-KEM ciphertext, ML-KEM shared secret, classical secret, and a domain
    /// label). The recommended default for new deployments: it binds the ML-KEM ciphertext into the
    /// derivation, a sharper construction than the HKDF combiner; the additional SHA3 cost is
    /// single-digit microseconds. Per
    /// <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">draft-connolly-cfrg-xwing-kem</a>
    /// — adapted because we don't ship a classical KEM in this layer; the classical secret comes
    /// from the host KEK.
    /// </summary>
    XWingHybrid = 2,
}
