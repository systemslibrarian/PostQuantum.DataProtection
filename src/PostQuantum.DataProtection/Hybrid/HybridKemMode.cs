namespace PostQuantum.DataProtection.Hybrid;

/// <summary>
/// Selects how the AES-256-GCM content key is derived inside the envelope.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Hybrid"/> is the secure default and the only setting recommended for production. It
/// derives the content key from the HKDF of <em>both</em> the ML-KEM-768 shared secret and the
/// symmetric secret carried by <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/>. An
/// attacker has to defeat <em>both</em> layers to recover plaintext, which is the whole point of a
/// hybrid KEM: classical-broken (e.g. weak passphrase) does not lose confidentiality because
/// ML-KEM is still in the way; quantum-broken (e.g. CRQC against the lattice) does not lose
/// confidentiality because the classical wrap is still in the way.
/// </para>
/// <para>
/// <see cref="MlKemOnly"/> drops the classical layer and uses only the ML-KEM shared secret. It is
/// intended for tests, KATs, and callers who explicitly do not have a classical KEK available. Do
/// not pick it lightly — the only way <see cref="MlKemOnly"/> beats <see cref="Hybrid"/> on a
/// production system is space (about 90 bytes per envelope) and the cost of one extra AES-GCM
/// unwrap on the host KEK.
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
    /// ML-KEM-768 combined with the symmetric KEK from
    /// <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/> via HKDF-SHA-256. The default.
    /// </summary>
    Hybrid = 1,

    /// <summary>
    /// ML-KEM-768 combined with the symmetric KEK via an X-Wing-style combiner
    /// (SHA3-256 over the ML-KEM ciphertext, ML-KEM shared secret, classical secret, and a domain
    /// label). Sharper construction in some adversary models than the HKDF combiner; the additional
    /// SHA3 cost is single-digit microseconds. Per
    /// <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">draft-connolly-cfrg-xwing-kem</a>
    /// — adapted because we don't ship a classical KEM in this layer; the classical secret comes
    /// from the host KEK.
    /// </summary>
    XWingHybrid = 2,
}
