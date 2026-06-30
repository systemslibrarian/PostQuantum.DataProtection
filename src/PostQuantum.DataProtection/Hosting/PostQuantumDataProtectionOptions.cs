using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Hosting;

/// <summary>
/// Configuration for <c>ProtectKeysWithPostQuantum()</c>.
/// </summary>
public sealed class PostQuantumDataProtectionOptions
{
    /// <summary>
    /// Path to the file that holds the long-lived PQ keypair(s). Created on first run. Required —
    /// the default <see cref="IPostQuantumKeyStore"/> writes to this path. Treat it like a
    /// database: back it up; losing it means losing the ability to decrypt persisted Data
    /// Protection keys.
    /// </summary>
    public string? KeyStorePath { get; set; }

    /// <summary>
    /// The hybrid mode for fresh encryptions. <see cref="HybridKemMode.XWingHybrid"/> (the default)
    /// and <see cref="HybridKemMode.Hybrid"/> are both production-grade; <see cref="HybridKemMode.MlKemOnly"/>
    /// is for tests and KAT runs. Existing envelopes decrypt under whatever mode they were written
    /// with, so changing this value is non-breaking — only fresh encryptions adopt it.
    /// </summary>
    public HybridKemMode Mode { get; set; } = HybridKemMode.XWingHybrid;

    /// <summary>
    /// How often <see cref="PostQuantumRotationHostedService"/> should rotate the active PQ keypair.
    /// <see langword="null"/> (the default) disables scheduled rotation — rotation stays a manual
    /// operator action. A typical production value is <c>TimeSpan.FromDays(90)</c> to match ASP.NET
    /// Core Data Protection's own default cadence. A non-null value must be strictly positive;
    /// <see cref="TimeSpan.Zero"/> or a negative span is rejected at registration (leave the property
    /// <see langword="null"/> to disable rather than setting it to zero).
    /// </summary>
    /// <remarks>
    /// Scheduled rotation does NOT delete old keypairs — they remain loaded so previously-wrapped
    /// Data Protection keys keep decrypting. Pruning is a separate, deliberate operator action. In a
    /// multi-replica deployment register an <see cref="Keys.IRotationLock"/> (e.g. the Redis package's
    /// distributed lock) so only one replica rotates per window.
    /// </remarks>
    public TimeSpan? RotationInterval { get; set; }

    /// <summary>
    /// When <see langword="true"/> (the default) the chain eagerly initializes on host startup — it
    /// resolves the host <see cref="PostQuantum.KeyManagement.IContentKeyProvider"/>, loads (or
    /// generates) the active ML-KEM keypair, and verifies the keystore path is writable — so a
    /// misconfiguration fails fast at boot with an actionable error instead of lazily on the first
    /// protected request. Set to <see langword="false"/> to keep initialization lazy.
    /// </summary>
    public bool ValidateOnStartup { get; set; } = true;

    /// <summary>
    /// Which FIPS 203 ML-KEM parameter set to target for fresh keypairs. Defaults to
    /// <see cref="MlKemParameterSet.Kem768"/> (NIST category 3, general-purpose). Existing keypairs
    /// in the keystore continue to decrypt under their original parameter set regardless of this
    /// setting — only newly-generated keypairs adopt the new value.
    /// </summary>
    public MlKemParameterSet ParameterSet { get; set; } = MlKemParameterSet.Kem768;
}
