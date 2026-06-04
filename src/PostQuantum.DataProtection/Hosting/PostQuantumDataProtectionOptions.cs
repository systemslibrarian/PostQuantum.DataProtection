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
    /// The hybrid mode for fresh encryptions. <see cref="HybridKemMode.Hybrid"/> is the only setting
    /// recommended for production; <see cref="HybridKemMode.MlKemOnly"/> is for tests and KAT runs.
    /// </summary>
    public HybridKemMode Mode { get; set; } = HybridKemMode.Hybrid;

    /// <summary>
    /// How often <see cref="PostQuantumRotationHostedService"/> should rotate the active PQ
    /// keypair when registered. Defaults to <see cref="TimeSpan.Zero"/>, which disables scheduled
    /// rotation. A typical production value is <see cref="TimeSpan.FromDays(double)"/> with 90
    /// days to match ASP.NET Core Data Protection's own default cadence.
    /// </summary>
    /// <remarks>
    /// Scheduled rotation does NOT delete old keypairs — they remain loaded so previously-wrapped
    /// Data Protection keys keep decrypting. Pruning is a separate, deliberate operator action.
    /// </remarks>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Which FIPS 203 ML-KEM parameter set to target for fresh keypairs. Defaults to
    /// <see cref="MlKemParameterSet.Kem768"/> (NIST category 3, general-purpose). Existing keypairs
    /// in the keystore continue to decrypt under their original parameter set regardless of this
    /// setting — only newly-generated keypairs adopt the new value.
    /// </summary>
    public MlKemParameterSet ParameterSet { get; set; } = MlKemParameterSet.Kem768;
}
