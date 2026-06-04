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
}
