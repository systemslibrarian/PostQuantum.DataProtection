namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// A non-secret, ops-friendly description of one PQ keypair held by
/// <see cref="PostQuantumKeyManager"/>. Safe to emit from a health endpoint, a metrics scraper,
/// or an admin tool — carries identifiers and timing only, never key material.
/// </summary>
public sealed record PostQuantumKeyDescriptor
{
    /// <summary>Stable identifier of the keypair (the same id that appears in <c>HybridKemEnvelope.PublicKeyId</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>The KEM algorithm label (currently always <c>"ML-KEM-768"</c>).</summary>
    public required string Algorithm { get; init; }

    /// <summary>When this keypair was generated (UTC).</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary><see langword="true"/> if this is the keypair fresh encryptions are wrapped under.</summary>
    public required bool IsActive { get; init; }
}
