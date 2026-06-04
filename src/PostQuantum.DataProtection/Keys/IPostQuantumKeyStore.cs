namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// Persists the long-lived <see cref="PostQuantumKeyPair"/>s used to encrypt and decrypt Data
/// Protection key material. The secret key is already envelope-encrypted by the time it reaches an
/// implementation — the store sees only opaque tokens.
/// </summary>
/// <remarks>
/// <para>
/// A production store should provide atomic writes (so a crash mid-rotation does not leave a
/// half-written file) and durability (so the keypair survives host restarts). The bundled
/// <see cref="FilePostQuantumKeyStore"/> does both for the file-on-disk case; cloud-backed stores
/// (blob, S3, KMS-bound) are roadmap.
/// </para>
/// <para>
/// The store should return <em>all</em> historically known keypairs from <see cref="LoadAllAsync"/>
/// so a payload encrypted under an older keypair still decrypts after a rotation. The active key
/// — the one used for fresh encryptions — is the one whose id matches <see cref="ActiveKeyId"/>.
/// </para>
/// </remarks>
public interface IPostQuantumKeyStore
{
    /// <summary>The id of the keypair that fresh encryptions should target. Null if the store is empty.</summary>
    string? ActiveKeyId { get; }

    /// <summary>Loads every keypair known to this store, in stable order.</summary>
    ValueTask<IReadOnlyList<PostQuantumKeyPair>> LoadAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Appends a new keypair to the store and marks it active. Must be atomic — a crash mid-save
    /// must leave either the prior state or the new state on disk, never a torn write.
    /// </summary>
    ValueTask SaveAsync(PostQuantumKeyPair newActive, CancellationToken cancellationToken = default);
}
