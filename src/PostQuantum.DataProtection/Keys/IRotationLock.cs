namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// Coordinates scheduled keypair rotation across multiple application replicas so that at most one
/// replica generates a new active keypair per rotation window. Optional — when no implementation is
/// registered the library assumes single-writer rotation (see <see cref="NullRotationLock"/>).
/// </summary>
/// <remarks>
/// <para>
/// Every bundled <see cref="IPostQuantumKeyStore"/> is last-write-wins on the active-key pointer: if
/// two replicas rotate at the same instant they each mint a keypair and the second write wins, which
/// is safe (both keypairs are retained and decrypt) but wasteful. Registering a distributed lock
/// turns the scheduled rotation into a single-leader operation: the replica that wins the lease
/// rotates, the others skip the window and pick up the new active key on their next load.
/// </para>
/// <para>
/// The lock applies only to the <em>scheduled</em> rotation driven by
/// <c>PostQuantumRotationHostedService</c>. A manual <see cref="PostQuantumKeyManager.RotateAsync"/>
/// call is the operator's responsibility to serialize.
/// </para>
/// </remarks>
public interface IRotationLock
{
    /// <summary>
    /// Attempts to acquire the rotation lease for up to <paramref name="leaseDuration"/>. Returns a
    /// handle to release on success, or <see langword="null"/> if another holder currently owns the
    /// lease (in which case the caller should skip this rotation window).
    /// </summary>
    /// <param name="leaseDuration">
    /// How long the lease is held before it expires automatically. Pick a value comfortably longer
    /// than a single rotation takes but short enough that a crashed holder does not block rotation
    /// for an unreasonable time.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An <see cref="IAsyncDisposable"/> whose disposal releases the lease, or <see langword="null"/>
    /// when the lease could not be acquired.
    /// </returns>
    ValueTask<IAsyncDisposable?> TryAcquireAsync(TimeSpan leaseDuration, CancellationToken cancellationToken = default);
}
