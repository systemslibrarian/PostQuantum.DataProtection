using System.Collections.Concurrent;
using PostQuantum.DataProtection.Keys;

namespace PostQuantum.DataProtection.Testing;

/// <summary>
/// In-memory <see cref="IPostQuantumKeyStore"/> for unit tests. Backed by a
/// <see cref="ConcurrentDictionary{TKey, TValue}"/>; thread-safe; no disk I/O; gone the moment the
/// instance is collected.
/// </summary>
/// <remarks>
/// <para>
/// Use this when you want to write tests against your own code that *consumes*
/// <see cref="PostQuantumKeyManager"/> without depending on the real file-backed or cloud-backed
/// store. For an end-to-end test of the encryption chain itself, prefer the integration tests in
/// this repo's <c>tests/PostQuantum.DataProtection.Tests</c>.
/// </para>
/// <para>
/// Pair with <see cref="PostQuantum.KeyManagement.Local.LocalContentKeyProvider"/> at a tiny
/// Argon2id work factor for the host KEK — the test extension methods do this for you.
/// </para>
/// </remarks>
public sealed class FakePostQuantumKeyStore : IPostQuantumKeyStore
{
    private readonly ConcurrentDictionary<string, PostQuantumKeyPair> _byId = new(StringComparer.Ordinal);
    private string? _activeKeyId;

    /// <inheritdoc />
    public string? ActiveKeyId => _activeKeyId;

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<PostQuantumKeyPair>> LoadAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<PostQuantumKeyPair> snapshot = _byId.Values
            .OrderBy(p => p.CreatedAtUnixMs)
            .ToArray();
        return new ValueTask<IReadOnlyList<PostQuantumKeyPair>>(snapshot);
    }

    /// <inheritdoc />
    public ValueTask SaveAsync(PostQuantumKeyPair newActive, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newActive);
        cancellationToken.ThrowIfCancellationRequested();
        _byId[newActive.KeyId] = newActive;
        _activeKeyId = newActive.KeyId;
        return ValueTask.CompletedTask;
    }
}
