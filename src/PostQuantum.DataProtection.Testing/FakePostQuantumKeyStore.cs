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

    /// <inheritdoc />
    public ValueTask<bool> DeleteAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        if (string.Equals(keyId, _activeKeyId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Refusing to delete the active PQ keypair '{keyId}'. Rotate first.");
        }

        return new ValueTask<bool>(_byId.TryRemove(keyId, out _));
    }

    /// <summary>The number of keypairs currently held. Useful for asserting rotation/pruning behaviour in tests.</summary>
    public int Count => _byId.Count;

    /// <summary>The ids of every keypair currently held, for test assertions.</summary>
    public IReadOnlyCollection<string> KeyIds => _byId.Keys.ToArray();

    /// <summary>
    /// Corrupts the wrapped secret key of the keypair with id <paramref name="keyId"/> so that any
    /// attempt to decapsulate (decrypt) under it fails closed with a <c>CryptographicException</c>.
    /// Use this to exercise your own code's fail-closed handling of unreadable key material. The
    /// public key and routing fields are left intact, so encryption to other keys is unaffected.
    /// </summary>
    /// <returns><see langword="true"/> if a keypair was corrupted; <see langword="false"/> if the id was unknown.</returns>
    public bool CorruptSecretKey(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        if (!_byId.TryGetValue(keyId, out PostQuantumKeyPair? pair))
        {
            return false;
        }

        byte[] garbage = pair.WrappedSecretKey.Length > 0 ? (byte[])pair.WrappedSecretKey.Clone() : new byte[1];
        garbage[^1] ^= 0xFF; // flip the last byte (secret-key ciphertext region) — unwrap fails the AEAD tag
        _byId[keyId] = pair with { WrappedSecretKey = garbage };
        return true;
    }
}
