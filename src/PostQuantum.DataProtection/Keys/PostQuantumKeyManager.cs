using System.Security.Cryptography;
using PostQuantum.DataProtection.Diagnostics;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Internal;
using PostQuantum.KeyManagement;

namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// Orchestrates the long-lived ML-KEM keypair lifecycle: loads it from an
/// <see cref="IPostQuantumKeyStore"/>, generates one on first run, and exposes encapsulate /
/// decapsulate operations that fan out to the right keypair by id.
/// </summary>
/// <remarks>
/// <para>
/// The secret key is always at rest as an opaque blob whose internals are written here and read
/// back here. The blob layout is:
/// </para>
/// <code>
/// [InnerWrappedDekToken : length-prefixed utf8]  // a WrappedContentKey.Encode() token from the host provider
/// [Nonce                : 12 raw bytes]          // AES-GCM nonce
/// [Tag                  : 16 raw bytes]          // AES-GCM tag
/// [SkCiphertext         : length-prefixed bytes] // AES-256-GCM ciphertext of the ML-KEM private key
/// </code>
/// <para>
/// On decapsulate the manager unwraps the inner DEK via <see cref="IContentKeyProvider"/>,
/// AES-GCM-decrypts the SK with that DEK, performs the BouncyCastle decapsulation, and zeroes the
/// plaintext SK buffer before returning the shared secret.
/// </para>
/// <para>
/// This type is safe for concurrent use. The internal lock guards keypair-table mutations; the
/// cryptographic operations themselves run outside the lock so a slow KMS call cannot block other
/// readers.
/// </para>
/// </remarks>
public sealed class PostQuantumKeyManager : IDisposable
{
    private const int SkNonceLength = 12;
    private const int SkTagLength = 16;

    private readonly IContentKeyProvider _contentKeys;
    private readonly IPostQuantumKeyStore _store;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly object _stateLock = new();

    private bool _loaded;
    private Dictionary<string, PostQuantumKeyPair> _byId = new(StringComparer.Ordinal);
    private string? _activeKeyId;

    /// <summary>Creates a manager that wraps secret keys via <paramref name="contentKeys"/> and persists keypairs in <paramref name="store"/>.</summary>
    public PostQuantumKeyManager(IContentKeyProvider contentKeys, IPostQuantumKeyStore store)
    {
        ArgumentNullException.ThrowIfNull(contentKeys);
        ArgumentNullException.ThrowIfNull(store);
        _contentKeys = contentKeys;
        _store = store;
    }

    /// <summary>Releases the load-coordination primitive. The content-key provider is not owned.</summary>
    public void Dispose() => _loadLock.Dispose();

    /// <summary>Id of the active keypair (the one fresh encryptions target). Triggers a load on first read.</summary>
    public async ValueTask<string> GetActiveKeyIdAsync(CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        lock (_stateLock)
        {
            return _activeKeyId ?? throw new InvalidOperationException("No active PQ keypair after load — this is a bug.");
        }
    }

    /// <summary>
    /// Returns the public key bytes of the keypair identified by <paramref name="keyId"/>, or of the
    /// active keypair when <paramref name="keyId"/> is null.
    /// </summary>
    public async ValueTask<(string KeyId, byte[] PublicKey)> GetPublicKeyAsync(string? keyId = null, CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        lock (_stateLock)
        {
            string targetId = keyId ?? _activeKeyId
                ?? throw new InvalidOperationException("No active PQ keypair after load — this is a bug.");

            if (!_byId.TryGetValue(targetId, out PostQuantumKeyPair? pair))
            {
                throw new KeyNotFoundException(
                    $"No PQ keypair with id '{targetId}' is loaded. Re-create the manager with the store that produced it.");
            }

            return (pair.KeyId, (byte[])pair.PublicKey.Clone());
        }
    }

    /// <summary>
    /// Decapsulates <paramref name="kemCiphertext"/> against the keypair with id <paramref name="keyId"/>.
    /// Unwraps the secret key on demand and zeroes the plaintext buffer before returning.
    /// </summary>
    /// <returns>The 32-byte ML-KEM shared secret. Caller must zero it after use.</returns>
    public async ValueTask<byte[]> DecapsulateAsync(string keyId, ReadOnlyMemory<byte> kemCiphertext, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);

        PostQuantumKeyPair pair;
        lock (_stateLock)
        {
            if (!_byId.TryGetValue(keyId, out PostQuantumKeyPair? value))
            {
                throw new KeyNotFoundException(
                    $"No PQ keypair with id '{keyId}' is loaded. The envelope was encrypted to a key this manager does not know.");
            }

            pair = value;
        }

        byte[] secretKey = await UnwrapSecretKeyAsync(_contentKeys, pair.WrappedSecretKey, cancellationToken).ConfigureAwait(false);
        try
        {
            return MlKem.Decapsulate(secretKey, kemCiphertext.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKey);
        }
    }

    /// <summary>
    /// Generates a fresh ML-KEM-768 keypair, wraps the secret key via the host
    /// <see cref="IContentKeyProvider"/>, and persists it as the new active keypair.
    /// </summary>
    /// <returns>The id of the new active keypair.</returns>
    public async ValueTask<string> RotateAsync(CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        return await RotateCoreAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Lists every keypair this manager has loaded, in ascending creation-time order. Carries only
    /// the non-secret routing fields and creation timestamp — safe to surface from health endpoints,
    /// metrics, or admin tooling. Triggers a load on first call.
    /// </summary>
    public async ValueTask<IReadOnlyList<PostQuantumKeyDescriptor>> ListKeysAsync(CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        lock (_stateLock)
        {
            string? activeId = _activeKeyId;
            return _byId.Values
                .OrderBy(p => p.CreatedAtUnixMs)
                .Select(p => new PostQuantumKeyDescriptor
                {
                    KeyId = p.KeyId,
                    Algorithm = p.Algorithm,
                    CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(p.CreatedAtUnixMs),
                    IsActive = string.Equals(p.KeyId, activeId, StringComparison.Ordinal),
                })
                .ToArray();
        }
    }

    private async ValueTask<string> RotateCoreAsync(CancellationToken cancellationToken)
    {
        (byte[] publicKey, byte[] privateKey) = MlKem.GenerateKeyPair();
        try
        {
            byte[] wrappedSk = await WrapSecretKeyAsync(_contentKeys, privateKey, cancellationToken).ConfigureAwait(false);

            var pair = new PostQuantumKeyPair
            {
                KeyId = PostQuantumKeyPair.ComputeKeyId(publicKey),
                Algorithm = MlKem.AlgorithmName,
                PublicKey = (byte[])publicKey.Clone(),
                WrappedSecretKey = wrappedSk,
                CreatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };

            await _store.SaveAsync(pair, cancellationToken).ConfigureAwait(false);

            lock (_stateLock)
            {
                _byId[pair.KeyId] = pair;
                _activeKeyId = pair.KeyId;
            }

            Telemetry.Rotations.Add(1);
            return pair.KeyId;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private async ValueTask EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _loaded))
        {
            return;
        }

        await _loadLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _loaded))
            {
                return;
            }

            IReadOnlyList<PostQuantumKeyPair> pairs = await _store.LoadAllAsync(cancellationToken).ConfigureAwait(false);
            string? activeId = _store.ActiveKeyId;

            lock (_stateLock)
            {
                _byId = pairs.ToDictionary(p => p.KeyId, StringComparer.Ordinal);
                _activeKeyId = activeId;
            }

            if (activeId is null)
            {
                _ = await RotateCoreAsync(cancellationToken).ConfigureAwait(false);
            }

            Volatile.Write(ref _loaded, true);
        }
        finally
        {
            _loadLock.Release();
        }
    }

    // === Secret-key wrap / unwrap ===========================================
    //
    // IContentKeyProvider wraps 32-byte DEKs, not arbitrary byte arrays. To wrap a 2400-byte ML-KEM
    // private key we use the standard envelope pattern: a fresh DEK from the host provider, AES-GCM
    // the SK with that DEK, and persist (wrapped DEK || nonce || tag || ciphertext) as one blob.

    private static async ValueTask<byte[]> WrapSecretKeyAsync(IContentKeyProvider contentKeys, byte[] secretKey, CancellationToken cancellationToken)
    {
        using ContentKey dek = await contentKeys.CreateContentKeyAsync(cancellationToken).ConfigureAwait(false);

        byte[] nonce = RandomNumberGenerator.GetBytes(SkNonceLength);
        byte[] tag = new byte[SkTagLength];
        byte[] ciphertext = new byte[secretKey.Length];

        using (var aes = new AesGcm(dek.Key, SkTagLength))
        {
            aes.Encrypt(nonce, secretKey, ciphertext, tag);
        }

        using var buffer = new MemoryStream();
        PortableEncoding.WriteString(buffer, dek.WrappedKey.Encode());
        PortableEncoding.WriteRaw(buffer, nonce);
        PortableEncoding.WriteRaw(buffer, tag);
        PortableEncoding.WriteBytes(buffer, ciphertext);
        return buffer.ToArray();
    }

    internal static async ValueTask<byte[]> UnwrapSecretKeyAsync(IContentKeyProvider contentKeys, byte[] wrappedSk, CancellationToken cancellationToken)
    {
        int offset = 0;
        string innerDekToken = PortableEncoding.ReadString(wrappedSk, ref offset);
        byte[] nonce = PortableEncoding.ReadRaw(wrappedSk, ref offset, SkNonceLength);
        byte[] tag = PortableEncoding.ReadRaw(wrappedSk, ref offset, SkTagLength);
        byte[] ciphertext = PortableEncoding.ReadBytes(wrappedSk, ref offset);

        if (offset != wrappedSk.Length)
        {
            throw new CryptographicException("Wrapped secret key blob contains trailing bytes.");
        }

        WrappedContentKey innerDek = WrappedContentKey.Decode(innerDekToken);
        using ContentKey dek = await contentKeys.UnwrapAsync(innerDek, cancellationToken).ConfigureAwait(false);

        byte[] secretKey = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(dek.Key, SkTagLength);
            aes.Decrypt(nonce, ciphertext, tag, secretKey);
            return secretKey;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secretKey);
            throw;
        }
    }
}
