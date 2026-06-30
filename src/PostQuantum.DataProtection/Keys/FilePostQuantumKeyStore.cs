using System.Text;

namespace PostQuantum.DataProtection.Keys;

/// <summary>
/// File-backed <see cref="IPostQuantumKeyStore"/>. Serialises the keyring as one Base64Url-encoded
/// <see cref="PostQuantumKeyPair"/> per line, plus a leading line that pins the active key id.
/// Writes are atomic via <c>File.Replace</c>; concurrent readers race-tolerant via a bounded retry.
/// </summary>
/// <remarks>
/// <para>
/// File format (UTF-8, no BOM):
/// </para>
/// <code>
/// active &lt;keyId&gt;
/// pair   &lt;base64url-token&gt;
/// pair   &lt;base64url-token&gt;
/// ...
/// </code>
/// <para>
/// The tokens carry no plaintext key material — the secret key is already wrapped by the host
/// <c>IContentKeyProvider</c>. Losing this file means losing the ability to decrypt persisted Data
/// Protection keys; treat it like a database and back it up.
/// </para>
/// </remarks>
public sealed class FilePostQuantumKeyStore : IPostQuantumKeyStore
{
    private const int MaxLines = 1_000;
    private const int RenameRetryCount = 5;
    private static readonly TimeSpan RenameRetryDelay = TimeSpan.FromMilliseconds(50);

    private readonly string _path;
    private readonly object _sync = new();
    private List<PostQuantumKeyPair> _pairs = [];
    private string? _activeKeyId;
    private bool _loaded;

    /// <summary>Creates a store rooted at <paramref name="path"/>. The directory is created on demand.</summary>
    public FilePostQuantumKeyStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    /// <inheritdoc />
    public string? ActiveKeyId
    {
        get
        {
            lock (_sync)
            {
                EnsureLoaded();
                return _activeKeyId;
            }
        }
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<PostQuantumKeyPair>> LoadAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            EnsureLoaded();
            return new ValueTask<IReadOnlyList<PostQuantumKeyPair>>(_pairs.ToArray());
        }
    }

    /// <inheritdoc />
    public ValueTask<bool> DeleteAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            EnsureLoaded();
            if (string.Equals(keyId, _activeKeyId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Refusing to delete the active PQ keypair '{keyId}'. " +
                    "Rotate first so a new keypair becomes active, then prune the previous one.");
            }

            int index = _pairs.FindIndex(p => string.Equals(p.KeyId, keyId, StringComparison.Ordinal));
            if (index < 0)
            {
                return new ValueTask<bool>(false);
            }

            _pairs.RemoveAt(index);
            WriteAtomically(_path, _pairs, _activeKeyId);
            return new ValueTask<bool>(true);
        }
    }

    /// <inheritdoc />
    public ValueTask SaveAsync(PostQuantumKeyPair newActive, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newActive);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_sync)
        {
            EnsureLoaded();

            // Replace any existing entry with the same id (rotation rewrites do this); otherwise append.
            int existing = _pairs.FindIndex(p => string.Equals(p.KeyId, newActive.KeyId, StringComparison.Ordinal));
            if (existing >= 0)
            {
                _pairs[existing] = newActive;
            }
            else
            {
                _pairs.Add(newActive);
            }

            _activeKeyId = newActive.KeyId;
            WriteAtomically(_path, _pairs, _activeKeyId);
        }

        return ValueTask.CompletedTask;
    }

    private void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }

        if (!File.Exists(_path))
        {
            _pairs = [];
            _activeKeyId = null;
            _loaded = true;
            return;
        }

        (_pairs, _activeKeyId) = ReadFile(_path);
        _loaded = true;
    }

    private static (List<PostQuantumKeyPair> Pairs, string? ActiveKeyId) ReadFile(string path)
    {
        string[] lines = File.ReadAllLines(path, Encoding.UTF8);
        if (lines.Length > MaxLines)
        {
            throw new InvalidOperationException(
                $"PostQuantum keyring file '{path}' has {lines.Length} lines (cap {MaxLines}); refusing to parse.");
        }

        var pairs = new List<PostQuantumKeyPair>();
        string? activeKeyId = null;

        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            int space = line.IndexOf(' ', StringComparison.Ordinal);
            if (space <= 0)
            {
                throw new FormatException($"Malformed PostQuantum keyring line in '{path}'.");
            }

            string kind = line[..space];
            string value = line[(space + 1)..].Trim();

            switch (kind)
            {
                case "active":
                    activeKeyId = value;
                    break;
                case "pair":
                    pairs.Add(PostQuantumKeyPair.Decode(value));
                    break;
                default:
                    // Forward-compat: ignore unknown line kinds so a newer writer can add lines a
                    // current reader does not understand without breaking the load. New required
                    // fields should bump the per-pair format version, not invent new line kinds.
                    break;
            }
        }

        if (activeKeyId is not null && pairs.TrueForAll(p => !string.Equals(p.KeyId, activeKeyId, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"PostQuantum keyring '{path}' names active key '{activeKeyId}' but no matching pair entry was found.");
        }

        return (pairs, activeKeyId);
    }

    private static void WriteAtomically(string path, IReadOnlyList<PostQuantumKeyPair> pairs, string? activeKeyId)
    {
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string tempPath = path + ".tmp." + Guid.NewGuid().ToString("N");
        try
        {
            var sb = new StringBuilder();
            if (activeKeyId is not null)
            {
                sb.Append("active ").Append(activeKeyId).Append('\n');
            }

            foreach (PostQuantumKeyPair pair in pairs)
            {
                sb.Append("pair ").Append(pair.Encode()).Append('\n');
            }

            // Use raw byte write so we do not emit a UTF-8 BOM (Windows-style File.WriteAllText would).
            File.WriteAllBytes(tempPath, Encoding.UTF8.GetBytes(sb.ToString()));

            if (File.Exists(path))
            {
                ReplaceWithRetry(tempPath, path);
            }
            else
            {
                try
                {
                    File.Move(tempPath, path);
                }
                catch (IOException) when (File.Exists(path))
                {
                    // TOCTOU: another writer (e.g. a concurrently cold-starting replica on a shared
                    // volume) created the file between our existence check and this move. Fall back to
                    // the retry-aware replace so we converge to the documented last-write-wins instead
                    // of throwing an unhandled IOException at startup.
                    ReplaceWithRetry(tempPath, path);
                }
            }
        }
        catch
        {
            if (File.Exists(tempPath))
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch (IOException)
                {
                    // Best-effort cleanup; the outer exception is what the caller needs to see.
                }
            }

            throw;
        }
    }

    private static void ReplaceWithRetry(string sourceFileName, string destinationFileName)
    {
        // On Windows a concurrent reader holding a share-handle on the destination can race
        // File.Replace and produce a transient IOException. Retry a few times with a small backoff;
        // POSIX rename does not need this but the retry is harmless there.
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                File.Replace(sourceFileName, destinationFileName, destinationBackupFileName: null);
                return;
            }
            catch (IOException) when (attempt < RenameRetryCount)
            {
                Thread.Sleep(RenameRetryDelay);
            }
        }
    }
}
