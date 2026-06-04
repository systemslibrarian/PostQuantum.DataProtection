using PostQuantum.KeyManagement.Local;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Test-suite-wide defaults. The Argon2id work factor is deliberately tiny so the suite runs in
/// seconds, not minutes. Do not copy these values into production code.
/// </summary>
internal static class TestDefaults
{
    public const string Passphrase = "correct horse battery staple — high-entropy fake for tests";

    public static LocalKekOptions FastKek => new()
    {
        DegreeOfParallelism = 1,
        MemorySizeInKib = 8 * 1024,   // 8 MiB — well below any production preset
        Iterations = 1,
    };

    public static LocalContentKeyProvider CreateContentKeyProvider() =>
        LocalContentKeyProvider.Create(Passphrase, FastKek);

    /// <summary>Returns a fresh, isolated temp directory; the caller deletes it.</summary>
    public static string CreateTempDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pq-dp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
