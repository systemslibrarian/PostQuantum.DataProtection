// Multi-replica simulation: two independent "replica" hosts share a single Azure Key Vault as
// their PQ keystore. Replica A mints a fresh PQ keypair, encrypts a payload, and writes the
// envelope to disk. Replica B starts cold, finds the keypair in the shared vault, loads it, and
// decrypts the envelope written by Replica A.
//
// To keep the sample runnable without an actual Azure account, both replicas point at an
// in-process fake IKeyVaultSecretClient that emulates Key Vault's "last write wins" semantics.
// The point is the SHAPE: one keystore, two consumers, mutually intelligible PQ envelopes.

using System.Collections.Concurrent;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MultiReplica.Sample;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.AzureKeyVault;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

var sharedFakeVault = new InProcessKeyVault();
var sharedKeyManagementSalt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);

Console.WriteLine("=== Replica A: encrypting a payload ===");
string protectedBlob;
string activeKeyIdA;

await using (ServiceProvider replicaA = BuildReplica("A", sharedFakeVault, sharedKeyManagementSalt))
{
    var pqKeys = replicaA.GetRequiredService<PostQuantumKeyManager>();
    activeKeyIdA = await pqKeys.GetActiveKeyIdAsync();
    Console.WriteLine($"  active PQ keypair: {activeKeyIdA}");

    IDataProtector protector = replicaA.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("multi-replica.shared-secret");
    protectedBlob = protector.Protect("a message from replica A to anyone with the keystore");
    Console.WriteLine($"  protected blob (truncated): {protectedBlob[..Math.Min(60, protectedBlob.Length)]}…");
}

Console.WriteLine();
Console.WriteLine("=== Replica B: starting cold, decrypting the payload ===");

await using (ServiceProvider replicaB = BuildReplica("B", sharedFakeVault, sharedKeyManagementSalt))
{
    var pqKeys = replicaB.GetRequiredService<PostQuantumKeyManager>();
    string activeKeyIdB = await pqKeys.GetActiveKeyIdAsync();
    Console.WriteLine($"  active PQ keypair: {activeKeyIdB} (same as A: {activeKeyIdA == activeKeyIdB})");

    IDataProtector protector = replicaB.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("multi-replica.shared-secret");
    string roundtripped = protector.Unprotect(protectedBlob);
    Console.WriteLine($"  decrypted: \"{roundtripped}\"");
}

Console.WriteLine();
Console.WriteLine("=== Replica B rotates the PQ keypair while A is offline ===");

string newKeyIdAfterRotation;
await using (ServiceProvider replicaB2 = BuildReplica("B", sharedFakeVault, sharedKeyManagementSalt))
{
    var pqKeys = replicaB2.GetRequiredService<PostQuantumKeyManager>();
    newKeyIdAfterRotation = await pqKeys.RotateAsync();
    Console.WriteLine($"  new active PQ keypair: {newKeyIdAfterRotation}");
}

Console.WriteLine();
Console.WriteLine("=== Replica A comes back, sees the new keypair, still decrypts the OLD payload ===");

await using (ServiceProvider replicaA2 = BuildReplica("A", sharedFakeVault, sharedKeyManagementSalt))
{
    var pqKeys = replicaA2.GetRequiredService<PostQuantumKeyManager>();
    string activeA2 = await pqKeys.GetActiveKeyIdAsync();
    Console.WriteLine($"  active PQ keypair on A: {activeA2} (matches B's rotation: {activeA2 == newKeyIdAfterRotation})");

    IReadOnlyList<PostQuantumKeyDescriptor> descriptors = await pqKeys.ListKeysAsync();
    Console.WriteLine($"  total keypairs loaded: {descriptors.Count} (the original + the rotated-in one)");

    IDataProtector protector = replicaA2.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("multi-replica.shared-secret");
    string roundtripped = protector.Unprotect(protectedBlob);
    Console.WriteLine($"  decrypted with the OLD keypair: \"{roundtripped}\"");
}

Console.WriteLine();
Console.WriteLine("Done. The shape works against a real Azure Key Vault, AWS Secrets Manager, or any other IPostQuantumKeyStore.");

static ServiceProvider BuildReplica(string name, IKeyVaultSecretClient sharedVault, byte[] sharedSalt)
{
    var services = new ServiceCollection();
    services.AddLogging(b => b.AddSimpleConsole(o =>
    {
        o.SingleLine = true;
        o.TimestampFormat = "[HH:mm:ss] ";
    }).SetMinimumLevel(LogLevel.Warning));

    // Same host KEK across both replicas: same passphrase + same salt => same KEK.
    services.AddSingleton<IContentKeyProvider>(_ => LocalContentKeyProvider.Create(
        "multi-replica-sample-passphrase",
        sharedSalt,
        new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 }));

    // Both replicas share the SAME fake Key Vault.
    services.AddSingleton<IPostQuantumKeyStore>(_ => new AzureKeyVaultPostQuantumKeyStore(sharedVault));

    services.AddSingleton<PostQuantumKeyManager>(sp => new PostQuantumKeyManager(
        sp.GetRequiredService<IContentKeyProvider>(),
        sp.GetRequiredService<IPostQuantumKeyStore>(),
        sp.GetService<ILogger<PostQuantumKeyManager>>()));

    services
        .AddDataProtection()
        .SetApplicationName("MultiReplica.Sample")
        .DisableAutomaticKeyGeneration()
        .Services
        .AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>()
        .Configure<PostQuantumKeyManager, IContentKeyProvider, ILoggerFactory>(
            (o, pqKeys, contentKeys, lf) =>
            {
                o.XmlEncryptor = new PostQuantumXmlEncryptor(pqKeys, contentKeys, HybridKemMode.Hybrid, lf.CreateLogger<PostQuantumXmlEncryptor>());
            });

    return services.BuildServiceProvider();
}

namespace MultiReplica.Sample
{
    internal sealed class InProcessKeyVault : IKeyVaultSecretClient
    {
        private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

        public ValueTask<string?> GetSecretValueAsync(string name, CancellationToken cancellationToken) =>
            new(_values.TryGetValue(name, out string? v) ? v : null);

#pragma warning disable CS1998
        public async IAsyncEnumerable<string> ListSecretNamesAsync(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
#pragma warning restore CS1998
        {
            foreach (string name in _values.Keys.OrderBy(n => n, StringComparer.Ordinal))
            {
                yield return name;
            }
        }

        public ValueTask<string> SetSecretValueAsync(string name, string value, CancellationToken cancellationToken)
        {
            _values[name] = value;
            return new ValueTask<string>(Guid.NewGuid().ToString("N"));
        }

        public ValueTask<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken)
            => new(_values.TryRemove(name, out _));
    }
}
