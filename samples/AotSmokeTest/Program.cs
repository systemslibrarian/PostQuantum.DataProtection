// AOT smoke test for PostQuantum.DataProtection on net10.
//
// What this program does:
//   1. Wires PostQuantum.KeyManagement (no DI binder reflection).
//   2. Generates a fresh in-memory ML-KEM-768 keypair via PostQuantumKeyManager.
//   3. Encapsulates + decapsulates against it.
//   4. Wraps a plaintext element through the full hybrid envelope and unwraps it.
//   5. Reports success/failure to stdout, exits 0/1.
//
// Build:
//   dotnet publish samples/AotSmokeTest -c Release -r linux-x64
//   dotnet publish samples/AotSmokeTest -c Release -r win-x64
//
// The build itself is the test: PublishAot=true succeeds iff the entire dependency closure
// is AOT-safe. We don't have any explicit warning suppression in this project.

using System.Xml.Linq;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using PostQuantum.DataProtection.Testing;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

try
{
    // Use the bundled in-memory pair to avoid filesystem IO.
    var keys = LocalContentKeyProvider.Create(
        "aot-smoke-passphrase-not-secret",
        new LocalKekOptions { DegreeOfParallelism = 1, MemorySizeInKib = 8 * 1024, Iterations = 1 });
    var store = new FakePostQuantumKeyStore();
    var manager = new PostQuantumKeyManager(keys, store);

    string activeId = await manager.GetActiveKeyIdAsync();
    if (!activeId.StartsWith("pq-mlkem768-", StringComparison.Ordinal))
    {
        Console.Error.WriteLine($"FAIL: unexpected key id '{activeId}'.");
        return 1;
    }

    var encryptor = new PostQuantumXmlEncryptor(manager, keys, HybridKemMode.Hybrid);
    var decryptor = new PostQuantumXmlDecryptor(manager, keys);

    var payload = new XElement("p", "aot-smoke-test-payload");
    var encrypted = encryptor.Encrypt(payload).EncryptedElement;
    var decrypted = decryptor.Decrypt(encrypted);

    if (decrypted.Value != "aot-smoke-test-payload")
    {
        Console.Error.WriteLine($"FAIL: roundtrip mismatch; got '{decrypted.Value}'.");
        return 1;
    }

    Console.WriteLine($"OK: PostQuantum.DataProtection roundtrip succeeded under AOT (active key {activeId}).");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"FAIL: {ex.GetType().Name}: {ex.Message}");
    return 1;
}
