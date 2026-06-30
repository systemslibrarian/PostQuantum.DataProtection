using System.Globalization;
using System.Xml.Linq;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    PrintHelp();
    return 0;
}

return args[0] switch
{
    "inspect" => CommandInspect(args[1..]),
    "keys" => await CommandKeys(args[1..]).ConfigureAwait(false),
    "doctor" => await CommandDoctor(args[1..]).ConfigureAwait(false),
    "verify" => CommandVerify(args[1..]),
    "version" => CommandVersion(),
    _ => Unknown(args[0]),
};

static int Unknown(string cmd)
{
    Console.Error.WriteLine($"pq-dp: unknown command '{cmd}'.");
    PrintHelp();
    return 2;
}

static void PrintHelp()
{
    Console.WriteLine("""
pq-dp — diagnostics CLI for PostQuantum.DataProtection.

USAGE
  pq-dp inspect <path-to-key.xml>      Inspect a Data Protection key XML file. Prints envelope
                                       routing fields, mode, public key id, and byte sizes.
  pq-dp keys list <keystore-path>      List every PQ keypair in a keystore file: id, algorithm,
                                       creation time, and which one is active.
  pq-dp keys export <keystore-path> [keyId]
                                       Print the (non-secret) public key, base64-encoded, for the
                                       given keypair id, or the active keypair if omitted.
  pq-dp doctor <keystore-path>         Health-check a keystore file: parseability, active-pointer
                                       consistency, key count, and age. Exit code 1 on problems.
  pq-dp verify <dp-key-directory>      Decode every PostQuantum.DataProtection envelope under a
                                       Data Protection key directory. Exit code 1 if any fail.
  pq-dp version                        Print the installed tool version.
  pq-dp --help                         Show this help.

NOTES
  No secrets are ever emitted. These commands read only non-secret routing/metadata; they do not
  need the host KEK and never decrypt key material.

EXAMPLES
  pq-dp inspect keys/data-protection/key-c6b3b03f.xml
  pq-dp keys list keys/pq-keystore.txt
  pq-dp doctor keys/pq-keystore.txt
  pq-dp verify keys/data-protection
""");
}

static int CommandVersion()
{
    string version = typeof(Program).Assembly
        .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
        .FirstOrDefault()?.InformationalVersion
        ?? typeof(Program).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    Console.WriteLine($"pq-dp {version}");
    return 0;
}

static int CommandInspect(string[] args)
{
    if (args.Length != 1)
    {
        Console.Error.WriteLine("pq-dp inspect: expected exactly one argument (path to key XML).");
        return 2;
    }

    string path = args[0];
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"pq-dp inspect: file not found: '{path}'.");
        return 1;
    }

    XDocument doc;
    try
    {
        doc = XDocument.Load(path);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"pq-dp inspect: '{path}' is not valid XML: {ex.Message}");
        return 1;
    }

    XElement? envelope = doc.Descendants(XName.Get(PostQuantumXmlEncryptor.XmlElementName, PostQuantumXmlEncryptor.XmlNamespace)).FirstOrDefault();
    if (envelope is null)
    {
        Console.Error.WriteLine(
            $"pq-dp inspect: no <{PostQuantumXmlEncryptor.XmlElementName}> element found in '{path}'. " +
            "This file is not protected by PostQuantum.DataProtection.");
        return 1;
    }

    string token = envelope.Value.Trim();
    if (!HybridKemEnvelope.TryDecode(token, out HybridKemEnvelope? decoded))
    {
        Console.Error.WriteLine($"pq-dp inspect: the envelope payload in '{path}' could not be decoded.");
        return 1;
    }

    Console.WriteLine($"File:                {path}");
    Console.WriteLine($"Format version:      {decoded.FormatVersion}");
    Console.WriteLine($"Mode:                {decoded.Mode}");
    Console.WriteLine($"KEM algorithm:       {decoded.KemAlgorithm}");
    Console.WriteLine($"Public key id:       {decoded.PublicKeyId}");
    Console.WriteLine($"KEM ciphertext:      {decoded.KemCiphertext.Length} bytes");
    Console.WriteLine($"Classical wrap:      {(decoded.ClassicalWrappedKeyToken.Length == 0 ? "(none — ML-KEM only mode)" : $"{decoded.ClassicalWrappedKeyToken.Length} chars")}");
    Console.WriteLine($"AES-GCM nonce:       {decoded.Nonce.Length} bytes");
    Console.WriteLine($"AES-GCM tag:         {decoded.Tag.Length} bytes");
    Console.WriteLine($"AES-GCM ciphertext:  {decoded.Ciphertext.Length} bytes");
    return 0;
}

static async Task<int> CommandKeys(string[] args)
{
    if (args.Length == 0)
    {
        Console.Error.WriteLine("pq-dp keys: expected a subcommand ('list' or 'export').");
        return 2;
    }

    return args[0] switch
    {
        "list" => await CommandKeysList(args[1..]).ConfigureAwait(false),
        "export" => await CommandKeysExport(args[1..]).ConfigureAwait(false),
        _ => UnknownKeysSub(args[0]),
    };
}

static int UnknownKeysSub(string sub)
{
    Console.Error.WriteLine($"pq-dp keys: unknown subcommand '{sub}' (expected 'list' or 'export').");
    return 2;
}

static async Task<int> CommandKeysList(string[] args)
{
    if (args.Length != 1)
    {
        Console.Error.WriteLine("pq-dp keys list: expected exactly one argument (path to keystore file).");
        return 2;
    }

    string path = args[0];
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"pq-dp keys list: keystore file not found: '{path}'.");
        return 1;
    }

    var store = new FilePostQuantumKeyStore(path);
    IReadOnlyList<PostQuantumKeyPair> pairs = await store.LoadAllAsync().ConfigureAwait(false);
    string? activeId = store.ActiveKeyId;

    if (pairs.Count == 0)
    {
        Console.WriteLine($"Keystore '{path}' contains no keypairs.");
        return 0;
    }

    Console.WriteLine($"{"ACTIVE",-7} {"KEY ID",-26} {"ALGORITHM",-13} CREATED (UTC)");
    foreach (PostQuantumKeyPair pair in pairs.OrderBy(p => p.CreatedAtUnixMs))
    {
        bool isActive = string.Equals(pair.KeyId, activeId, StringComparison.Ordinal);
        string created = DateTimeOffset.FromUnixTimeMilliseconds(pair.CreatedAtUnixMs).UtcDateTime.ToString("u", CultureInfo.InvariantCulture);
        Console.WriteLine($"{(isActive ? "  *" : "   "),-7} {pair.KeyId,-26} {pair.Algorithm,-13} {created}");
    }

    return 0;
}

static async Task<int> CommandKeysExport(string[] args)
{
    if (args.Length is < 1 or > 2)
    {
        Console.Error.WriteLine("pq-dp keys export: expected <keystore-path> [keyId].");
        return 2;
    }

    string path = args[0];
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"pq-dp keys export: keystore file not found: '{path}'.");
        return 1;
    }

    var store = new FilePostQuantumKeyStore(path);
    IReadOnlyList<PostQuantumKeyPair> pairs = await store.LoadAllAsync().ConfigureAwait(false);
    string? targetId = args.Length == 2 ? args[1] : store.ActiveKeyId;

    if (targetId is null)
    {
        Console.Error.WriteLine($"pq-dp keys export: keystore '{path}' has no active keypair and no id was given.");
        return 1;
    }

    PostQuantumKeyPair? pair = pairs.FirstOrDefault(p => string.Equals(p.KeyId, targetId, StringComparison.Ordinal));
    if (pair is null)
    {
        Console.Error.WriteLine($"pq-dp keys export: no keypair with id '{targetId}' in '{path}'.");
        return 1;
    }

    Console.WriteLine($"Key id:     {pair.KeyId}");
    Console.WriteLine($"Algorithm:  {pair.Algorithm}");
    Console.WriteLine($"Public key: {Convert.ToBase64String(pair.PublicKey)}");
    return 0;
}

static async Task<int> CommandDoctor(string[] args)
{
    if (args.Length != 1)
    {
        Console.Error.WriteLine("pq-dp doctor: expected exactly one argument (path to keystore file).");
        return 2;
    }

    string path = args[0];
    Console.WriteLine($"Keystore: {path}");

    if (!File.Exists(path))
    {
        Console.WriteLine("  [FAIL] file does not exist.");
        return 1;
    }

    var store = new FilePostQuantumKeyStore(path);
    IReadOnlyList<PostQuantumKeyPair> pairs;
    try
    {
        pairs = await store.LoadAllAsync().ConfigureAwait(false);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  [FAIL] could not parse keystore: {ex.Message}");
        return 1;
    }

    int problems = 0;
    int warnings = 0;
    string? activeId = store.ActiveKeyId;

    Console.WriteLine($"  [ OK ] parsed {pairs.Count} keypair(s).");

    if (pairs.Count == 0)
    {
        Console.WriteLine("  [FAIL] keystore is empty — no keypairs to decrypt with.");
        return 1;
    }

    if (activeId is null)
    {
        Console.WriteLine("  [FAIL] no active keypair pointer.");
        problems++;
    }
    else if (pairs.All(p => !string.Equals(p.KeyId, activeId, StringComparison.Ordinal)))
    {
        Console.WriteLine($"  [FAIL] active pointer '{activeId}' does not match any stored keypair.");
        problems++;
    }
    else
    {
        Console.WriteLine($"  [ OK ] active keypair '{activeId}' is present.");
    }

    if (pairs.Count == 1)
    {
        Console.WriteLine("  [WARN] only one keypair present — no rotation history yet.");
        warnings++;
    }

    PostQuantumKeyPair? active = pairs.FirstOrDefault(p => string.Equals(p.KeyId, activeId, StringComparison.Ordinal));
    if (active is not null)
    {
        TimeSpan age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeMilliseconds(active.CreatedAtUnixMs);
        Console.WriteLine($"  [INFO] active keypair age: {age.Days} day(s).");
        if (age.TotalDays > 365)
        {
            Console.WriteLine("  [WARN] active keypair is over a year old — consider rotating.");
            warnings++;
        }
    }

    Console.WriteLine(problems > 0
        ? $"Result: {problems} problem(s), {warnings} warning(s)."
        : warnings > 0 ? $"Result: healthy, {warnings} warning(s)." : "Result: healthy.");

    return problems > 0 ? 1 : 0;
}

static int CommandVerify(string[] args)
{
    if (args.Length != 1)
    {
        Console.Error.WriteLine("pq-dp verify: expected exactly one argument (path to Data Protection key directory).");
        return 2;
    }

    string dir = args[0];
    if (!Directory.Exists(dir))
    {
        Console.Error.WriteLine($"pq-dp verify: directory not found: '{dir}'.");
        return 1;
    }

    int ok = 0, skipped = 0, failed = 0;
    foreach (string file in Directory.EnumerateFiles(dir, "*.xml", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
    {
        XElement? envelope = null;
        try
        {
            envelope = XDocument.Load(file)
                .Descendants(XName.Get(PostQuantumXmlEncryptor.XmlElementName, PostQuantumXmlEncryptor.XmlNamespace))
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [FAIL] {file}: not valid XML ({ex.Message}).");
            failed++;
            continue;
        }

        if (envelope is null)
        {
            skipped++;
            continue;
        }

        if (HybridKemEnvelope.TryDecode(envelope.Value.Trim(), out HybridKemEnvelope? decoded))
        {
            Console.WriteLine($"  [ OK ] {Path.GetFileName(file)}: {decoded.Mode}, {decoded.KemAlgorithm}, key {decoded.PublicKeyId}.");
            ok++;
        }
        else
        {
            Console.WriteLine($"  [FAIL] {file}: PostQuantum envelope present but could not be decoded.");
            failed++;
        }
    }

    Console.WriteLine($"Result: {ok} decoded, {failed} failed, {skipped} non-PostQuantum file(s) skipped.");
    return failed > 0 ? 1 : 0;
}

internal static partial class Program;
