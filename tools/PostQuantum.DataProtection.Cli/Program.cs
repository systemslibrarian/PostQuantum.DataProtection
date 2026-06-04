using System.Xml.Linq;
using PostQuantum.DataProtection;
using PostQuantum.DataProtection.Hybrid;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    PrintHelp();
    return 0;
}

return args[0] switch
{
    "inspect" => CommandInspect(args[1..]),
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
  pq-dp inspect <path-to-key.xml>      Inspect a Data Protection key XML file.
                                       Prints envelope routing fields, mode, public key id, and
                                       byte sizes. No secrets are emitted.
  pq-dp version                        Print the installed tool version.
  pq-dp --help                         Show this help.

EXAMPLES
  pq-dp inspect keys/data-protection/key-c6b3b03f-b73a-477b-92e5-d19ae0e0b5fd.xml
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

internal static partial class Program;
