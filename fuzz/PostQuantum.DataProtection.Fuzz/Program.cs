// SharpFuzz harness for PostQuantum.DataProtection's untrusted-input decoders. Drives both the
// HybridKemEnvelope decoder and the PostQuantumKeyPair decoder with attacker-controlled bytes.
//
// Usage with afl-fuzz (Linux):
//   sharpfuzz src/PostQuantum.DataProtection/bin/Release/net10.0/PostQuantum.DataProtection.dll
//   afl-fuzz -i corpus -o findings -- dotnet fuzz/PostQuantum.DataProtection.Fuzz/bin/Release/net10.0/PostQuantum.DataProtection.Fuzz.dll envelope
//
// The "target" CLI arg selects which decoder to fuzz. "envelope" hits HybridKemEnvelope.Decode;
// "keypair" hits PostQuantumKeyPair.Decode.

using System.Text;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using SharpFuzz;

string target = args.Length > 0 ? args[0] : "envelope";

Action<ReadOnlySpan<byte>> handler = target switch
{
    "keypair" => FuzzKeypair,
    _ => FuzzEnvelope,
};

Fuzzer.OutOfProcess.Run(stream =>
{
    using var ms = new MemoryStream();
    stream.CopyTo(ms);
    byte[] bytes = ms.ToArray();
    handler(bytes);
});

static void FuzzEnvelope(ReadOnlySpan<byte> bytes)
{
    // The decoder expects a Base64Url string. Treat the fuzzer's bytes as either:
    //   (a) raw UTF-8 to interpret as a token directly, or
    //   (b) a binary blob to Base64Url-encode and pass in.
    // (a) hits the Base64Url parser's hostile-input handling.
    // (b) hits the post-decode binary parser.
    if (bytes.Length == 0)
    {
        return;
    }

    string asText = Encoding.UTF8.GetString(bytes);
    TryDecodeEnvelope(asText);

    string asBase64Url = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    TryDecodeEnvelope(asBase64Url);
}

static void TryDecodeEnvelope(string token)
{
    try
    {
        _ = HybridKemEnvelope.Decode(token);
    }
    catch (ArgumentException) { /* expected */ }
    catch (FormatException) { /* expected */ }
}

static void FuzzKeypair(ReadOnlySpan<byte> bytes)
{
    if (bytes.Length == 0)
    {
        return;
    }

    string asText = Encoding.UTF8.GetString(bytes);
    TryDecodeKeypair(asText);

    string asBase64Url = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    TryDecodeKeypair(asBase64Url);
}

static void TryDecodeKeypair(string token)
{
    try
    {
        _ = PostQuantumKeyPair.Decode(token);
    }
    catch (ArgumentException) { /* expected */ }
    catch (FormatException) { /* expected */ }
}
