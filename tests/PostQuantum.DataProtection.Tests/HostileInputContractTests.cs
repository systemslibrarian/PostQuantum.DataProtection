using System.Security.Cryptography;
using System.Text;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.DataProtection.Keys;
using Xunit;

namespace PostQuantum.DataProtection.Tests;

/// <summary>
/// Property-based "fuzz lite" tests: drive thousands of random byte arrays through both decoders
/// and assert the documented exception-type contract. Any exception other than
/// <see cref="ArgumentException"/> or <see cref="FormatException"/> is a defect — the contract is
/// that malformed input is rejected cleanly, never thrown as a system-level fault.
/// </summary>
/// <remarks>
/// The standalone <c>fuzz/PostQuantum.DataProtection.Fuzz</c> SharpFuzz harness explores the same
/// surface with AFL-driven mutation; this test is what runs on every PR.
/// </remarks>
public sealed class HostileInputContractTests
{
    private const int Iterations = 10_000;
    private const int MaxByteLength = 4_096;

    [Fact]
    public void Envelope_Decode_only_throws_documented_exception_types_for_random_input()
    {
        // Seed deterministically so a failure is reproducible. The seed is arbitrary; any value
        // that exercises a reasonable input distribution is fine.
        byte[] seed = SHA256.HashData(Encoding.UTF8.GetBytes("PostQuantum.DataProtection envelope-contract-fuzz"));
        var random = new Random(BitConverter.ToInt32(seed, 0));

        for (int i = 0; i < Iterations; i++)
        {
            int length = random.Next(0, MaxByteLength);
            byte[] bytes = new byte[length];
            random.NextBytes(bytes);

            string asText = SafeUtf8(bytes);
            ExpectDocumentedFailureOrSuccess(() => HybridKemEnvelope.Decode(asText), iteration: i, source: "utf8");

            string asBase64Url = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            ExpectDocumentedFailureOrSuccess(() => HybridKemEnvelope.Decode(asBase64Url), iteration: i, source: "base64url");
        }
    }

    [Fact]
    public void Keypair_Decode_only_throws_documented_exception_types_for_random_input()
    {
        byte[] seed = SHA256.HashData(Encoding.UTF8.GetBytes("PostQuantum.DataProtection keypair-contract-fuzz"));
        var random = new Random(BitConverter.ToInt32(seed, 0));

        for (int i = 0; i < Iterations; i++)
        {
            int length = random.Next(0, MaxByteLength);
            byte[] bytes = new byte[length];
            random.NextBytes(bytes);

            string asText = SafeUtf8(bytes);
            ExpectDocumentedFailureOrSuccess(() => PostQuantumKeyPair.Decode(asText), iteration: i, source: "utf8");

            string asBase64Url = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            ExpectDocumentedFailureOrSuccess(() => PostQuantumKeyPair.Decode(asBase64Url), iteration: i, source: "base64url");
        }
    }

    [Fact]
    public void TryDecode_envelope_never_throws_for_any_random_input()
    {
        byte[] seed = SHA256.HashData(Encoding.UTF8.GetBytes("PostQuantum.DataProtection envelope-trydecode-fuzz"));
        var random = new Random(BitConverter.ToInt32(seed, 0));

        for (int i = 0; i < Iterations; i++)
        {
            int length = random.Next(0, MaxByteLength);
            byte[] bytes = new byte[length];
            random.NextBytes(bytes);

            string asText = SafeUtf8(bytes);
            _ = HybridKemEnvelope.TryDecode(asText, out _);

            string asBase64Url = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            _ = HybridKemEnvelope.TryDecode(asBase64Url, out _);
        }
    }

    private static void ExpectDocumentedFailureOrSuccess(Action action, int iteration, string source)
    {
        try
        {
            action();
        }
        catch (ArgumentException)
        {
            // Documented contract.
        }
        catch (FormatException)
        {
            // Documented contract.
        }
        catch (Exception ex)
        {
            throw new Xunit.Sdk.XunitException(
                $"Iteration {iteration} ({source}) threw an undocumented exception type {ex.GetType().FullName}: {ex.Message}");
        }
    }

    private static string SafeUtf8(byte[] bytes)
    {
        // Encoding.UTF8.GetString on arbitrary bytes is safe (it inserts replacement characters
        // for invalid sequences) — but we want raw bytes occasionally too, so reach the decoder
        // through both paths.
        return Encoding.UTF8.GetString(bytes);
    }
}
