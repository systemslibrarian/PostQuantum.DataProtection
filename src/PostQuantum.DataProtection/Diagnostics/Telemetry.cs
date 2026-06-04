using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;

namespace PostQuantum.DataProtection.Diagnostics;

/// <summary>
/// The single <see cref="Meter"/> + <see cref="ActivitySource"/> the library publishes from.
/// Subscribe with <c>builder.Services.AddOpenTelemetry().WithMetrics(m =&gt;
/// m.AddMeter(Telemetry.MeterName))</c> (or any other listener) to consume.
/// </summary>
/// <remarks>
/// <para>
/// <b>Counters</b>
/// </para>
/// <list type="bullet">
///   <item><description><c>pq_dataprotection.encryptions</c> — number of envelopes produced, tagged with <c>mode</c>.</description></item>
///   <item><description><c>pq_dataprotection.decryptions</c> — number of envelopes successfully decoded and decrypted, tagged with <c>mode</c>.</description></item>
///   <item><description><c>pq_dataprotection.decrypt_failures</c> — number of envelopes that failed to decrypt, tagged with <c>reason</c>.</description></item>
///   <item><description><c>pq_dataprotection.rotations</c> — number of PQ keypair rotations.</description></item>
/// </list>
/// <para><b>Histograms</b></para>
/// <list type="bullet">
///   <item><description><c>pq_dataprotection.encrypt.duration</c> — milliseconds per envelope encryption.</description></item>
///   <item><description><c>pq_dataprotection.decrypt.duration</c> — milliseconds per envelope decryption.</description></item>
/// </list>
/// <para>
/// Names use dot-separated identifiers per the OpenTelemetry naming conventions; OTel exporters
/// translate them to the target system's convention (Prometheus underscores, etc.).
/// </para>
/// </remarks>
public static class Telemetry
{
    /// <summary>The Meter / ActivitySource name the library publishes from. Stable across versions.</summary>
    public const string MeterName = "PostQuantum.DataProtection";

    /// <summary>The version emitted on the Meter / ActivitySource. Reflects the running assembly.</summary>
    public static readonly string MeterVersion =
        typeof(Telemetry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(Telemetry).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    internal static readonly Meter Meter = new(MeterName, MeterVersion);
    internal static readonly ActivitySource ActivitySource = new(MeterName, MeterVersion);

    internal static readonly Counter<long> Encryptions =
        Meter.CreateCounter<long>("pq_dataprotection.encryptions", unit: "{envelope}", description: "Number of post-quantum data-protection envelopes produced.");

    internal static readonly Counter<long> Decryptions =
        Meter.CreateCounter<long>("pq_dataprotection.decryptions", unit: "{envelope}", description: "Number of post-quantum data-protection envelopes successfully decrypted.");

    internal static readonly Counter<long> DecryptFailures =
        Meter.CreateCounter<long>("pq_dataprotection.decrypt_failures", unit: "{envelope}", description: "Number of post-quantum data-protection envelopes that failed to decrypt.");

    internal static readonly Counter<long> Rotations =
        Meter.CreateCounter<long>("pq_dataprotection.rotations", unit: "{rotation}", description: "Number of post-quantum keypair rotations.");

    internal static readonly Histogram<double> EncryptDuration =
        Meter.CreateHistogram<double>("pq_dataprotection.encrypt.duration", unit: "ms", description: "Time spent producing a post-quantum data-protection envelope.");

    internal static readonly Histogram<double> DecryptDuration =
        Meter.CreateHistogram<double>("pq_dataprotection.decrypt.duration", unit: "ms", description: "Time spent decrypting a post-quantum data-protection envelope.");
}
