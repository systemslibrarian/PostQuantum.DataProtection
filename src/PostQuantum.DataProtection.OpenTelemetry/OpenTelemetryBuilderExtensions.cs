using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using PostQuantum.DataProtection.Diagnostics;

namespace PostQuantum.DataProtection.OpenTelemetry;

/// <summary>
/// One-line wiring of the <see cref="Telemetry"/> Meter and ActivitySource into OpenTelemetry's
/// metrics and tracing pipelines.
/// </summary>
public static class OpenTelemetryBuilderExtensions
{
    /// <summary>
    /// Registers the <c>PostQuantum.DataProtection</c> Meter with this provider, so its counters
    /// and histograms flow through to whatever exporter the host configured (Prometheus, OTLP,
    /// Console, etc.).
    /// </summary>
    public static MeterProviderBuilder AddPostQuantumDataProtectionInstrumentation(this MeterProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddMeter(Telemetry.MeterName);
    }

    /// <summary>
    /// Registers the <c>PostQuantum.DataProtection</c> ActivitySource with this provider, so the
    /// "Encrypt" / "Decrypt" activities show up in traces alongside the host's other spans.
    /// </summary>
    public static TracerProviderBuilder AddPostQuantumDataProtectionInstrumentation(this TracerProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddSource(Telemetry.MeterName);
    }
}
