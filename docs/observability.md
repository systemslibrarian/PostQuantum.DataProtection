# Observability reference

`PostQuantum.DataProtection` publishes a single `Meter` and a single `ActivitySource`, both named
**`PostQuantum.DataProtection`** (the value of `Telemetry.MeterName`). The `ActivitySource` name
**equals** the meter name *by design* — the same constant names both, so one subscription string
covers metrics and traces.

This page is the authoritative list of metric instruments and activities. For the EventId-based log
signals, see [`docs/logging.md`](logging.md); for production alert thresholds, see
[`docs/deployment.md`](deployment.md).

## Wiring

### With the OpenTelemetry satellite package

The `PostQuantum.DataProtection.OpenTelemetry` package gives you one call each.

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddPostQuantumDataProtectionInstrumentation())
    .WithTracing(t => t.AddPostQuantumDataProtectionInstrumentation());
```

`AddPostQuantumDataProtectionInstrumentation` is an extension on both `MeterProviderBuilder` and
`TracerProviderBuilder`; each registers the `PostQuantum.DataProtection` source with that pipeline so
the counters, histograms, and activities flow to whatever exporter the host configured (Prometheus,
OTLP, Console, etc.).

### Without the package (manual)

If you don't want the satellite package, subscribe by name using the constant directly:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("PostQuantum.DataProtection"))
    .WithTracing(t => t.AddSource("PostQuantum.DataProtection"));
```

Both forms are equivalent — the package helpers simply pass `Telemetry.MeterName` to `AddMeter` /
`AddSource`.

## Metrics

| Instrument | Type | Unit | Tags | Meaning |
|---|---|---|---|---|
| `pq_dataprotection.encryptions` | `Counter<long>` | `{envelope}` | `mode` | Envelopes produced. |
| `pq_dataprotection.decryptions` | `Counter<long>` | `{envelope}` | `mode` | Envelopes decrypted successfully. |
| `pq_dataprotection.decrypt_failures` | `Counter<long>` | `{envelope}` | `reason` | Failed decrypts. `reason` values include `wrong_xml_element`, `malformed_envelope`, `key_not_found`, `auth_failure`. |
| `pq_dataprotection.rotations` | `Counter<long>` | `{rotation}` | *(none)* | PQ keypair rotations. |
| `pq_dataprotection.encrypt.duration` | `Histogram<double>` | `ms` | `mode` | Time spent producing an envelope. |
| `pq_dataprotection.decrypt.duration` | `Histogram<double>` | `ms` | `mode` | Time spent decrypting an envelope. |

The `mode` tag is the `HybridKemMode` of the envelope (`Hybrid` or `MlKemOnly`).

## Traces / Activities

| Activity name | Tags |
|---|---|
| `PostQuantum.DataProtection.Encrypt` | `pq.mode`, `pq.publicKeyId` |
| `PostQuantum.DataProtection.Decrypt` | `pq.mode` (set on the failure path) |
| `PostQuantum.DataProtection.Rotate` | `pq.parameterSet`, `pq.newKeyId` |

## What to alert on

- **Page** on a rising `pq_dataprotection.decrypt_failures` rate — especially with
  `reason=key_not_found` or `reason=auth_failure`. `key_not_found` means an envelope references a
  keypair that isn't loaded (missing keystore or missing keypair); `auth_failure` means AES-GCM
  authentication failed — a tampered envelope or, across replicas, the wrong host KEK. Both map to
  the `Error`-level log events 3 and 4 in [`docs/logging.md`](logging.md).
- **Watch** that `pq_dataprotection.rotations` fires at your configured cadence. Its *absence* over a
  rotation interval means scheduled rotation isn't happening — cross-check the rotation log events
  (20–23) in [`docs/logging.md`](logging.md).

For concrete alert thresholds and severities, see [`docs/deployment.md`](deployment.md).

## Prometheus name translation

Instrument names use dot-separated identifiers per the OpenTelemetry naming conventions. OTel
exporters normalize these to the target system's convention — for Prometheus, **dots become
underscores**. So `pq_dataprotection.encrypt.duration` is scraped as
`pq_dataprotection_encrypt_duration` (with the exporter's usual histogram suffixes such as
`_bucket`, `_sum`, and `_count`).

---

*To God be the glory — 1 Corinthians 10:31.*
