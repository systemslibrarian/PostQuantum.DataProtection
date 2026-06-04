# PostQuantum.DataProtection.OpenTelemetry

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

One-line OpenTelemetry wiring for
[`PostQuantum.DataProtection`](https://www.nuget.org/packages/PostQuantum.DataProtection)'s built-in
Meter and ActivitySource.

> ⚠️ **Preview (`0.1.0-preview.4`).** Tracks the core preview cadence.

## Install

```bash
dotnet add package PostQuantum.DataProtection.OpenTelemetry --prerelease
```

## Use it

```csharp
using PostQuantum.DataProtection.OpenTelemetry;

builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m
        .AddPostQuantumDataProtectionInstrumentation()      // <-- one line
        .AddPrometheusExporter())
    .WithTracing(t => t
        .AddPostQuantumDataProtectionInstrumentation()      // <-- one line
        .AddOtlpExporter());
```

That's it. Your existing exporter sees:

**Metrics**

- `pq_dataprotection.encryptions` (counter, tagged `mode`)
- `pq_dataprotection.decryptions` (counter, tagged `mode`)
- `pq_dataprotection.decrypt_failures` (counter, tagged `reason`)
- `pq_dataprotection.rotations` (counter)
- `pq_dataprotection.encrypt.duration` (histogram, ms)
- `pq_dataprotection.decrypt.duration` (histogram, ms)

**Traces**

- `PostQuantum.DataProtection.Encrypt` and `PostQuantum.DataProtection.Decrypt` activities, tagged
  with `pq.mode` and `pq.publicKeyId`.

The core package emits these on its own — this shim only opts in to the OpenTelemetry SDK so the
core stays SDK-free.

---

*To God be the glory — 1 Corinthians 10:31.*
