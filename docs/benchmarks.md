# Benchmarks

Cost of one PQ envelope at the cryptographic layer. Numbers below are from BenchmarkDotNet 0.14,
short-job, on a Windows 11 host running .NET 10.0.300 (single AMD x86_64 core), captured during
the `0.1.0-preview.3` build. Your hardware will differ; the shape of the numbers will not.

## ML-KEM-768 micro-cost

| Operation            | Mean      | Allocations |
| -------------------- | --------- | ----------- |
| `GenerateKeyPair`    | ~75 µs    | ~27 KiB     |
| `Encapsulate`        | ~93 µs    | ~31 KiB     |
| `Decapsulate`        | ~101 µs   | ~38 KiB     |

ML-KEM-768 keypair generation is one-shot at first-run + once per rotation. Encapsulation runs on
every Data Protection key persist; decapsulation runs once per persisted key on host startup and
once per key invalidation/rotation thereafter.

## End-to-end envelope cost

Realistic payload (≈ 250 bytes of Data Protection descriptor XML), full chain — ML-KEM +
classical wrap + AES-256-GCM + XML wrapping.

| Operation                       | Mean      | Allocations |
| ------------------------------- | --------- | ----------- |
| `Envelope Encrypt (Hybrid)`     | ~89 µs    | ~72 KiB     |
| `Envelope Encrypt (MlKemOnly)`  | ~87 µs    | ~65 KiB     |
| `Envelope Decrypt (Hybrid)`     | ~137 µs   | ~75 KiB     |
| `Envelope Decrypt (MlKemOnly)`  | ~137 µs   | ~68 KiB     |

The classical layer in `Hybrid` mode adds ≈ 2 µs and ≈ 7 KiB per envelope on top of `MlKemOnly`.
For the security improvement of belt-and-braces post-quantum + classical, this is a free
trade-off.

## What this means for production

ASP.NET Core Data Protection rotates its own keys every ~90 days by default and holds a handful
of active keys at any time. **Envelope encryption is a startup-path cost** (≈ 100 µs per key,
once per key persist) — not a request-path cost. Cookie verification, antiforgery validation,
and `IDataProtector.Unprotect` all read keys from the in-memory key ring; they never go through
this envelope.

Concretely: a host with 8 active Data Protection keys pays ≈ 1.1 ms total to unwrap them at
startup, once per process. After that, the envelope is invisible to the request path.

## Reproducing

```bash
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*'
```

Filter to a single suite:

```bash
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*MlKem*'
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*Envelope*'
```

The `--job short` flag runs a brief BenchmarkDotNet job suitable for CI / quick sanity checks.
Drop it for production-quality measurements (≈ 60 s per benchmark instead of ~10 s).

## Honest scope

These are micro-benchmarks of the cryptographic work. They do not include:

- Disk I/O against the keystore (single sync write, sub-millisecond on local SSD).
- The Argon2id host KEK derivation (one-shot at startup; bounded by the chosen
  `KekWorkFactor`).
- Network latency from a cloud-backed key store (not yet shipped — see `future.md`).

For end-to-end host-startup latency, profile the host.

---

*To God be the glory — 1 Corinthians 10:31.*
