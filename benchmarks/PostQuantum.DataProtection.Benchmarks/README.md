# PostQuantum.DataProtection.Benchmarks

BenchmarkDotNet harness for the post-quantum data-protection chain.

## Run

```bash
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks --framework net10.0 -- --filter '*'
```

Filter to one suite:

```bash
# Just the ML-KEM-768 micros
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*MlKem*'

# Just the end-to-end envelope numbers
dotnet run -c Release --project benchmarks/PostQuantum.DataProtection.Benchmarks -- --filter '*Envelope*'
```

## What gets measured

- `MlKemBenchmarks` — pure FIPS 203 cost: keygen, encapsulate, decapsulate.
- `EnvelopeBenchmarks` — what ASP.NET Core Data Protection actually pays per key persist / load:
  ML-KEM + classical wrap + AES-256-GCM + XML.

## Honest scope

These are micro-benchmarks. They do not include disk I/O against the keystore, the
Argon2id-derived KEK cost at host startup (that is a one-shot anyway), or network latency from a
cloud-backed key store. They tell you the *crypto cost* of one envelope. For end-to-end host
startup latency, profile the host.

---

*To God be the glory — 1 Corinthians 10:31.*
