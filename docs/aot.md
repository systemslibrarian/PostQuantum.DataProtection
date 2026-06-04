# AOT and trimming compatibility

`PostQuantum.DataProtection` is **not** AOT-compatible today, and is therefore not
trim-compatible either. This document is the honest audit: what we tried, what we found, and
what would have to change.

Status as of **`0.1.0-preview.3`**.

## Result

| Property                        | Status              |
| ------------------------------- | ------------------- |
| `IsAotCompatible`               | ❌ NOT set          |
| `IsTrimmable`                   | ❌ explicitly false |
| Library code emits `IL2026/IL3050` warnings | ✅ No (clean) |
| Transitive deps are AOT-clean   | ❌ BouncyCastle uses reflection |

## What we tried

Enabling `<IsAotCompatible>true</IsAotCompatible>` on the library `.csproj`. The library's own
source compiles AOT-clean — no reflection, no `MakeGenericType`, no `Assembly.Load`, no JSON
serialization with reflection contracts. The only AOT-incompatible code path lives in
`BouncyCastle.Cryptography 2.6.x`, which the ML-KEM implementation transitively depends on. BC
uses runtime reflection for several internal service-provider lookups; the trimming analyser
correctly reports those code paths as unverifiable.

We are not going to publish a `<IsAotCompatible>true</IsAotCompatible>` we cannot stand behind,
so the flag stays off until either:

1. A future BouncyCastle release annotates the relevant code paths with
   `DynamicallyAccessedMembers` / `RequiresUnreferencedCode` so the analyser can verify them, or
2. We route the ML-KEM operations through the BC FIPS module (which has different
   distribution constraints — see [`KNOWN-GAPS.md` §3](../KNOWN-GAPS.md#3-not-fips-140-validated)), or
3. .NET ships ML-KEM in `System.Security.Cryptography` directly (announced for `net10.0` and
   evaluated for a future preview — see [`future.md`](../future.md)).

## What this means for consumers

- **AOT/NativeAOT publishes are not supported.** A `dotnet publish -p:PublishAot=true` of a host
  that depends on this library will produce IL2026 warnings from BouncyCastle and may exhibit
  runtime failures on the ML-KEM path. Do not deploy.
- **`PublishTrimmed=true` is not supported** for the same reason.
- **Standard non-AOT publishes work normally** — this is the entire .NET deployment shape that
  is not AOT, including every cloud container target we have tested against.

## When does this change?

The roadmap in [`future.md`](../future.md) tracks the path to AOT compatibility. Realistically:

- **Short-term:** unchanged. BouncyCastle 2.6.x is the only mature C# ML-KEM-768 implementation
  and the AOT story is not on its roadmap.
- **Medium-term:** the BCL ML-KEM API on `net10.0+` is the strongest candidate. A future preview
  may provide a `PostQuantum.DataProtection.Bcl` shim that routes through it on `net10.0` and
  falls back to BouncyCastle on `net8.0;net9.0`. That shim could carry `IsAotCompatible=true` on
  the `net10.0` target.
- **Long-term:** once the BCL API is the only path, `IsAotCompatible=true` becomes universal.

## Comparison with the rest of `PostQuantum.*`

`PostQuantum.KeyManagement` sets `IsAotCompatible=true`. It can do so because its only
cryptographic dependency is `Konscious.Security.Cryptography.Argon2`, which is AOT-clean. Our
ML-KEM path is the difference.

---

*To God be the glory — 1 Corinthians 10:31.*
