# AotSmokeTest

A minimal console program that **publishes Ahead-Of-Time (AOT)** to prove the
`PostQuantum.DataProtection` library's `net10.0` target is genuinely AOT-clean — not just
"`IsAotCompatible=true` is set."

## Why this exists

It is easy for an AOT claim to drift: a new transitive dependency lands, a reflection-using
helper sneaks in, an analyzer warning gets suppressed. This program is a **build-time** test
for that drift. If `PublishAot=true` succeeds with zero warnings, the chain is AOT-safe end to
end.

## Prerequisites

AOT publish needs the platform's native toolchain installed:

- **Linux/macOS** — `gcc`, `clang`, `lld`, or equivalent (most distros have one by default).
- **Windows** — Visual Studio 2022 Build Tools with the "Desktop development with C++" workload,
  *or* `lld-link.exe` on `PATH`. The .NET SDK uses `vswhere.exe` to locate the linker.

The IL-level AOT analysis (the part that proves the library is AOT-clean) runs **before**
the native link, so even without the native toolchain you can verify the analysis succeeds:

```bash
dotnet publish samples/AotSmokeTest -c Release 2>&1 | grep -E "IL[23]0|warning|error" | head -20
```

A clean log with no `IL2026` / `IL3050` lines = the library and its closure are AOT-safe at the
IL level. The final native link is a separate, platform-toolchain concern.

## Build

Linux:

```bash
dotnet publish samples/AotSmokeTest -c Release -r linux-x64
./samples/AotSmokeTest/bin/Release/net10.0/linux-x64/publish/AotSmokeTest
```

Windows:

```powershell
dotnet publish samples/AotSmokeTest -c Release -r win-x64
.\samples\AotSmokeTest\bin\Release\net10.0\win-x64\publish\AotSmokeTest.exe
```

The published binary is fully native — no JIT, no runtime metadata, no
`Microsoft.NETCore.App` shared framework dependency.

Expected output:

```text
OK: PostQuantum.DataProtection roundtrip succeeded under AOT (active key pq-mlkem768-...).
```

## What's being tested

- ML-KEM-768 keypair generation through `System.Security.Cryptography.MLKem` (BCL path on net10).
- AES-256-GCM via `System.Security.Cryptography.AesGcm`.
- HKDF-SHA-256 via `System.Security.Cryptography.HKDF`.
- The XML wrap / unwrap pipeline.
- The `FakePostQuantumKeyStore` from `PostQuantum.DataProtection.Testing` to keep the IO
  surface in-process.
- The local `PostQuantum.KeyManagement` `LocalContentKeyProvider` with the smallest Argon2id
  profile.

## What's NOT exercised here

- `ProtectKeysWithPostQuantum(IConfigurationSection)` — that one method requires reflection
  and is annotated with `[RequiresUnreferencedCode]` + `[RequiresDynamicCode]`. Use the
  `Action<PostQuantumDataProtectionOptions>` overload in AOT contexts.
- The cloud-store packages (`AzureKeyVault`, `Aws`, `Redis`) — those depend on cloud SDKs whose
  AOT story is owned by their respective vendors. See [`docs/aot.md`](../../docs/aot.md).

---

*To God be the glory — 1 Corinthians 10:31.*
