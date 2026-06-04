# AOT and trimming compatibility

`PostQuantum.DataProtection` is **AOT-compatible on `net10.0`** and not AOT-compatible on
`net8.0` / `net9.0`. This document is the per-target audit.

Status as of **`0.1.0-preview.5`**.

## Result

| Target framework | `IsAotCompatible` | `IsTrimmable` | Why |
|---|---|---|---|
| **`net10.0`** | ✅ `true` | ✅ `true` | ML-KEM routes through `System.Security.Cryptography.MLKem` (BCL). AOT-clean. |
| `net9.0` | ❌ false | ❌ false | ML-KEM routes through BouncyCastle, which uses runtime reflection. |
| `net8.0` | ❌ false | ❌ false | Same as net9.0. |

The library emits zero `IL2026` / `IL3050` warnings on the `net10.0` build under the
`latest-recommended` analyser ruleset.

## How

The `MlKem` static class is split across three source files selected at compile time:

```text
src/PostQuantum.DataProtection/Hybrid/
  MlKem.cs                    # shared metadata + public surface (both targets)
  MlKem.Bcl.cs                # #if NET10_0_OR_GREATER         — uses System.Security.Cryptography.MLKem
  MlKem.BouncyCastle.cs       # #if !NET10_0_OR_GREATER        — uses BouncyCastle
```

The `.csproj` makes the BouncyCastle package reference conditional:

```xml
<PackageReference Include="BouncyCastle.Cryptography" Version="2.6.2"
                  Condition="'$(TargetFramework)' != 'net10.0'" />
```

…and turns AOT analysis on for `net10.0` only:

```xml
<IsAotCompatible Condition="'$(TargetFramework)' == 'net10.0'">true</IsAotCompatible>
<IsTrimmable Condition="'$(TargetFramework)' == 'net10.0'">true</IsTrimmable>
```

A consumer that publishes their host AOT (`dotnet publish -p:PublishAot=true`) targeting
`net10.0` gets a fully AOT-compiled chain.

## The one API surface that requires annotation

`ProtectKeysWithPostQuantum(IConfigurationSection)` uses `IConfigurationSection.Bind(object)`
internally, which is reflection-based and not AOT-safe. The method is annotated with
`[RequiresUnreferencedCode]` and `[RequiresDynamicCode]` so the AOT analyser propagates the
warning to the call site — letting consumers choose between:

1. **Use the delegate overload instead** (`ProtectKeysWithPostQuantum(o => ...)`) — fully
   AOT-safe.
2. **Suppress the warning at the call site** — accept that the host pulls in a reflective
   binder.
3. **Annotate the host's `Main` with the same attributes** — propagate the requirement up.

## What about envelope compatibility across targets?

The BCL `MLKem` and the BouncyCastle `MLKemPrivateKeyParameters` both implement FIPS 203 and
produce byte-for-byte identical outputs for the same inputs. An envelope written by a
`net8.0` host (BC) decodes correctly on a `net10.0` host (BCL) and vice versa. The
`AcvpKatTests` pin this against the NIST vector on both targets.

## Comparison with the rest of `PostQuantum.*`

| Library | AOT on net10 | Notes |
|---|---|---|
| `PostQuantum.KeyManagement` | ✅ | Argon2id via Konscious — AOT-clean across all targets. |
| `PostQuantum.DataProtection` | ✅ (net10 only) | This library. BCL-only on net10; BC on net8/9. |
| `PostQuantum.DataProtection.AzureKeyVault` | depends on Azure SDK | Azure SDK is not formally AOT-supported yet. |
| `PostQuantum.DataProtection.Aws` | depends on AWS SDK | AWS SDK is not formally AOT-supported yet. |
| `PostQuantum.DataProtection.Redis` | depends on StackExchange.Redis | StackExchange.Redis is not formally AOT-supported yet. |
| `PostQuantum.DataProtection.OpenTelemetry` | ✅ | Thin shim; no AOT-hostile code. |
| `PostQuantum.DataProtection.Testing` | ✅ | In-memory fakes; no reflection. |
| `PostQuantum.DataProtection.Cli` | ✅ | The `pq-dp` tool is a console app; could be published AOT. |

The cloud-store packages will become AOT-compatible when their SDK dependencies declare it.
For an AOT host that uses one of those stores today, the warnings propagate up but the binaries
still ship; the cloud SDKs work at runtime.

## Verifying

To prove the `net10.0` target is AOT-clean, restore the repo and run:

```bash
dotnet build src/PostQuantum.DataProtection -c Release -f net10.0 /p:WarningLevel=9999
```

Expect **0 warnings, 0 errors**. Any `IL2026` / `IL3050` would surface as a build error under
the repo's `TreatWarningsAsErrors=true` policy.

---

*To God be the glory — 1 Corinthians 10:31.*
