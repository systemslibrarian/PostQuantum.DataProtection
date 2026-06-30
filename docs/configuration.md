# Configuration reference

`PostQuantum.DataProtection` is configured through `PostQuantumDataProtectionOptions`. This page is
the full reference: the registration entry points, every option, and how to bind from
`appsettings.json`.

## Registration entry points

There are two ways to wire the chain in, depending on whether you already have an
`IDataProtectionBuilder`. Each comes in three overloads with identical shapes.

**Prerequisite:** all of these require `IContentKeyProvider` to be registered first — call
`AddPostQuantumKeyManagement(...)` from
`PostQuantum.KeyManagement.Extensions.DependencyInjection`. The post-quantum envelope's classical
layer (and the at-rest wrap of the long-lived ML-KEM secret key) is built on that provider.

### `services.AddPostQuantumDataProtection(...)`

The convenience entry point. It calls `AddDataProtection()` for you and then
`ProtectKeysWithPostQuantum(...)` in a single call — the discoverable mirror of
`services.AddDataProtection()`. Use it when you are setting up Data Protection from scratch. The
returned `IDataProtectionBuilder` can be chained further (e.g. `.PersistKeysToFileSystem(...)`).

```csharp
services.AddPostQuantumDataProtection(o =>
{
    o.KeyStorePath = "keys/pq-keystore.txt";
    o.Mode = HybridKemMode.XWingHybrid;
});
```

| Overload | Use when |
|---|---|
| `AddPostQuantumDataProtection(Action<PostQuantumDataProtectionOptions>)` | You want to set options in code. AOT-safe. |
| `AddPostQuantumDataProtection(string keyStorePath)` | You only need to set the keystore path; everything else stays default. |
| `AddPostQuantumDataProtection(IConfigurationSection)` | You bind options from configuration. **Not** trim/AOT-safe (see below). |

### `builder.ProtectKeysWithPostQuantum(...)`

The extension on an existing `IDataProtectionBuilder`. Use it when you already call
`AddDataProtection()` (or need to compose with other Data Protection configuration before/after).

```csharp
services
    .AddDataProtection()
    .ProtectKeysWithPostQuantum(o => o.KeyStorePath = "keys/pq-keystore.txt");
```

| Overload | Use when |
|---|---|
| `ProtectKeysWithPostQuantum(Action<PostQuantumDataProtectionOptions>)` | You want to set options in code. AOT-safe. |
| `ProtectKeysWithPostQuantum(string keyStorePath)` | You only need to set the keystore path. |
| `ProtectKeysWithPostQuantum(IConfigurationSection)` | You bind options from configuration. **Not** trim/AOT-safe. |

## Options reference

Every property lives on `PostQuantumDataProtectionOptions`.

| Property | Type | Default | Description |
|---|---|---|---|
| `KeyStorePath` | `string?` | `null` | **Required.** Path to the file that holds the long-lived PQ keypair(s); created on first run and used by the default `IPostQuantumKeyStore`. An empty/whitespace value throws at registration. Treat it like a database: back it up — losing it means losing the ability to decrypt persisted Data Protection keys. |
| `Mode` | `HybridKemMode` | `XWingHybrid` | Hybrid mode for **fresh** encryptions. `XWingHybrid` (2) and `Hybrid` (1) are both production-grade; `MlKemOnly` (0) is for tests and KAT runs. Changing this is non-breaking: existing envelopes decrypt under whatever mode they were written with — only fresh encryptions adopt the new value. |
| `RotationInterval` | `TimeSpan?` | `null` | How often the rotation hosted service rotates the active PQ keypair. `null` disables scheduled rotation (it stays a manual operator action). A non-null value **must be strictly positive** — `TimeSpan.Zero` or a negative span is rejected at registration; leave it `null` to disable rather than setting zero. Typical production value: `TimeSpan.FromDays(90)`. |
| `ParameterSet` | `MlKemParameterSet` | `Kem768` | Which FIPS 203 ML-KEM parameter set to target for **new** keypairs (`Kem512`, `Kem768`, `Kem1024`). `Kem768` is NIST category 3, general-purpose. Existing keypairs keep their recorded parameter set and continue to decrypt regardless of this setting. |
| `ValidateOnStartup` | `bool` | `true` | When `true`, the chain eagerly initializes at host startup — resolves `IContentKeyProvider`, loads (or generates) the active keypair, and verifies the keystore path is writable — so misconfiguration fails fast at boot with an actionable error instead of lazily on the first protected request. Set to `false` to defer initialization to first use. |

> Scheduled rotation never deletes old keypairs — they remain loaded so previously-wrapped Data
> Protection keys keep decrypting. Pruning is a separate, deliberate operator action. In a
> multi-replica deployment register an `IRotationLock` (e.g. the Redis package's distributed lock)
> so only one replica rotates per window.

## Configure from `appsettings.json`

The configuration keys map directly to the option property names. Enums bind by their member name.

```json
{
  "PostQuantumDataProtection": {
    "KeyStorePath": "keys/pq-keystore.txt",
    "Mode": "XWingHybrid",
    "RotationInterval": "90.00:00:00",
    "ParameterSet": "Kem768",
    "ValidateOnStartup": true
  }
}
```

```csharp
services.AddPostQuantumDataProtection(
    builder.Configuration.GetSection("PostQuantumDataProtection"));
```

> The `IConfigurationSection` overload binds via reflection over `PostQuantumDataProtectionOptions`
> and is **not** trim/AOT-safe — use the `Action<PostQuantumDataProtectionOptions>` overload for
> trimmed or Native AOT hosts.

## Related

- [`docs/keystores.md`](keystores.md) — choosing and wiring an `IPostQuantumKeyStore`.
- [`docs/deployment.md`](deployment.md) — production posture and the pre-deployment checklist.
- [`docs/observability.md`](observability.md) — logging, metrics, and health checks.
- [`docs/troubleshooting.md`](troubleshooting.md) — diagnosing startup and decryption failures.

---

*To God be the glory — 1 Corinthians 10:31.*
