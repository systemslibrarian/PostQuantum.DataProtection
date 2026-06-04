# PostQuantum.DataProtection.Redis

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

`StackExchange.Redis`-backed `IPostQuantumKeyStore` for
[`PostQuantum.DataProtection`](https://www.nuget.org/packages/PostQuantum.DataProtection). Pairs
naturally with `Microsoft.AspNetCore.DataProtection.StackExchangeRedis.PersistKeysToStackExchangeRedis`
so the Data Protection keys themselves *and* the PQ keypairs that wrap them both live in the
same Redis instance.

> ⚠️ **Preview (`0.1.0-preview.4`).**

## Install

```bash
dotnet add package PostQuantum.DataProtection.Redis --prerelease
```

## Wire it up

```csharp
builder.Services.AddPostQuantumKeyManagement(...);

builder.Services
    .AddDataProtection()
    .PersistKeysToStackExchangeRedis(redis, "DP-keys")
    .ProtectKeysWithPostQuantum(o => o.KeyStorePath = "keys/unused.txt");

builder.Services.AddPostQuantumDataProtectionRedis("localhost:6379");
```

## What goes into Redis

| Key | Type | Contents |
|---|---|---|
| `pq-dataprotection:pairs` | hash | one field per keypair (`field=keyId`, `value=PostQuantumKeyPair.Encode()`) |
| `pq-dataprotection:active` | string | the active keypair id |

Both keys can be namespaced by passing a different `prefix` argument to
`AddPostQuantumDataProtectionRedis(...)`.

---

*To God be the glory — 1 Corinthians 10:31.*
