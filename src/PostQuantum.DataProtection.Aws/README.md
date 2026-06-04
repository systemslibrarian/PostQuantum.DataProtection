# PostQuantum.DataProtection.Aws

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

AWS Secrets Manager-backed `IPostQuantumKeyStore` for
[`PostQuantum.DataProtection`](https://www.nuget.org/packages/PostQuantum.DataProtection).

> ⚠️ **Preview (`0.1.0-preview.4`).** Tracks the core preview cadence.

## Install

```bash
dotnet add package PostQuantum.DataProtection.Aws --prerelease
```

## Wire it up

```csharp
using Amazon;

builder.Services.AddPostQuantumKeyManagement(...);
builder.Services
    .AddDataProtection()
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/unused-pq-keystore.txt"; // ignored when AWS store is registered
    });

// Replace the file store with AWS Secrets Manager.
builder.Services.AddPostQuantumDataProtectionAws(o =>
{
    o.Region = RegionEndpoint.USEast1;
    // o.Credentials = ...   // optional; defaults to the AWS SDK credential chain
    // o.SecretPrefix = "pq-dp-prod";   // optional; defaults to "pq-dataprotection"
});
```

Or, with the AWS SDK default credential / region resolution:

```csharp
builder.Services.AddPostQuantumDataProtectionAws();
```

## What goes into Secrets Manager

| Secret name                            | Contents                                      |
| -------------------------------------- | --------------------------------------------- |
| `pq-dataprotection-{keyId}`            | The `PostQuantumKeyPair.Encode()` token       |
| `pq-dataprotection-active`             | The active keypair id                         |

The PQ secret key is wrapped under the host KEK before it reaches AWS — AWS sees opaque bytes.

## Required IAM permissions

The credential principal needs:

- `secretsmanager:GetSecretValue`
- `secretsmanager:ListSecrets`
- `secretsmanager:PutSecretValue`
- `secretsmanager:CreateSecret`

Scope to the secret name pattern (`pq-dataprotection-*` by default).

The store never deletes or updates secret metadata; pruning historical keypairs is a deliberate
operator action. See [`KNOWN-GAPS.md` §5](../../KNOWN-GAPS.md#5-pq-keypair-rotation-must-keep-old-keys-readable).

## Cost

- **Startup**: 1 List + N Get calls. With 100 keypairs that is 101 API calls.
- **Rotation**: 2 Put/Create calls per rotation.
- **Steady state**: zero — the store caches in memory after first load.

Secrets Manager pricing in `us-east-1` at the time of writing is $0.40 per secret per month plus
$0.05 per 10 000 API calls. Even a fleet with rapid rotation (daily) and a 100-replica cold start
matrix sits comfortably below $5/month per ring.

---

*To God be the glory — 1 Corinthians 10:31.*
