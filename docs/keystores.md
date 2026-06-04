# Choosing a PQ key store

`PostQuantum.DataProtection` ships four `IPostQuantumKeyStore` implementations as separate
packages. This page is the practical decision matrix.

Status as of **`0.1.0-preview.6`**.

## The contract every store implements

| Operation | Frequency | Latency budget |
|---|---|---|
| `LoadAllAsync` | once per host boot | seconds — runs on the startup thread |
| `SaveAsync` | once per rotation | seconds — runs on the rotation thread / admin endpoint |
| `DeleteAsync` | rare (manual prune) | seconds |
| Active key id query | every encryption | **microseconds** — cached in memory after first load |

The cache means **the per-request hot path never touches the store**. The store only matters at
startup and on rotation.

## Side-by-side

| Property | `File` | `AzureKeyVault` | `Aws` | `Redis` |
|---|---|---|---|---|
| **Package** | (bundled in core) | `PostQuantum.DataProtection.AzureKeyVault` | `PostQuantum.DataProtection.Aws` | `PostQuantum.DataProtection.Redis` |
| **Durability** | as durable as the mounted volume | Key Vault SLA (99.99%) | Secrets Manager SLA (99.99%) | as durable as the Redis deployment (typically AOF + RDB) |
| **Cross-replica share** | needs shared filesystem | native — every replica sees the same vault | native — every replica sees the same vault | native — every replica sees the same Redis |
| **Audit trail** | filesystem audit (you wire it) | Key Vault audit log | CloudTrail | Redis ACL log + you wire it |
| **Per-rotation cost** | 1 file write | 2 secret writes | 2 secret writes | 1 HSET + 1 SET |
| **Per-boot cost** | 1 file read | 1 list + N gets | 1 list + N gets | 1 HGETALL + 1 GET |
| **Cold start latency** | < 1 ms | ~50–200 ms / call | ~50–200 ms / call | < 5 ms |
| **Cost at 100 replicas, 1 rotation / quarter** | $0 | < $1/mo | < $1/mo | included in your Redis bill |
| **Auth model** | filesystem ACLs | Entra ID / managed identity | IAM | Redis ACL or AUTH |
| **AOT-safe** | ✅ (core) | depends on Azure SDK | depends on AWS SDK | depends on StackExchange.Redis |
| **Works offline** | ✅ | ❌ | ❌ | depends on Redis topology |

## Decision tree

```text
Are you running on a single host with persistent local storage?
├── Yes  → File store (it's bundled; no extra package needed)
└── No
    │
    Are you on Azure?
    ├── Yes  → AzureKeyVault
    └── No
        │
        Are you on AWS?
        ├── Yes  → Aws (Secrets Manager)
        └── No
            │
            Do you already operate Redis for Data Protection
            (PersistKeysToStackExchangeRedis)?
            ├── Yes  → Redis (one Redis instance holds both DP keys and PQ keypairs)
            └── No
                │
                Implement IPostQuantumKeyStore against your durable store of choice
                (see src/PostQuantum.DataProtection.Aws for the reference shape).
```

## Detailed per-store guidance

### `FilePostQuantumKeyStore` (bundled in `PostQuantum.DataProtection`)

**Best for:** single-host deployments; dev/test; air-gapped environments; CI smoke tests.

**Posture:**
- Single-writer + many-readers model. Multi-replica deployments need a shared filesystem
  (NFS, EFS, Azure Files) and a write-discipline rule (one replica acts as the rotator).
- Atomic writes via temp + `File.Replace` with a bounded retry on Windows. Race-free in
  practice for single-writer.

**Wire-up:**

```csharp
builder.Services
    .AddDataProtection()
    .ProtectKeysWithPostQuantum(o => o.KeyStorePath = "keys/pq-keystore.txt");
```

**Operational reminder:** treat `pq-keystore.txt` like a database file — back it up, monitor disk
space, fail readiness if it disappears.

### `AzureKeyVaultPostQuantumKeyStore` (`PostQuantum.DataProtection.AzureKeyVault`)

**Best for:** Azure-native deployments; compliance regimes that require Key Vault audit logs;
multi-replica AKS / App Service / Container Apps.

**Posture:**
- Each keypair becomes a secret named `pq-dataprotection-{keyId}`; active pointer in
  `pq-dataprotection-active`.
- Active pointer written **after** the keypair so a crash leaves an "orphan keypair" rather
  than a "ghost active pointer."
- Soft-delete is on by default at the vault level; deleted keypairs are recoverable for the
  configured retention period.

**Wire-up:**

```csharp
builder.Services.AddPostQuantumDataProtectionAzureKeyVault(new Uri("https://my-vault.vault.azure.net/"));
```

**Required IAM:** `secret get` + `secret list` + `secret set` (+ `secret delete` if you call
`PruneOlderThanAsync`). RBAC role: `Key Vault Secrets Officer`.

### `AwsSecretsManagerPostQuantumKeyStore` (`PostQuantum.DataProtection.Aws`)

**Best for:** AWS-native deployments; ECS / EKS / Lambda; compliance regimes that want
CloudTrail records of every key access.

**Posture:** parallel to Azure Key Vault. Same secret-prefix pattern, same active-pointer-last
write order.

**Wire-up:**

```csharp
builder.Services.AddPostQuantumDataProtectionAws(o => o.Region = Amazon.RegionEndpoint.USEast1);
```

**Required IAM:**
`secretsmanager:GetSecretValue`, `:ListSecrets`, `:PutSecretValue`, `:CreateSecret`,
`:DeleteSecret` (if you prune). Scope the resource ARN to `pq-dataprotection-*`.

### `RedisPostQuantumKeyStore` (`PostQuantum.DataProtection.Redis`)

**Best for:** hosts that already use Redis for `PersistKeysToStackExchangeRedis`; deployments
where you want everything (DP keys + PQ keypairs) in the same data plane.

**Posture:**
- One hash (`pq-dataprotection:pairs`) keyed by keypair id; active pointer in
  `pq-dataprotection:active`.
- The Redis durability story is whatever you configure (AOF every write, RDB snapshots, RAFT
  for cluster).

**Wire-up:**

```csharp
builder.Services.AddPostQuantumDataProtectionRedis("redis.internal:6379");
```

**Required Redis ACL:** read + write on the configured prefix; no `FLUSHDB` or `KEYS` needed.

## Disaster recovery matrix

| Scenario | File | AKV | AWS | Redis |
|---|---|---|---|---|
| Replica lost | safe (others still have it) | safe | safe | safe |
| One AZ lost | depends on volume replication | safe (zone-redundant) | safe (zone-redundant) | depends on Redis topology |
| Region lost | depends on backup cadence | recover from soft-delete or geo-paired vault | recover from cross-region replication | recover from cross-region replication |
| Operator deletes by mistake | restore from backup | soft-delete recovery (default 90 days) | recovery window (default 7–30 days) | restore from AOF / RDB |
| Host KEK passphrase rotated | re-derives transparently | re-derives transparently | re-derives transparently | re-derives transparently |
| Host KEK passphrase lost | **total loss** | **total loss** | **total loss** | **total loss** |

The host KEK passphrase is the single point of failure across all four stores by design — they
all store the PQ secret key already-wrapped by it. See
[`KNOWN-GAPS.md` §B2](../KNOWN-GAPS.md#b2-the-host-kek-is-load-bearing).

## Custom stores

If none of the four fit, implement `IPostQuantumKeyStore` directly. The reference is
[`src/PostQuantum.DataProtection.Aws/AwsSecretsManagerPostQuantumKeyStore.cs`](../src/PostQuantum.DataProtection.Aws/AwsSecretsManagerPostQuantumKeyStore.cs)
— it's deliberately compact (≈ 150 LOC including the narrow `IAwsSecretsManagerClient` seam
for unit tests).

The contract has only four methods and one property:

- `ActiveKeyId` (property, cached after first load)
- `LoadAllAsync(CancellationToken)`
- `SaveAsync(PostQuantumKeyPair, CancellationToken)`
- `DeleteAsync(string keyId, CancellationToken)` — default-implemented as not-supported; you
  override to enable pruning.

The required invariants:

- Atomic save (the keypair entry **before** the active-pointer update so a crash leaves an
  orphan keypair, never a ghost active pointer).
- Refuse to delete the active keypair (throw `InvalidOperationException`).
- Thread-safe (the bundled stores cache in memory after first load and serialise loads on a
  single lock).

---

*To God be the glory — 1 Corinthians 10:31.*
