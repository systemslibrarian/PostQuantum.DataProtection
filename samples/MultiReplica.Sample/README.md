# MultiReplica.Sample

A standalone console program that simulates two ASP.NET Core replicas sharing a single Azure Key
Vault as their PQ keystore.

## What it demonstrates

1. **Replica A** starts, mints the inaugural PQ-768 keypair, stores it in the shared vault,
   and uses it to protect a payload.
2. **Replica B** starts cold, sees the keypair already in the vault, loads it, and decrypts
   the payload Replica A produced.
3. **Replica B rotates** the active PQ keypair while A is offline.
4. **Replica A comes back**, sees both keypairs in the vault, picks up the new active one, and
   still decrypts the OLD payload because the old keypair stays loaded.

This is the shape of a real multi-replica deployment behind a load balancer or a Kubernetes
Service. Any replica can rotate; all replicas converge on the next read.

To keep the sample runnable without an Azure account, both replicas share an in-process fake
`IKeyVaultSecretClient` that emulates the per-secret "last write wins" semantics of Key Vault.
For production, swap that for the real `AzureKeyVaultPostQuantumKeyStore` registered via
`AddPostQuantumDataProtectionAzureKeyVault(vaultUri)`.

## Run

```bash
cd samples/MultiReplica.Sample
dotnet run
```

Sample output:

```text
=== Replica A: encrypting a payload ===
  active PQ keypair: pq-mlkem768-4a3b…
  protected blob (truncated): CfDJ8Aa8d…

=== Replica B: starting cold, decrypting the payload ===
  active PQ keypair: pq-mlkem768-4a3b… (same as A: True)
  decrypted: "a message from replica A to anyone with the keystore"

=== Replica B rotates the PQ keypair while A is offline ===
  new active PQ keypair: pq-mlkem768-9f2c…

=== Replica A comes back, sees the new keypair, still decrypts the OLD payload ===
  active PQ keypair on A: pq-mlkem768-9f2c… (matches B's rotation: True)
  total keypairs loaded: 2 (the original + the rotated-in one)
  decrypted with the OLD keypair: "a message from replica A to anyone with the keystore"

Done. The shape works against a real Azure Key Vault, AWS Secrets Manager, or any other IPostQuantumKeyStore.
```

---

*To God be the glory — 1 Corinthians 10:31.*
