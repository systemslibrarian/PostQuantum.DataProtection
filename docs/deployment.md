# Deployment guide

This is the operational checklist for running `PostQuantum.DataProtection` in production. It is
intentionally opinionated; every recommendation is what we would do, not the maximum-flexibility
menu of options.

Status as of **`0.1.0-preview.3`**.

## 1. What you are responsible for

| Concern | Owner |
|---|---|
| Host KEK passphrase (the `KeyManagement:Passphrase` string) | You. Use a real secret manager. |
| The keystore file (`pq-keystore.txt`) | You. Persist on durable storage. Back it up. |
| The Data Protection key directory | You. Persist alongside the keystore. |
| The Argon2id work factor | You. Pick `Moderate` or higher in production. |
| ML-KEM key wrapping, envelope correctness, atomic writes | The library. |

The library does **two** things on your behalf — it wraps Data Protection keys with ML-KEM-768 +
AES-256-GCM, and it persists the long-lived ML-KEM keypair atomically. Everything else is on you.

## 2. The pre-deployment checklist

Before shipping a host running this library to production, verify:

- [ ] **Passphrase comes from a secret manager.** Not `appsettings.json`. Not a hard-coded
  string. Azure Key Vault Secrets, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault — any
  of them. The passphrase should never appear in source, in container env files committed to
  Git, or in CI logs.
- [ ] **`KekWorkFactor` is set to `Moderate` or higher.** `Interactive` is the library default for
  general use; `Moderate` is the production floor (256 MiB / 4 iterations / parallelism 4). See
  [PostQuantum.KeyManagement's
  SECURITY.md](https://github.com/systemslibrarian/PostQuantum.KeyManagement/blob/main/SECURITY.md#recommended-argon2id-profile-in-production)
  for the full rationale.
- [ ] **The keystore path and the Data Protection key directory point at durable storage.**
  Container-local disk is not durable. Mount a volume, an NFS share, an S3-backed CSI mount, an
  Azure Files mount — anything that survives a container restart.
- [ ] **Both paths are backed up.** Losing the keystore means losing the ability to decrypt every
  Data Protection key. Losing the Data Protection key directory means every existing cookie /
  antiforgery token / session is invalid. They are linked — back them up together, in the same
  snapshot.
- [ ] **The host runs a health check** that exercises the chain. Wire
  `AddHealthChecks().AddPostQuantumDataProtection()` and surface it from `/health` (or your
  liveness/readiness probe). If this returns Unhealthy, the host should not accept request
  traffic.
- [ ] **`/admin`-type endpoints that expose `ListKeysAsync` are gated** behind real
  authentication. The output is non-secret, but exposing it widely advertises your rotation
  cadence and PQ keypair lineage.

## 3. The multi-replica model

The bundled `FilePostQuantumKeyStore` is **single-writer + many-readers**. That is the model
ASP.NET Core Data Protection itself assumes for `PersistKeysToFileSystem`, and it is the only
shape this library is tested against today.

In a multi-replica deployment (Kubernetes pods, multiple App Service instances, an autoscaling
group), the safe pattern is one of:

1. **Shared storage with single-writer discipline.** Mount the same volume (NFS, Azure Files, EFS)
   on every replica; gate writes (rotation) through an admin endpoint exercised on only one
   replica, or run a separate "rotator" job. Reads (decapsulation) are concurrent-safe.
2. **Single replica per Data Protection identity.** Each replica gets its own keystore and DP key
   directory. Workable for stateless internal services with their own session boundaries; *not*
   workable for shared cookie auth across replicas.

A cloud-backed `IPostQuantumKeyStore` (Azure Key Vault, AWS KMS — see [`future.md`](../future.md))
removes this concern entirely. Until those ship, prefer option 1.

## 4. KEK rotation playbook

The classical KEK (in `PostQuantum.KeyManagement`) and the PQ keypair are separate things. They
rotate on independent cadences and for different reasons.

### Classical KEK (the Argon2id-derived secret)

- Rotate when: a passphrase is suspected of being compromised; a quarter has elapsed; a key admin
  changes role.
- How: in `PostQuantum.KeyManagement`, call
  `LocalContentKeyProvider.Rotate(newPassphrase)` on the running host, then immediately persist
  the keyring (`AddPostQuantumKeyManagement` does this through `IKeyringStore`). Old KEKs stay in
  the ring; payloads wrapped under the old KEK still unwrap.
- Effect on this library: the PQ keypair's wrapped-SK blob is re-encryptable under the new KEK
  via a `PostQuantumKeyManager.RotateAsync()` (which generates a fresh PQ keypair under the new
  active KEK). Existing PQ keypairs in the keystore continue to be readable through the old KEK
  in the keyring.

### PQ keypair

- Rotate when: a quarter has elapsed; a `pq-keystore.txt` exfiltration is suspected (treat as a
  red-button event); a new ML-KEM parameter set lands and you want fresh hardware.
- How: `await pq.RotateAsync()` on the running host — see the `/rotate-pq` endpoint in the
  sample.
- Effect on Data Protection keys: existing DP keys persist under the old PQ keypair; the
  keystore retains the old keypair and decrypts them correctly. Fresh DP keys are wrapped under
  the new active PQ keypair.

### Order of operations (paranoid mode)

If both rotate in the same window (rare):

1. Rotate the classical KEK first.
2. Persist the keyring; verify the host comes back healthy.
3. Rotate the PQ keypair. This produces a fresh keypair under the *new* KEK.
4. Verify `AddPostQuantumDataProtection()` health check stays Green throughout.

## 5. Disaster recovery matrix

| Scenario | Recovery |
|---|---|
| Keystore deleted, no backup | **Total loss.** Every DP key wrapped under any keypair in the lost store is unrecoverable. Sessions / cookies / antiforgery state must be regenerated. |
| Keystore deleted, backup exists | Restore the file. Restart the host. Done. |
| DP key directory lost, keystore intact | DP keys are gone. Existing cookies are invalid; the host will mint fresh DP keys at startup and they will be wrapped correctly. User-visible: forced sign-out. |
| DP key directory restored from yesterday, keystore restored from yesterday | Works. The library does not embed time-bound state in the envelope itself; DP's own activation/expiration windows take it from there. |
| Host KEK passphrase lost | **Total loss.** Same as deleted keystore. |
| Host KEK passphrase exfiltrated | Treat as keystore exfiltration. Rotate the classical KEK; rotate the PQ keypair; rotate every DP key (set short activation windows); audit for downstream breach. |
| BC version drift produces wire-incompatible ML-KEM bytes | The pinned KAT (`MlKemKatTests`) fails CI before the change ships. If somehow it shipped, every existing keypair is unreadable; restore the keystore from before the upgrade, downgrade BC, redeploy. |

## 6. Monitoring

Subscribe to the `PostQuantum.DataProtection` Meter / ActivitySource (see `docs/observability`
once written; `Telemetry.MeterName` is the value to pass to OpenTelemetry):

| Signal | What it tells you |
|---|---|
| `pq_dataprotection.encryptions` counter | Rate of fresh DP keys being wrapped. Spikes mean DP is rotating its own keys. |
| `pq_dataprotection.decryptions` counter | Rate of keystore reads. High and sustained = something is bypassing the in-memory key ring. |
| `pq_dataprotection.decrypt_failures` counter (tagged by `reason`) | **Page on any non-zero rate.** Reasons: `wrong_xml_element`, `malformed_envelope`, `unsupported_algorithm`, `unknown_keypair`, `auth_failed`. |
| `pq_dataprotection.rotations` counter | Rate of PQ keypair rotations. Should be very low (≈ once per quarter). Anomalous spikes mean someone is hitting `RotateAsync()`. |
| `pq_dataprotection.encrypt.duration` histogram | P95 should sit < 1 ms on modern hardware. Sustained drift = profile the host. |
| `pq_dataprotection.decrypt.duration` histogram | Same. |
| `AddPostQuantumDataProtection()` health check | Should be Healthy on every probe. **Page if Unhealthy.** |

## 7. Pre-shipping smoke test

A 30-second sanity check before flipping production traffic:

```bash
# 1. Boot the host.
ASPNETCORE_ENVIRONMENT=Production dotnet run --project YourHost

# 2. Hit /health. Expect HTTP 200 with the post-quantum-data-protection entry as Healthy.
curl -fs https://your-host/health | jq .entries.\"post-quantum-data-protection\".status

# 3. Issue a request that mints a cookie; capture and replay it.
curl -c /tmp/cookies -fs https://your-host/some-protected-endpoint > /dev/null
curl -b /tmp/cookies -fs https://your-host/some-protected-endpoint > /dev/null
# Both should succeed. If the second fails, the keystore unwrap path is broken.

# 4. Verify the on-disk shape.
ls keys/data-protection/  # one or more key-*.xml
grep -l 'pqEnvelope' keys/data-protection/key-*.xml  # every file should hit
```

If any step fails, **do not flip traffic.** Roll back to the previous host, investigate, and try
again.

---

*To God be the glory — 1 Corinthians 10:31.*
