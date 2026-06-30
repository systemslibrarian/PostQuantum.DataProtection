# Troubleshooting and incident response

This is the page you reach for when something has gone wrong in production. It is structured as a
set of **Symptom → Likely cause → What to do** entries, followed by a read-only diagnostics section
and an incident-response runbook.

It is a companion to the [deployment guide](deployment.md) — that document tells you how to run the
library correctly; this one tells you how to read the failure when you didn't. Where the two
overlap (the disaster-recovery matrix, the multi-replica model, the KEK rotation playbook) this page
links rather than repeats.

Status as of **`0.1.0-preview.7`**.

> **First principle.** Almost every failure in this library reduces to one of two questions:
> *can the host reach its KEK?* and *does the manager still have the keypair that wrapped this
> envelope?* Keep those two questions in mind and most symptoms below explain themselves.

---

## 1. The app throws at startup: "PostQuantum.DataProtection failed to initialize on startup"

**Symptom.** The host refuses to start. The exception is an `InvalidOperationException` whose message
begins:

> PostQuantum.DataProtection failed to initialize on startup. The active ML-KEM keypair could not be
> loaded or generated.

This comes from `PostQuantumStartupValidator`. By design it runs eagerly at boot (when
`ValidateOnStartup` is `true`, the default) and exercises the entire at-rest path — it resolves the
host `IContentKeyProvider`, unwraps or mints a DEK, loads or generates the active ML-KEM keypair, and
writes to the keystore. If any link is broken it fails **here**, with an actionable message, instead
of much later inside ASP.NET Core Data Protection's key-ring loader. Read the **inner exception** —
it carries the real cause. The three common ones:

### 1a. The host `IContentKeyProvider` is missing or misconfigured

**Likely cause.** You called `ProtectKeysWithPostQuantum(...)` but never registered the classical
layer with `AddPostQuantumKeyManagement(...)`, or you registered it with the **wrong passphrase**.
The PQ keypair's secret key is wrapped by an `IContentKeyProvider` DEK; with no provider (or the
wrong KEK) the manager cannot wrap a new keypair or unwrap the existing one.

**What to do.**

- Confirm `AddPostQuantumKeyManagement(...)` is present in startup and runs **before** the Data
  Protection wiring.
- Confirm the passphrase resolves from your secret manager at runtime (not an empty string, not a
  stale environment variable). The passphrase that wraps the keystore today must match the one that
  wrapped it originally — see 1c and §3.
- If the inner exception is a `CryptographicException` / authentication-tag mismatch, you have a
  wrong-KEK problem, not a missing-provider problem; jump to §3.

### 1b. The keystore path is not writable

**Likely cause.** On first run the manager *generates* the inaugural keypair and writes it to the
keystore. If the configured `KeyStorePath` directory does not exist, is read-only, or is on a volume
that hasn't mounted yet, the write fails and startup fails with it. The inner exception is typically
an `IOException` / `UnauthorizedAccessException` naming the path.

**What to do.**

- Verify the keystore directory exists and the host's user can write to it.
- Verify the durable volume is mounted **before** the app starts (an init container, a readiness
  gate, or a startup probe ordering issue is the usual culprit in Kubernetes).
- See the deployment guide's note that container-local disk is not durable —
  [deployment.md §1–2](deployment.md).

### 1c. A previously-generated keypair cannot be unwrapped under the current KEK

**Likely cause.** The keystore already contains a keypair, but the current `IContentKeyProvider`
cannot unwrap its secret key — because the passphrase changed, the keyring that held the old KEK was
not carried forward, or the keystore entry is corrupt. The inner exception is a
`CryptographicException`.

**What to do.** This is the same failure as §3 surfacing at boot. Restore the original KEK /
passphrase (and its keyring, if the classical layer has rotated). The keystore and the KEK that
wrapped it must travel together; one without the other is unrecoverable. See the disaster-recovery
matrix in [deployment.md §5](deployment.md).

### A note on `ValidateOnStartup = false`

Setting `PostQuantumDataProtectionOptions.ValidateOnStartup = false` makes the validator return
immediately and defers the same check to the first protected request. **It does not fix anything** —
it only moves the failure from boot (where your readiness probe catches it before traffic arrives) to
the first user request (where it manifests as a 500 mid-flight). Leave it at the default `true` in
production unless you have a specific reason to tolerate a slow/lazy first request, and even then
prefer wiring `AddHealthChecks().AddPostQuantumDataProtection()` so the chain is still exercised
before traffic.

---

## 2. Decrypt fails: "No PQ keypair with id '...' is loaded"

**Symptom.** Requests fail (or the health check goes Unhealthy) with a `KeyNotFoundException`:

> No PQ keypair with id '...' is loaded. The envelope was encrypted to a key this manager does not
> know.

This is thrown by `PostQuantumKeyManager.DecapsulateAsync` when a Data Protection key's envelope
names a `PublicKeyId` that is **not present** in the keystore the manager loaded. The library is
fail-closed: it will not silently substitute another key.

**Likely cause.**

- The keystore was **swapped** — the host is pointed at a different keystore file than the one that
  wrapped these DP keys.
- The keypair was **pruned too early** (`PruneOlderThanAsync` removed a keypair that DP keys were
  still wrapped under).
- A **replica is reading a different keystore** than the one that did the encryption (see §5).

**What to do.**

- Restore the keystore that produced the envelope. Use `pq-dp inspect <key.xml>` to read the
  `Public key id` the envelope demands (§7), then `pq-dp keys list <keystore>` to confirm whether
  that id is present in the store you're running against.
- **Never prune keypairs younger than the maximum lifetime of any Data Protection key in your
  system.** ASP.NET Core DP keys default to a 90-day lifetime; prune only well beyond that window
  plus a safety margin. `PruneOlderThanAsync` carries this hazard in its own XML docs — pruning a
  keypair makes every DP key wrapped under it permanently unreadable.
- If the keystore is genuinely gone with no backup, this is unrecoverable for the affected DP keys;
  see §4 and the disaster-recovery matrix in [deployment.md §5](deployment.md).

---

## 3. `CryptographicException` / authentication-tag mismatch unwrapping the secret key

**Symptom.** A `CryptographicException` (often surfaced as an AES-GCM authentication-tag mismatch)
when the manager unwraps an ML-KEM secret key. It may appear at startup (§1c) or on the first
decapsulation.

**Likely cause.** The wrapped-SK blob is intact but the **classical KEK is wrong** — the host
passphrase changed, the keyring that held the old KEK was not carried forward, or the keystore entry
is corrupt. AES-GCM is authenticated, so the wrong key (or a flipped byte) fails the tag check rather
than returning garbage. This is the library working as intended: it refuses to proceed on
unauthenticated material.

**What to do.**

- Restore the **original** host KEK / passphrase. If the classical layer rotated, restore the full
  keyring so the old KEK is still available to unwrap older keypairs — `PostQuantum.KeyManagement`
  retains old KEKs in the ring precisely so this keeps working.
- Treat the keystore and its KEK as a single unit: **they must travel together** in the same backup
  snapshot. A keystore restored without its matching KEK is unrecoverable, exactly like the "Host KEK
  passphrase lost" row of the [disaster-recovery matrix](deployment.md).
- If the KEK is correct and the error persists, suspect a corrupt keystore entry; restore the
  keystore from backup.

---

## 4. Users are signed out / forced re-login after a deploy

**Symptom.** After a deployment, every user is logged out, antiforgery tokens are rejected, and any
`IDataProtector`-protected payload at rest fails to unprotect.

**Likely cause — two very different ones, with very different outcomes:**

1. **The Data Protection key directory was lost** (container-local disk, an unmounted volume, a fresh
   ephemeral path). The DP keys are gone but the keystore is intact.
2. **DPAPI-protected DP keys were migrated across a host or OS.** Windows DPAPI / `ProtectKeysWith*`
   bindings are host- or user-bound; copying those keys to a different machine makes them
   undecryptable there. This is **not** a PostQuantum.DataProtection failure — it is the classical DP
   key-protection layer — but it presents identically.

**What to do.**

- **Case 1 is recoverable.** Losing only the DP key directory (with the keystore intact) is the
  benign case: the host mints fresh DP keys at startup, wraps them under the active PQ keypair, and
  carries on. The only user-visible effect is the forced re-issue (one sign-out). Restore the DP key
  directory from backup if you want to preserve existing sessions; otherwise let it re-mint.
- **Case 2** is a migration-design problem. See [migration.md](migration.md) for moving DP keys
  between hosts/OSes correctly. Do not migrate DPAPI-bound keys verbatim across machines.
- **Losing the keystore itself is the unrecoverable case** — distinct from losing the DP key
  directory. If the keystore is gone with no backup, every DP key wrapped under any keypair it held
  is unrecoverable; see the [disaster-recovery matrix](deployment.md).

---

## 5. Multi-replica: rotation happens on more than one replica / duplicate keypairs appear

**Symptom.** `pq-dp keys list` shows more new keypairs than expected, or the
`pq_dataprotection.rotations` counter spikes across multiple replicas in the same window. Multiple
replicas appear to have rotated independently.

**Likely cause.** The single-writer assumption was violated. The bundled file keystore is
**single-writer, many-readers**, and the default `IRotationLock` is `NullRotationLock`, which always
grants the lease. With scheduled rotation enabled on several replicas sharing one keystore and **no
distributed lock registered**, more than one replica can rotate per window.

**What to do.**

- Register a distributed lock so only one replica rotates per window. The Redis satellite package
  does this in one line — `AddPostQuantumDataProtectionRedis(connectionString)` replaces both the
  keystore and the `IRotationLock` with Redis-backed implementations (the lock uses a short-lived
  `SET … NX PX` lease). See [keystores.md](keystores.md) and [configuration.md](configuration.md).
- Or enforce single-writer rotation another way: rotate from a single leader-elected replica, a
  dedicated rotator job, or a manual admin action — see the multi-replica model in
  [deployment.md §3](deployment.md).
- **This is wasteful, not corrupting.** Rotation only ever *adds* a new active keypair; old keypairs
  remain loaded and keep decrypting previously-wrapped DP keys. Last-write-wins on the active pointer
  is safe — you just accumulate extra keypairs you didn't need. Register the lock to stop the churn.

---

## 6. Registration throws: "RotationInterval must be strictly positive when set"

**Symptom.** The app fails at registration (not at runtime) with:

> PostQuantumDataProtectionOptions.RotationInterval must be strictly positive when set …

**Likely cause.** You set `RotationInterval = TimeSpan.Zero` (or a negative value), intending to
disable scheduled rotation. Zero is rejected because it is ambiguous and would mean "rotate
constantly."

**What to do.** Leave `RotationInterval` **`null`** to disable scheduled rotation — that is the
sentinel for "off." Set it to a positive interval (a typical production value is
`TimeSpan.FromDays(90)`) only when you want the background rotation service to run. See
[configuration.md](configuration.md).

---

## 7. Read-only diagnostics during an incident: the `pq-dp` CLI

The `pq-dp` tool is built for exactly this moment. **Every command is read-only, emits no secrets,
and needs no host KEK** — it reads only non-secret routing/metadata and never decrypts key material.
You can run it against a copy of production artifacts safely.

| Command | Use it to … |
|---|---|
| `pq-dp doctor <keystore>` | Triage the keystore first. Checks parseability, that the active-key pointer resolves to a stored keypair, key count, and active-key age. Exit code 1 on problems. |
| `pq-dp keys list <keystore>` | List every keypair (id, algorithm, creation time, which is active). Cross-check the id an envelope demands (§2) against what the store actually holds. |
| `pq-dp keys export <keystore> [keyId]` | Print the non-secret public key (base64) for a keypair, to compare keystores across replicas. |
| `pq-dp verify <dp-key-dir>` | Decode every PostQuantum envelope under a DP key directory. Exit code 1 if any fail to decode — fast way to spot a corrupt/foreign key file. Non-PostQuantum files are skipped. |
| `pq-dp inspect <key.xml>` | Read one DP key file's envelope: format version, mode, KEM algorithm, **public key id**, and byte sizes. This is how you learn which keypair a stuck DP key needs. |

**A typical incident flow.** When decryption is failing (§2/§3):

1. `pq-dp inspect <the failing key.xml>` → note the `Public key id` it requires.
2. `pq-dp keys list <keystore>` → is that id present? If not, you're pointed at the wrong/pruned
   keystore (§2). If present, the failure is the unwrap path — a KEK problem (§3), which the CLI
   cannot diagnose because it never touches the KEK.
3. `pq-dp doctor <keystore>` → confirm the active pointer is consistent and the store parses.
4. `pq-dp verify <dp-key-dir>` → confirm whether the problem is one file or the whole directory.

---

## 8. Incident runbook: "the keystore may be exfiltrated"

Treat a suspected `pq-keystore.txt` (or Redis keystore) exfiltration as a red-button event. The
secret keys in the keystore are wrapped under the host KEK, so an attacker who has only the keystore
cannot use it **unless they also have the KEK** — but you should assume worst case and rotate both,
**KEK first**.

The order matters: rotating the KEK first means the new PQ keypair is wrapped under the **new** KEK,
not the compromised one.

1. **Rotate the classical host KEK.** Follow the KEK rotation playbook in
   [deployment.md §4](deployment.md). In `PostQuantum.KeyManagement`, rotate the passphrase and
   persist the keyring; the old KEK stays in the ring so existing keypairs still unwrap. Verify the
   host comes back healthy.
2. **Rotate the PQ keypair.** Call `PostQuantumKeyManager.RotateAsync()` (the sample exposes this as
   `/rotate-pq`). This generates a fresh keypair wrapped under the **new** active KEK and makes it
   active. Old keypairs remain loaded so previously-wrapped DP keys keep decrypting.
3. **Roll the Data Protection keys.** Force fresh DP keys with short activation windows so traffic
   migrates onto envelopes wrapped under the new PQ keypair quickly.
4. **Verify throughout.** Keep the `AddPostQuantumDataProtection()` health check Green and watch
   `pq_dataprotection.decrypt_failures` (tagged by `reason`) — a spike of `auth_failed` or
   `unknown_keypair` during the roll tells you a replica is still on stale material.
5. **Audit for downstream breach.** An exfiltrated keystore plus a compromised KEK means assume the
   wrapped DP keys were readable; rotate any secrets those DP keys protected and follow the
   "passphrase exfiltrated" row of the [disaster-recovery matrix](deployment.md).

> Do **not** prune the old keypairs as part of incident response. They are still needed to decrypt
> DP keys minted before the roll completed. Prune only after every DP key wrapped under them has aged
> out (§2).

---

*To God be the glory — 1 Corinthians 10:31.*
