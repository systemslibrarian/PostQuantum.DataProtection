# PostQuantum.DataProtection

Post-quantum / hybrid key wrapping for ASP.NET Core Data Protection.

This site is the rendered API reference plus the long-form docs from the repository. The
authoritative sources are in the GitHub repository linked in the top-right corner.

## Where to start

- **Getting started**: [`README.md`](../README.md) — value proposition, when to use, quick start.
- **Threat model**: [`docs/threat-model.md`](../docs/threat-model.md) — attacker model and the 10
  numbered security invariants.
- **Wire format**: [`docs/wire-format.md`](../docs/wire-format.md) — the precise byte layout.
- **Deployment**: [`docs/deployment.md`](../docs/deployment.md) — pre-deploy checklist,
  multi-replica, KEK rotation, disaster recovery.
- **Migration**: [`docs/migration.md`](../docs/migration.md) — moving from DPAPI / Azure Key
  Vault / Certificate to PQ wrap without disrupting users.
- **Benchmarks**: [`docs/benchmarks.md`](../docs/benchmarks.md) — real numbers.
- **AOT**: [`docs/aot.md`](../docs/aot.md) — why it's not AOT-compatible yet.
- **Supply chain**: [`docs/supply-chain.md`](../docs/supply-chain.md) — SBOM recipes, build
  verification.

## API reference

See the [API](api/) section.

---

*To God be the glory — 1 Corinthians 10:31.*
