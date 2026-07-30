# Backup, restore, and integrity operations

LoomDB file-backed stores expose one online backup boundary. The backup is a directory, not an opaque
archive: operators can inspect it, copy it with ordinary enterprise tooling, and independently verify
every byte before a restore.

## Safety contract

- `Loom::backup_to` holds the maintenance boundary and the branch-head mutation lock from the final
  ref-log flush through the copy. The refs and content-addressed pages therefore name one committed
  prefix.
- An ANN rebuild prepares immutable pages outside the branch lock for latency reasons. It holds the
  maintenance read lock through publication; backup and GC take the maintenance write lock first. A
  backup cannot miss an unpublished rebuild and then capture a ref that names it.
- The live `loom/store.lock` file is not copied. A restored process creates and owns a new lock.
- `loom-backup-manifest.json` allow-lists every regular file with its exact length and BLAKE3 digest.
  Verification refuses symlinks, special files, missing files, extra files, duplicate or escaping paths,
  and unsupported manifest versions.
- Backup and restore never overwrite. They build in a private sibling directory, sync the files and
  directory, and publish with one rename.
- Restore does not silently activate a database. Open the new path through
  `Loom::open_production_attested` (or the deployment's chosen production constructor) with the current
  actor registry and governance generation.

The BLAKE3 manifest is an integrity allow-list, not an authenticity signature. It detects a changed
backup file when the manifest is trusted, but an attacker who can replace both the files and manifest
can forge a self-consistent backup. Production backups therefore require immutable/off-account storage
and an external signature or control-plane record of the manifest bytes. Native signed backup manifests
remain Phase 4 work and are not claimed here.

## Operator commands

Build once:

```sh
cargo build --release -p loomctl
export PATH="$PWD/target/release:$PATH"
```

Inspect refs and heads without changing the existing database:

```sh
loomctl inspect --path /var/lib/loom/acme --tenant acme
```

Re-hash every page and manifest reachable from every branch and tag:

```sh
loomctl verify --path /var/lib/loom/acme --tenant acme
```

Create and independently verify a backup:

```sh
loomctl backup \
  --path /var/lib/loom/acme \
  --tenant acme \
  --out /backups/loom/acme-2026-07-29

loomctl verify-backup --path /backups/loom/acme-2026-07-29
```

Restore to a new path. The tenant comparison occurs before any destination is published:

```sh
loomctl restore \
  --path /backups/loom/acme-2026-07-29 \
  --expected-tenant acme \
  --out /var/lib/loom/acme-restored
```

Then open `/var/lib/loom/acme-restored` with the production actor-key attestation and run application
read/query smoke tests before traffic is switched.

## Required deployment drill

Run this drill for every target filesystem, CSI driver, backup agent, and object-store topology:

1. Start a sustained write workload and create branches while the database is live.
2. Run `loomctl backup` and continue the workload.
3. Run `loomctl verify-backup` from a different host or trust domain.
4. Restore to a new path and open it with the current production actor registry/attestation.
5. Run `loomctl verify`, enumerate the expected branches, and execute known-answer reads and taint
   queries.
6. Record recovery time, restored commit/head IDs, manifest digest, software revision, and operator.
7. Do not promote the restore if the tenant, actor registry generation, integrity report, or known-answer
   checks differ.

The repository test `online_backup_restores_to_one_consistent_prefix_during_a_write_storm` automates the
storage invariant. The environment-specific drill remains an operations responsibility because CSI
snapshots, backup products, mount options, and recovery time objectives are properties of the deployed
system, not of this crate alone.

## Remaining Phase 3 work

This closes the storage mechanism, not all enterprise operations. Open work remains:

- scheduled retention and immutable/off-account backup policy;
- metrics and traces for backup duration, bytes, failures, last successful recovery point, scrub damage,
  and recovery drills;
- `loomctl` provenance-chain and `taint` dry-run views;
- documented RPO/RTO targets validated on customer-scale data;
- encryption/key-management policy for backup media at the platform layer.
- native signing and trust-root rotation for backup manifests (until then, use the backup platform's
  immutable control plane or an external signature).
