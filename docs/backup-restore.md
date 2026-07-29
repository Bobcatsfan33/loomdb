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

The BLAKE3 manifest is an integrity allow-list, not by itself an authenticity
signature. Production uses the signed commands below: LoomDB writes a detached
Ed25519 record inside the private backup directory before its atomic publish.
The signature binds a domain separator, the operator-selected trust-root ID,
and the exact manifest bytes. Verification requires both that expected key ID
and its public key, then verifies every declared file digest. An attacker who
can replace both files and manifest cannot mint a replacement signature.

Key generation, custody, rotation, revocation, and off-account retention remain
deployment responsibilities. Signing keys must come from the enterprise KMS/HSM
workflow and be presented through a mode-0600 file; do not pass private key
material in process arguments or environment variables.

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

The unsigned commands are appropriate for local integrity diagnostics. The
production door is signed:

```sh
loomctl backup-signed \
  --path /var/lib/loom/acme \
  --tenant acme \
  --out /backups/loom/acme-2026-07-29 \
  --signing-key-file /run/secrets/loom-backup-signing.hex \
  --key-id backup-root-2026-q3

loomctl verify-backup-signed \
  --path /backups/loom/acme-2026-07-29 \
  --public-key-file /etc/loom/trust/backup-root-2026-q3.hex \
  --key-id backup-root-2026-q3
```

Restore to a new path. The tenant comparison occurs before any destination is published:

```sh
loomctl restore \
  --path /backups/loom/acme-2026-07-29 \
  --expected-tenant acme \
  --out /var/lib/loom/acme-restored
```

Production restore requires the same expected trust root:

```sh
loomctl restore-signed \
  --path /backups/loom/acme-2026-07-29 \
  --expected-tenant acme \
  --out /var/lib/loom/acme-restored \
  --public-key-file /etc/loom/trust/backup-root-2026-q3.hex \
  --key-id backup-root-2026-q3
```

Then open `/var/lib/loom/acme-restored` with the production actor-key attestation and run application
read/query smoke tests before traffic is switched.

## Required deployment drill

Run this drill for every target filesystem, CSI driver, backup agent, and object-store topology:

1. Start a sustained write workload and create branches while the database is live.
2. Run `loomctl backup` and continue the workload.
3. Run `loomctl verify-backup-signed` from a different host or trust domain,
   using the independently provisioned public trust root.
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
- automated KMS/HSM signing-key delivery and trust-root rotation drills (the
  native signed-manifest door is implemented; custody remains platform policy).
