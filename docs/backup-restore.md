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

## Scheduling, retention, and signals

The commands above are the mechanism. The reference host profile renders the **operations** around
them — when they run, who runs them, how long copies live, and what the host can see — from
[`deploy/reference/profile.json`](../deploy/reference/profile.json), the same declarative way as
everything else. See [`host-profile.md`](host-profile.md) §8.

### The constraint everything else follows from

`FileRefStore::open` holds an **exclusive** advisory lock on `<store>/loom/store.lock` for the
store's lifetime, so a scheduled job **cannot back up a volume a live `loomd` is serving** — it would
fail every night. This is not a limitation to work around quietly; it is proven at the command
boundary (`a_backup_cannot_be_taken_from_a_store_a_daemon_is_holding`).

So the profile declares a **point-in-time source** the platform provides — a CSI volume-snapshot
clone, a storage-array clone, or a filesystem snapshot — and the backup job mounts *that*,
read-only. The renderer refuses to emit a job that mounts a live tenant claim, and the gate refuses
a profile whose `claimTemplate` would render one.

### The four scheduled roles, and why they are four

| Role | Runs | Identity | Holds |
|---|---|---|---|
| `backup` | `loomctl backup-signed` against the clone | `loomd-backup` | the signing key **only** |
| `verify` | `loomctl verify-backup-signed` against the trust root | `loomd-backup-verifier` | the public trust root **only** |
| `prune` | `loomctl backup-prune --apply` | `loomd-backup` | the legal-hold register |
| `rehearsal` | `loomctl restore-signed` to a fresh path, then `loomctl verify` | `loomd-backup-verifier` | the public trust root |

**The verifier is not the writer.** A signature is worth the independence of the party checking it,
so the job that produces backups and the job that blesses them are different identities holding
different secrets, and neither can do the other's job. That is enforced by which secret each
container may mount — not by convention — and the gate checks it on the rendered bytes.

### Receipts, and what they are not

`backup-signed --metrics-file` writes an operational receipt *beside* the backup —
`<backup>.receipt.json`, never inside it, because verification refuses a file the signed manifest
does not allow-list. The receipt records the recovery point, duration, bytes, and key id, and it is
what lets verification later report *which point in time* it proved restorable.

The receipt is **unsigned and is not an authenticity claim**. The loomDB trust-root signature over
the exact manifest bytes is, and remains, the only authenticity check. A rewritten receipt moves a
number on a dashboard; it cannot make a tampered backup verify, and a receipt whose manifest digest
no longer matches is ignored. A storage vendor's checksum sits in exactly the same position: it may
coexist, it never substitutes.

### Retention and legal hold

```sh
loomctl backup-prune \
  --root /var/backups/loomd/acme \
  --keep-days 35 --minimum-copies 7 \
  --legal-hold-file /etc/loomd/retention/legal-hold.json \
  --metrics-file /var/lib/loomd-metrics/acme-prune.prom \
  --apply
```

Four rules, and every one of them is a reason to **keep**:

1. **A legal hold names it** — nothing overrides this, not age, not policy, not `--apply`.
2. It is one of the newest `--minimum-copies`.
3. It is younger than `--keep-days`.
4. Otherwise it is pruned.

Without `--apply` the command prints the plan and removes nothing. It refuses to run inside a live
store, never follows a symlink, and never deletes an entry it does not positively recognize as a
backup — a retention tool that deletes what it does not understand eventually deletes something else.
An unreadable hold register is an **error**, never an empty one.

The hold register is a JSON document on the read-only retention mount:

```json
{"schemaVersion": 1, "holds": [{"backup": "acme-2026-07-29", "reason": "litigation hold 2026-114"}]}
```

A hold with no recorded reason is refused: an unexplained hold cannot be reviewed or lifted.

### The immutable, off-account copy

The staging root is local. The copy that survives a compromise of the deployment is the host's:
the profile declares its **named mechanism** (`object-lock-compliance`, a WORM appliance, or a tape
vault), its retention window, and that it is **off-account** — and validation requires all three.
`object-lock` *governance* mode is rejected, because a principal holding the bypass permission can
delete under it, and that principal is exactly the adversary an immutable copy exists to survive.
The immutable window must be at least as long as local retention.

loomDB **cannot write to that target**: no build links an object-storage client, in any profile,
which the air-gap dependency inspection re-proves on every CI run. Replication into it is the
platform's job, and the profile says so rather than pretending otherwise.

### Signals

`loomctl` links no exporter and opens no socket. Each command writes a fixed set of unlabelled
Prometheus series atomically to `--metrics-file`, and the host's collector reads them:

| Signal | Meaning |
|---|---|
| `loomdb_backup_last_success_timestamp_seconds` | when a backup last completed |
| `loomdb_backup_last_verified_timestamp_seconds` | when one was last independently verified |
| `loomdb_backup_last_verified_recovery_point_seconds` | *which* point in time that verification proved |
| `loomdb_backup_duration_seconds`, `_bytes`, `_files` | the shape of the last run |
| `loomdb_backup_failures_total` | 1 if the last run failed — **written on the failure path too** |
| `loomdb_backup_scrub_damaged_objects` | objects an integrity scrub found damaged |
| `loomdb_backup_retained_copies`, `_pruned_total`, `_legal_hold_retained` | what retention did |

**No signal carries a tenant identifier**, for the same reason `loomd` forbids a tenant dimension on
its RPC instruments: a tenant name in a metric is tenant data leaving through the monitoring
pipeline. One job serves one tenant and writes one file, so the *path* carries the tenant and the
collector attaches workload labels itself.

The rendered alerts (`deploy/reference/kubernetes/50-backup-alerts.yaml`) fire on a stale backup, a
backup nobody verified, a failing job, and detected damage. The stale-backup rule uses `absent()`
deliberately: a job that never ran emits nothing, and silence must not read as health.

A metric is an operational record, not an authenticity claim. `last_success` saying "yesterday" does
not prove a restorable backup exists — only verification against the trust root does. The signals
exist so a *missing* backup is loud.

### The restore rehearsal

The rehearsal takes the **newest** backup on the shelf, verifies its signature against the trust root
as part of `restore-signed`, restores it to a **fresh path**, and scrubs the result. (It picks the
newest, not "the newest one the verify job blessed" — the two jobs share the shelf and nothing else,
by design. A backup that fails here fails loudly and reports damage.) It
never overwrites and never activates: `restore-signed` refuses any destination that already exists,
so a rehearsal pointed at a live store fails rather than destroying it, and the profile cannot even
render one — the rehearsal path may not overlap a tenant data directory, and the rehearsal job mounts
the backup shelf read-only. Promoting a rehearsed store is a separate, deliberate operator act.

## Recovery objectives

**Approved 2026-08-01: RPO 24 hours, RTO 4 hours.**

| | Target | Why this number |
|---|---|---|
| **RPO** — worst-case data loss | 24 h | The deployed schedule takes one signed backup a day (`backupIntervalSeconds: 86400`), so a day is the honest worst case. The stale-backup alert fires at 36 h (`maxAgeSeconds: 129600`), which is one missed run. |
| **RTO** — time to a serving store | 4 h | Restore, attested reopen, and the known-answer checks below, with room for a human in the loop. |

These describe the mechanism **actually deployed**. Approving targets tighter than the schedule would
make a drill fail by construction instead of measuring anything; approving these makes the drill
measure reality. They are pre-production targets and revisitable per deployment — tightening them is
a schedule change (a shorter `backupIntervalSeconds` and a matching `maxAgeSeconds`), not a
re-labelling.

**Every drill records the measured recovery point and recovery time as first-class results**, not
merely pass/fail against the targets. If the real numbers come in far better — and on developer
hardware they do — that evidence is what justifies tightening the targets when a customer contract
demands it. Receipts are retained under [`docs/drills/`](drills/).

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

The storage mechanism and the operations around it are now both in the repository. What remains is
work no amount of configuration can do for you:

- **documented RPO/RTO targets validated on customer-scale data.** The profile renders a schedule and
  an alert threshold; neither is a measurement. Nobody has run this against a customer-scale store on
  the target storage stack, so `RES-01` and the `EXT-DR` gate stay open.
- **the environment-specific drill below, executed and signed.** The rendered rehearsal proves the
  restore path works on the shelf it can reach; it does not prove your CSI driver, backup product, or
  mount options behave.
- **encryption and key-management policy for backup media** at the platform layer.
- **automated KMS/HSM signing-key delivery and trust-root rotation drills.** The signed-manifest door
  is implemented and the profile keeps the signing key on its own owner-only mount, but custody,
  ceremony, and rotation remain platform policy — `CRYPTO-01` and `EXT-HSM` stay open.
- **`loomctl` provenance-chain and `taint` dry-run views** (a diagnostics gap, not a safety one).

Closed by this increment: scheduled signed backups, an independent verifier in a separate trust
domain, retention with legal hold, a declared immutable/off-account target, operational signals with
a stale-backup alert, and a restore rehearsal that cannot overwrite or activate production.
