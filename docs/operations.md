# Operating LoomDB in an air-gapped enclave

This is the **proof-of-offline manifest**. It exists so a skeptic can confirm LoomDB's two air-gap
guarantees *themselves*, without trusting us:

1. **The running software needs no network.** The whole test suite passes with no route to the outside
   world.
2. **The shipped binary cannot reach object storage.** An air-gap build of `loomd` links no
   object-storage client at all — not "is configured not to use one", *does not contain one*.

Every claim below comes with the exact command that verifies it. Two of them run on every CI build
(the [`no-egress`](#guarantee-1-the-suite-runs-with-no-network) and
[`airgap`](#guarantee-2-loomd-contains-no-object-storage-client) jobs in
`.github/workflows/ci.yml`), so the certification is reproduced continuously, not asserted once.

---

## The one network dependency, and how it is removed

LoomDB's data path is pure and local. The *only* code in the entire workspace that links an
object-storage client is `loom-branch`'s remote **sleep/wake** path — `Loom::sleep` / `Loom::wake`,
which put a tenant to sleep in object storage and wake it back. That path pulls `substrate-store`, and
`substrate-store` pulls `object_store` (and, inside it, the S3/GCS/Azure clients).

It lives behind a Cargo feature, `remote`, which is **on by default**:

```toml
# crates/loom-branch/Cargo.toml
[features]
default = ["remote"]
remote  = ["dep:substrate-store"]   # the ONLY thing that links an object-storage client
airgap  = []                        # a marker naming the posture (see below)
```

The feature is `default-features = false` all the way up the dependency chain
(`loom-provenance`, `loom-memory`, `loom-query`, `loom-mcp`), so building with
`--no-default-features` compiles the sleep/wake path — and every transitive S3 client — **out
entirely**. Because Cargo features are additive and cannot *remove* a feature, the air-gap build is
`--no-default-features --features airgap`, and the `airgap` feature is a marker so code and docs can
name the posture explicitly.

> This is a compile-time amputation, not a runtime switch. An operator cannot misconfigure it back on,
> and an auditor verifies it by inspecting the artifact — not by trusting that `--network none` stays
> applied in production.

Build an air-gapped `loomd`:

```sh
cargo build --release -p loom-mcp --no-default-features --features airgap
# → target/release/loomd, with no object-storage client compiled in.
```

---

## Guarantee 1: the suite runs with no network

**Claim:** nothing in LoomDB needs egress. Sleep/wake tests use an in-memory object-store backend; the
oracles, the demo, and the soaks are all local.

**Verify it yourself.** Vendor the dependencies while the network is up, then run the whole suite inside
a container with no network namespace at all:

```sh
mkdir -p .cargo
cargo vendor vendor > vendor-config.toml
cat vendor-config.toml >> .cargo/config.toml

docker run --rm --network none \
  -v "$PWD":/w -w /w \
  -e CARGO_HOME=/w/.cargo-home \
  rust:1 \
  cargo test --workspace --offline --lib --bins --tests
```

`--network none` gives the container no route anywhere. If any test reached for the network it would
fail. It does not. This is the `no-egress` job in CI, run on every build.

---

## Guarantee 2: `loomd` contains no object-storage client

**Claim:** an air-gap build of `loomd` does not link `object_store` (or `substrate-store`) at all.

### The authoritative check — the dependency graph

This is the check to trust, because it discriminates and is reproducible on any machine:

```sh
# The air-gap build's non-dev dependency graph — grep finds nothing:
cargo tree -p loom-mcp --no-default-features --features airgap -e no-dev | grep -i object_store
#   → (no output, exit 1)

# Contrast: the DEFAULT (remote-on) build DOES contain it:
cargo tree -p loom-mcp -e no-dev | grep -i object_store
#   → object_store v0.11.x  (present)
```

The air-gap build has neither `object_store` nor `substrate-store` anywhere in its graph, so no code
path can possibly reach an object-storage client — there is none to reach. This is the `airgap` job in
CI: it builds `loomd` air-gapped and fails the build if `cargo tree` finds either crate, so the
amputation cannot silently regress if someone re-adds a `default-features` edge.

### Binary confirmation (and its honest limit)

As a second, artifact-level check, the built binary carries no `object_store` symbols:

```sh
cargo build --release -p loom-mcp --no-default-features --features airgap
nm -C target/release/loomd | grep -i object_store   # → (nothing)
```

**Honest caveat (rule: say where we are weak):** link-time dead-code elimination can also strip
`object_store` from a *remote-on* release binary when the sleep/wake path is never called, so on its
own the symbol check does not always distinguish the two builds. The **dependency-graph check above is
the discriminating one**; the symbol check confirms the air-gap binary carries no such client, it does
not by itself prove a remote-on binary would.

---

## Offline clock and licensing behaviour

An air-gapped enclave cannot phone home to check a licence, so LoomDB uses substrate-security's
offline model, and **nothing it decides can stop a read or a write**:

- **The clock never runs backwards.** A `HighWaterClock` persists the furthest-forward time ever seen
  and never accepts anything earlier. Set the system clock back and the licence does not un-expire; a
  legitimate ±30-day drift is tolerated silently.
- **An expired or missing licence degrades, it does not stop.** The licence engine returns `Degraded`
  (which disables fleet-administration features only). Reads and writes are unaffected and remain so.

Both properties are proven, not asserted, by **Soak A** (`crates/loom-soak/tests/airgap_endurance.rs`),
which runs a 120-day accelerated clock with ±30-day jumps and a licence that expires mid-run, and
asserts the clock never regresses and reads *and* writes keep succeeding across expiry — including a
write proven to succeed while the licence is `Degraded`.

---

## The two long soaks (the L5 endurance gate)

Both gate on **zero errors AND flat memory** across a full window — a slow leak in a process meant to
stay up for a year is a guaranteed outage, so a leak *fails* the run (`loom_soak::FlatMemory`).

| Soak | File | Proves |
| --- | --- | --- |
| A — airgap endurance | `airgap_endurance.rs` | 120-day clock, ±30-day jumps, licence expiry with reads/writes never stopping, storage exhaustion backpressures cleanly and never corrupts; flat memory. Runs air-gapped. |
| B — multi-tenant concurrency | `multitenant_endurance.rs` | cross-tenant isolation (AT-039) and branch isolation (AT-040) hold under concurrent churn, merges stay idempotent; flat memory. |

They run at a small default on every push (the `test` job, ~seconds), and at the full window nightly
on the CI runner:

```sh
# The full window (what the nightly `soak` job runs):
LOOM_SOAK_ITERS=50000 cargo test -p loom-soak --release --test airgap_endurance -- --nocapture
LOOM_SOAK_ITERS=8000 LOOM_SOAK_WORKERS=8 \
    cargo test -p loom-soak --release --test multitenant_endurance -- --nocapture
```

---

## Signed offline update bundles

An enclave still has to receive updates — a renewed licence, a new policy, a model artifact, a software
build. They arrive on physical media, so the only thing between the enclave and a tampered update is a
signature it can check **offline**, against a public key it already holds.

### What the enclave does (verify, offline)

```sh
loom-bundle-tool verify \
  --public /keys/loom-release.pub \
  --require-kind policy \
  --require-id policy-2026-07 \
  --require-version 3 \
  --in policy-2026-07.bundle
#   → VERIFIED: bundle "policy-2026-07" kind=policy version=3 (…) — safe to apply.
#   exit 0  → apply it.   any non-zero exit → DO NOT apply.
```

`verify` checks that the signature is valid over the bundle's manifest, that
the payload's BLAKE3 hash matches the hash inside that signed manifest, and
that the signed `kind`, `id`, and `version` exactly match the approved change.
That last gate matters: an authentic old software release or authentic policy
bundle is still not authorized at a different update door. `inspect` prints the
manifest without verifying and is never an approval step.

### How a software release is built and signed

The `production-release` GitHub environment owns the
`LOOM_BUNDLE_SIGNING_KEY` secret, the independently distributed
`LOOM_BUNDLE_PUBLIC_KEY` variable, required approvers, and a deployment audit
trail. A protected semantic-version tag starts
`.github/workflows/release-bundle.yml`; there is no arbitrary payload or manual
signing input.

```sh
# The pipeline signs only the locked, feature-amputated air-gap binary:
loom-bundle-tool sign --key "$KEY_PATH" \
  --kind software --id "loomd-<sha>" --version "<tag>" \
  --in dist/loomd --out dist/loomd.bundle

# It then proves the private key matches the separately configured public key
# and that every authorized claim survived signing:
loom-bundle-tool verify --public "$PUBLIC_KEY_PATH" \
  --require-kind software --require-id "loomd-<sha>" \
  --require-version "<tag>" --in dist/loomd.bundle
```

The production keypair is generated **offline** by the operator
(`loom-bundle-tool keygen --out-secret … --out-public …`). The private half is
entered only into the protected environment; the public half and its
fingerprint are distributed to enclaves through a separate, authenticated
trust-root ceremony. The public key attached to a release is evidence and a
convenience copy, not a trust-on-first-use authority.

The workflow refuses vulnerable locked Rust dependencies, proves the release
dependency graph contains no object-storage client, pins Rust 1.89.0 and every
third-party action, and uses the tagged commit time plus remapped source paths.
It compiles `loomd` twice into independent target directories and requires the
binaries to be byte-identical. Only after that reproducibility gate and
exact-claim self-verification does it emit an
SPDX SBOM, SHA-256 checksums, a release receipt, and GitHub build provenance,
then create the GitHub release with those artifacts. The native bundle remains
the offline authenticity mechanism; GitHub provenance is complementary
procurement evidence.

An exported Ed25519 seed in a protected CI environment is the current signing
boundary. Organizations that require a non-exportable HSM/KMS key must replace
that step with their approved signer while preserving the exact manifest bytes
and all verification gates; HSM integration is not claimed by this repository.

---

## Summary of the checks an auditor can run

| Guarantee | Command | Expected |
| --- | --- | --- |
| Suite needs no network | `docker run --network none … cargo test --workspace --offline` | green |
| `loomd` links no object store | `cargo tree -p loom-mcp --no-default-features --features airgap -e no-dev \| grep object_store` | no output |
| Clock/licence never stop serving | `cargo test -p loom-soak --test airgap_endurance` | green |
| Isolation holds under churn | `cargo test -p loom-soak --test multitenant_endurance` | green |
| Update authorization | `loom-bundle-tool verify --public <key> --require-kind <kind> --require-id <id> --require-version <version> --in <bundle>` | exit 0 only if genuine and exactly approved |
| Release provenance | `gh attestation verify <artifact> --repo Bobcatsfan33/loomdb` | tagged workflow identity and matching subject digest |
| Host profile upholds its controls | `python3 scripts/verify_host_profile.py` | valid, no drift, 69 unsafe postures rejected |
| Restart reopens the store; a second process cannot take it | `cargo test -p loom-mcp --test host_profile` | green |

## The reference host profile

Everything in this document is about the engine and its artifact. The *deployment* around it — network
identity, TLS, process isolation, resource ceilings, one-pool-per-tenant routing — is the host's, and
the supported reference posture for it is [host-profile.md](host-profile.md), rendered from
[`deploy/reference/profile.json`](../deploy/reference/profile.json):

```sh
python3 scripts/verify_host_profile.py          # validate, check drift, reject 69 unsafe postures
python3 scripts/render_host_profile.py --write  # regenerate after editing profile.json
```

Read it before deploying. It is a reference posture, not a production approval.

## One tenant, one store

Each `loomd` process serves exactly one tenant out of exactly one store:

| Variable | Meaning |
|---|---|
| `LOOM_TENANT` | The tenant this process serves. Defaults to `default`. |
| `LOOM_DATA_DIR` | The durable store. **Unset means in-memory** — nothing survives the process. |

Both are read once at startup, so no request can name a tenant or a store, and no request can reach
another tenant's data. With `LOOM_DATA_DIR` set, the daemon opens a durable store and a restarted host
reopens the same committed state.

The directory is validated fail-closed: it must be a real directory (not a symlink that could be
repointed at another tenant's store between restarts) and must not be world-writable. A missing
directory — a mount that failed to attach — stops startup rather than silently serving an empty store.
`crates/loom-mcp/tests/host_profile.rs` proves each of these at the process boundary.

Group-writable is deliberately **allowed** here, unlike for the policy file. Kubernetes applies
`fsGroup` to a mounted volume by granting the group write access, so a `g+w` store is the normal state
for a non-root pod with a persistent volume; rejecting it would stop the reference profile from
running. A second writer is excluded where it actually can be — the advisory lock below — not by the
directory mode.

Two further operational facts follow from the engine being one stdio stream per tenant:

- **A second process cannot take an owned store.** `FileRefStore::open` holds an exclusive advisory
  lock on `<store>/loom/store.lock`; the loser exits with "already open by another process". Releasing
  the owner releases the lock, so a clean restart reacquires it.
- **Capability tokens do not survive a restart.** The token issuer key is generated per process, so
  clients must re-open a session after the daemon restarts.

## Write authenticity: the attested open

Under the reference host profile `loomd` does not open its store with `Loom::open`. It opens with
`Loom::open_production_attested`, so a write arriving over MCP is verified against the key of the
actor the envelope *claims to be* — an unsigned write, a forged signature, and an actor nobody
registered are each refused rather than recorded.

Three variables carry the material, and they are **all-or-nothing**: set none and the daemon behaves
as it always did (attributable, unauthenticated — the embedded and development posture); set some but
not all and it refuses to start rather than run with authentication half-configured.

| Variable | Meaning | Where it comes from |
|---|---|---|
| `LOOM_ACTOR_REGISTRY_FILE` | The tenant's actor→key map and the governance attestation over it | the read-only actor-registry mount |
| `LOOM_ACTOR_GOVERNANCE_KEY_FILE` | The governance verifying key | the read-only trust-root mount — an independent channel from the registry it signs |
| `LOOM_ACTOR_MIN_GENERATION` | The rollback floor. Must be ≥ 1 | deployment configuration, rendered into the manifest a reviewer reads |

Everything is checked **before any store file is opened**: the governance signature, the tenant the
attestation was issued for, the rollback floor, and the registry fingerprint. Each failure stops
startup and names itself — `actor registry rollback refused`, `actor key registry fingerprint
mismatch`, `actor registry governance signature is invalid`, `actor registry attestation tenant
mismatch`. The registry file itself is validated the same fail-closed way as the policy file: a
regular file, at most 1 MiB, never group- or world-writable, never a symlink.

**Revoking an actor** is therefore two steps and both are auditable: issue a new registry at a higher
generation without that actor, and raise `actorRegistryMinGeneration` in `profile.json`. Raising the
floor is what stops the revoked-but-still-validly-signed registry from being replayed.

Clients sign `WriteEnvelope::signing_bytes()` off-process and pass the result as the `signature`
argument to `observe`, `claim.assert`, and `branch.merge`.
`crates/loom-mcp/tests/actor_registry.rs` proves all of this at the process boundary, including that
a declared registry which cannot be verified never falls back to an unauthenticated open.

## Backup operations

The signed-backup mechanism is in [backup-restore.md](backup-restore.md); this is what the reference
profile schedules around it, and the two operational facts an operator needs first.

**A backup cannot read a live store.** The engine holds an exclusive advisory lock on
`<store>/loom/store.lock` for its process lifetime, so a job pointed at the volume `loomd` is serving
fails with "already open by another process". Every scheduled backup therefore runs against a
platform-provided point-in-time clone, and the profile refuses to render one that mounts a live
tenant volume.

**The verifier is not the writer.** Four scheduled roles — backup, verify, prune, rehearsal — run as
two identities holding two different secrets. The writer mounts the owner-only signing key; the
verifier and the rehearsal mount the public trust root and never the signing key. A signature
checked by whoever produced it is not an independent check, so this is enforced by which secret each
container may mount and is checked on the rendered bytes.

Signals reach the host as unlabelled Prometheus series written atomically to `--metrics-file` —
`loomctl` links no exporter and opens no socket. `loomdb_backup_failures_total` is written on the
failure path too, and the rendered stale-backup alert uses `absent()`, because a job that never ran
emits nothing and silence must not read as health. No signal carries a tenant identifier; the file
path does, and the collector attaches workload labels itself.

Retention keeps a copy for any of three reasons — a legal hold names it, it is one of the newest
`--minimum-copies`, or it is younger than `--keep-days` — and is a dry run until `--apply`. It
refuses to run inside a live store, and an unreadable hold register is an error, never an empty one.

## Request admission and secure defaults

`loomd` is one tenant per process and starts with a deny-by-default policy. Production supplies a
JSON-encoded `PolicySet` through `LOOM_POLICY_FILE`; the same reviewed policy is compiled into both
the MCP influence checks and the operator action gateway. The file must be a regular file (not a
symlink/device), at most 1 MiB, not group/world-writable on Unix, contain a 1–128 byte version, and
contain no more than 10,000 bounded rules. Invalid or ambiguous configuration stops startup.

The legacy permissive development posture is available only with
`LOOM_ALLOW_PERMISSIVE_POLICY=true`; never set it in a production workload. It is mutually exclusive
with `LOOM_POLICY_FILE` and emits a supervisor-visible warning.

Every input frame is read with a hard allocation bound and then passes a per-process token bucket:

| Variable | Default | Accepted range |
|---|---:|---:|
| `LOOM_MAX_REQUEST_BYTES` | 1 MiB | 256 bytes–16 MiB |
| `LOOM_REQUESTS_PER_SECOND` | 100 | 1–100,000 |
| `LOOM_REQUEST_BURST` | 200 | 1–1,000,000 |

Invalid values stop startup with exit code 2. Oversized and rate-limited requests return JSON-RPC
`-32001` without entering the engine. Put connection limits, cgroups, tenant storage quotas, and
network DDoS controls in the supervisor or gateway; the stdio daemon cannot enforce those host-level
budgets.

## Optional OpenTelemetry

Telemetry is compiled out by default and is structurally forbidden in an `airgap` build. Build the
connected deployment explicitly:

```sh
cargo build --locked --release -p loom-mcp --features observability
```

Set `LOOM_OTEL_ENABLED=true` and configure the OTLP/HTTP exporter with the standard
`OTEL_EXPORTER_OTLP_*` variables. An invalid enable flag or exporter initialization error stops
startup; explicit operator intent never silently degrades to an unobserved process. The instruments
are:

- `loomd.rpc.requests`
- `loomd.rpc.failures`
- `loomd.rpc.denied`
- `loomd.rpc.duration` (seconds)
- `loomd.rpc` spans

Dimensions are allow-listed to known RPC methods, known tool names, and `ok`/`denied`/`error`.
Tenant IDs, request IDs, arguments, tokens, keys, source text, and response bodies are never exported.
Route OTLP through the enterprise Collector for mTLS, batching, redaction, and backend fan-out. Alert
on denial/error rate and latency SLO burn; retain telemetry under the same access and evidence policy
as other security-relevant operational logs.
