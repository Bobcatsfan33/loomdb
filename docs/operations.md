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
loom-bundle-tool verify --public /keys/loom-release.pub --in policy-2026-07.bundle
#   → VERIFIED: bundle "policy-2026-07" kind=policy version=3 (…) — safe to apply.
#   exit 0  → apply it.   any non-zero exit → DO NOT apply.
```

`verify` checks **both** that the signature is valid over the bundle's manifest *and* that the
payload's BLAKE3 hash matches the hash inside that signed manifest — so a genuine signature over one
payload can never be reused to bless a swapped one. `inspect` prints the manifest without verifying.

### How a release is signed (the key never touches the repo)

Signing reads the private key from a **file path**, which the release pipeline
(`.github/workflows/release-bundle.yml`) fills from the `LOOM_BUNDLE_SIGNING_KEY` repository secret,
writes to a throwaway file, and deletes immediately after signing. The key never enters the source, a
commit, or a build log.

```sh
# What the pipeline runs (the key file is populated from the secret, not committed):
loom-bundle-tool sign --key "$KEY_PATH" \
  --kind software --id "loomd-<sha>" --version "<tag>" \
  --in target/release/loomd --out loomd.bundle
```

The production keypair is generated **offline** by the operator
(`loom-bundle-tool keygen --out-secret … --out-public …`); only the public half is distributed to
enclaves, and only the secret *path* is handed to the pipeline. The mechanism (sign/verify, payload-swap
rejection, tamper rejection, format-version gating) is covered by `loom-bundle`'s unit tests, which run
in the ordinary `test` job with a throwaway dev key.

---

## Summary of the checks an auditor can run

| Guarantee | Command | Expected |
| --- | --- | --- |
| Suite needs no network | `docker run --network none … cargo test --workspace --offline` | green |
| `loomd` links no object store | `cargo tree -p loom-mcp --no-default-features --features airgap -e no-dev \| grep object_store` | no output |
| Clock/licence never stop serving | `cargo test -p loom-soak --test airgap_endurance` | green |
| Isolation holds under churn | `cargo test -p loom-soak --test multitenant_endurance` | green |
| Update authenticity | `loom-bundle-tool verify --public <key> --in <bundle>` | exit 0 only if genuine |
