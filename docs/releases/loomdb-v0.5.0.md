**A database an agent can branch like git — that records where every belief came from, and can undo
exactly what a poisoned input contaminated.**

This is the adoption release. It collects everything since `loomdb-v0.2` — the `v0.3` and `v0.4`
feature tags, which were never published as Releases, plus the whole P0→P9.1 enterprise-readiness
program — and adds the things a stranger needs in order to try it.

## Try it in 38 seconds

```sh
git clone https://github.com/Bobcatsfan33/loomdb
cd loomdb
cargo run -p loom-mcp --example taint_recall
```

No LLM, no API key, no server, no network. A scripted agent drives the real MCP surface in-process and
prints the two moments that are the whole point:

1. **The influence policy refuses the injection.** A poisoned page says *"suspend every account"*, the
   agent proposes exactly that, and it is refused — not by a string filter, but because `Untrusted`
   evidence is structurally unable to authorize a suspension.
2. **`taint(S)` names exactly what the poisoned source contaminated**, listing the **irreversible**
   real-world action first — with its receipt and its registered compensating action — ahead of the
   writes it can simply revert.

The example checks both guarantees itself and exits non-zero if either breaks.

*(38 seconds measured on an Apple M2, 8 cores, 8 GiB, macOS 15.7.4, rustc 1.97.0, from a clean checkout
with an empty `target/` and a warm cargo registry cache. Almost all of it is the first build.)*

## Status — the honest version

**LoomDB is a software release candidate. It is _not approved for production deployment_, and that
decision is recorded in the repository rather than in someone's head.**

[`docs/enterprise-readiness.json`](https://github.com/Bobcatsfan33/loomdb/blob/main/docs/enterprise-readiness.json)
carries 12 controls — 5 implemented, 7 partial — each with its evidence *and its gaps*, **5 open
blocking external gates**, `"deploymentDecision": "not-approved"`, and a review date of 2026-10-29.
`scripts/verify_enterprise_readiness.py` runs in CI and **fails the build** if a control claims
evidence it does not have.

The five open gates are the ones no amount of code closes from inside a repository: a **hardware key
ceremony** (keys are provisioned in AWS KMS and round-trip-verified, but no dual-control ceremony has
been held, and both keys are `status: pending`), a **customer-scale disaster-recovery sign-off**
(drills are measured on developer hardware and say so), a **third-party penetration test**, an
**operations rota**, and a **compliance audit**.

Cutting this version does not change any of that, and is not meant to.

## What is in it

- **Adoption**: the `taint_recall` example, a README written for someone with no context, a measured
  quickstart, `CONTRIBUTING.md` with executed commands, `CODE_OF_CONDUCT.md`, and
  `docs/known-limits.md`.
- **Enterprise readiness, P0→P9.1**: actor trust, verified online backup, offline release
  authorization, authenticated backup manifests, observability, the gated procurement evidence index,
  the reference host profile (69 unsafe postures rejected), attested writes in `loomd`, backup
  scheduling and retention with legal hold, corrected build flavours, trust-root custody with rotation
  under dual control, recovery and incident exercises with measured RPO/RTO, and backup signature
  format v2.
- **Engine work from v0.3 and v0.4**: the HNSW build made O(N·log N) and proven to 1M vectors; the ANN
  index made live via background compaction with **0 staleness**; refs made log-structured, taking
  per-commit cost from 41 ms at 100k branches to ~1.4 ms flat.

Full detail in [CHANGELOG.md](https://github.com/Bobcatsfan33/loomdb/blob/main/CHANGELOG.md).

## Fixed: the release pipeline had never actually run

`release-bundle.yml` triggered on `tags: v*`. Every tag this project has ever cut is `loomdb-vX.Y`,
which does not match. So the signing, SBOM, provenance, and publish steps **never executed once**, and
`loomdb-v0.1` and `loomdb-v0.2` were published by hand with no assets at all. The pull-request half of
the workflow kept passing the whole time, which is why it went unnoticed for four tags.

The trigger now matches this project's tag convention. An explicit patch version is still required —
hence `loomdb-v0.5.0` rather than `loomdb-v0.5` — because the version is bound into the signed bundle
claim and verified by exact match, and an ambiguous version there authorizes more than one artifact.

## Verifying this release

Every artifact is covered by GitHub build provenance and listed in `SHA256SUMS`.

```sh
# provenance
gh attestation verify loomd --repo Bobcatsfan33/loomdb

# checksums
sha256sum -c SHA256SUMS

# the native Ed25519 bundle signature — this is the one an enclave checks with no network
./loom-bundle-tool verify \
  --public loom-release.pub \
  --require-kind software \
  --require-id "<bundle_id from release-receipt.json>" \
  --require-version loomdb-v0.5.0 \
  --in loomd.bundle
```

The bundle signature is the authenticity check that works offline; GitHub provenance is complementary
procurement evidence. `release-receipt.json` binds the release tag, the source revision, the bundle id,
and the three digests.

The shipped `loomd` is the **air-gap** build: the workflow proves its dependency graph contains no
object-storage client before signing it, and builds it twice into separate target directories and
compares the bytes.

## Known limits — read these before an evaluation

Stated because they are still true. Full text with measurements in
[`docs/known-limits.md`](https://github.com/Bobcatsfan33/loomdb/blob/main/docs/known-limits.md).

- **Wake over object storage is ≈1 RTT to your object store.** Whether that clears the 250 ms bar is
  *geography*, not code. Measured to Sydney — a deliberately extreme worst case, server and bucket on
  opposite sides of the planet — the median clears and the **p99 (~345 ms) does not**. In-region, even
  the ~2 RTT tail clears with wide margin. The cold first-ever wake is ~4 RTT and stays that way: the
  overlay-manifest chain is pointer-chasing, so it is inherently serial and cannot be batched.
- **HNSW recall is distribution-dependent.** ≥0.99 on realistic clustered embeddings at the default
  beam; materially lower on uniform/adversarial vectors and lower still at 1M, where ef=64 gives ~0.28.
- **Retrieval scans below a measured ~20k-vector crossover**, and the scan is *faster* there.
- **A 1M-vector index build takes ~5.6 min** on a stock runner.
- **Phase 3 operations are partially closed**: OpenTelemetry, `loomctl` provenance/taint views, and a
  restore drill per storage topology are still open.
- **One `Loom` per store directory** (OS advisory lock).
- **Signature verification is opt-in, and key issuance is external.**
- **Multi-tenancy is a signed-token router**, one substrate pool per tenant — isolation rests on that
  model, not on row-level filtering.

## Contributing

[`CONTRIBUTING.md`](https://github.com/Bobcatsfan33/loomdb/blob/main/CONTRIBUTING.md) has the setup
commands, executed and timed, and the one trap worth knowing before you hit it: `cargo test
--all-targets` *runs* the `harness = false` benchmarks and will appear to hang for ~50 minutes.

There are [good first issues](https://github.com/Bobcatsfan33/loomdb/labels/good%20first%20issue), each
with a code pointer, acceptance criteria, and a note on the obvious-but-wrong fix.

Apache-2.0.
