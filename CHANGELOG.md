# Changelog

All notable changes to LoomDB. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions are the `loomdb-vX.Y[.Z]` tags on this repository.

**A note on what "released" means here.** LoomDB is a **software release candidate** and is **not
approved for production deployment** — see [`docs/enterprise-readiness.json`](docs/enterprise-readiness.json),
which records that decision, its reason, and the five open blocking gates. Cutting a version does not
change that; the decision flips when human ceremonies, audits, and a penetration test actually happen.

---

## loomdb-v0.5.0 — the adoption release

*Everything merged since `loomdb-v0.2`, including the `v0.3` and `v0.4` feature tags, which were never
published as GitHub Releases.*

### Added — a way in for people who did not write this

- **A runnable example.** `cargo run -p loom-mcp --example taint_recall` — no LLM, no API key, no
  server, no network. A scripted agent drives the real MCP surface in-process and prints the two
  moments that are the point: the influence policy refusing an injected *"suspend every account"*, and
  `taint(S)` returning the contaminated set with the irreversible action listed **first**, carrying its
  receipt and its registered compensating action. The example checks both guarantees itself and exits
  non-zero if either breaks. (#25)
- **A README a stranger can use** — what it is, who it is for, a Mermaid diagram of the provenance and
  taint flow, and a quickstart measured at **38 seconds** from `git clone` to output with its
  conditions stated. (#24)
- **`CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`**, with every setup command executed rather than
  recalled, the `cargo test --all-targets` trap documented, and a section on how the repository's
  evidence discipline works. (#34)
- **[`docs/known-limits.md`](docs/known-limits.md)** — every bound LoomDB knows about itself, moved out
  of the README in full, nothing withdrawn.

### Added — the enterprise-readiness program (P0 → P9.1)

- **P0 — actor trust and cross-process ownership** hardened. (#1)
- **P1 — verified online backup and `loomctl` operations.** (#2)
- **P2 — offline release authorization hardened**, exact kind/id/version claims. (#3)
- **P3 — production backup manifests authenticated** with native Ed25519. (#4)
- **P4 — `loomd` operations and observability**, optional OTLP behind a feature. (#11)
- **P5 — procurement evidence gated**: the expiring, CI-validated evidence index. (#12)
- **P6 — the reference production host profile**: 2 tenants, 20 rendered artifacts, **69 unsafe
  postures rejected**, all checked by `scripts/verify_host_profile.py`. (#13)
- **P6.1 — the attested constructor wired into `loomd`**: MCP writes are signature-authenticated
  against a governance-attested actor registry. (#14)
- **P7 — backup operations**: scheduling, retention with legal hold, observability, and rehearsal,
  with a writer/verifier trust-domain split. (#15)
- **P7.1 — build flavours corrected.** Storage posture and telemetry are orthogonal; exactly one of
  `remote`/`airgap` must be declared. Four supported flavours compile and three forbidden combinations
  are rejected by name, checked by `scripts/verify_build_flavours.sh`. (#16)
- **P8 — trust-root custody.** A `Signer` interface that signs the *exact* caller bytes, a read-only
  fail-closed trust-root register, named keys for all three signing roles (`actor-governance`,
  `release`, `backup-root`), statuses (pending/active/retired/revoked), and rotation as a sequence —
  expand → activate → drill → revoke — with dual control on the two transitions that change what
  verifies. (#17)
- **P9 — recovery and incident exercises with measured evidence.** Point-in-time clone, measured
  RPO/RTO against approved targets (24 h / 4 h), known-answer checks, ten fault injections, and
  generated incident notifications. (#18)
- **P9.1 — backup signature format v2.** A design note first (#19), then the implementation (#20).
  v1 signed the domain separator, key id, and **the entire manifest** — measured at **5,680 bytes on a
  27-file store**, already 1,584 bytes over the AWS KMS `Sign` limit of 4,096 and growing with the
  store. v2 signs a domain-separated, length-prefixed key id plus the manifest **digest**: **95 bytes,
  fixed**. The verifier **recomputes** the digest and never trusts the value the record carries.
  Also adds the AWS KMS signer backend (`ECC_NIST_EDWARDS25519` / `ED25519_SHA_512` / `MessageType:
  RAW`) behind an off-by-default feature, because `loom-keys` is in `loomd`'s air-gap graph.

### Added — engine work carried by the v0.3 and v0.4 tags

- **v0.3 — the HNSW index build made O(N·log N)**, proven to 1M vectors on a headroom host. The
  N·log N constant stays flat across 1k→1M while the N² constant collapses ~240×. A 1M-vector build
  runs in **~5.6 min**.
- **v0.4 — the ANN index made live.** An indexed write appends to an in-branch buffer and `search_ann`
  unions the graph with a bounded buffer scan, so a freshly written vector is searchable **immediately
  — 0 staleness**; a background fold moves the buffer into the graph off the write path, published by
  compare-and-set. Placement was decided by measurement: an inline insert cost ~220 ms of per-write
  latency on the AT-045-certified write path.
- **The refs file is no longer rewritten per commit.** Log-structured `RefEdit` frames with periodic
  compaction took per-commit cost from **41 ms and a 12.4 MB rewrite at 100k branches to ~1.4 ms flat**
  (O(branches) → O(1)), re-certified at `AT045_STRIDE=1`.

### Fixed

- **The release pipeline had never run.** `release-bundle.yml` triggered on `tags: v*`, which matched
  none of `loomdb-v0.1` … `loomdb-v0.4`. Every release to date was published by hand with **no signed
  bundle, no SBOM, and no provenance**, while the PR-triggered half of the workflow kept passing —
  which is exactly why it went unnoticed. The trigger now matches this project's actual tag convention.
  An explicit patch version is still required, because the version is bound into the signed bundle
  claim.

### Verification for this version

| Claim | Command | Result |
|---|---|---|
| Tests | `cargo test --workspace --lib --bins --tests` | 353 passing, 54 binaries |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Acceptance board | `docs/at-map.md` | AT-001…047 green |
| Readiness manifest | `python3 scripts/verify_enterprise_readiness.py` | 12 controls, 5 open blocking gates, decision=not-approved |
| Host profile | `python3 scripts/verify_host_profile.py` | 2 tenants, 20 artifacts, 69 unsafe postures rejected |
| Build flavours | `bash scripts/verify_build_flavours.sh` | 4 supported compile, 3 forbidden rejected |

### Known limits carried forward, unchanged

Stated because they are still true, not buried. Full text with measurements in
[`docs/known-limits.md`](docs/known-limits.md).

- **Wake over object storage is ≈1 RTT to your object store**, so whether it clears the 250 ms bar is
  *geography*. Measured to Sydney — a deliberately extreme worst case — the median clears and the
  **p99 (~345 ms) does not**. In-region deployments clear it with wide margin. Cold first-ever wake is
  ~4 RTT: the overlay-manifest chain is pointer-chasing and inherently serial.
- **HNSW recall is distribution-dependent.** ≥0.99 on realistic clustered embeddings at the default
  beam; materially lower on uniform/adversarial vectors and lower still at 1M.
- **Retrieval scans below a measured ~20k-vector crossover.**
- **Phase 3 operations are partially closed** — OpenTelemetry, `loomctl` provenance/taint views, and
  per-topology restore drills remain open.
- **Signature verification is opt-in and key issuance is external.**
- **No HSM ceremony has been held.** The KMS keys are provisioned and round-trip-verified, and both
  are `status: pending` — provisioned is not trusted.

---

## loomdb-v0.4 — the live ANN index

Tagged 2026-07-27. Not published as a GitHub Release; folded into v0.5.0 above.

## loomdb-v0.3 — HNSW build scaling

Tagged 2026-07-25. Not published as a GitHub Release; folded into v0.5.0 above.

## loomdb-v0.2 — air-gap certification

Released 2026-07-21. L5 air-gap certification, the no-egress suite, signed offline update bundles, and
endurance soaks. **AT-045 (crash at any byte) closed**, and the acceptance board has been full since.

## loomdb-v0.1 — the agent-native database

Released 2026-07-15. L1–L4 and `loomd`, the MCP server: sessions-as-branches, the record-level merge
engine, durable refs and the commit DAG, provenance and taint-and-recall, memory and retrieval, the
policy/influence/action layer, and bitemporal as-of queries (AQL v0).
