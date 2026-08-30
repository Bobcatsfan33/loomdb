# Known limits

> Linked from the [README](../README.md). This is the full text of every bound loomDB knows about
> itself — moved out of the README so the front page stays readable, **not** to soften it. Nothing
> here has been shortened or withdrawn; the README carries a one-line summary of each entry and
> points here.

We would rather you find these here than in an evaluation. None affects correctness; each is a cost or a
bound stated plainly.

- **Retrieval's default is an O(entries) scan below a measured ~20k-vector crossover; the per-branch HNSW
  index accelerates past it and builds in O(N·log N) (v0.3, measured).** The scan is *correct*, exact, and
  branch-isolated (the load-bearing property, oracle-checked), and a latency bench
  (`crates/loom-branch/benches/ann_vs_scan.rs`) shows it is also *faster* than the ANN below ~20k indexed
  vectors (in-memory, DIM=64) — so scan stays the default for small/medium branches, and the accelerator
  earns its keep at scale (2.6× at 50k, widening); "ANN whenever an index exists" would be 6× slower at
  1k. (In-memory is the conservative case for the ANN — on object storage the scan's O(N) page reads move
  the crossover left.) The **HNSW** index is kept **in the branch**, never a shared
  index that would reintroduce the cross-branch leak the isolation was designed out ([invariant
  I-11](invariants.md)), with recall@10 ≥ 0.85 proven against the exact scan. **v0.3 made the build
  scale:** it builds the graph in RAM (unit-normalized vectors, a bare-dot distance, an epoch-tagged
  visited set) and persists once in a sorted pass, and a build-complexity benchmark
  (`crates/loom-core/tests/hnsw_build_scaling.rs`, 1k→1M, release, clustered real-embedding-shaped data,
  run on a stock CI runner) shows it tracks **N·log N, not N²** — the N·log N constant stays flat (~2×
  across the whole range, cache drift only) while the N² constant **collapses ~240×**. A **1M-vector
  build runs in ~5.6 min** (~340 µs/insert on that runner); recall@10 holds at **1.000 (1k) / 0.996 (1M
  at the default ef=64) / 1.000 (1M at ef=128)**. Parameters: M=16, Mmax0=2M, efConstruction=200,
  efSearch=64. **Recall is strongly distribution-dependent, and the number above is on realistic
  clustered embeddings** (real embeddings live near topics, not spread uniformly): recall@10 ≥ 0.99 there
  at the default beam. On the *pathological* case — uniform-random, near-orthogonal vectors, where the
  true top-10 are barely separated from everything else — recall is much lower, and the deficit **grows
  with N**: at 100k, ef=64 gives ~0.51 and a wider beam recovers it (0.87 at ef=256, 0.96 at ef=512); at
  1M, ef=64 gives ~0.28 and even ef=512 reaches only ~0.71. Recall climbs monotonically with the beam at
  both scales — the graph the build produces is **navigable** — but uniform high-dim vectors at 1M sit
  near the regime where nearest-neighbour is barely defined and recall is hard for *any* index (and no
  real embedding model produces them). So the honest claim is **≥ 0.99 on realistic clustered embeddings
  at the default beam; materially lower on uniform/adversarial distributions and lower still at scale** —
  stated conditioned on the distribution, the way the wake number states hot-vs-cold. *(The
  build was never O(N²): the insert has always navigated the graph — greedy descent
  plus a bounded beam, not a brute-force scan. What v0.3 removed was a large per-insert **constant**,
  paid through the per-operation tree/bincode path plus M scattered write-amplifying leaf writes; it
  **cut the constant and took construction off the per-op store**, and did not replace a scan that was
  never there.)* **v0.4 made the index LIVE (slice 2c, resolved on the number).** The placement — inline
  on every write vs. background compaction — was decided by measurement (`benches/ann_amplification.rs`):
  an inline insert added growing amplification (~1.7–2.2× and climbing) and, disqualifyingly, ~220 ms of
  per-write latency that grows with the graph, on the AT-045-certified write path. So **compaction**: an
  indexed write appends its vector to an in-branch buffer (reserved, ~1× baseline, same commit);
  `search_ann` **unions** the graph with a bounded buffer brute-scan, so a freshly-written vector is
  searchable **immediately — 0 staleness**; and a background fold moves the buffer into the graph off the
  write path, published by a **compare-and-set** on the head so it never stalls or clobbers a live write.
  The buffer→graph handoff is one atomic commit — a crash leaves every vector in the buffer *or* the graph,
  never neither (AT-045 over the fold) — and the fold racing appends and searches loses nothing and
  double-indexes nothing (a wake-class concurrency gate). Fresh vectors are now live, not an explicit-build
  snapshot.
- ~~**The refs file is rewritten in full on every commit** — O(branches).~~ **RETIRED (Phase 2):** refs
  are now **log-structured** — a commit *appends* one `RefEdit` frame (`refs.log`), folded into a
  `refs.snapshot` by periodic compaction. Per-commit cost went from **41 ms and a 12.4 MB rewrite at 100k
  branches to ~1.4 ms flat** (O(branches) → O(1), measured `benches/refs_scaling.rs`); recovery reads the
  snapshot once (~40 ms at 100k). The full ref write path was re-certified at `AT045_STRIDE=1` — every
  byte, including a crash mid-compaction (`docs/refs-design.md`, `tests/crash.rs`).
- **Phase 3 operations are partially closed, not complete.** File-backed stores now have an online
  backup boundary: it holds branch mutation and ANN-maintenance publication, flushes refs, copies one
  committed prefix, excludes the live process lock, and writes an allow-list manifest with a BLAKE3
  digest and length for every file. Verification refuses missing, extra, changed, non-regular, or
  symlinked files; restore verifies first, requires the expected tenant in `loomctl`, never overwrites,
  and publishes through one directory rename. A write-storm test restores a value from a valid committed
  prefix. `loomctl inspect`, `verify`, `backup`, `verify-backup`, and `restore` are available and
  read-only against existing stores. The production door adds native Ed25519-authenticated
  `backup-signed`, `verify-backup-signed`, and `restore-signed` commands; key identity is bound into
  the signature and private keys are loaded only from mode-0600 files. **Still open:** OpenTelemetry
  metrics/tracing, provenance-chain and `taint` diagnostic views in `loomctl`, scheduled backup
  retention, deployment-managed KMS/HSM key delivery and rotation drills, and a restore drill on each
  target filesystem/object-store topology. See
  [`docs/backup-restore.md`](backup-restore.md).
- **Wake-over-object-storage wide-area p99 > 250 ms — REFRAMED as topology-bound, not an engine gap.**
  *(This is the disposition of the v0.1 "wake p99 exceeds the 250 ms bar over a wide-area link" known-limit
  — restated here, not silently dropped, so an evaluator who read the v0.1 list finds where it went. The
  argument that moves it from "engine gap" to "topology" is the measurement directly below, and it is
  recorded in the plan of record, [`docs/v0.3-plan.md`](v0.3-plan.md).)* Wake latency is now a
  function of link RTT, not of the algorithm — measured, stated in round-trips. AT-047's *correctness* —
  sleep, wipe the disk, wake elsewhere, identical results, branch
  names back — is proven, and this is **loom's own session sleep/wake path**, not FlockDB's DuckDB wake.
  Its **latency** is measured against a real S3 endpoint (`crates/loom-branch/tests/wake_latency.rs`),
  reported in **RTT-multiples** because absolute ms swing run-to-run (1 warm GET ≈ 160–230 ms depending on
  route):
  - **Same-runner** (low-latency endpoint): p99 ~13 ms — inside 250 ms over the protocol (not a wide-area
    number).
  - **Wide-area, cold first-ever wake** (intercontinental bucket, Sydney — `wake-latency-widearea.yml`):
    **~4 RTT** (p50 ~920 ms). The overlay-manifest chain is **pointer-chasing** (head → overlay-base → …,
    each id inside the previous), so it is *inherently serial* and cannot be batched when the ids aren't
    known yet. This is the unavoidable cold cost.
  - **Wide-area, hot re-wake with the learned warm set** (substrate ≥ v1.4.2, `at_047_hot_vs_cold`): the
    warm set records the manifest ids *and* page ids a session faults, `sleep()` carries them in the token,
    and the next wake **hydrates them in one concurrent batch and awaits it** before the first read. The
    algorithm is **optimal, and the test proves it**: after hydration the read faults **zero** objects, so
    the entire cost is the hydrate's own concurrent fetch — a *pure function of the connection pool*:
    - **Cold pool** (a wake after the server has been idle): **~2.3 RTT** (p50 ~634 ms). S3's REST API is
      HTTP/1.1, so the batch's *N* concurrent GETs open *N* connections and each pays a fresh TLS
      handshake — one extra round-trip on top of the GET.
    - **Warm pool** (a busy server, or a maintained keep-alive pool — `prewarm` in the harness):
      **~1.03 RTT** (p50 **232 ms** / p99 278 ms). Reusing idle keep-alive connections removes the
      handshake, and the warm read on top is **essentially free** — the hot re-wake *is* the one-round-trip
      hydrate. Measured to Sydney, RTT ≈ 226 ms.
  - **The warm pool closes the cold-start gap (v1.5.0).** "Warm pool" is no longer a condition to hope
    for: `substrate::WarmPool` (`RemoteTier::spawn_warm_pool`) holds `min_idle` keep-alive connections
    open, so a wake after an idle gap finds them warm. Measured wide-area (Sydney): a cold-start hot
    re-wake with **no pool is 2.88 RTT** (p50 499 ms — the handshake tax), and **with the pool ~1 RTT at
    the median** (p50 179 ms) — but the **p99 stays ~2 RTT** (345 ms), a second round-trip the tail can
    still pay at this extreme distance. So, scoped with the same median-vs-tail honesty as the hot/cold
    number above: the warm pool **removes the cold-start handshake tax and delivers ~1 RTT at the median
    even to the most extreme link**; the **p99 tail can still pay a second RTT**, and **bursts beyond
    `min_idle` pay handshakes** (default sized to the hydrate width; no real burst profile yet to size it
    larger). This hands off cleanly to topology below: in a realistic **in-region** deployment
    (single-digit-ms RTT), even 2 RTT is comfortably under 250 ms at p99 — the tail only bites cross-planet.
  - **What that means for the 250 ms bar — it is TOPOLOGY, not code.** With a warm pool the wake is
    **≈ 1 RTT to your object store**, and no code beats the speed of light: whether 1 RTT clears 250 ms is
    a function of *distance*. So the honest SLA is exactly that — **"wake ≈ 1 RTT to your object store"** —
    and the deployment recommendation follows: **co-locate the object tier in-region** with the LoomDB
    server, where RTT is single-digit-to-low-tens-of-ms and **even the ~2 RTT p99 tail clears 250 ms with
    wide margin**. The Sydney numbers here are a *deliberately extreme* worst case — server and object
    store on opposite sides of the planet — chosen to show the floor, not a topology anyone should run: at
    that distance the **median** clears 250 ms and the **p99 (~345 ms) does not**, which is geography, not
    an engine gap — and it is precisely the tail the in-region recommendation removes. For a
    genuinely global fleet, a **regional object-cache tier** (a future feature, not built speculatively)
    would keep wake ~1 RTT everywhere. The cold *first-ever* wake stays ~4 RTT regardless (the serial
    chain walk, until the ids are known). An **airgap** deployment does not wake from object storage at all
    (local storage), so none of this applies to it.
- **One `Loom` per store directory.** The normal file-backed open path holds an OS advisory lock for the
  lifetime of the store, so a second process is refused before it can race the ref log. Custom VFS
  implementations must enforce equivalent ownership at their own boundary.
- **Signature verification is opt-in, and key issuance is external.** With an actor registry, every
  write is signed and verified (AT-026); without one, writes are attributable but not authenticated.
  Governance attestations authorize a registry and prevent rollback, but the PKI/HSM workflow that
  proves who may receive an actor key remains external. (Signed **offline update bundles** —
  `loom-bundle` — solve authenticity and exact kind/id/version authorization for updates *into* an
  enclave, offline. Software releases additionally carry reproducible-build, SPDX, checksum, and
  GitHub provenance evidence; non-exportable HSM integration remains deployment-owned. See
  [`docs/operations.md`](operations.md).)
- **Multi-tenancy is a signed-token router, one substrate pool per tenant.** Cross-tenant isolation is
  structural — the token carries its tenant *inside its signature*, the router routes by it, and a
  tampered or unregistered tenant gets a byte-identical `Unauthorized` (no existence oracle), held under
  concurrent churn by Soak B. The bound worth naming: isolation rests on that one-pool-per-tenant model,
  not on row-level filtering that could be got wrong.

The security posture, and what LoomDB does **not** defend against, is in [the threat
model](threat-model.md).

