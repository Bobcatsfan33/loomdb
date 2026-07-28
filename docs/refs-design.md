# Refs past O(branches) — design of record (Phase 2)

## The number that chose the design (guardrail 5)

Current refs (`FileRefStore::save`) bincode-serialize the **entire** `Refs` — every branch, every tag, and
the whole commit DAG — and atomic-write it (fsync'd) on **every** commit. Measured (on-disk, fsync'd,
median, `benches/refs_scaling.rs`):

| branches | encoded | save/commit | recovery load |
|---|---|---|---|
| 10 | 1.2 KB | 4.52 ms | 0.015 ms |
| 1 000 | 124 KB | 4.38 ms | 0.337 ms |
| 100 000 | 12.4 MB | **40.99 ms** | **44.84 ms** |

Below ~1k branches the two `atomic_write` fsyncs (~4.4 ms) dominate and the rewrite is free; at 100k the
12.4 MB serialize+write+fsync takes over. **The full-file rewrite is what grows** — O(branches + commits)
per commit.

## The decision: log-structured append + periodic compaction — not per-ref objects

Both a log and per-ref objects make a commit O(1). The log wins on two counts:

1. **The number** points at the *rewrite*, not the file count. An append replaces the 12.4 MB rewrite with
   one small framed record + one fsync — flat (~the 4 ms fsync floor) regardless of branch count.
2. **The structure rules per-ref out.** The `commits` DAG grows with **total commits, forever** (one edge
   per commit — and it is not optional: it is the merge second-parent the double-counting oracle guards).
   Per-ref-**per-branch** objects do not address the DAG at all, and 100k+ tiny files/objects is its own
   operational hazard (inode pressure, directory scans, object-count/list latency). A log appends
   branch-head moves *and* DAG edges uniformly, and compaction bounds both.

## Shape

Two files under `loom/`:

- **`refs.snapshot`** — a full `Refs` bincode snapshot, written atomically (temp → fsync → rename →
  fsync-dir). The compaction baseline.
- **`refs.log`** — an append-only log of `RefEdit` deltas since the last snapshot. Each record is a
  **frame**: `[u32 len][payload][8-byte BLAKE3 prefix of payload]`. The checksum is how a torn trailing
  frame (a crash mid-append) is detected and discarded on read.

`RefEdit` (each idempotent / last-write-wins — this is what makes replay safe, see below):
`SetHead{branch,to}`, `CreateBranch{name,at}`, `RemoveBranch{name}`, `SetTag{tag,to}`, `RemoveTag{tag}`,
`RecordCommit{commit,parents}` (sets the parent list — overwrite), `AddParent{commit,parent}` (set-union).

- **`load`** = read the snapshot, then replay every valid log frame **in append order** on top of it,
  stopping at the first torn/short/checksum-failed frame (the tail).
- **`apply(edits)`** = append the frames, fsync once; if the log has grown past a threshold, compact.
- **`save(refs)`** = write a fresh snapshot atomically, then truncate the log. This is compaction, and it
  is also how the root init and a sleep-resume seed a store.
- **compaction** is self-contained: the store reconstructs the full `Refs` from *its own* snapshot+log
  (it is the source of truth — it does not need the session's in-memory copy), writes the new snapshot,
  truncates. Triggered by log size inside `apply`, so the session never sees it.

## I-8 preserved, and stated where (acceptance bar c)

I-8 for loom: **the manifest is durable before the ref that points at it.** Unchanged. `apply` is called
from exactly where `persist` was — *after* the substrate manifest commit is durable (`session.rs`
`set_head`/`create_branch`/`write_merge`). The append is fsync'd, so the ref becomes durable strictly
after the manifest. A crash *between* the manifest commit and the log append leaves the new manifest
unreferenced (orphan garbage GC sweeps) and the branch at its old head — **a lost last commit, the
recoverable failure**, exactly as today. The alternative (ref before manifest → a ref into the void) is
still never produced.

## Why no sequence numbers are needed (compaction-crash-safety)

Compaction writes the new snapshot atomically **before** truncating the log. A crash in between leaves the
new snapshot + the *old, un-truncated* log. On the next `load` the old log is replayed on top of the new
snapshot — and every edit is idempotent/last-write-wins (`SetHead` sets, `RecordCommit` overwrites,
`CreateBranch` inserts the same value, `RemoveBranch`/`RemoveTag` are no-ops if absent, `AddParent` is a
set-union), so replaying already-incorporated edits changes nothing. Replay is **chronological** (append
order) and the snapshot is a **prefix** of that history, so no edit is ever applied out of order and a
branch can never be reverted to an older head. Correctness therefore needs only: (a) chronological replay,
(b) idempotent edits, (c) truncate strictly after the snapshot is durable. No per-record sequence numbers,
no generation counter.

## The after number (acceptance bar a/e, `benches/refs_scaling.rs`, same axes)

| branches | per-commit **apply** | (before: full save) | compaction save | recovery load |
|---|---|---|---|---|
| 10 | 1.20 ms | 4.5 ms | 8.97 ms | 0.07 ms |
| 1 000 | 1.61 ms | 4.4 ms | 9.94 ms | 0.89 ms |
| 100 000 | **1.36 ms** | **41.0 ms** | 40.80 ms | **39.65 ms** |

Per-commit is now **flat ~1.4 ms** across 10 → 100k branches — O(branches) → O(1), ~30× at 100k, and even
below the old small-N cost (one append fsync vs `atomic_write`'s two). Compaction (`save`) is still
O(branches) but **amortized** — it runs only when the log outgrows the snapshot, not per commit. Recovery
`load` at 100k is **~40 ms**: one snapshot read plus a tiny log replay — inherently O(branches), paid once
at startup, and the honest cost of holding 100k branches.

## Acceptance bar — status

- (a) before number — **done** (table at top).
- (b) decision recorded with the number — **done** (this doc).
- (c) I-8 preserved by construction, stated where — **done** (the I-8 section; `apply` sits where
  `persist` did, after the manifest is durable).
- (d) `AT045_STRIDE=1` re-driven over the new ref store **including a crash mid-compaction** — **done,
  green (82.8 s)**; certification logged in `tests/crash.rs` (the three sweeps, incl.
  `at_045_crash_during_ref_compaction_recovers_to_a_prefix`).
- (e) recovery time at 100k branches — **done, ~40 ms** (table above).
- (f) README Known-limits refs row retired in the same commit that earns it — **done**.

## Post-verification hardening (review findings F1–F3)

- **F1 (fixed — was a real durable-loss bug).** `apply`'s compaction released the store lock around
  `reconstruct` (the log read) and re-took it for the truncate. A second thread's *acknowledged* append
  landing in that window was destroyed by the truncate without being folded into the snapshot — durable
  loss with **no crash involved**, invisible to the single-threaded crash sweep. Fixed by holding the lock
  across the whole reconstruct→snapshot→truncate. Guarded by
  `a_concurrent_append_is_never_destroyed_by_a_compaction` (8 threads, unique branch per append, low floor
  → constant compaction); it destroyed **785 of 1600** acked appends on the pre-fix code and passes on the
  fix. Ref-store change ⇒ `AT045_STRIDE=1` re-driven, green.
- **F2 (documented).** The truncate crash-safety argument — idempotent chronological replay makes the
  truncate an *optimization* not a correctness step, the POSIX size-flush assumption, and the note that
  `CrashVfs` models "torn at a byte" not "metadata reordered across files" — is written on
  `write_snapshot_and_reset_log` in `refs.rs`.
- **F3 (documented).** The **single-process** assumption (one `Loom` per store directory; the store
  serializes *within* a process but has no cross-process lock file) is stated on the `RefStore` trait and
  on the README Known-limits list.
