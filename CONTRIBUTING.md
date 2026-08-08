# Contributing to LoomDB

Thanks for looking. This is a small project with an unusual amount of machinery around evidence, and
the fastest way to have a good time here is to know why that machinery exists before you trip over
it. This page is short on ceremony and long on the two things that actually matter: **the commands
that work**, and **how claims get made in this repo**.

Every command below was executed on a real checkout while writing this file. The timings are from an
Apple M2 (8 cores, 8 GiB, macOS 15.7.4), rustc 1.97.0, with a warm build cache — treat them as
*relative* costs, not promises about your machine.

---

## Setup

You need Rust and nothing else. No database to install, no service to run, no API key, no network at
runtime.

```sh
git clone https://github.com/Bobcatsfan33/loomdb
cd loomdb
cargo run -p loom-mcp --example taint_recall
```

**Measured: 38 seconds** from `git clone` to output on a clean checkout (empty `target/`, warm cargo
registry cache). Almost all of it is the first build.

If that printed `✔ Both moments held.` you have a working development environment.

### MSRV

**Rust 1.89.0.** CI has a job that installs exactly 1.89.0 and runs `cargo check --locked --workspace
--all-targets`, so a feature newer than that will be caught even if it compiles fine for you. If you
need something newer, that is a conversation, not a patch.

---

## The commands

These are exactly what CI runs. If they pass locally they will almost certainly pass there.

| What | Command | Measured |
|---|---|---|
| Format | `cargo fmt --all --check` | <1 s |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 4 s warm |
| Tests | `cargo test --workspace --lib --bins --tests` | **218 s**, 353 passing |
| Doctests | `cargo test --workspace --doc` | 3 s |
| The example | `cargo run -p loom-mcp --example taint_recall` | 0.02 s once built |
| The acceptance demo | `cargo test -p loom-mcp --test demo -- --nocapture` | seconds |
| Readiness manifest | `python3 scripts/verify_enterprise_readiness.py` | <1 s |
| Host profile | `python3 scripts/verify_host_profile.py` | <1 s |
| Build flavours | `bash scripts/verify_build_flavours.sh` | 15 s |

The Python scripts are **not executable** — invoke them with `python3`, not `./`.

### ⚠️ Never run `cargo test --all-targets`

This one will cost you an hour if nobody tells you.

`--all-targets` implies `--benches`. Several benches in this workspace are declared `harness = false`,
which means the "bench" is a plain `main()` — so `cargo test --all-targets` doesn't *check* them, it
**runs** them. Full benchmark suites. It has hung this workspace for roughly **50 minutes** while
looking like a stuck test run.

Use the documented `cargo test --workspace --lib --bins --tests`.

**The nuance worth keeping straight:** `--all-targets` is *fine* with `cargo check` and `cargo
clippy` — those compile the benches without executing them, which is why CI uses it in both places.
It is only `cargo test --all-targets` that detonates.

### The test suite leaves the tree clean — keep it that way

`cargo test --workspace --lib --bins --tests` should leave `git status --porcelain` **empty**. If a
change of yours makes the suite write into the working tree, that is a bug in the change, not a
quirk to document.

The one place this went wrong is worth knowing, because it is an easy pattern to reintroduce: the
recovery drill used to write its receipt straight into `docs/drills/`, so every test run rewrote
committed evidence with fresh timestamps. It now writes to a scratch directory by default — and still
reads it back, so the write path stays exercised. To regenerate the retained evidence deliberately:

```sh
LOOM_DRILL_RETAIN=1 cargo test -p loom-drill --test recovery_drill
```

---

## How this repo is run

This is the part that will make your PR land smoothly or bounce, so it is worth two minutes.

LoomDB makes load-bearing claims — that a merge doesn't lose writes, that a poisoned source can be
traced to everything it touched, that an air-gapped build contains no network client. The project's
whole position is that those claims are *checked*, not asserted. So the review standard is less "is
this code good" and more **"what would make this false, and does something catch it?"**

### 1. Claims are measured, and measurements carry their conditions

No number goes into a doc, a comment, or a commit message unless someone ran it. And it goes in with
the conditions attached, because a latency number without a topology or a recall number without a
data distribution is decoration.

Compare: *"wake is fast"* versus *"wake ≈ 1 RTT to your object store; measured to Sydney, p50 179 ms
with a warm pool, p99 ~345 ms, which does not clear the 250 ms bar at that distance."* The second one
is useful and the first one is marketing. See [`docs/known-limits.md`](docs/known-limits.md) for the
house style.

If you don't have a measurement, say the thing you *do* know. "Not measured" is a perfectly good line
in a PR.

### 2. A new guard must be *proven to fire*

If you add a check, you must show it catches the thing it is for — by breaking that thing on purpose
and watching the check fail. A guard that has only ever been observed passing is not evidence; it is a
green light of unknown wiring.

This is not hypothetical hygiene. Guards in this repo have been fail-open on arrival:

- A `printf "%s" "$graph" | grep -q PATTERN` check under `pipefail` reported **clean** for a graph
  that *did* contain the forbidden pattern — grep exits at the first match, `printf` takes `EPIPE`,
  and the pipeline reports failure. Reproduced only at ~1 MB; a 3-line test input did not show it.
- A CI step spelled `cargo run … | tee out.log` would have masked a failing program's exit code,
  because the default `bash -e` reports a pipeline's *last* status. `set -o pipefail` is load-bearing
  in `.github/workflows/ci.yml` for exactly this reason.

The `taint_recall` example is the pattern to copy: it checks its own guarantees, and the PR that added
it demonstrated that flipping the influence rule from `Deny` to `Allow` makes it exit 1.

### 3. The model oracles are not negotiable

Four subsystems — branch/merge, taint, retrieval isolation, policy — each have a **naive reference
implementation**: maps of maps, no B-tree, no pages, obviously correct and far too slow to ship. CI
runs randomized operation sequences against both and compares.

They have earned their keep. Between them they found a re-merge that silently **double-counted a
counter**, provenance overwritten by the data commit, a taint that stopped at merge boundaries — and
in one case a *test* that was wrong while the engine was right.

If you change merge, provenance, retrieval, or policy semantics, **the oracle changes too**, and it
changes to match the specification rather than to match your implementation. An oracle edited until it
agrees with the code under test has stopped being an oracle.

### 4. Limits get stated, not quietly dropped

When something is slow, bounded, or unfinished, it goes in [`docs/known-limits.md`](docs/known-limits.md)
with the measurement. When a limit is later resolved, it is **struck through and annotated**, not
deleted — an evaluator who read the old list needs to find out where it went. Look at the refs entry
for the house pattern.

### 5. The readiness manifest's decision fields are off limits

[`docs/enterprise-readiness.json`](docs/enterprise-readiness.json) records that LoomDB is **not
approved for production deployment**, with five open external gates. `deploymentDecision` and
`softwareReleaseCandidate` are **not** to be changed by a code PR. Those flip when a human ceremony,
audit, or pen test actually happens — never as a side effect of shipping a feature.
`scripts/verify_enterprise_readiness.py` will fail your build if a control claims evidence it lacks.

### 6. One concern per PR

Branch from `main`, never stack. A README fix and a merge-engine change do not travel together, and a
PR that regenerates drill evidence while also adding a feature is two reviews wearing one coat.

---

## Submitting

1. Branch from `main`.
2. Make the change. Add the test, the oracle update, or the measurement that makes it checkable.
3. Run fmt, clippy, and the test suite from the table above.
4. **Sign off your commits** — this project uses the
   [Developer Certificate of Origin](https://developercertificate.org/). `git commit -s` adds the
   trailer; a PR without it will fail the check.
5. Open the PR. Say what you measured and what you did not.

A good PR description here reads like a lab note: what changed, what you checked, what you *couldn't*
check, and what would have to be true for it to be wrong.

### Where to start

Issues labelled
[**good first issue**](https://github.com/Bobcatsfan33/loomdb/labels/good%20first%20issue) are real
gaps with a code pointer and acceptance criteria, and each one names the obvious-but-wrong fix so you
can avoid it.

If you want to understand the system first, read in this order: the
[README](README.md) → [`crates/loom-mcp/examples/taint_recall.rs`](crates/loom-mcp/examples/taint_recall.rs)
→ [`docs/invariants.md`](docs/invariants.md) → [`docs/at-map.md`](docs/at-map.md).

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
