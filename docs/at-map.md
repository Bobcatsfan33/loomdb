# AT-ID map — what is actually green

> The catalog is [`substrate/docs/05`](https://github.com/Bobcatsfan33/substrate/blob/main/docs/05-loomdb-test-spec.md).
> This file says, honestly, which of those IDs have a test that **failed before the change and passes
> after it**, which only have *types*, and which are deferred and why.
>
> A capability is not done when it works. It is done when the test that would have caught it failing
> is green. Anything else on this page is not a claim, it is a plan.

Status as of **L1 + persistence + L2 (provenance, taint, staleness, signatures) complete**.

> The rules that must not be "optimized" away later are in [invariants.md](./invariants.md). Each one
> is there because breaking it produced a bug that **did not fail loudly**.

---

## Green — a test exists, and it fails if the behaviour is removed

| ID | What it asserts | Test |
|---|---|---|
| **AT-001** | A write with no valid envelope is refused at the entry point, and nothing is written. | `at_001_a_write_without_an_envelope_is_refused` |
| **AT-010** | A branch's writes are invisible in its base **and** to its siblings. | `at_010_branches_are_isolated_from_their_base_and_from_each_other` |
| **AT-012** | **Merge is record-granular.** Two unrelated facts in the same physical page merge cleanly. | `at_012_unrelated_facts_in_the_same_page_do_not_conflict` |
| **AT-013** | Convergent edits (two agents, same conclusion) merge silently. Not a conflict. | `at_013_convergent_edits_merge_silently` |
| **AT-014** | Counters merge arithmetically: `10 + 3 + 5 = 18`, not 13 or 15. | `at_014_counters_merge_arithmetically` |
| **AT-015** | Provenance rank breaks ties — a verified system record beats a confident language model. | `at_015_provenance_rank_breaks_a_tie` |
| **AT-017** | A genuine conflict produces a report an LLM can act on, and **nothing is written**. | `at_017_a_merge_conflict_is_legible_to_a_model` |
| **AT-018** | Rewind abandons without destroying — the discarded hypothesis stays readable. | `at_018_a_rewound_branch_is_still_auditable` |
| **AT-046** | A restart finds the branches, the data, **and the merge edges**. Re-merging after a restart is a no-op, not a double-count. | `at_046_a_restart_finds_the_branches_the_data_and_the_merge_edges`, `at_046_reopening_twice_is_idempotent` |
| **AT-047** | Sleep the tenant, **wipe the disk**, wake elsewhere. Identical results, and the branch names come back with the data. | `at_047_sleep_wipe_wake_and_the_branches_come_back` |
| **AT-002** | **The read-set is captured by the engine.** A caller cannot launder a derivation by omitting it from the envelope — what it *read* is what it is derived from, whatever it declares. | `at_002_a_caller_cannot_launder_a_derivation_by_omission` |
| **AT-020** | Taint reaches **both children of a fork** — a poisoned write inherited before the fork contaminates every branch that descends from it. And it **crosses a merge**: a conclusion merged into `main` is still downstream. | `at_020_taint_reaches_both_children_of_a_fork`, `at_020_taint_survives_a_merge_into_main` |
| **AT-021** | The plan is **exact** — completeness *and* precision. Verified against a naive flood-fill model over 10,000 randomized runs. | `at_021_taint_names_exactly_what_is_downstream_and_nothing_else`, `taint_names_exactly_the_contaminated_set` (oracle) |
| **AT-023** | Invalidated evidence makes a claim **`Stale`, not gone**. The scalpel, not the sledgehammer: it stays readable and auditable, and stops being action-eligible. | `at_023_invalidated_evidence_makes_a_claim_stale_not_gone` |
| **AT-024** | `taint()` **proposes and never acts.** It returns a dry run. Nothing is mutated. | `at_024_taint_proposes_and_never_acts` |
| **AT-025** | A pathological derivation graph is **refused, not chased** — the walk is bounded at depth 64. | `at_025_a_pathological_derivation_graph_is_refused_not_chased` |
| **AT-026** | **Envelope signatures verify.** An unsigned write is refused; an actor **cannot impersonate another actor** (the key is looked up by the actor the envelope *claims to be*); rewriting `intent` after signing invalidates the write; an **unregistered actor is refused, not trusted**. | `at_026_an_unsigned_write_is_refused_when_the_database_authenticates_writers`, `at_026_an_actor_cannot_impersonate_another_actor`, `at_026_tampering_with_the_intent_breaks_the_signature`, `at_026_an_unregistered_actor_is_refused_rather_than_trusted` |

**AT-019 — token scope is inescapable.** Green **for the surfaces that exist today**: `read`, `write`,
`scan`, `rewind`, `branch`, and `merge` (both sides — a merge reads the source and writes the target,
and forgetting the source would let a session merge in a branch it was never allowed to see). It must
be **re-asserted when the MCP server and the CLI land in L4**, because the catalog's wording is "through
every surface", and two of those surfaces do not exist yet. Tracked, not closed.

**AT-001 — the shape. AT-026 — the signature. Both now green, and they are different claims.**
AT-001 makes a write **attributable**: actor, session, branch and intent are all required, because a
write whose author or purpose is unknown is a write nobody can audit. That is *what the write claims*.
AT-026 makes it **authentic** — it checks the claim is true.

**AT-026 — LANDED in L2.** Ed25519. `Loom::with_actor_keys(..)` turns it on, and then **every write
must be signed** and verifies against the registered key of the actor the envelope claims to be.

Two honest notes on its limits:
- **It is opt-in.** A database with *no* actor registry does not check signatures at all — envelopes are
  attributable but not authenticated. That is the right default for a single-process embedded database
  where the only writer is the process itself, and the **wrong** default the moment two agents can reach
  the same database. It is documented at the field, not hidden.
- **Key distribution is not solved here.** LoomDB verifies against keys you hand it. Where those keys
  come from, how they rotate, and how a compromised one is revoked is **not built** (see L3.5).

**AT-022 — SHAPED, and deliberately empty.** The `RecallPlan`'s `irreversible` section is **built and
wired**: it is the first field of the struct and the first section of the report, always, and the report
already says out loud that *rewinding a branch reverts writes — it does not un-suspend an account*. A
test asserts the byte offset of `"CANNOT BE UNDONE"` precedes `"CAN be reverted"`, so it cannot be
quietly reordered.

**It stays empty until the action gateway lands in L3.5**, because there is nothing irreversible in the
system yet to put in it. The shape is honest. The content is not there. **Not claimed as green.**

---

## Types only — the shape is right, nothing enforces it end to end

These are the ones worth being blunt about. `loom-core` has the types and some unit tests. There is
**no acceptance test that drives them through `Loom`**, because in several cases the API they would
need does not exist yet.

| ID | What exists | What is missing |
|---|---|---|
| **AT-003** — observation ≠ claim | `Observation` and `Claim` are distinct types with distinct fields. | No ingestion path, so nothing can *accidentally* turn an observation into a claim, and nothing tests that it doesn't. The invariant is currently true by absence. |
| **AT-006** — supersession is not deletion | `ClaimStatus::Superseded` exists. | **No code path ever sets it.** There is no supersession machinery at all. |
| **AT-008** — confidences are not averaged | `Confidence::comparable_with` refuses to compare across methods or calibrations, with a unit test. | Nothing in the engine *aggregates* confidences, so there is no place the guard is enforced. It is a guard against code that has not been written. |

---

## Deferred — named, with the reason, so they are tracked rather than lost

| ID | Deferred to | Why |
|---|---|---|
| **AT-004** — late arrival | **L2/L3** | `Interval` is bitemporal and unit-tested, but there is **no as-of query API**. Nothing can be asked "what did you believe last week", so nothing can be tested. |
| **AT-005** — correction preserves history | **L2** | Needs the correction path: closing a `known` interval and opening a new one. Not built. |
| **AT-007** — unsupported claim cannot act | **storage half green; action half L3.5** | `Claim::is_action_eligible()` and `ineligibility_reason()` exist and are unit-tested, and the message tells a model what to *do*. But **there is no action path to refuse**, so the half that matters is untested. |
| **AT-009** — as-of is reproducible | **L2/L3** | Same reason as AT-004: no as-of API. |
| **AT-016** — merge re-evaluates policy | **L3.5** | There is no policy engine. The merge already *replays as new writes on the target* rather than transplanting pages, which is the structural precondition — the hook exists, the policy does not. |
| **AT-022** — taint names what it *cannot* undo | **L3.5** | The **shape is built and the report already leads with it** — every plan opens with the irreversible section and says out loud that rewinding a branch does not un-suspend an account. But the section stays **empty** until the action gateway exists to put anything in it. The scaffolding is honest; the content is not there yet. |
| **AT-027 – AT-039** | **L3.5** | Action gateway and influence policy. |
| **AT-040 – AT-044** | **L3** | Memory and retrieval. |
| **AT-045** — crash at any byte | **later** | Inherited from substrate (50,000 crash cycles there), but **not yet re-driven with LoomDB-shaped workloads**. The ref write is a second durable object with its own ordering, and it deserves its own crash injection. Named so it is tracked. |

---

## What L2 changed, and the two bugs it found

**AT-002 is the one that matters.** The read-set is captured **by the engine**, on the session, at
`Loom::read`. The envelope's `derived_from` can only ever make the set *bigger* — a caller that omits
what it read does not thereby un-derive it. This is the difference between provenance and a comment.

Two real bugs, both silent, both caught by tests rather than by reading the code:

**The commit-ordering bug.** Provenance was written in a commit *before* the data commit, so the data
commit's `set_head` overwrote it. Every derivation node, on every write, was discarded. `taint()`
cheerfully reported that nothing was contaminated. The fix is not "commit in the other order" — it is
to stop needing two commits: a node now records the commit its write was **based on**, so provenance
goes into the *same* transaction as the data, and a crash can no longer separate the two.

**The merge boundary.** The merge engine reads through the tree, not through `Loom::read`, so the
read-set never saw what a merge merged — and a merged record landed in `main` with **no parents at
all**, looking like a clean, freshly-authored fact. Every taint stopped dead at the first merge, which
is the path an agent takes on *every run*. A merged record is now derived from the node that produced
it on each side, **per key** (the first fix gave every record the union of every parent, which made the
taint over-report *and* blew past the page size on a 2,000-key merge — the oracle caught it as
`PageTooLarge`).

**The taint oracle disagreed with the engine, and the engine was right.** The model unioned a key's
parents across writes; but a key can be *overwritten*, and a conclusion built on a re-derived, clean
version of a claim is genuinely clean. The model was rebuilt per-write. Worth recording because the
temptation was to "fix" the engine to match a wrong model.

## What persistence changed

**The "known gap" is closed.** Branch refs, tags, and the commit DAG — including every merge's second
parent — are durable. *"Where is branch h2 after a restart"* has an answer, and `at_046` fails if it
stops having one.

The merge-edge half is the one worth naming: substrate's manifests have one parent, LoomDB records the
second itself, and losing it across a restart would have **silently restored the double-counting bug**
(merge twice, and a `+3` becomes a `+6`, and the merge reports success). `at_046` re-merges *after* the
restart and asserts the result does not move. That test fails if the DAG is dropped.

It also surfaced a real bug **in substrate**: `sleep()` uploaded only the head manifest, so a database
whose head was an *overlay* — the normal case since P4 — woke up unable to read any page the top
overlay did not hold. The old lifecycle test never caught it because it wrote every page in a single
commit, so everything *was* in the top overlay. Fixed in `substrate-v1.2.1`; manifests now tier to
object storage, and `sleep` uploads the head's whole ancestry over both edges.

## AT-011 — branch creation is cheap. **Measured, and it holds.**

Held until persistence landed, because branching now writes a durable ref, and any figure taken before
that would have been a figure for a different operation. It has landed, so here are the numbers.

**200 branch operations per baseline, on-disk (real ref write, real fsync).** Reproduce with:

```
cargo bench -p loom-branch --bench branching
LOOM_SEED_BATCH=1000000 LOOM_BENCH_SIZES=1000000 cargo bench -p loom-branch --bench branching
```

| baseline | p50 | p95 | p99 | db on disk |
|---:|---:|---:|---:|---:|
| 1 000 | 8.00 ms | 9.99 ms | 11.01 ms | <1 MB |
| 10 000 | 5.99 ms | 6.95 ms | 7.33 ms | 4 MB |
| 100 000 | 5.99 ms | 7.01 ms | 8.00 ms | 37 MB |
| 1 000 000 | 5.91 ms | 7.39 ms | 8.01 ms | 370 MB |

**The claim AT-011 makes is not "6 ms". It is "the column does not move."** A thousand-fold increase in
the size of the database does not change the cost of forking it, because forking does not read it — it
writes a ref and takes a manifest id. If p95 climbed with the baseline, something would be copying the
database, and the claim would be false. Across 1K → 1M, p95 moves from 9.99 ms to 7.39 ms; it does not
climb.

The absolute figure is ~6 ms, and it is **dominated by one fsync of the refs file** — not by anything to
do with the size of the data. It is not 6 µs, and we are not going to call it instant.

*(Figures from one developer machine. The thing that should reproduce on yours is the flatness of the
column, not the millisecond.)*

### 10 000 000 — **not measured, and not estimated**

The 10M baseline **did not run.** It failed with `StorageFull`: the host had 3.5 GiB free, and a 10M-record
LoomDB needs about **3.7 GB**.

That is not a guess — it falls straight out of the table above. The footprint is linear at **~370 bytes
per record** (37 MB at 100K, 370 MB at 1M), because pages are content-addressed and stored **at full page
size**, and LoomDB writes **four records for every one you write** (the data, its derivation node, a
latest-node pointer, a source-index entry).

So: an environment limit, not a LoomDB limit, and it will run on a machine with ~10 GB free. But **the
number is not in this table, because we did not take it.** We are not going to extrapolate a p99 from
three other rows and print it as a measurement.

---

## Write amplification — **found by benchmarking, fixed before L3**

### What was wrong

**Write cost grew with the size of the database.** The same 100,000 records cost:

| how it was written | before |
|---|---|
| one commit of 100,000 | 9.4 s |
| ten commits of 10,000 | **36.9 s** |

Same data, same records. The only variable was the **number of commits** — so a commit's cost was
scaling with the size of the *tree*, not the size of the *batch*. Each commit was rewriting a large
fraction of the database.

### The cause, stated correctly

A first version of this page said *three of four* records per write have random keys. That was wrong,
and the corrected count is **two of four**:

| record | key | locality |
|---|---|---|
| the data | the caller's key | caller's |
| the derivation node | **the node's content hash** | **random** |
| the source-index entry | source + **the node's content hash** | **random** |
| the latest-node pointer | the *data* key | fine already |

A `NodeId` is a content hash, so storing a node **at** its id put every provenance write at a uniformly
random point in the keyspace. Once the tree held more leaves than a commit held records, a commit's
random keys touched *nearly every leaf* — so nearly every leaf was dirtied, re-encoded, re-hashed and
written.

### The fix

**Nothing ever looks a node up by id from storage.** `taint()` scans the provenance range and builds the
`id → node` map in memory. So the content hash never needed to be the *storage key* — only the
*identity*, which it still is, inside the node.

Nodes now live at an **append-ordered** key: `(branch, sequence)`. The source index is append-ordered
too, within each source's range, with the node id moved into the **value** — putting it in the key is
what made it random in the first place. A commit's provenance now lands at the **tail** of its branch's
range instead of scattered across every leaf.

The branch is *in* the key, and that is load-bearing: without it two diverged branches would both write
sequence `N` — same key, different nodes — and merging them would produce a **conflict on the provenance
itself**, which is not a question any caller can answer.

### What it bought — measured

Seeding 100,000 records, varying only the number of commits:

| commits | before | after |
|---:|---:|---:|
| 1 × 100,000 | 9.4 s | 13.0 s |
| 10 × 10,000 | **36.9 s** | **11.4 s** |
| 100 × 1,000 | *(not taken)* | **17.2 s** |

**The claim is the flatness, not the seconds.** Before, ten commits cost **3.9×** what one commit cost —
the amplification. After, ten commits cost **0.88×** and a hundred commits cost **1.3×**. Cost no longer
tracks the number of commits, which is what "writes stop rewriting the database" means.

Two other real bugs were fixed on the way, both found by benchmarking rather than by reading:
- `Tree::is_full()` bincode-serialised the **entire leaf on every insert** — O(leaf) per record, making
  a leaf fill in O(leaf²). Now tracked incrementally, with one real encode at the fullness boundary.
- The insert path **deep-cloned every node it descended through** — a heap allocation for *every key in
  the leaf*, to insert one record. Now moved, not cloned.

**Both oracles were re-run after the layout change** — taint at 10,000 randomized cases, branch at
4,000 — because the storage keys moved underneath the provenance engine, and agreement with the model is
something to re-prove, not assume.

### Still true, still not fixed

**The refs file is rewritten in full on every commit.** That is O(branches), not O(1). It does not show
up against baseline *size* — which is what AT-011 claims — but it will show up on a tenant with a great
many branches. Not optimised, and not hidden.
