# AT-ID map — what is actually green

> The catalog is [`substrate/docs/05`](https://github.com/Bobcatsfan33/substrate/blob/main/docs/05-loomdb-test-spec.md).
> This file says, honestly, which of those IDs have a test that **failed before the change and passes
> after it**, which only have *types*, and which are deferred and why.
>
> A capability is not done when it works. It is done when the test that would have caught it failing
> is green. Anything else on this page is not a claim, it is a plan.

Status as of **loomdb-v0.2 (in progress)** — L1 → L4 complete, v0.2 underway.

**The full scoreboard: AT-001 through AT-047 are ALL green or structurally satisfied.** AT-045
(crash-at-any-byte, LoomDB-shaped) was the one item deferred at the v0.1 tag; it is **closed in v0.2**
(below), so the board no longer has an exception. Four model oracles hold under fuzzing (branch/merge,
taint, isolation, policy). The Q3 demo (docs/04 §3.1) runs verbatim in CI, no LLM, and steps 8 and 10
are asserted as the bar.

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
| **AT-040** | **Branch-aware indexes — isolation is structural.** A sibling branch's write is never retrieved, because index entries live in the branch's own tree and a sibling has a different head manifest. Verified by a model oracle at 3,000 randomized runs: what a branch retrieves equals what the model says is visible there, **and never a sibling's fact**. | `at_040_a_siblings_write_is_never_retrieved`, `retrieval_sees_exactly_the_branch_and_never_a_sibling` (oracle) |
| **AT-041** | **Every packed item is cited.** An uncited entry cannot be *constructed* (the only constructor refuses it), so no retrieval can pack one. The citation is the record's own `SourceRef` — the same one the provenance DAG holds — derived at write time, not a caller's assertion. | `IndexEntry::new` unit tests + asserted in every retrieval test |
| **AT-042** | **Adversarial budgets.** A well-formed `PackedContext` under any budget × any candidate count — 50 tokens vs 100,000 candidates, unbounded vs 3, zero vs 1 — with no panic, no item truncated mid-evidence, no uncited item. A 2,000-case property test proves the invariant, not two examples. | `at_042_a_tiny_budget_against_a_huge_candidate_set`, `..._a_huge_budget_against_a_tiny_candidate_set`, `..._a_zero_budget_is_empty_not_a_crash`, `pack_is_always_well_formed` |
| **AT-043** | **Stale claims are down-ranked and marked.** A stale claim that matches *better* than a fresh one still loses to it (penalty applied to the whole score), and arrives in the context flagged `stale` so the model knows not to lean on it — penalised, never silently dropped or silently trusted. | `at_043_a_stale_claim_is_penalised_and_flagged` |
| **AT-044** | **Forgetting propagates.** Forget a source and every governed representation derived from it (index entries carrying the embedding/text/summary) is removed and every dependent claim is `Invalidated` — in one commit, via the same taint walk L2 uses. The record stays readable; only the derived representation goes. The completion report accounts for all of it and **leads with what it cannot undo** (empty until L3.5, honestly). | `at_044_forgetting_a_source_removes_everything_derived_from_it`, `at_044_the_report_is_shaped_to_lead_with_the_irreversible` |
| **AT-022** | **Taint names the action it cannot undo — first.** `taint_with_actions` fills the `RecallPlan`'s IRREVERSIBLE section: the account already suspended, its receipt, and either a registered compensating action or an explicit human escalation. Listed ahead of the reversible writes, and the report leads with it. When there is no compensation, the plan says so rather than inventing one. **This is demo step 10.** | `at_022_taint_lists_the_suspended_account_first_with_its_receipt`, `at_022_no_compensation_is_stated_not_faked` |
| **AT-027** | **Agents cannot act — structurally.** `AgentStore` has `propose` and no `execute`. A `compile_fail` doctest (run in CI) proves `agent.execute(..)` does not compile; if someone adds the method, the build goes red. Proposing calls no connector. | `at_027_proposing_does_nothing_by_itself` + the `compile_fail` doctest on `AgentStore` |
| **AT-028** | **Idempotency.** 100 concurrent retries of one idempotency key → the connector is invoked **once**; every caller gets the same `ActionId`. | `at_028_idempotent_under_concurrent_retries` |
| **AT-029** | **`Indeterminate` is honest.** A connector timeout is `Indeterminate` — not a guessed success or failure — and blocks nothing else. | `at_029_a_timeout_is_indeterminate` |
| **AT-030** | **Stale evidence cannot authorize.** A proposal citing a `Stale` claim is refused, and nothing executes. | `at_030_stale_evidence_cannot_authorize` |
| **AT-031** | **Simulation containment.** A proposal from a simulation branch may not reach a production connector; the branch context travels with the proposal to the gateway. | `at_031_simulation_cannot_touch_production` |
| **AT-032** | **No terminal success without a receipt.** A connector that reports success but returns no receipt does **not** reach `Succeeded` — it is `Indeterminate`. `is_success()` is true only for `Succeeded{receipt}`. | `at_032_success_carries_a_receipt`, `at_032_success_without_a_receipt_is_not_terminal_success` |
| **AT-033** | **The kill switch** disables new actions (global + per-tenant) while reads, writes, and audit stay fully available — the refused action is itself recorded and auditable. | `at_033_kill_switch_disables_actions` |
| **AT-034** | **The injection is refused.** `Untrusted`-labeled evidence may not authorize `identity.suspend_account`, even at 0.99 confidence; a `VerifiedSystem`-backed equivalent is allowed, proving it is the *label* being refused. **Demo step 8.** | `at_034_untrusted_evidence_cannot_authorize_a_suspension` |
| **AT-035** | **Labels propagate through derivations.** A claim derived from an `Untrusted` scrape is itself `Untrusted` — the effective label is the most-restrictive of everything read, carried through the read-set, cheap and transitive. | `at_034_...` (asserts the derived claim's label) |
| **AT-036** | **Influence is filtered *before* packing.** `retrieve_filtered` drops a restricted candidate before scoring, so it never reaches the packer or the window. Scrubbing the model's output afterward is the architecture this forbids, and this is not it. | `at_036_restricted_data_is_filtered_before_packing` |
| **AT-037** | **Policy fails closed.** No applicable rule → deny. Verified as an invariant by the policy oracle (engine allows ⇒ some allow truly applied), 10,000 cases. | `no_applicable_rule_always_denies`, `engine_agrees_with_the_truth_table` (policy oracle) |
| **AT-038** | **Decisions are versioned and recorded.** Every `PolicyDecision` carries the policy version, the request evaluated, and a one-line rationale — "what allowed/forbade this" has an exact answer. | `a_decision_records_the_version_and_request` + carried on every gateway `ActionRecord` |

**AT-019 — token scope is inescapable.** Green **for the surfaces that exist today**: `read`, `write`,
`scan`, `rewind`, `branch`, `merge` (both sides — a merge reads the source and writes the target, and
forgetting the source would let a session merge in a branch it was never allowed to see), and now
**retrieval and forget** (both authorise through the *same* issuer as `read`, rather than a second,
weaker check). It must be **re-asserted when the MCP server and the CLI land in L4**, because the
catalog's wording is "through every surface", and those two surfaces do not exist yet. Tracked, not
closed.

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

**AT-022 — FILLED in L3.5, and now green.** The `RecallPlan`'s `irreversible` section was shaped in L2
(first field, first rendered, `"CANNOT BE UNDONE"` before `"CAN be reverted"`, guarded by byte offset).
L3.5 pours real content into it: `Provenance::taint_with_actions(source, &executed)` matches every
executed action against the contaminated set and lists the ones downstream — the suspended account, its
receipt, and either the connector's registered compensating action or an explicit escalation to a human.
When there is no compensation, it says so rather than inventing one. This is demo step 10, and it is
green (`at_022_taint_lists_the_suspended_account_first_with_its_receipt`).

The dependency direction stayed clean: taint (`loom-provenance`) and the gateway (`loom-action`) are
siblings and neither depends on the other. The fact taint needs — `loom_core::ExecutedAction` — is a
plain value both can name; the gateway produces it, taint consumes it.

Now green: AT-003 (an ingested observation infers no claim — the as-of query finds none), AT-006
(supersession keeps the old version, marked `Superseded`), AT-008 (`Confidence::combine` refuses across
methods/calibrations), AT-004/005/009 (the bitemporal as-of query), AT-016 (merge re-evaluates policy),
AT-022 (taint fills the irreversible section), AT-039 (cross-tenant is structurally impossible), and
AT-007 (the gateway refuses a no-evidence claim, naming the missing evidence).

---

## Held — measured, published, and honest about what one number cannot show

| ID | Status |
|---|---|
| **AT-011** — branch creation is cheap | **Measured. See below.** Flat p50 (~6 ms, one fsync of the refs file) across 1K → 1M records. The claim is that the column does not move, and it does not. 10M was not run (host disk); we did not print a number we did not take. |

---

## AT-045 — closed in v0.2. The one asterisk is gone.

**AT-045 — crash at any byte, LoomDB-shaped.** GREEN. `at_045_crash_at_any_byte_recovers_to_a_prefix`
puts **one `CrashVfs` under both the pager and the ref store** and sweeps the byte budget from zero past
a full loom workload (observe · claim · branch · claims · merge), crashing the write path at **every byte
boundary**. At each crash point the rebooted database must **reopen** (no ref pointing at a non-durable
manifest — invariant I-8) and every **acknowledged** write (one whose call returned `Ok`, i.e. after its
ref fsync'd) must still be present and decode cleanly — nothing acknowledged is lost, nothing torn. The
default run samples ~200 crash points in ~2 s; `AT045_STRIDE=1` runs the exhaustive every-byte sweep
(~5 min), and CI runs it in its own job.

This is what makes the v0.1 board's credibility complete rather than asterisked: the ref-write ordering
was enforced and unit-tested before, and it is now proven under crash injection at LoomDB granularity,
not merely inherited from substrate's engine-level suite.

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
