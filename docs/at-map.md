# AT-ID map — what is actually green

> The catalog is [`substrate/docs/05`](https://github.com/Bobcatsfan33/substrate/blob/main/docs/05-loomdb-test-spec.md).
> This file says, honestly, which of those IDs have a test that **failed before the change and passes
> after it**, which only have *types*, and which are deferred and why.
>
> A capability is not done when it works. It is done when the test that would have caught it failing
> is green. Anything else on this page is not a claim, it is a plan.

Status as of **L1 + persistence complete**.

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

**AT-019 — token scope is inescapable.** Green **for the surfaces that exist today**: `read`, `write`,
`scan`, `rewind`, `branch`, and `merge` (both sides — a merge reads the source and writes the target,
and forgetting the source would let a session merge in a branch it was never allowed to see). It must
be **re-asserted when the MCP server and the CLI land in L4**, because the catalog's wording is "through
every surface", and two of those surfaces do not exist yet. Tracked, not closed.

**AT-001 — the shape, not the signature.** The envelope's *presence and structural completeness* are
enforced (actor, session, branch, and intent are all required — a write whose author or purpose is
unknown is a write nobody can audit). The `signature` field exists and is **empty**. Verifying it is
**AT-026**, and it is deferred to L2 along with the rest of the provenance engine.

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
| **AT-002** — read-set is engine-captured | **L2** (the next task after persistence) | This is the invariant that a caller **cannot launder a derivation by omission**. It needs read-set tracking on the session transaction, which is the heart of the provenance engine. The `derived_from` field exists and is caller-supplied today — which is exactly the weak version AT-002 exists to eliminate. |
| **AT-004** — late arrival | **L2/L3** | `Interval` is bitemporal and unit-tested, but there is **no as-of query API**. Nothing can be asked "what did you believe last week", so nothing can be tested. |
| **AT-005** — correction preserves history | **L2** | Needs the correction path: closing a `known` interval and opening a new one. Not built. |
| **AT-007** — unsupported claim cannot act | **storage half green; action half L3.5** | `Claim::is_action_eligible()` and `ineligibility_reason()` exist and are unit-tested, and the message tells a model what to *do*. But **there is no action path to refuse**, so the half that matters is untested. |
| **AT-009** — as-of is reproducible | **L2/L3** | Same reason as AT-004: no as-of API. |
| **AT-016** — merge re-evaluates policy | **L3.5** | There is no policy engine. The merge already *replays as new writes on the target* rather than transplanting pages, which is the structural precondition — the hook exists, the policy does not. |
| **AT-026** — envelope signatures verify | **L2** | Signature field present, empty, unverified. |
| **AT-020 – AT-025** — taint, staleness, recall | **L2** | The whole provenance layer. AT-022 (taint names what it *cannot* undo) additionally needs the action layer to be non-trivial — the `RecallPlan`'s `irreversible` section is designed now and stays empty until L3.5. |
| **AT-027 – AT-039** | **L3.5** | Action gateway and influence policy. |
| **AT-040 – AT-044** | **L3** | Memory and retrieval. |
| **AT-045** — crash at any byte | **later** | Inherited from substrate (50,000 crash cycles there), but **not yet re-driven with LoomDB-shaped workloads**. The ref write is a second durable object with its own ordering, and it deserves its own crash injection. Named so it is tracked. |

---

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

## Held: AT-011 (branch creation is cheap)

There is a test, and it passes. **The number it produces is not worth publishing yet, and it is not
being published.**

The property is *"cost is independent of baseline size"*, and a single measurement against a single
3,000-record in-memory database cannot demonstrate independence of anything. Worse, the figure would
**regress the moment durable writes exist**, because branching will then involve persisting a ref —
and we do not ship numbers we cannot reproduce.

So the current test is a **guard against catastrophic regression** (it asserts branching stays under
100 ms and that nothing has started copying the database), and it is labelled as such.

**Still held, and now for a sharper reason.** Persistence has landed, and branching now writes a ref —
so the figure would have changed anyway, exactly as predicted. The real measurement — **p95 and p99
across 1K / 1M / 10M-record baselines**, because "independent of baseline size" is a claim one number
cannot support — is a benchmark, not a test, and it goes in only when it can be reproduced.

There is also a **known cost to be honest about**: the refs file is rewritten in full on every commit.
That is O(branches), not O(1), and on a tenant with a million sleeping sessions it will matter. It does
not affect correctness, it has not been optimised, and it is written down here rather than discovered
in a benchmark later.
