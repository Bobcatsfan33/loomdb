# Invariants

> Rules that look like implementation details and are not. Each one is here because **breaking it
> produced a bug that did not fail loudly** — the database kept working, kept returning success, and
> quietly told a lie.
>
> If you are about to "simplify" something on this page, the test named beside it will stop you. That
> is what the test is for. Do not delete the test to make the change pass.

---

## I-1. Provenance and data commit in **one transaction**, never two

**The rule.** A write and the derivation nodes describing it go into the **same** substrate
transaction, and therefore the same commit. There is no ordering between them to get right, because
there is no "between".

**Why it is not two commits.** A derivation node names the commit its write was **based on** — the head
it was derived against — and *not* the commit that contains it. That is what makes one transaction
possible. It is also the more useful of the two, because it is exactly the rewind boundary a
`RecallPlan` wants: *"move the branch back to before this write."*

**What breaking it did.** The first implementation wrote provenance in a commit *before* the data
commit. The data commit's `set_head` then overwrote it. **Every derivation node, on every write, was
silently discarded.** Nothing errored. `taint()` cheerfully reported that nothing was contaminated —
which is the single worst thing this system can say, because the customer believes it.

Writing provenance *after* instead is not a fix; it just moves which commit loses. Two commits also
means a crash can land between them, leaving a write with no provenance and no way to tell.

**Guarded by.** `crates/loom-branch/tests/oracle.rs` (the branch model oracle notices the extra commits
in the DAG within seconds) and every `at_02x` provenance acceptance test.

---

## I-2. A merge carries derivation parents forward, **per key**

**The rule.** A merged record is derived from the node that produced it **on each side**, and that edge
is recorded. The parents are attached **per key** — record `K` gets `K`'s parents, not the merge's.

**Why.** The merge engine reads through the tree, not through `Loom::read`, so the session's read-set
never sees what a merge merged. Without this, a merged record lands on the target with **no derivation
parents at all** — a clean-looking, freshly-authored fact with no history.

**What breaking it did.** Every taint stopped dead at the first merge boundary. That is not a corner
case: forking a hypothesis, working on it, and merging it back into `main` is what an agent does on
*every run*. `taint()` would report a `main` branch "contained" while it was full of conclusions derived
from a poisoned source.

**And the fix has a wrong version, which we shipped first.** Giving every merged record the *union* of
every parent in the merge is wrong twice: record `K` is not derived from record `J`'s ancestors (so the
taint over-reports, and a plan that over-reports is a plan nobody runs), and the node blob grows with
the size of the merge — a 2,000-key merge produced an 18 KB derivation node *per record* and blew past
the page size. **Precision and size were the same bug.**

**Guarded by.** `at_020_taint_survives_a_merge_into_main` (fails without the carry) and
`the_prefilter_never_drops_a_record` (which failed with `PageTooLarge` on the union version).

---

## I-3. The latest-node pointer is **reserved**, and never merged

**The rule.** `\x00loom/latest/<key>` lives in the reserved keyspace: hidden from `scan`, excluded from
merge candidates.

**Why.** Derivation nodes are immutable and content-addressed, so they merge cleanly. This pointer is
the opposite — **mutable per-branch bookkeeping**. Two branches that both wrote the same key hold two
different, equally valid pointers.

**What breaking it did.** Handing it to the merge engine as data produced a conflict on an opaque
32-byte blob, with a report asking the caller to choose between two hashes. That is a question nobody
can answer, and one the caller never asked. It broke AT-013 (convergent edits must merge silently) and
AT-015.

The merge **recomputes** the pointer instead, and carries the real provenance across via I-2.

---

## I-4. The engine captures the read-set. The caller may only **add** to it.

**The rule.** What a session *read* is what its writes are derived from. `WriteEnvelope::derived_from`
can make that set bigger. It cannot make it smaller.

**Why.** Otherwise a caller — or an attacker steering one — **launders a derivation by omission**:
reads the poisoned source, declines to mention it, and writes a conclusion that looks independent. This
is AT-002, and it is the difference between provenance and a comment.

**Guarded by.** `at_002_a_caller_cannot_launder_a_derivation_by_omission`.

---

## I-5. An ambiguous merge base is **refused**, not guessed

**The rule.** Criss-cross merges have more than one merge base. LoomDB refuses.

**Why.** Picking one silently produces a merge that is *defensibly* wrong — the arithmetic works, the
result is plausible, and it is not what either branch meant. A database that guesses under ambiguity is
worse than one that stops, because you cannot audit a guess.

**Guarded by.** the branch model oracle, which generates criss-cross histories and would otherwise
disagree with the engine.

---

## I-6. Commit ids come from a **monotonic** clock

**The rule.** `CommitClock` never returns the same instant twice.

**Why.** Manifests are content-addressed. Two commit events with identical content and identical
timestamps hash to the **same manifest id** — so they are the same commit, and one of them silently
vanishes. (Substrate has the mirror of this rule: the *root* manifest is stamped `created_at_ms: 0`, so
that reopening a database reproduces the same root id rather than diverging on reopen.)

---

## I-7. The `RecallPlan` leads with what it **cannot** undo

**The rule.** `irreversible` is the first field of the struct and the first section of the report,
always — even when it is empty.

**Why.** Rewinding a branch reverts writes. **It does not un-suspend an account, un-send an email, or
un-file a report.** A recall plan that opens with "here are 40 writes to revert" invites an operator to
believe the contamination is undone when the part that reached the world is not. Every plan says
**DRY RUN**.

**Guarded by.** `the_report_leads_with_what_it_cannot_undo`, which asserts the byte offset of
`"CANNOT BE UNDONE"` precedes `"CAN be reverted"`. It is a crude test on purpose: it fails if anyone
reorders the report for aesthetics.

**Status:** the section is **built and wired, and stays empty until the action gateway lands in L3.5**
— there is nothing irreversible in the system yet to put in it. The shape is honest; the content is not
there. That is AT-022, and it is tracked, not claimed.

---

## I-8. Manifests durable **before** the ref that points at them

**The rule.** In `refs.rs`: the manifest is persisted, *then* the ref is written (atomically).

**Why.** The other order leaves a branch name pointing at a manifest that does not exist. On restart the
database refuses to open — a ref is a promise that its target is there.

---

## I-9. An unknown actor is **refused**, not trusted

**The rule.** When a database has an actor registry, a write from an actor with no registered key is
rejected (`UnknownActor`). Signatures are verified against the key of the actor the envelope **claims
to be**.

**Why.** Failing *open* is the interesting bug: an attacker picks an authoritative-sounding name nobody
has registered — `"acme-compliance-bot"` — and, with no key to check against, the write sails through
and the audit trail records a ghost as its author. And verifying against the signer rather than the
claimant would let any registered agent write as any other.

**Guarded by.** `at_026_an_actor_cannot_impersonate_another_actor`,
`at_026_an_unregistered_actor_is_refused_rather_than_trusted`,
`at_026_tampering_with_the_intent_breaks_the_signature` (the signature covers `intent` — the field an
auditor actually reads).

---

## I-10. A test that passes with the fix reverted is **not a test**

**The rule.** Every capability names the AT-IDs it turns green, and the test must **fail before** the
change and **pass after** it. Verify the failing half by actually reverting the change.

**Why this is on a page of database invariants.** Because it caught a worthless test. The first version
of `at_020_taint_survives_a_merge_into_main` asserted that `main` appeared in the taint plan — and it
did, with the fix reverted, because the merged *observation* re-cites its own source when it lands. The
test proved nothing. It now asserts the **derived conclusion** survives the merge, which is the thing
that actually breaks.
