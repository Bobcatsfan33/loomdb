<div align="center">

# LoomDB

**A database an agent can branch like git — that records where every belief came from, and can undo exactly what a poisoned input contaminated.**

[![CI](https://github.com/Bobcatsfan33/loomdb/actions/workflows/ci.yml/badge.svg)](https://github.com/Bobcatsfan33/loomdb/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Built on substrate](https://img.shields.io/badge/engine-substrate%20v1.1-purple.svg)](https://github.com/Bobcatsfan33/substrate)

</div>

---

## Why agents break databases

Every database in production was designed for a client that is either a human or a deterministic program. An LLM agent violates their assumptions on its first request.

**The client knows what it wants to do.** A transaction is a plan. Agents don't have plans, they have *hypotheses*. An agent wants to try something, look at the result, and abandon it — while keeping the abandoned attempt around, comparing it against two others, and merging the winner. The primitive for that is `ROLLBACK`, which is useless here.

**Writes are trustworthy because the client is trusted.** An agent's write is a *derivation*: it read six documents of unknown provenance, one of which may have been poisoned by whoever wrote that web page, and produced a fact. Six months later that source turns out to be compromised. *"Which of my 400,000 stored facts are downstream of it?"* is unanswerable in every database on the market — an audit log records **that** a write happened, not **what it was derived from**.

**The agent only reads and writes.** It does not. It suspends accounts, closes tickets, and files reports. A database that records an agent's beliefs but not its *effects* is auditing the harmless half.

LoomDB's primitives are the ones agents actually need: **observe, claim, branch, merge, rewind, retrieve, act, taint.**

## A session is a branch

```rust
let db = Loom::in_memory(TenantId::new("acme"))?;
let (session, token) = db.open_session()?;          // forks the tenant base image. O(1). copies nothing.

// Three hypotheses.
let (h1, token) = db.branch(&token, &session.branch, "credential-stuffing")?;
let (h2, token) = db.branch(&token, &session.branch, "travel")?;
let (h3, token) = db.branch(&token, &session.branch, "compromised-device")?;

// Each agent writes freely in its own branch. Nobody sees anyone else.
db.write(&token, &h2, key, claim, &envelope)?;

// h2 won. Merge it; rewind the others — and they stay auditable.
db.merge(&token, &h2, &session.branch, &MergePolicy::Conflict, &envelope)?;
db.rewind(&token, &h1, &session.base)?;
```

A million idle sessions are a million manifests: bytes in object storage, no compute. That's what makes speculation affordable, and it comes from the engine underneath — [**substrate**](https://github.com/Bobcatsfan33/substrate), where a fork costs **98 nanoseconds** regardless of database size.

## Four things that are unusual

**Merge happens at record granularity, not page granularity.** Two agents writing two unrelated facts that land in the same 64 KiB page must **not** conflict. A merge engine that reports conflicts between things that don't conflict is a merge engine that lies, and an agent will either escalate for nothing or learn to ignore conflicts. Substrate's page-level diff is a *prefilter*; the merge is over records.

**Typed merge rules, because most agent concurrency isn't a conflict.** Counters merge arithmetically (two branches each incrementing by 3 from 10 gives **16**, not 13 — taking either side's value would silently discard the other agent's work while reporting a clean merge). Sets union. Claims resolve by validity, then by *provenance rank* — a claim derived from a verified system record outranks one a language model inferred, however confident the model was.

**Observations are not claims.** The identity provider said the account signed in from Belarus — that's an *observation*. "This account is compromised" is a *claim* derived from it, by a method, with a confidence, and it can be wrong in ways the observation cannot. And the invariant that follows: **a claim with no evidence can be stored, but can never authorize an action.**

**No write exists without an envelope.** Actor, session, branch, delegation chain, what it was derived from, and *why* — enforced at the write entry point, not as middleware someone can forget. A bypassable audit trail is worse than none, because it is believed.

## Why you should be suspicious of this, and what we did about it

This was written fast, largely by an AI. That should worry you. Enthusiasm is not a rebuttal, so here is the evidence:

**A model oracle with a real two-parent commit DAG.** A naive reference implementation — maps of maps, no B-tree, no pages, no prefilter — differentially tested against the real engine under randomized branch/write/merge sequences. **It found three real bugs in the merge engine**, including one where merging twice silently **double-counted a counter** because substrate's single-parent manifests don't record that a merge happened. It also caught two successive half-fixes for that bug before the correct one.

**It found the criss-cross case, too.** Once two branches have concurrently absorbed each other's work, their history has *more than one* equally-valid merge base, and a three-way merge with any single one is a guess. LoomDB **refuses**, and says why. A database that admits it does not know is worth more than one that guesses confidently.

**And it caught a broken test.** The prefilter test accused the engine of dropping records; the engine was right and the *test* was wrong (`n as i8` wrapped at 256 and wrote the seed value back). We would rather find that here.

## Status

**L1 complete** — sessions-as-branches, capability tokens, the record-level merge engine, and the B+tree record store. 59 tests, clippy clean.

Next: **L2** provenance and taint-and-recall · **L3** memory and retrieval · **L3.5** the action gateway and influence policy · **L4** the MCP server.

## The action layer is coming, and it's the point

Taint-and-recall reverts *writes*. It cannot un-suspend an account. So the `RecallPlan` will have two sections, and the **irreversible** one is listed first: the actions already taken, their receipts, and either a registered compensating action or an explicit escalation to a human. A taint report that shows six reverted writes and quietly omits the account it suspended is not an audit tool — it's a liability.

## Reading order

The architecture of record lives in the substrate repository:

1. [`docs/03`](https://github.com/Bobcatsfan33/substrate/blob/main/docs/03-agent-native-database-architecture.md) — the architecture
2. [`docs/05`](https://github.com/Bobcatsfan33/substrate/blob/main/docs/05-loomdb-test-spec.md) — the acceptance catalog (AT-001…AT-047) and the integrity invariants
3. [`docs/loom-format.md`](docs/loom-format.md) — the on-page record format

## License

Apache-2.0.
