# LoomDB threat model

> A storage engine earns trust once, by being unembarrassed about its limits. This document says what
> LoomDB defends against, how, and — the part that matters — **what it does not defend against yet.** A
> truthful "we do not stop that" is worth more than a confident claim that gets found out in a POC.

LoomDB is an agent-native database: an LLM agent reads documents of unknown provenance, derives beliefs,
and — through a gateway — takes actions in the world. The adversary is not (only) an outsider. It is
**the agent's own inputs**: a scraped page an attacker wrote, engineered to steer the agent into an
action it should never take. Most of what follows is about surviving your own context window.

---

## §1 — What LoomDB defends against, and the mechanism

| Threat | Defense | Enforced by |
|---|---|---|
| **Prompt injection → destructive action** | Untrusted-labeled evidence may not authorize a privileged action, *however confident* the derived claim. The instruction stays a string in a context window. | The policy engine (deny-overrides, fail-closed) at the action gateway. **AT-034.** Demo step 8. |
| **Laundering a derivation by omission** | What a session *read* is what its writes are derived from — the engine captures it, the caller cannot shrink it. | Engine-captured read-set. **AT-002**, invariant I-4. |
| **"Which facts are downstream of this poisoned source?"** | `taint(S)` names **exactly** the contaminated set — completeness *and* precision — across forks and merges. | The taint walk + its model oracle (10,000 runs). **AT-020/021.** |
| **A taint report that hides the harm it cannot undo** | The `RecallPlan` lists executed actions — the suspended account, its receipt, its compensation — **first**, before the reversible writes. | `taint_with_actions`, invariant I-7. **AT-022.** Demo step 10. |
| **An agent taking an action directly** | There is **no execute method** on the agent surface — not through the API, not through MCP. Agents propose; the gateway acts. | Structural (a `compile_fail` test guards it). **AT-027**, invariant I-12. |
| **Restricted data reaching a public answer** | Labels propagate through every derivation, and restricted candidates are filtered **before** the context is packed — never scrubbed after. | Label propagation + pre-pack filter. **AT-035/036.** |
| **A double-charged / double-executed action** | One idempotency key → at most one side effect, under concurrent retries. | The gateway's idempotency store. **AT-028.** |
| **A conclusion built on withdrawn evidence acting** | A `Stale`/unsupported claim cannot authorize an action; the refusal names the missing dependency. | The gateway's evidence check. **AT-007/030.** |
| **A capability escaping its scope** | A token reaches no branch outside its scope, **through every surface including MCP**. | The token issuer, re-proven at the MCP boundary. **AT-019.** |
| **Forging a write's author** | With an actor registry, every write is signed and verified against the *claimed* actor's key; an unknown actor is refused, not trusted. **Through `loomd` too**: under the reference host profile the daemon opens with `Loom::open_production_attested`, and a registry it cannot verify stops startup rather than downgrading to unauthenticated writes. | Ed25519 envelope signatures, fail-closed. **AT-026**, invariant I-9. `crates/loom-mcp/tests/actor_registry.rs`. |
| **One tenant reaching another's data** | Structurally impossible: the tenant *is* the substrate pool. A known-good key of tenant B is, from tenant A, indistinguishable from one that never existed. | One tenant per pool. **AT-039.** |
| **A signal turning the database into a weapon** | `taint()` is a dry run; execution is a separate, token-gated call. The kill switch disables *actions* while leaving reads, writes, and audit fully available. | **AT-024/033.** |
| **Crash mid-commit** | The commit point is an fsync'd WAL record before the manifest install; data survives a crash at any byte. | substrate's `DurableStore` (50,000 crash cycles). **AT-045 partial — see §3.** |

---

## §2 — What LoomDB is NOT

- **Not a SIEM, not a WAF, not a network security product.** It does not inspect traffic, detect
  intrusions, or scan for malware. It is the *system of record* for what an agent believed and did, and
  the machinery to contain a bad input after the fact.
- **Not a policy author.** It *enforces* a policy (deny-overrides, fail-closed) and records every
  decision. It does not tell you what your policy should be. A permissive policy is a permissive
  database; the engine guarantees the policy is applied and audited, not that it is wise.
- **Not a key-management system.** It verifies signatures against keys you register (§3). Issuing,
  rotating, and revoking those keys is out of scope.

---

## §3 — What LoomDB does NOT defend against (yet), stated plainly

Each of these is a real gap. None is hidden.

1. **Key distribution, rotation, and revocation.** Signature verification (AT-026) checks a write
   against a key you handed the engine. Where that key came from, and what happens when it is
   compromised, LoomDB does not address in v0.1. **Consequence:** the authenticity guarantee is only as
   good as your out-of-band key management. Signature checking is also *opt-in at the library* — a
   `Loom::open` with no registry leaves writes attributable but not authenticated. It is **not**
   optional under the reference host profile: there, the daemon is given a governance-signed registry
   and a rollback floor, and it refuses to start without them (see §1 and
   [host-profile.md](host-profile.md) §3). Rotation and revocation of the actor keys *inside* that
   registry, and custody of the governance signing key, remain yours.

2. **A malicious operator.** The action gateway takes a human approval before executing. LoomDB does not
   defend against the human approver being the adversary, or against an operator with database access
   rewriting policy. It records what they did — the audit trail is honest — but it does not prevent an
   authorized insider from authorizing harm. Defense-in-depth (separation of duties, the kill switch,
   the immutable audit DAG) reduces but does not eliminate this.

3. **A compromised connector.** LoomDB decides *whether* an action may run and records that it did. The
   connector that actually suspends the account is trusted to do what it says and return an honest
   receipt. A connector that lies (reports success it did not achieve) is caught only insofar as it
   returns no receipt (AT-032) — a connector that fabricates a receipt is outside the model.

4. **Side channels and timing.** The cross-tenant guarantee (AT-039) is about *identifiers and
   errors* — a tenant cannot name or confirm another's data. One process/pool per tenant plus bounded
   request size and a per-process token bucket prevent one tenant from entering another tenant's
   trusted process or consuming an unbounded request buffer. They do not analyze timing, shared-host
   cache, memory-bandwidth, or kernel-scheduler side channels. High-assurance deployments must use
   dedicated nodes or confidential-compute isolation where those channels are in scope; the reference
   host profile ([host-profile.md](host-profile.md)) does **not** provide them, and says so.

5. **Denial of service.** The taint walk is bounded (AT-025), `loomd` drains newline-delimited requests
   without allocating beyond `LOOM_MAX_REQUEST_BYTES`, and each single-tenant process enforces
   `LOOM_REQUESTS_PER_SECOND` with `LOOM_REQUEST_BURST`. These are admission controls, not a complete
   DDoS defense: connection limits, CPU/memory cgroups, tenant storage quotas, and upstream network
   flood protection belong to the deployment platform. The reference host profile now *renders* the
   host half of that — CPU/memory/pid/file ceilings, a default-deny network policy, and an
   authenticated front door that owns connection lifecycle — but rendering a ceiling is not the same as
   proving throughput under attack, and no load or flood test backs these numbers.

6. **A client that holds a real key and signs a false thing.** Write authenticity through `loomd` is
   now enforced (§1), but a signature answers exactly one question: did the holder of this actor's
   key sign these bytes. It does not establish that the holder is who you believe, that the key has
   not been stolen from the agent runtime, or that the agent was not steered into signing a
   truthful-looking write. Those are, respectively, your key custody, your workload isolation, and —
   for the injection case — the policy engine's job at the action gateway (AT-034), not the
   signature's.

7. **AT-045 at LoomDB granularity.** Data commits ride substrate's 50,000-cycle crash suite. The durable
   **ref write** — a second object with its own ordering (invariant I-8) — is enforced and unit-tested
   but has **not** yet been driven through 50,000 crash-and-recover cycles under LoomDB-shaped workloads.
   Deferred to v0.2, tracked in [at-map.md](at-map.md). Until then, the crash-safety claim for the ref
   layer rests on the ordering proof, not on the crash-injection proof.

---

## §4 — The trust anchor

LoomDB's guarantees rest on substrate's: content-addressed immutable pages, a single fsync'd commit
point, crash recovery, and one-pool-per-tenant isolation. If substrate is wrong, LoomDB is wrong.
Substrate's own threat model and its 50,000-cycle crash suite are the foundation this document builds
on, and they are audited separately in that repository.
