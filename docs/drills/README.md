# Recovery and incident exercises

**The drill is code, not a runbook.** `cargo test -p loom-drill` runs it: a database is written to,
cloned mid-flight, backed up, lost, verified from a separate trust domain, restored somewhere new,
reopened through the attested path, and checked against expectations recorded before the failure.
What it measures lands in [`docs/drills/`](.) as a retained receipt.

A runbook rots the moment the mechanism changes. This drill drives `Loom::backup_to_signed`,
`loom-keys`, `restore_signed_backup`, and `Loom::open_production_attested` directly, so if any of
them changes the drill changes with it or goes red.

---

## What one drill does

```
  seed ──► clone ──────────────────────────► FAILURE
            │         (writes continue)          │
            ▼                                    │
         backup-signed                           │  recovery point = failure - clone
            │                                    │
            ▼                                    ▼
         verify (separate trust domain) ──► restore to a NEW path ──► attested reopen
                                                                      │
                                           recovery time ─────────────┘
```

The clone is taken **before** the last writes, so the recovery point is a real gap. The known-answer
checks assert exactly that boundary: everything written before the clone must come back, everything
written after it — records *and* branches — must not. A drill whose recovery point is zero proves
nothing about recovery.

Recovery is then measured to a store that is **servable**, not merely present: verified against its
signature through custody, restored, reopened attested, integrity-scrubbed, read back by
known-answer, and taint-walked.

---

## Measured — `local-filesystem-copy-clone`

| | Measured | Target | |
|---|---|---|---|
| Recovery point (this drill) | **0.17s** | 24h | the gap between clone and failure |
| Recovery point (production) | bounded by the backup interval, **24h** | 24h | what actually bounds it |
| Recovery time | **0.09s** on 24163 bytes | 4h | restore → attested → verified |

**Read the recovery-point row carefully.** 0.17s is how long this drill let
writes continue after the clone on a developer laptop. It is evidence that *the boundary is in the
right place*, and it is **not** a claim about how much work a real outage would lose — in production
that is the backup schedule, 24 hours. The receipt records both, side by side, so the small number
cannot be quoted as the large one.

The recovery-time number is honest and small for the same reason: 24163 bytes on local
disk. It is not evidence about customer-scale data, and the receipt says which topology produced it.

- **11/11 known-answer checks matched** — branch heads, record reads, absence of
  post-clone work, absence of the post-clone branch, and a taint walk over a restored source.
- **4 faults injected in the receipt, all refused, survivors intact.** The full battery is
  10 tests in `crates/loom-drill/tests/fault_injection.rs`.
- **Integrity clean, attested reopen succeeded, backend `software`.**

---

## What the faults prove

Each asserts two things: the operation is **refused**, and the refusal **names the fault** — so an
operator at 3am can tell corrupted media from a revoked key from the wrong tenant's backup. Each also
asserts the **survivors**: the live store and the shelf are both intact afterwards.

| Fault | Refused by |
|---|---|
| bit flip in a backup part | the manifest's BLAKE3 allow-list |
| bit flip in the signed manifest | the signature over the exact manifest bytes |
| another tenant's backup | the tenant comparison, before anything is published |
| an unregistered key id | custody — `no trust root named …` |
| **a revoked key whose signature is still valid** | custody — `REVOKED`, carrying the recorded reason |
| a stale actor-registry generation | the rollback floor — `rollback refused` |
| a destination that cannot be created | the restore, publishing nothing (a file blocking the path — **not** a true ENOSPC; see below) |
| a backup killed mid-flight | build-in-a-sibling-then-rename: a partial publish is not a backup |
| a restore killed mid-flight | nothing published; shelf and live store both intact |
| a restore aimed at a live store | the drill's own guard rail, before anything is read |

---

## The incident path

`loom_drill::incident` generates notification content **from the receipt**: what was lost, what
bounds it, how long recovery took, which backup was consumed, which trust root verified it. Every
figure comes out of measurements, including the unflattering ones — a notification that says
"recovery completed within objectives" is exactly the sentence written when nothing was measured.

Two audiences, because they are owed different things: operations gets identifiers and the topology's
blind spots; the customer gets the window of work they would have lost, in their terms.

**Nothing here is delivered.** `delivered` is always `false` and every notification carries what
delivery would require — a named on-call rota, a paging system wired to it, an accountable
communications channel, and a documented notifiability decision. All of that is `EXT-OPERATIONS` and
remains open.

---

## What this is NOT evidence for

The receipt lists this itself, in `notExercised`, so it travels with the artifact:

- CSI volume snapshots and clone provisioning
- storage-array or filesystem snapshot primitives
- third-party backup products and their agents
- immutable off-account object-lock targets
- customer-scale data volumes
- multi-node or cross-availability-zone recovery
- a true ENOSPC / full-filesystem injection (a file blocking the destination path stands in for it; filling a filesystem is not portably arrangeable here)

**`EXT-DR` remains open.** These drills ran on developer hardware, at developer scale, against a
directory-copy clone and a software-backed key. Customer-scale data, the target storage stacks, and
SRE sign-off are external, and no drill in this repository was run against production-shaped storage.
