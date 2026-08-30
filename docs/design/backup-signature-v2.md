# Design note — backup signature format v2

**Status:** proposed. No code implements this yet; that is P9.1b, and this note is the thing to argue
with first.

**Decision this records:** the backup trust root joins the AWS KMS ceremony as phase 2, and to do
that the backup signature format gains a version 2 that signs a *digest* rather than the whole
manifest. Approved 2026-08-02. Phase 1 — `actor-governance` and `release` — needs none of this and
proceeds unchanged.

---

## §1 — Why, precisely

AWS KMS `Sign` accepts a `Message` of **0–4096 bytes**, and pure Ed25519 (`ED25519_SHA_512`, the
algorithm loomDB uses) requires `MessageType: RAW` — the prehash variant `ED25519_PH_SHA_512` is
HashEdDSA, a different signature scheme this codebase cannot verify. So a signing payload above
4 KiB simply cannot be signed by KMS.

The v1 backup payload is the domain separator, the key id, a separator byte, and **the entire
manifest**:

```rust
// crates/loom-branch/src/backup.rs — v1
SIGNATURE_DOMAIN ("loomdb-backup-manifest-signature-v1\0", 36 bytes)
  || key_id
  || 0x00
  || manifest_bytes          // ← grows with every file in the store
```

The manifest lists every file with its path, length, and BLAKE3 digest, so this grows without bound.
The P9 drill measured it on the smallest store a drill can build:

| | bytes |
|---|---|
| Fixed overhead (domain + `backup-root-2026-q3` + separator) | 56 |
| Manifest, for **27 files** | 5,624 |
| **Total v1 payload** | **5,680** |
| KMS `Sign` RAW limit | 4,096 |
| **Over by** | **1,584** |

Recorded in [`docs/drills/local-filesystem-copy-clone.json`](../drills/local-filesystem-copy-clone.json).
A 27-file store is already 39% over. A real tenant is far worse.

### Why not simply leave this root on another backend

That was the alternative, and it was rejected deliberately. Permanently keeping one root of three on
different custody fragments the ceremony story — and the odd one out would be the **DR-critical**
root, the one whose failure mode is "the backups cannot be trusted during an incident". One custody
model for all three roles is worth a versioned format change.

---

## §2 — The format

```
SIGNATURE_DOMAIN_V2 ("loomdb-backup-manifest-signature-v2\0", 36 bytes)
  || (key_id.len() as u64).to_le_bytes()     //  8 bytes, length-prefixed
  || key_id                                  //  the operator-chosen trust-root identity
  || blake3(manifest_bytes)                   // 32 raw bytes — RECOMPUTED, see §3
```

**95 bytes** for a 19-character key id, **fixed** — it does not grow with the store. 4,001 bytes of
headroom under the KMS limit, and the number does not move when a tenant does.

The length prefix on `key_id` is not decoration. v1 used a `0x00` separator, which is safe only
because a key id cannot contain a NUL; length-prefixing removes the reliance on that and matches the
framing already used by `WriteEnvelope::signing_bytes` and the actor-attestation payload. A signed
encoding where two different (key id, digest) pairs could produce the same bytes is a signature that
means less than it appears to.

The `BackupSignature` record itself is unchanged in shape — `format_version` becomes `2`, and
`manifest_blake3` stays where it is. What changes is only *which bytes the signature covers*.

---

## §3 — The trap this note exists to avoid

> **The verifier MUST recompute the digest from the exact manifest bytes. It must never verify the
> signature over the digest value the record carries.**

If the verifier took `record.manifest_blake3` as the value to check the signature against, the format
would be trivially forgeable:

1. An attacker takes a genuine backup with a valid `(digest D, signature S)` pair.
2. They replace the manifest with `M′`, describing entirely different files.
3. They leave `record.manifest_blake3 = D` and `record.ed25519 = S` untouched.
4. The verifier checks `S` over `D` — and it verifies, because it always did.

The signature would then bind *a claim the record makes about itself*, not the manifest. **Integrity
is not authenticity.** A digest sitting beside the data it describes is an integrity check; only a
signature over a digest the verifier computed itself is an authenticity check.

So the verification order is fixed and not an implementation detail:

```
1. read the manifest bytes
2. computed = blake3(manifest_bytes)                    ← the verifier's own value
3. if record.manifest_blake3 != computed  →  refuse     (a diagnostic, not the check)
4. verify record.ed25519 over payload_v2(key_id, computed)
5. only now decode the manifest and check every file digest
```

Step 3 is worth keeping even though step 4 no longer depends on it: a mismatch there is a clear
"this record does not describe this manifest" for an operator, ahead of a bare signature failure.
But it is *advisory*. Step 4 uses `computed`, never `record.manifest_blake3`, and the implementation
should make that impossible to get wrong — the record's field should not be in scope where the
payload is built.

**A test must assert exactly this attack**: swap the manifest, leave the record's digest and
signature intact, and require the refusal. A v2 implementation that passes every other test and fails
that one is worse than v1.

---

## §4 — Old backups verify forever

**v1 is not deprecated, is not migrated, and is never rewritten.**

A backup is an artifact that was signed once, correctly, under the rules in force at the time. Going
back and re-signing it would mean the archive's authenticity depends on a key we hold *today* rather
than on the one that was trusted when the backup was taken — which is exactly backwards for the thing
whose job is to survive a compromise.

So:

- `verify_signed_backup*` dispatches on `record.format_version` and accepts **1 and 2**, using each
  version's own payload construction.
- Nothing rewrites a v1 record. There is no migration command and there should not be one.
- **Test fixtures are ADDED, not regenerated.** The existing v1 fixtures stay byte-identical, and a
  v2 fixture set is added alongside. A commit that touches an existing v1 fixture is a commit that
  has silently changed what "v1 verifies" means, and review should treat it that way.
- The v1 payload builder stays in the tree, exercised by the v1 fixtures. It is not dead code; it is
  the definition of how to read the archive.

An unknown `format_version` — 3, or 0, or a value from a newer build — is **refused**, never
guessed at. Same rule the bundle format already follows.

---

## §5 — Dual acceptance, so the key rotation can overlap

The point of this change is a key rotation, and P8's rotation sequence deliberately has an overlap
window: `expand → activate → drill → revoke`, with the superseded root **retired** rather than
revoked so artifacts signed before the rotation keep verifying.

That means during phase 2 the shelf will hold both:

| Backup taken | Signed by | Format |
|---|---|---|
| before the ceremony | software-backed root | v1 |
| after the ceremony | KMS root, `ECC_NIST_EDWARDS25519` | v2 |

Both must verify, at the same time, from the same register, with no operator flag distinguishing
them. The verifier reads the format from the record and dispatches; custody resolves the key id
independently, exactly as it does today. **Format version and trust root are orthogonal** — a v2
backup signed by a software key and a v1 backup signed by a KMS key are both coherent, and neither
should require special handling.

Which format the **writer** emits is a separate, later switch. The safe order is: land v2
verification everywhere first, confirm every verifier in the fleet accepts it, and only then start
emitting v2. A writer that emits a format some verifier does not yet accept is the same
distribute-then-trust mistake `expand` exists to prevent.

---

## §6 — What must be true before v2 is called supported

1. `cargo test -p loom-branch --test backup` green, with **both** fixture sets.
2. The §3 attack test present and passing — swapped manifest, original record, refused.
3. An unknown `format_version` refused by name.
4. **The P9 drill re-runs end to end on a v2-signed backup** — clone, backup, independent
   verification through custody, restore, attested reopen, known answers, faults — and a fresh
   receipt is retained showing the v2 signed-payload size under 4,096. A format that has not been
   through a recovery is a format nobody has recovered from.
5. The air-gap dependency inspection unchanged: this adds no dependency and must not.
6. `docs/backup-restore.md` and `docs/key-custody.md` §5 updated, with the KMS constraint moved from
   "open question" to "resolved, phase 2 unblocked".

Only when all six hold does `backup-root` join the ceremony.

---

## §7 — What this does not do

- **It does not close `EXT-HSM`.** No ceremony has been run; this only removes the technical
  obstacle to running one for the third role.
- **It does not change the other two roles.** `actor-governance` and `release` payloads are ~100 and
  ~200 bytes and go to KMS unchanged, under the same `ED25519_SHA_512` / `RAW` combination.
- **It does not weaken the backup mechanism.** The manifest still allow-lists every file with a
  length and a digest, restore still refuses to overwrite, and the trust-root signature remains the
  authenticity check — a storage vendor's checksum still never substitutes for it.
- **It does not touch `deploymentDecision` or `softwareReleaseCandidate`.**
