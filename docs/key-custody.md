# Trust-root custody

loomDB signs three different things with three different authorities. Before P8, each one verified
against *whatever public key you handed it*.

| Role | Signs | Verified by | Private half lives |
|---|---|---|---|
| `actor-governance` | the actor-registry attestation | `loomd`, at startup | never on an engine host |
| `release` | the offline update bundle manifest | the enclave, before applying | the release pipeline |
| `backup-root` | the backup manifest | the independent verifier job | the backup writer |

A check that accepts any valid key is not an authorization decision. It says *someone* signed this —
not *the party we trust for this role, still, today*. A retired key verifies exactly as well as the
current one. **A revoked key verifies exactly as well as it did the day before it was revoked.**

So refusing one has to be a decision somebody records. This is where that decision lives.

---

## §1 — The register

`loom-keys` reads a **trust-root register**: a JSON file the deployment mounts read-only, naming keys
per role.

```jsonc
{
  "schemaVersion": 1,
  "roots": [{
    "keyId": "gov-2026-q3",           // an identity, bound into verification and every receipt
    "role": "actor-governance",       // roles are separate authorities
    "algorithm": "ed25519",           // bound: a key cannot be used under one it is not registered for
    "publicKey": "<64 hex characters>",
    "backend": "software",            // where the private half lives — labels custody, never widens it
    "status": "active",               // pending | active | retired | revoked
    "generation": 3,                  // monotonic within a role; rotation moves forward only
    "ceremony": {
      "reference": "CEREMONY-2026-Q3",
      "approvals": [
        {"approver": "pki-officer", "atUnix": 1800000000},
        {"approver": "security-lead", "atUnix": 1800000000}
      ]
    }
  }]
}
```

It is validated fail-closed on load, exactly like the policy file and the actor registry: a regular
file, size-bounded, never a symlink that could be repointed between restarts, never group- or
world-writable — anything that can rewrite the register can appoint its own trust roots.

**It is deliberately not self-signed.** A register signed by a key the register itself names is a
circular argument, and one signed by a further key only moves the question. It arrives the way every
other trust root arrives: through an independent, authenticated channel onto a read-only mount. What
it buys over the bare public key it replaced is everything a bare key cannot express — role,
algorithm, status, and who approved making it so. A file an attacker can rewrite was already game
over when it held one public key; now the same file can also say **revoked**, which the old shape
simply could not.

### Status, and what each one permits

| Status | Verifies | Signs | Meaning |
|---|---|---|---|
| `pending` | no | no | staged by `expand`; distributed but trusted for nothing yet |
| `active` | yes | yes | the one key that signs for this role |
| `retired` | yes | no | superseded; still verifies what it signed before the rotation |
| `revoked` | **no** | no | refused. The material still verifies; this is the decision not to accept it |

At most one `active` key per role. Two would make "which key signs" a coin flip.

---

## §2 — The signer interface signs bytes, and nothing else

```rust
pub trait Signer {
    fn key_id(&self) -> &str;
    fn role(&self) -> KeyRole;
    fn algorithm(&self) -> Algorithm;
    fn backend(&self) -> Backend;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;   // EXACT caller-supplied bytes
}
```

Every signed format in this workspace predates custody and survives it byte for byte: the bundle
manifest's bincode, the backup manifest's exact bytes, the actor-attestation's domain-separated
payload. So the interface is deliberately anaemic — it does not serialize, canonicalize, wrap, or
timestamp anything.

That anaemia is the design. A backend that formats anything can change what a signature *means*, and
swapping custody must never invalidate an artifact signed before the swap.
`the_signer_signs_exactly_the_bytes_it_was_given` pins it.

### Custody is labelled, never assumed

Every `SignedReceipt` records the `backend` that produced it. A drill against a software key proves
the *sequence* works and proves nothing about hardware custody, and `loomctl keys drill` says so in
its own output:

```
"backend": "software",
"custody_claim": "SOFTWARE-BACKED DRILL. This proves the rotation sequence, not hardware custody.
                  EXT-HSM remains open."
```

A register entry declaring a backend this binary cannot drive is **refused**, not quietly signed in
software instead: a receipt claiming hardware custody must come from hardware.

---

## §3 — Rotation is a sequence, not a swap

```
  expand          activate            drill            revoke
  ──────          ────────            ─────            ──────
  add the new     new → Active        sign and         old → Revoked
  key, Pending    old → Retired       verify both
```

Swapping a trust root in one move leaves an instant where some verifiers hold the new key and some do
not, and every artifact signed in that window verifies for only half the fleet. The sequence removes
that instant: `expand` distributes the key while it authorizes nothing; `activate` moves signing and
leaves the old key **verifying**, so last week's backups and yesterday's bundles keep verifying; the
drill proves both halves; and `revoke` — the only step that invalidates anything — is last and
separately approved.

```sh
loomctl keys expand   --trust-roots R --role release --key-id release-2026-q4 \
                      --public-key-file new.pub --generation 4 \
                      --ceremony CEREMONY-2026-Q4 --approver pki-officer --approver security-lead
loomctl keys activate --trust-roots R --role release --key-id release-2026-q4
loomctl keys drill    --trust-roots R --role release --signing-key-file new.key
loomctl keys revoke   --trust-roots R --role release --key-id release-2026-q3 --reason "superseded"
```

**Dual control** gates the two transitions that change what verifies — `activate` and `revoke` —
requiring two *distinct* approvers recorded against a ceremony reference. loomDB does not run the
ceremony; it requires that one happened and that the register says where the evidence is.

**Revoking the last key that verifies seals the role**: nothing signed for it will ever verify again.
That is a legitimate incident posture and it must be asked for explicitly (`--seal-role`).

---

## §4 — Every refusal is named

A verifier that fails with "signature invalid" for all of these gives an operator nothing to act on,
and gives an auditor no way to tell a rotation mistake from an attack.

| Situation | Error |
|---|---|
| the id is not registered for this role | `UnknownKeyId` |
| it is registered, for a different role | `RoleMismatch` |
| it was revoked | `KeyRevoked` — **carrying the recorded reason** |
| it is staged, not yet trusted | `KeyNotTrusted` |
| the artifact claims another algorithm | `AlgorithmMismatch` |
| the bytes do not verify | `SignatureInvalid` |
| nothing trusted in the role verifies it | `NoTrustedKey`, naming how many were tried |
| the role has no key that may sign | `NoActiveSigner` |
| one approver tried to promote or revoke | `DualControlRequired` |
| the register asks for a backend we cannot drive | `BackendUnavailable` |

---

## §5 — What P8 did *not* do, stated plainly

1. **No ceremony has been run.** Everything here was exercised against **software-backed** keys.
   `EXT-HSM` is open and P8 does not touch it. A green drill is evidence the sequence works, not
   evidence of custody.

2. **AWS KMS signs Ed25519. The blocker P8 raised is resolved, and nothing changes.**

   P8 recorded that AWS KMS offered RSA and ECDSA only, so an Ed25519 product would need CloudHSM or
   an algorithm migration. That was **out of date**: AWS KMS added Ed25519/EdDSA support on
   **2025-11-07**, in all regions. Checked against the
   [key spec reference](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html)
   and the [Sign API reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html):

   | | value |
   |---|---|
   | Key spec | `ECC_NIST_EDWARDS25519` (signing and verification only) |
   | Signing algorithm | `ED25519_SHA_512` — NIST FIPS 186-5 §7.6, **pure** EdDSA |
   | Message type | `RAW` (required for `ED25519_SHA_512`) |

   `ED25519_SHA_512` with `MessageType: RAW` is *exactly* the scheme
   `ed25519_dalek::VerifyingKey::verify_strict` already checks. So: **AWS KMS stays the production
   backend, every signed format stays byte-identical, `Algorithm` keeps its single `Ed25519`
   variant, and CloudHSM and an algorithm migration are both off the table.**

   Do **not** use `ED25519_PH_SHA_512`. That is HashEdDSA (FIPS 186-5 §7.8, `MessageType: DIGEST`) —
   a different signature scheme producing signatures this codebase will not verify. The distinction
   is a one-word difference in a console dropdown and a total difference in outcome.

   **One real constraint remains, and it is per-role.** `Sign` accepts a `Message` of **0–4096
   bytes**, and `RAW` is required for pure Ed25519, so a signing payload larger than 4 KiB cannot go
   through KMS unmodified:

   | Role | Signed payload | Fits 4 KiB? |
   |---|---|---|
   | `actor-governance` | domain + tenant + generation + fingerprint — fixed, ~100 bytes | yes, comfortably |
   | `release` | bincode of seven small manifest fields, ~200 bytes | yes |
   | `backup-root` | domain + key id + **the whole backup manifest**, which lists every file | **grows with the store** |

   **P9 measured it, and the backup role does not fit.** On the smallest store a drill can build —
   27 files, 24163 bytes restored — the backup signing payload is
   already **5680 bytes**, 1584 over the
   4096-byte limit, and it grows with every file in the store. See
   [`docs/drills/local-filesystem-copy-clone.json`](drills/local-filesystem-copy-clone.json).

   So the position is:

   - **`actor-governance` and `release` can move to KMS unchanged.** Both payloads are small and
     fixed-shape. The ceremony order Ryan chose puts actor-governance first, which is the role with
     the most headroom — nothing blocks starting.
   - **`backup-root` cannot, without a decision.** The options are to sign a digest of the manifest
     instead of the manifest (a signed-format change, and the record already carries
     `manifest_blake3`, so the change is small but real), to use `ED25519_PH_SHA_512` (a *different*
     signature scheme — `ed25519-dalek` will not verify it, so also a format change), or to keep the
     backup trust root on a backend without the 4 KiB ceiling. **This is undecided and is a
     prerequisite for moving that one key, not for the ceremony as a whole.**

3. **The register is not signed** (§1), and its integrity rests on the read-only mount and the
   channel that delivered it.

4. **Only the actor-governance role is wired end to end in a daemon.** `loomd` verifies its
   attestation through custody at startup. The release and backup roles are wired at the library and
   `loomctl` boundary; the release *pipeline* still signs with a key file, and moving that to the
   register is deployment work.

---

## §6 — Verifying it yourself

| Claim | Command |
|---|---|
| The custody model holds | `cargo test -p loom-keys` |
| Rotation works as commands | `cargo test -p loomctl --test key_custody` |
| A revoked governance key stops `loomd` | `cargo test -p loom-mcp --test actor_registry` |
| A retired key still attests what it signed before the rotation | same |
| What this deployment trusts right now | `loomctl keys inspect --trust-roots <register>` |
