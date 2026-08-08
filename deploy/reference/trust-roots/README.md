# Reference trust roots

**There is no committed production trust-root register, and that is the accurate state.**

This directory used to hold `production.json`, naming two AWS KMS keys — `actor-governance` and
`release` — both `pending`, both provisioned on 2026-08-02 and verified by a read-only `kms:Sign`
round-trip ([`docs/drills/kms-roundtrip.json`](../../../docs/drills/kms-roundtrip.json)).

**On 2026-08-08 the AWS account was closed and both keys were destroyed with it.** No dual-control
ceremony had been held; neither key was ever activated; neither ever signed a release. The register
was removed rather than edited, for a reason worth stating plainly:

> Marking a key `revoked` in a register requires **two distinct recorded approvers** — `loom-keys`
> enforces that at load time, and refuses a register whose revoked entry has none. That check exists
> so a revocation is a decision somebody signed for. Writing two names into that file to make it load
> again would have been fabricating a ceremony that never happened, which is precisely the thing this
> whole subsystem exists to prevent. Closing a cloud account is not a governance ceremony.

So the honest options were "an entry that lies about its status" or "no entry". This is no entry.

## What is still here, and why

The two `.der` files are the **exported public halves** of those destroyed keys. They are retained as
historical evidence: they let anyone re-check the SPKI hashes recorded in the round-trip receipt, so
that record stays verifiable even though the private halves are gone. They are **not** an active
trust root, they authorize nothing, and nothing loads them at runtime.

## What a deployment must supply

A real deployment mounts its own register read-only at the path its unit file names — see
`governanceKeyPath` in [`../profile.json`](../profile.json). Build it with `loomctl`:

```sh
loomctl keys expand   --trust-roots <register> --role actor-governance --key-id <id> \
                      --public-key-file <hex> --generation 1 \
                      --ceremony <reference> --approver <who> --approver <who-else>
loomctl keys activate --trust-roots <register> --role actor-governance --key-id <id>
loomctl keys inspect  --trust-roots <register>
```

## Current custody, stated plainly

**The release trust root is software-backed.** Release bundles are signed by an Ed25519 key held as a
GitHub Actions secret (`LOOM_BUNDLE_SIGNING_KEY`), generated with `loom-bundle-tool keygen`. That is a
weaker custody model than a non-exportable KMS or HSM key, and it is the current reality rather than
the intended end state.

**`EXT-HSM` is open** and is further from closed than it was before the account was shut down. Full
detail in [`docs/key-custody.md`](../../../docs/key-custody.md) §5.
