# loomDB reference production host profile

The supported deployment posture for loomDB, expressed as configuration a gate can check.
**Read [`docs/host-profile.md`](../../docs/host-profile.md) first** — it explains the boundary, the
controls, and what this profile deliberately does not give you.

This is not an approval to deploy loomDB in production;
[`docs/enterprise-readiness.json`](../../docs/enterprise-readiness.json) still records
`deploymentDecision: "not-approved"`.

## Layout

| Path | What it is |
|---|---|
| `profile.json` | **The source of truth.** Edit this, never the rendered files. |
| `Containerfile` | Non-root distroless image: air-gap `loomd` plus `loom-bundle-tool` and `loomctl`. Hand-written. |
| `kubernetes/` | Rendered manifests: namespace + restricted PSA, default-deny NetworkPolicy, front-door config, one StatefulSet per tenant. |
| `systemd/` | Rendered units: `loomd@.service` (templated, one instance per tenant) and one env file per tenant. |

Everything under `kubernetes/` and `systemd/` is **generated**. Each file says so in its first two
lines, and the gate fails on drift.

## Working on it

```sh
python3 scripts/verify_host_profile.py          # the gate CI runs
python3 scripts/render_host_profile.py --write  # regenerate after editing profile.json
python3 scripts/render_host_profile.py --check  # drift only
```

`verify_host_profile.py` does three things: validates `profile.json`, proves the committed artifacts
match it byte for byte, and applies 48 unsafe postures that must each be rejected — two tenants
sharing a store, an anonymous client, a writable root filesystem, a mutable image tag, an actor
registry that is mounted but never enforced, and so on. The renderer validates before it renders and
never repairs a declaration, so an unsafe posture has no rendered form.

Adding a tenant is one entry in `profile.json` plus `--write`. It is never an edit to an existing
workload: one tenant, one process, one store.

## Before you deploy

1. Build the image and put its **digest** in `profile.json` (`image.digest`), then set
   `digestIsPlaceholder` to `false`. The committed digests are declared placeholders — this
   repository publishes no image. Do the same for `frontDoor.image.digest`.
2. Pin the `Containerfile`'s base images by digest against your own mirror.
3. Create the four externally managed secrets named in `profile.json`. Policy, actor registry, and
   trust roots are yours to own and rotate; none is baked into the image. The actor-registry secret
   needs one governance-signed registry document per tenant, and the trust-root secret needs the
   actor-governance public key alongside the release key — `loomd` will not start without them. The
   document shape and the rollback floor are in
   [`docs/host-profile.md`](../../docs/host-profile.md) §4.3.
4. Substitute your own SPIFFE trust domain and authorized client identities.
5. Re-run the gate.
