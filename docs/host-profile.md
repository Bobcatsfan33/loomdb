# The reference production host profile

loomDB is an **embedded, one-tenant-per-process engine**. It proves storage integrity, authorization
invariants, provenance, taint containment, bounded request admission, signed backups, and release
authenticity. It does not own network identity, TLS, process isolation, resource ceilings, key
custody, backup scheduling, or human operations — the deploying organization does.

That split is honest but it is not, on its own, *actionable*. "The host must provide process
isolation" is a sentence a buyer cannot test. This document and the artifacts in
[`deploy/reference`](../deploy/reference) turn it into a configuration a reviewer can read, a gate can
check, and an operator can deploy.

> **What this is not.** It is not an approval to deploy loomDB in production
> ([`enterprise-readiness.json`](enterprise-readiness.json) still records
> `deploymentDecision: "not-approved"`, and this increment does not change that). It is not a managed
> service, and it does not move any host responsibility into the engine. It is a *reference*: the
> posture we support, expressed precisely enough to argue with.

---

## §1 — The shape, and why it is this shape

`loomd` speaks newline-delimited JSON-RPC **over stdio**. It binds no socket. It has no TLS, no
authentication of a network peer, and no tenant router — by construction, not by omission:

```
                pod / host boundary
  ┌──────────────────────────────────────────────────────┐
  │  ┌───────────────┐  loopback   ┌──────────────────┐  │
  │  │  front door   │ ──────────▶ │  stdio bridge    │  │
  │  │  mTLS 8443    │ 127.0.0.1   │  ▼               │  │
  │  │  (host's)     │             │  loomd  (stdio)  │  │
  │  └───────────────┘             └──────────────────┘  │
  │         ▲                               │            │
  │         │ authorized SPIFFE id          ▼            │
  │         │                        /var/lib/loomd/<t>  │
  └─────────┼──────────────────────────────────────────┬─┘
            │                                          │
      agent runtime                        one tenant, one store
```

**One tenant per process, one process per store.** The tenant is fixed by `LOOM_TENANT` and the store
by `LOOM_DATA_DIR`, both read once at startup. There is no request field that names a tenant, so
there is no request that can reach another tenant's data. Cross-tenant isolation is the shape of the
deployment, not a `WHERE tenant = ?` someone forgets — the same structural move as AT-039.

A second tenant is a second workload with its own volume, rendered from its own entry in
[`profile.json`](../deploy/reference/profile.json).

**Consequences of stdio you must design for:**

- **The engine is one sequential stream.** One request, one response, in order. The front door owns
  connection lifecycle, concurrency, and queueing. It must not fan two clients onto one stdio pair
  expecting interleaved replies.
- **Capability tokens do not survive a restart.** The token issuer key is generated per process
  (`TokenIssuer::generate`), so every token minted by a previous process is invalid after a restart.
  Clients must re-open a session on reconnect. This is proven at the process boundary in
  `crates/loom-mcp/tests/host_profile.rs`.
- **Writes must arrive already signed.** Under this profile the engine authenticates every write
  against the actor's registered key, and a signature the *server* applied would prove only that the
  server wrote something. So the client signs `WriteEnvelope::signing_bytes()` with the key of the
  actor it claims to be, off-process, and passes the result as the `signature` argument to `observe`,
  `claim.assert`, and `branch.merge`. It signs only the fields it controls; the engine authenticates
  before it attaches the read-set it captured, so engine-captured provenance is never something a
  client would have had to predict in order to sign.
- **`loomd` has no health endpoint.** A stdio process cannot answer an HTTP probe. The front door
  serves `/healthz` for the pod; the engine's own liveness signal is the process itself — the
  supervisor restarts it when it exits — plus its OTLP instruments in the connected flavour (§4.6).

---

## §2 — The declarative profile

[`deploy/reference/profile.json`](../deploy/reference/profile.json) is the source of truth.
`scripts/render_host_profile.py` validates it and renders the committed Kubernetes manifests and
systemd units; `scripts/verify_host_profile.py` gates all of it in CI.

```sh
python3 scripts/verify_host_profile.py          # validate + drift + rendered controls + tamper battery
python3 scripts/render_host_profile.py --write  # after editing profile.json
```

Rendering is validation-first and **never repairs a declaration**. There is no rendered configuration
that expresses two tenants in one process, an anonymous client, a writable root filesystem, a
permissive policy, or a mounted actor registry the daemon never verifies against — the renderer
refuses to emit one. That is what makes the guarantee structural rather than advisory, and the gate
proves it by applying **69 unsafe postures and requiring every one to be rejected**. A validator
nobody has watched fail is not evidence.

Everything is checked in as real YAML and real unit files, and the gate compares bytes, so what a
reviewer reads is exactly what the declaration produces.

---

## §3 — The controls, and where each one actually lives

| Control | Where it is realized | Checked by |
|---|---|---|
| One tenant per process **and per data directory** | `LOOM_TENANT` + `LOOM_DATA_DIR` per workload; unique tenant ids, volumes, and non-nesting stores | renderer refuses duplicates/nesting; gate re-checks the rendered bytes for a foreign tenant id |
| Authenticated TLS / mesh identity in front of the engine | front door: `require_client_certificate: true`, TLS 1.3, SPIFFE SAN match, explicit authorized identities | gate: front-door config + `authorizedClientIdentities` non-empty |
| No public unauthenticated MCP endpoint | bridge and admin bind `127.0.0.1`; only the mTLS port and a static-200 health port are exposed | gate: bind addresses, NetworkPolicy ingress |
| Non-root, read-only root fs, dedicated writable data mount | `runAsNonRoot`, uid/gid 65532, `readOnlyRootFilesystem: true`, the data volume as the only writable path; distroless `nonroot` image | gate: hardening block, Containerfile `USER`, rendered `runAsUser` |
| seccomp / AppArmor / SELinux | `seccompProfile: RuntimeDefault`, AppArmor `runtime/default`, `seLinuxOptions.type`; systemd `SystemCallFilter=@system-service` with `~@privileged @resources …` | gate rejects `Unconfined`/`unconfined` |
| CPU, memory, file, process, request limits | pod `requests`/`limits` + `LOOM_MAX_REQUEST_BYTES`/`LOOM_REQUESTS_PER_SECOND`/`LOOM_REQUEST_BURST`; systemd `CPUQuota`/`MemoryMax`/`LimitNOFILE`/`TasksMax` | gate bounds each against the engine's accepted ranges |
| Default-deny network policy | `loomd-default-deny` (empty podSelector, both policy types, no rules) + one narrow allow per direction; systemd `IPAddressDeny=any` | gate: the deny object must carry no rules |
| Immutable artifact digest + offline bundle verification | images referenced only by `@sha256:`; `verify-release-bundle` initContainer / `ExecStartPre` runs `loom-bundle-tool verify` with exact kind, id, and version against the mounted trust root | gate: digest shape, no tags, bundle fields present |
| Externally managed policy, actor registry, trust roots | read-only secret mounts at `/etc/loomd/{policy,actors,trust}`, mode `0440`, non-overlapping | gate: `source: secret`, `readOnly`, mode not group-writable |
| **Write authenticity: every MCP write is signature-verified** | `LOOM_ACTOR_REGISTRY_FILE` + `LOOM_ACTOR_GOVERNANCE_KEY_FILE` + `LOOM_ACTOR_MIN_GENERATION` make `loomd` open with `Loom::open_production_attested`; a missing or unverifiable registry stops startup | gate: all three rendered exactly once per tenant, in both flavours, pointing at that tenant's own registry; `crates/loom-mcp/tests/actor_registry.rs` proves it at the process boundary |
| **Scheduled, verified, retained, rehearsed backups** | four CronJobs / templated timers per tenant against a point-in-time clone; writer and verifier are separate identities holding separate secrets; retention with legal hold; rehearsal to a fresh path (§8) | gate: no job mounts a live tenant claim, the verifier never mounts the signing key, the rehearsal never names a data directory and mounts the shelf read-only, alerts read only signals `loomctl` writes; `crates/loomctl/tests/backup_operations.rs` |
| No service-account token unless documented | `automountServiceAccountToken: false` on both the ServiceAccount and the pod | gate: `true` requires a written justification; a stale justification with no token is also rejected |
| Health + fixed-cardinality metrics | front-door `/healthz` liveness/readiness probes; the four `loomd.rpc.*` instruments over HTTPS OTLP **in the connected flavour only** (§4.6) | gate: instruments ⊆ what the daemon emits, tenant-bearing dimensions stay forbidden, and telemetry cannot be enabled on a build with no exporter |

Least privilege is per container, not per pod: the bundle verifier sees only the trust root, the
engine never sees the proxy's private key, and the proxy never sees the policy or the actor registry.

---

## §4 — What the host must supply

The profile renders configuration for these; it does not ship them, because shipping them would move
host responsibilities into loomDB.

1. **The front door.** An mTLS terminator (Envoy here; a mesh sidecar is equivalent) that
   authenticates the client, authorizes its identity explicitly, and forwards to the loopback bridge.
   *Requirements:* require a client certificate; authorize named identities, not "any valid cert";
   TLS ≥ 1.2 (1.3 in the reference); never bind the bridge or its own admin interface off-host;
   serialize requests onto the engine's single stdio stream.
2. **The stdio bridge.** Whatever adapts the loopback socket to `loomd`'s stdin/stdout — socket
   activation, a supervisor, or the proxy spawning it as a child. It must be loopback-only and must
   not multiplex two clients onto one engine process.
3. **Secrets.** The reviewed `PolicySet`, the governance-signed actor registry, the release trust
   root and bundle, the actor-governance trust root, and the front door's certificate, key, and
   client CA. All rotate outside this repository.

   The **actor registry** is one JSON document per tenant, on the `/etc/loomd/actors` mount:

   ```json
   {
     "schemaVersion": 1,
     "actors": { "alpha-agent": "<64 hex characters — an Ed25519 verifying key>" },
     "attestation": { "tenant": "alpha-corp", "generation": 7, "fingerprint": "…", "signature": [ … ] }
   }
   ```

   `attestation` is the serialized `ActorRegistryAttestation` your governance process issues offline
   with `ActorRegistryAttestation::issue(tenant, generation, keys, &governance_signing_key)`. The
   **rollback floor** (`actorRegistryMinGeneration` in `profile.json`) is deployment configuration,
   not part of the registry: raising it after a revocation must be a change a reviewer sees in the
   manifest, never a number the compromised material could carry. `loomd` refuses a floor of `0`.

4. **The trust-root ceremony — twice, for two different authorities.** The loomDB release public key
   must arrive through a separate, authenticated channel. A digest published beside an artifact by a
   storage vendor is **not** a substitute for the signature: `loom-bundle-tool verify` checks the
   loomDB trust-root signature over the manifest, the payload's BLAKE3 hash inside that signed
   manifest, and the exact approved kind/id/version.

   The **actor-governance** public key is a second, independent trust root — it answers "who may
   write into this tenant", not "is this build ours" — and the profile refuses to let one key serve
   both roles, or to let the governance key be delivered on the same mount as the registry it signs.
5. **Monitoring and operations.** OTLP collection with mTLS, alerting on the denial/error rate and
   latency SLO burn, and the human on-call and incident procedures the readiness manifest still
   records as open external gates.
6. **A decision about telemetry, because the build and the switch must agree.** The reference image is
   `--no-default-features --features airgap`, which compiles the OTLP exporter out entirely — so the
   profile renders *no* `LOOM_OTEL_ENABLED`, no OTLP endpoint, and `egress: []`. Setting the variable
   on that binary would configure nothing, and the gate refuses the combination rather than letting
   the manifests advertise a metrics pipeline that cannot exist. It refuses the mirror image too:
   linking the exporter into a build that never enables it is attack surface carried for nothing.

   For the **connected** flavour, build
   `--no-default-features --features airgap,observability` — telemetry *and* still no
   object-storage client anywhere in the graph — then set `image.build` to match, flip
   `observability.enabled`, and add the collector to `egressAllowed`. The gate then validates the
   instruments and the forbidden dimensions. Telemetry is never a reason to reintroduce an S3
   client.

   **Storage posture and telemetry are orthogonal, and all four corners are built.** Until P7.1 a
   blanket `compile_error!` in `crates/loom-mcp/src/lib.rs` rejected `airgap,observability`
   outright, so the connected flavour this section documents — and that the profile validator
   accepted — could not actually be compiled. Nothing caught it, because nothing built it. The guard
   is now narrowed to what is genuinely contradictory (both storage postures at once, or neither
   declared), and `scripts/verify_build_flavours.sh` compiles all four flavours, requires each
   forbidden combination to be rejected by name, and checks that each graph links what its flavour
   claims — including that the connected air-gap flavour *does* carry an exporter, so it cannot
   advertise a pipeline it could not serve.

   Either way the pod's health signal is the front door's `/healthz`, because a stdio process cannot
   answer a probe.

---

## §5 — Deploying it

```sh
# 1. Build and record the digest.
podman build -f deploy/reference/Containerfile -t loomd:local .
#    Put the resulting digest in profile.json (image.digest) and set digestIsPlaceholder to false.

# 2. Re-render and gate.
python3 scripts/render_host_profile.py --write
python3 scripts/verify_host_profile.py

# 3. Create the externally managed secrets (names come from profile.json).
kubectl -n loomdb-reference create secret generic loomd-policy       --from-file=alpha.json=…
#    One governance-signed registry document per tenant; the file names come from
#    tenants[].actorRegistryFile.
kubectl -n loomdb-reference create secret generic loomd-actor-registry \
    --from-file=alpha.json=… --from-file=beta.json=…
#    Two independent trust roots: the release key, and the actor-governance key.
kubectl -n loomdb-reference create secret generic loomd-trust-root \
    --from-file=loom-release.pub=… --from-file=loomd.bundle=… \
    --from-file=actor-governance.pub=…
kubectl -n loomdb-reference create secret tls     loomd-frontdoor-identity --cert=… --key=…

# 4. Apply in order. The namespace's restricted Pod Security Standard and the default-deny
#    NetworkPolicy must exist before any workload.
kubectl apply -f deploy/reference/kubernetes/
```

The systemd profile is the same posture without Kubernetes: `loomd@.service` is templated, so
`systemctl enable --now loomd@alpha` starts exactly one tenant from
`/etc/loomd/loomd-alpha.env`. `RequiresMountsFor=` means an unmounted store stops startup rather than
serving an empty one.

**Adding a tenant** is one entry in `profile.json` plus `--write`. It is never a change to an existing
workload.

---

## §6 — What this profile does NOT give you

Stated plainly, in the spirit of [the threat model](threat-model.md) §3.

1. **The committed image digests are declared placeholders.** `image.digest` and
   `frontDoor.image.digest` are all-zero and all-one sha256 values with
   `digestIsPlaceholder: true`, because this repository publishes no image. The digest-pinning
   *mechanism* is real and enforced — a tag cannot be rendered — but the specific digests are yours
   to supply. The gate cannot tell whether you did.
2. **The base images in the Containerfile are pinned by version tag, not digest.** The deployment
   manifests are digest-only; the build recipe is not. Mirror and pin them for a reproducible build.
3. **No timing or shared-hardware isolation.** Per threat model §3.4, one process per tenant plus
   bounded admission stops one tenant from *naming or entering* another's data. It does not address
   cache, memory-bandwidth, or scheduler side channels. If those are in scope, use dedicated nodes or
   confidential compute; this profile does not provide them.
4. **The resource numbers are a starting point, not a sizing model.** 2 CPU / 4 GiB / 50 GiB per
   tenant is a plausible default. No capacity study backs it.
5. **Nothing here has run in a Fortune 500 production topology.** The manifests are gated for
   internal consistency and posture. They have not been applied to a production cluster by us, no
   third party has assessed them, and no recovery exercise has been run against them.
6. **Recovery objectives are declared, not measured.** Backups now run on a schedule, are verified
   from a separate trust domain, are retained under policy with legal hold, and are rehearsed (§8).
   What is *not* here is a number anyone measured: no RPO or RTO has been established on
   customer-scale data using the target storage stack, and the rendered `maxAgeSeconds` is a
   threshold the profile enforces, not a recovery objective the deployment has met. The rehearsal
   proves the restore path works on the shelf it can reach; it does not prove your CSI driver, your
   backup product, or your mount options behave. `RES-01` and the `EXT-DR` gate remain open.
7. **HSM/KMS key custody is unchanged.** The signing boundary is still an exported Ed25519 seed in a
   protected CI environment (see [operations.md](operations.md)). `CRYPTO-01` and `EXT-HSM` remain
   open. This applies to the actor-governance key too: `loomd` only ever *verifies* with it, and it
   is never present on the engine's host — but where it is custodied, and how a compromise is
   revoked, is still yours.
8. **Write authenticity now holds, and stops exactly at the signature.** `loomd` opens attested, so a
   write over MCP verifies against the key of the actor it claims to be (§3, and
   `crates/loom-mcp/tests/actor_registry.rs`). What that proves is that *the holder of that actor's
   key signed these bytes*. It does not prove the holder is the person or system you think it is,
   that the key has not been stolen, or that the agent was not manipulated into signing something
   truthful-looking — key custody at the client is the deploying organization's, and prompt
   injection is contained by the policy engine, not by a signature.

---

## §7 — Verifying the profile yourself

| Claim | Command | Expected |
|---|---|---|
| Profile valid, artifacts current, unsafe postures rejected | `python3 scripts/verify_host_profile.py` | `69 unsafe postures rejected` |
| Rendering is deterministic | `python3 scripts/render_host_profile.py --check` | no drift |
| Restart reopens the same store, integrity intact | `cargo test -p loom-mcp --test host_profile` | green |
| A repointable or shared-writable store stops startup | same test file | green |
| A second process cannot take an owned store | same test file (`a_second_process_cannot_take_a_store_that_is_already_owned`) | green |
| **`loomd` verifies writes against the mounted registry** | `cargo test -p loom-mcp --test actor_registry` | green — an unsigned, impersonated, or unregistered write is refused |
| **A stale, tampered, or unloadable registry stops startup** | same test file | green — and never falls back to an unauthenticated open |
| The same restart and ownership criteria hold attested | same test file | green |
| Write authenticity / registry attestation (library) | `cargo test -p loom-branch --release --test acceptance at_026` | green |
| The image links no object-storage client | `cargo tree -p loom-mcp --no-default-features --features airgap -e no-dev \| grep object_store` | no output |
| Backups are scheduled, verified, retained, and rehearsed | `cargo test -p loomctl --test backup_operations` | green |
| A backup cannot be taken from a store a daemon holds | same test file (`a_backup_cannot_be_taken_from_a_store_a_daemon_is_holding`) | green — this is why the profile schedules against a clone |
| A legal hold outranks retention | same test file | green |
| Enterprise evidence still consistent | `python3 scripts/verify_enterprise_readiness.py` | valid, `decision=not-approved` |

---

## §8 — Backup operations

The signed-backup *mechanism* — an atomic publish, a manifest allow-list, a detached Ed25519
signature over the exact manifest bytes, a restore that refuses to overwrite — is described in
[backup-restore.md](backup-restore.md) and is unchanged. This section is the *operations* the profile
renders around it, and everything in it follows from one fact.

### §8.1 — A backup cannot read a live store

`FileRefStore::open` takes an **exclusive** advisory lock on `<store>/loom/store.lock` and holds it
for the process lifetime. A scheduled job pointed at the volume `loomd` is serving therefore fails
with *"already open by another process"* — every night, forever. That is not a theory; it is
`a_backup_cannot_be_taken_from_a_store_a_daemon_is_holding` in
`crates/loomctl/tests/backup_operations.rs`.

So the profile declares a **point-in-time source** the platform provides:

```jsonc
"pointInTimeSource": {
  "kind": "csi-volume-snapshot-clone",       // or storage-array-clone, filesystem-snapshot
  "claimTemplate": "loomd-snapshot-{tenant}" // never a tenant's live volumeClaim
}
```

The platform snapshots the tenant volume and binds the result as that claim; the backup job mounts
it read-only. The renderer refuses a `claimTemplate` that would render a live claim or that serves
two tenants from one source, and the gate re-checks it on the emitted `claimName:` lines. **Taking
the snapshot is the host's job** — loomDB does not call a Kubernetes API and mounts no service-account
token to do so.

### §8.2 — Four roles, two identities, and why they are not one

| Role | Command | Runs as | Mounts |
|---|---|---|---|
| `backup` | `loomctl backup-signed --root` against the clone | `loomd-backup` | the signing key, owner-only `0400` |
| `verify` | `loomctl verify-backup-signed --root` (newest on the shelf) | `loomd-backup-verifier` | the public trust root |
| `prune` | `loomctl backup-prune --apply` | `loomd-backup` | the legal-hold register |
| `rehearsal` | `loomctl restore-signed --root --out-root` (fresh path) | `loomd-backup-verifier` | the public trust root |

The writer mints its destination and the readers resolve the newest backup themselves: neither is
handed a path by the other, because they run at different times as different identities and share
nothing but the shelf. An **empty shelf is an error**, so a pipeline that quietly stopped producing
backups cannot report success forever.

**A signature is worth the independence of the party checking it.** So the writer and the verifier
are different identities holding different secrets, delivered on different mounts, and neither can do
the other's job: the verifier cannot produce a backup, and the writer cannot mint the verification
that blesses one. The gate checks this per rendered job, in both flavours — a verifier that mounted
the signing key, or a job that mounted both, is rejected.

The engine pod carries none of this. A volume declared on a pod projects its secret whether or not a
container mounts it, so the tenant workload declares exactly the volumes its containers use, and the
gate refuses a tenant manifest that names any backup secret.

### §8.3 — Retention, legal hold, and the immutable copy

Retention keeps a copy for any of three reasons — a legal hold names it, it is one of the newest
`minimumCopies`, or it is younger than `keepDays` — and is a dry run until `--apply`. It refuses to
run inside a live store, never follows a symlink, and never deletes what it does not positively
recognize as a backup.

The copy that survives a compromise of the deployment is the host's, and the profile makes the
declaration checkable rather than aspirational: a **named** WORM mechanism, a retention window at
least as long as local retention, and **off-account**, all required. `object-lock` *governance* mode
is rejected — a principal holding the bypass permission can delete under it, and that principal is
precisely the adversary an immutable copy exists to survive.

loomDB **cannot write to that target**: no build links an object-storage client, in any profile,
re-proven by the air-gap dependency inspection on every CI run. Replication into it is the platform's
job and the profile says so.

### §8.4 — Signals, and the limits of a number

`loomctl` links no exporter and opens no socket. Each command writes a fixed set of **unlabelled**
Prometheus series atomically to `--metrics-file`; the *path* carries the tenant and the collector
attaches workload labels. No signal carries a tenant identifier, for the same reason `loomd` forbids
a tenant dimension on its RPC instruments.

The profile may only declare signals `loomctl` actually writes, and must declare the ones the alerts
read. The rendered rules fire on a stale backup, a backup nobody verified, a failing job, and
detected damage; the stale rule uses `absent()`, because a job that never ran emits nothing and
silence must not read as health. `maxAgeSeconds` must exceed the backup period — an alert below it
fires forever and gets muted — and may not exceed four periods.

**A metric is an operational record, not an authenticity claim.** `last_success` saying "yesterday"
does not prove a restorable backup exists; only verification against the trust root does. The signals
exist so a *missing* backup is loud.

### §8.5 — What §8 does not give you

- **No measured RPO or RTO.** `maxAgeSeconds` is a threshold the profile enforces, not an objective
  the deployment has met on customer-scale data. See §6.6.
- **The rehearsal proves the restore path, not your storage stack.** It restores from the shelf it
  can reach. Your CSI driver, backup product, mount options, and recovery time are still yours to
  drill — the procedure is in [backup-restore.md](backup-restore.md).
- **Backup key custody is unchanged.** The signing key is on its own owner-only mount and the engine
  never sees it, but the ceremony, custody, and rotation behind it are `CRYPTO-01`/`EXT-HSM`, still
  open.
- **Nothing here has run in a production topology**, per §6.5. The jobs are gated for internal
  consistency and posture; no third party has assessed them and no recovery exercise has been run
  against them.
