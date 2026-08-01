#!/usr/bin/env python3
"""Gate the reference production host profile.

Three checks, in order:

1. **The committed profile is valid** and the rendered Kubernetes/systemd artifacts are current, so
   what a reviewer reads is what the declaration produces.
2. **The rendered text upholds the controls that live in the output**, not just in the declaration —
   one tenant per manifest, no permissive-policy escape hatch anywhere, every image by digest.
3. **The gate actually fires.** Every unsafe posture is applied to an in-memory copy of the profile
   and must be rejected. A validator nobody has watched fail is not evidence; this is the same
   discipline as the false-approval check in the enterprise-readiness job.

Run it:
    python3 scripts/verify_host_profile.py
"""

from __future__ import annotations

import copy
import json
import pathlib
import re
import sys
from typing import Any, Callable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import backup_operations  # noqa: E402
from render_host_profile import (  # noqa: E402
    PROFILE,
    RENDER_ROOT,
    ProfileError,
    drift,
    render,
    validate,
    volume_name,
)


def load_raw() -> dict[str, Any]:
    return json.loads(PROFILE.read_text(encoding="utf-8"))


# ── 2. invariants that live in the rendered output ───────────────────────────────────────────────


def check_rendered(profile: dict[str, Any], artifacts: dict[str, str]) -> list[str]:
    """Assert the emitted configuration cannot express the postures the profile forbids."""
    problems: list[str] = []
    tenants = profile["tenants"]
    mounts = profile["externalMounts"]

    for relative, content in sorted(artifacts.items()):
        # The permissive development policy must never be *configured*. A comment may explain why it
        # is absent, so this looks for the variable being set — as a Kubernetes env entry or as a
        # systemd assignment — rather than for the word appearing anywhere.
        for pattern in (
            "name: LOOM_ALLOW_PERMISSIVE_POLICY",
            "LOOM_ALLOW_PERMISSIVE_POLICY=",
            "LOOM_ALLOW_PERMISSIVE_POLICY:",
        ):
            if pattern in content:
                problems.append(f"{relative} configures LOOM_ALLOW_PERMISSIVE_POLICY ({pattern!r})")
        # Every image reference is a digest. A mutable tag would break the immutable-artifact control.
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith(("image:", "- image:")):
                reference = stripped.split(":", 1)[1].strip()
                if "@sha256:" not in reference:
                    problems.append(f"{relative} pins an image by tag, not digest: {reference}")
        if "runAsUser: 0" in content or "runAsUser: root" in content:
            problems.append(f"{relative} would run as root")

    # ── THE CROSS-TENANT ROUTING CHECK, on the rendered bytes ───────────────────────────────────
    # A tenant's manifest must name that tenant and no other. If a rendering bug or a hand edit ever
    # put two tenants' identities or stores in one workload, this fails — the guarantee is checked on
    # the artifact that gets applied, not only on the declaration it came from.
    for tenant in tenants:
        relative = f"kubernetes/30-tenant-{tenant['name']}.yaml"
        content = artifacts.get(relative)
        if content is None:
            problems.append(f"{relative} was not rendered")
            continue
        if f"LOOM_TENANT\n              value: {tenant['tenantId']}" not in content:
            problems.append(f"{relative} does not set LOOM_TENANT to {tenant['tenantId']}")
        if content.count("name: LOOM_TENANT") != 1:
            problems.append(f"{relative} sets LOOM_TENANT more than once")
        if content.count("name: LOOM_DATA_DIR") != 1:
            problems.append(f"{relative} sets LOOM_DATA_DIR more than once")

        # ── THE WRITE-AUTHENTICITY CHECK, on the rendered bytes ─────────────────────────────────
        # Mounting an actor registry and not enforcing it was the honest gap this increment closes.
        # It is checked here, on the manifest that gets applied, because the daemon opens attested
        # only if all three variables reach it: a rendering that mounted `/etc/loomd/actors` and set
        # none of them would produce exactly the registry-declared-but-unattested daemon we removed.
        for variable, expected in (
            ("LOOM_ACTOR_REGISTRY_FILE", tenant["actorRegistryFile"]),
            (
                "LOOM_ACTOR_GOVERNANCE_KEY_FILE",
                profile["writeAuthentication"]["governanceKeyPath"],
            ),
            ("LOOM_ACTOR_MIN_GENERATION", str(tenant["actorRegistryMinGeneration"])),
        ):
            if content.count(f"name: {variable}") != 1:
                problems.append(f"{relative} must set {variable} exactly once")
            if not any(
                f"name: {variable}\n              value: {form}" in content
                for form in (expected, f'"{expected}"')
            ):
                problems.append(f"{relative} does not set {variable} to {expected}")
        # Telling the daemon to verify against a registry it cannot read is a daemon that will not
        # start. The mount must actually be projected into the engine container, read-only.
        registry_mount = (
            f"- name: {volume_name('actorRegistry')}\n"
            f"              mountPath: {mounts['actorRegistry']['mountPath']}\n"
            "              readOnly: true"
        )
        if registry_mount not in content:
            problems.append(
                f"{relative} does not mount the actor registry read-only into the engine container, "
                "so the registry the daemon is told to verify against would not be there"
            )

        for other in tenants:
            if other["name"] == tenant["name"]:
                continue
            if other["tenantId"] in content:
                problems.append(
                    f"{relative} names another tenant's id {other['tenantId']!r}; one process "
                    "must serve exactly one tenant"
                )
            if other["dataDir"] in content:
                problems.append(
                    f"{relative} names another tenant's data directory {other['dataDir']!r}"
                )
            if other["actorRegistryFile"] in content:
                problems.append(
                    f"{relative} names another tenant's actor registry "
                    f"{other['actorRegistryFile']!r}; an attestation binds one registry to one "
                    "tenant"
                )

        # The systemd flavour is the same posture without Kubernetes, so it carries the same three
        # variables. A unit that started an unauthenticated daemon would be the gap re-opened on the
        # other deployment path.
        unit_env = f"systemd/loomd-{tenant['name']}.env"
        environment = artifacts.get(unit_env)
        if environment is None:
            problems.append(f"{unit_env} was not rendered")
            continue
        for variable, expected in (
            ("LOOM_ACTOR_REGISTRY_FILE", tenant["actorRegistryFile"]),
            (
                "LOOM_ACTOR_GOVERNANCE_KEY_FILE",
                profile["writeAuthentication"]["governanceKeyPath"],
            ),
            ("LOOM_ACTOR_MIN_GENERATION", str(tenant["actorRegistryMinGeneration"])),
        ):
            if f"\n{variable}={expected}\n" not in environment:
                problems.append(f"{unit_env} does not set {variable} to {expected}")

    namespace = artifacts["kubernetes/00-namespace.yaml"]
    if "pod-security.kubernetes.io/enforce: restricted" not in namespace:
        problems.append("the namespace does not enforce the restricted Pod Security Standard")
    if "automountServiceAccountToken: false" not in namespace:
        problems.append("the service account still mounts a token")

    policy = artifacts["kubernetes/10-network-policy.yaml"]
    # Default deny: an empty pod selector plus both policy types, with no rules under the deny object.
    if "podSelector: {}" not in policy:
        problems.append("the network policy does not select every pod for default deny")
    deny = policy.split("---")[0]
    for required in ("- Ingress", "- Egress"):
        if required not in deny:
            problems.append(f"the default-deny network policy is missing policyType {required}")
    if "ingress:" in deny or "egress:" in deny:
        problems.append(
            "the default-deny network policy carries rules; it must deny by naming both policy "
            "types with no rules at all"
        )

    front_door = artifacts["kubernetes/20-front-door-config.yaml"]
    declared = profile["frontDoor"]
    if "require_client_certificate: true" not in front_door:
        problems.append("the front door does not require a client certificate")
    # Scalars are emitted quoted (see to_yaml); accept either form so the check tracks the control and
    # not the quoting style.
    if not any(
        f"address: {form}" in front_door
        for form in (declared["bridgeBindAddress"], f'"{declared["bridgeBindAddress"]}"')
    ):
        problems.append("the stdio bridge is not bound to loopback")
    if not any(
        f"address: {form}" in front_door
        for form in (declared["adminBindAddress"], f'"{declared["adminBindAddress"]}"')
    ):
        problems.append("the proxy admin interface is not bound to loopback")
    # Every authorized client must be an *authenticated* identity, not merely a valid certificate.
    for identity in declared["authorizedClientIdentities"]:
        if identity not in front_door:
            problems.append(f"the front door does not authorize {identity}")
    if "authenticated:" not in front_door:
        problems.append(
            "the front door authorizes by something other than an authenticated principal; a valid "
            "certificate alone must not be sufficient"
        )

    unit = artifacts["systemd/loomd@.service"]
    for required in ("ProtectSystem=strict", "NoNewPrivileges=yes", "IPAddressDeny=any"):
        if required not in unit:
            problems.append(f"the systemd unit is missing {required}")
    if "CapabilityBoundingSet=\n" not in unit:
        problems.append("the systemd unit does not empty the capability bounding set")

    problems.extend(check_container_image(profile))
    problems.extend(check_backup_operations(profile, artifacts))
    problems.extend(check_signal_catalogue())
    return problems


def check_signal_catalogue() -> list[str]:
    """The profile's closed signal list must equal what `loomctl` actually emits.

    `KNOWN_BACKUP_SIGNALS` is the reason a profile cannot wire an alert to a metric nothing writes.
    That is only true while the two stay in step, so this reads the constants out of
    `crates/loomctl/src/metrics.rs` and compares — a signal renamed on one side and not the other
    fails here rather than becoming an alert that silently never fires.
    """
    source = RENDER_ROOT.parents[1] / "crates" / "loomctl" / "src" / "metrics.rs"
    if not source.is_file():
        return [f"{source} is missing; the signal catalogue cannot be checked"]
    emitted = set(re.findall(r'^pub const [A-Z_]+: &str = "([a-z0-9_]+)";', source.read_text(
        encoding="utf-8"
    ), flags=re.MULTILINE))
    declared = backup_operations.KNOWN_BACKUP_SIGNALS
    problems = []
    for signal in sorted(declared - emitted):
        problems.append(
            f"backup_operations.KNOWN_BACKUP_SIGNALS names {signal!r}, which loomctl does not emit"
        )
    for signal in sorted(emitted - declared):
        problems.append(
            f"loomctl emits {signal!r}, which the profile's signal catalogue does not know about"
        )
    return problems


def without_comments(content: str) -> str:
    """The configuration a parser would see. A comment explains a control; it cannot violate one."""
    return "\n".join(
        line for line in content.splitlines() if not line.lstrip().startswith("#")
    )


def check_backup_operations(profile: dict[str, Any], artifacts: dict[str, str]) -> list[str]:
    """Assert the rendered backup jobs uphold the controls that live in the emitted configuration."""
    problems: list[str] = []
    backup = profile["backupOperations"]
    mounts = profile["externalMounts"]
    signing_volume = volume_name("backupSigningKey")
    trust_volume = volume_name("backupTrustRoot")

    # ── THE ENGINE POD MUST NEVER MATERIALIZE A BACKUP SECRET ───────────────────────────────────
    # A volume declared on a pod projects its secret whether or not a container mounts it. The
    # engine signs nothing and verifies no backup, so neither the signing key nor its trust root has
    # any business being in that pod.
    for tenant in profile["tenants"]:
        engine = artifacts[f"kubernetes/30-tenant-{tenant['name']}.yaml"]
        for secret in (
            mounts["backupSigningKey"]["secretName"],
            mounts["backupTrustRoot"]["secretName"],
            mounts["retentionHolds"]["secretName"],
        ):
            if secret in engine:
                problems.append(
                    f"kubernetes/30-tenant-{tenant['name']}.yaml projects {secret!r} into the "
                    "engine pod; the engine neither signs nor verifies backups"
                )

    for tenant in profile["tenants"]:
        relative = f"kubernetes/40-backup-{tenant['name']}.yaml"
        content = artifacts.get(relative)
        if content is None:
            problems.append(f"{relative} was not rendered")
            continue

        # ── THE LIVE-VOLUME REFUSAL, ON THE RENDERED BYTES ──────────────────────────────────────
        # loomd holds an exclusive lock on its store, so a job that mounted the live claim would
        # fail every night. Nothing rendered here may mount one. Comments are stripped first: the
        # header explains the refusal by naming the claim, and prose mounts nothing.
        effective = without_comments(content)
        for other in profile["tenants"]:
            if f"claimName: {other['volumeClaim']}" in effective:
                problems.append(
                    f"{relative} mounts the live tenant volume {other['volumeClaim']!r}; the "
                    "engine holds an exclusive lock on it and the job could not read it"
                )
            if other["name"] != tenant["name"] and other["tenantId"] in effective:
                problems.append(
                    f"{relative} names another tenant's id {other['tenantId']!r}; one backup job "
                    "covers exactly one tenant"
                )
        expected_source = backup["pointInTimeSource"]["claimTemplate"].replace(
            "{tenant}", tenant["name"]
        )
        if f"claimName: {expected_source}" not in content:
            problems.append(f"{relative} does not mount the point-in-time source {expected_source}")

        # ── THE SEPARATE TRUST DOMAIN, ON THE RENDERED BYTES ────────────────────────────────────
        # Split the file into its four CronJobs and check, per job, that the writer holds only the
        # signing key and the verifier and rehearsal hold only the public trust root. An independent
        # check performed by whoever produced the artifact is not independent.
        jobs = {}
        for block in content.split("\n---\n"):
            for role in backup_operations.SCHEDULE_ROLES:
                if f"name: loomd-{role}-{tenant['name']}\n" in block:
                    jobs[role] = block
        missing = set(backup_operations.SCHEDULE_ROLES) - set(jobs)
        if missing:
            problems.append(f"{relative} is missing the {sorted(missing)} job(s)")
        for role, block in jobs.items():
            identity = backup_operations.JOB_IDENTITY[role]
            if f"serviceAccountName: {identity}" not in block:
                problems.append(f"{relative} job {role!r} does not run as {identity}")
            holds_signing = signing_volume in block
            holds_trust = trust_volume in block
            if holds_signing and holds_trust:
                problems.append(
                    f"{relative} job {role!r} mounts both the backup signing key and its trust "
                    "root; one secret that both writes and blesses a backup defeats the "
                    "independent check"
                )
            if role == "backup" and not holds_signing:
                problems.append(f"{relative} job {role!r} cannot sign: no signing key is mounted")
            if role in {"verify", "rehearsal"}:
                if holds_signing:
                    problems.append(
                        f"{relative} job {role!r} mounts the backup signing key; the independent "
                        "verifier must not be able to produce what it checks"
                    )
                if not holds_trust:
                    problems.append(
                        f"{relative} job {role!r} cannot verify: no trust root is mounted"
                    )
            if "schedule:" not in block:
                problems.append(f"{relative} job {role!r} has no schedule")
            if "concurrencyPolicy: Forbid" not in block:
                problems.append(
                    f"{relative} job {role!r} allows concurrent runs; two backups publishing into "
                    "one staging root race each other"
                )
            if "automountServiceAccountToken: false" not in block:
                problems.append(f"{relative} job {role!r} mounts a service-account token")
            # Nothing may depend on a per-run identifier the two flavours express differently: the
            # tool mints destinations and resolves the newest backup itself. A rendered `$(…)` would
            # be a job looking for a backup named after itself.
            if "$(" in without_comments(block):
                problems.append(
                    f"{relative} job {role!r} interpolates a runtime variable into its arguments; "
                    "destinations are minted by loomctl so both flavours mean the same thing"
                )
        # The writer mints onto the shelf; the verifier and the rehearsal resolve the newest backup
        # on it. Neither is handed a path by the other.
        for role, expected in (
            ("backup", ["--root"]),
            ("verify", ["--root"]),
            ("rehearsal", ["--root", "--out-root"]),
        ):
            block = jobs.get(role, "")
            for flag in expected:
                if f"- {flag}\n" not in block:
                    problems.append(f"{relative} job {role!r} does not use {flag}")

        # ── THE REHEARSAL MUST NOT BE ABLE TO ACTIVATE OR OVERWRITE ─────────────────────────────
        rehearsal = jobs.get("rehearsal", "")
        if tenant["dataDir"] in rehearsal:
            problems.append(
                f"{relative} rehearsal names tenant {tenant['name']!r}'s live data directory; a "
                "rehearsal restores beside production, never onto it"
            )
        if backup["rehearsal"]["restorePath"] not in rehearsal:
            problems.append(f"{relative} rehearsal does not restore into the rehearsal path")
        if "--out" not in rehearsal or "restore-signed" not in rehearsal:
            problems.append(f"{relative} rehearsal is not a signed restore to a new path")
        # Retention prunes the staging root, so the rehearsal must only ever read it.
        staging_mount = f"- name: staging\n                  mountPath: {backup['stagingPath']}"
        if f"{staging_mount}\n                  readOnly: true" not in rehearsal:
            problems.append(f"{relative} rehearsal mounts the backup shelf writable")

        prune = jobs.get("prune", "")
        if "--legal-hold-file" not in prune:
            problems.append(f"{relative} retention runs with no legal-hold register")
        for tenant_any in profile["tenants"]:
            if tenant_any["dataDir"] in prune:
                problems.append(f"{relative} retention is pointed at a live store")

    # ── THE ALERTS MUST READ SIGNALS SOMETHING ACTUALLY WRITES ──────────────────────────────────
    alerts = artifacts["kubernetes/50-backup-alerts.yaml"]
    for signal in backup_operations.REQUIRED_BACKUP_SIGNALS:
        if signal not in alerts:
            problems.append(f"the rendered alerts do not read {signal}")
    if f"> {backup['maxAgeSeconds']}" not in alerts:
        problems.append("the stale-backup alert does not use the declared maxAgeSeconds")
    if "absent(loomdb_backup_last_success_timestamp_seconds)" not in alerts:
        problems.append(
            "the stale-backup alert does not fire when the signal is absent; a job that never ran "
            "emits nothing, and silence must not read as health"
        )
    for tenant in profile["tenants"]:
        if tenant["tenantId"] in alerts:
            problems.append(
                f"the rendered alerts name tenant {tenant['tenantId']!r}; these series are "
                "unlabelled and the collector attaches workload labels itself"
            )

    # ── THE SYSTEMD FLAVOUR MUST MEAN THE SAME THING ────────────────────────────────────────────
    for role in backup_operations.SCHEDULE_ROLES:
        timer = artifacts.get(f"systemd/loomd-{role}@.timer")
        unit = artifacts.get(f"systemd/loomd-{role}@.service")
        if timer is None or unit is None:
            problems.append(f"the systemd flavour is missing the {role!r} service or timer")
            continue
        if "INVALID(" in timer:
            problems.append(
                f"systemd/loomd-{role}@.timer could not express the cron schedule exactly"
            )
        if "Persistent=true" not in timer:
            problems.append(
                f"systemd/loomd-{role}@.timer skips a run the host was down for instead of "
                "catching it up"
            )
        if "IPAddressDeny=any" not in unit:
            problems.append(f"systemd/loomd-{role}@.service does not deny outbound addresses")
        if role == "backup" and backup["signingKeyPath"] not in unit:
            problems.append("the systemd backup unit does not sign with the declared key")
        if role in {"verify", "rehearsal"} and backup["signingKeyPath"] in unit:
            problems.append(
                f"systemd/loomd-{role}@.service reads the backup signing key; the independent "
                "verifier must not be able to produce what it checks"
            )
        for tenant in profile["tenants"]:
            if tenant["dataDir"] in unit:
                problems.append(
                    f"systemd/loomd-{role}@.service names a live tenant store; the engine holds an "
                    "exclusive lock on it"
                )
    return problems


def check_container_image(profile: dict[str, Any]) -> list[str]:
    """The image build must match the identity and posture the manifests assume."""
    problems: list[str] = []
    path = RENDER_ROOT / "Containerfile"
    if not path.is_file():
        return [f"{path.name} is missing"]
    content = path.read_text(encoding="utf-8")
    hardening = profile["hardening"]

    expected_user = f"USER {hardening['runAsUser']}:{hardening['runAsGroup']}"
    if expected_user not in content:
        problems.append(
            f"Containerfile does not declare '{expected_user}'; the image identity must match the "
            "runAsUser/runAsGroup the manifests enforce"
        )
    if "USER root" in content or "USER 0" in content:
        problems.append("Containerfile runs as root")
    # The image must be the amputated build: no object-storage client compiled in.
    if "--no-default-features" not in content or "airgap" not in content:
        problems.append(
            "Containerfile does not build loomd air-gapped "
            "('--no-default-features --features airgap')"
        )
    if "--locked" not in content:
        problems.append("Containerfile does not build --locked against the reviewed graph")
    for line in content.splitlines():
        if line.startswith("FROM ") and ":latest" in line:
            problems.append(f"Containerfile floats a base image on :latest: {line.strip()}")
    return problems


# ── 3. the gate must fire ───────────────────────────────────────────────────────────────────────


def with_change(mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    document = load_raw()
    mutate(document)
    return document


def unsafe_postures() -> list[tuple[str, Callable[[dict[str, Any]], None]]]:
    """Every posture the reference profile must refuse to express."""

    def share_tenant_id(document: dict[str, Any]) -> None:
        document["tenants"][1]["tenantId"] = document["tenants"][0]["tenantId"]

    def share_data_dir(document: dict[str, Any]) -> None:
        document["tenants"][1]["dataDir"] = document["tenants"][0]["dataDir"]

    def nest_data_dir(document: dict[str, Any]) -> None:
        document["tenants"][1]["dataDir"] = document["tenants"][0]["dataDir"] + "/nested"

    def share_volume(document: dict[str, Any]) -> None:
        document["tenants"][1]["volumeClaim"] = document["tenants"][0]["volumeClaim"]

    def share_name(document: dict[str, Any]) -> None:
        document["tenants"][1]["name"] = document["tenants"][0]["name"]

    def run_as_root(document: dict[str, Any]) -> None:
        document["hardening"]["runAsUser"] = 0

    def writable_root(document: dict[str, Any]) -> None:
        document["hardening"]["readOnlyRootFilesystem"] = False

    def allow_privilege_escalation(document: dict[str, Any]) -> None:
        document["hardening"]["allowPrivilegeEscalation"] = True

    def keep_capabilities(document: dict[str, Any]) -> None:
        document["hardening"]["dropCapabilities"] = ["NET_BIND_SERVICE"]

    def unconfined_seccomp(document: dict[str, Any]) -> None:
        document["hardening"]["seccompProfile"] = "Unconfined"

    def unconfined_apparmor(document: dict[str, Any]) -> None:
        document["hardening"]["apparmorProfile"] = "unconfined"

    def mount_token(document: dict[str, Any]) -> None:
        document["hardening"]["automountServiceAccountToken"] = True

    def stale_token_justification(document: dict[str, Any]) -> None:
        document["hardening"]["serviceAccountTokenJustification"] = "used to be needed"

    def anonymous_clients(document: dict[str, Any]) -> None:
        document["frontDoor"]["requireClientCertificate"] = False

    def any_valid_certificate(document: dict[str, Any]) -> None:
        document["frontDoor"]["authorizedClientIdentities"] = []

    def weak_tls(document: dict[str, Any]) -> None:
        document["frontDoor"]["minimumTlsVersion"] = "TLSv1_0"

    def expose_the_bridge(document: dict[str, Any]) -> None:
        document["frontDoor"]["bridgeBindAddress"] = "0.0.0.0"

    def expose_admin(document: dict[str, Any]) -> None:
        document["frontDoor"]["adminBindAddress"] = "0.0.0.0"

    def mutable_image(document: dict[str, Any]) -> None:
        document["image"]["digest"] = "latest"

    def unpinned_proxy(document: dict[str, Any]) -> None:
        document["frontDoor"]["image"]["digest"] = "v1.31-latest"

    def drop_bundle_verification(document: dict[str, Any]) -> None:
        del document["image"]["bundle"]["publicKeyPath"]

    def ship_an_object_store_client(document: dict[str, Any]) -> None:
        document["image"]["build"] = "--release"

    def bake_in_the_policy(document: dict[str, Any]) -> None:
        document["externalMounts"]["policy"]["source"] = "image"

    def writable_secret(document: dict[str, Any]) -> None:
        document["externalMounts"]["policy"]["mode"] = "0460"

    def writable_trust_root(document: dict[str, Any]) -> None:
        document["externalMounts"]["trustRoot"]["readOnly"] = False

    def overlapping_mounts(document: dict[str, Any]) -> None:
        document["externalMounts"]["trustRoot"]["mountPath"] = document["externalMounts"]["policy"][
            "mountPath"
        ]

    def policy_outside_the_mount(document: dict[str, Any]) -> None:
        document["tenants"][0]["policyFile"] = "/tmp/policy.json"

    def permissive_policy_file(document: dict[str, Any]) -> None:
        document["tenants"][0]["policyFile"] = "/etc/loomd/policy/permissive.json"

    def no_policy_at_all(document: dict[str, Any]) -> None:
        del document["tenants"][0]["policyFile"]

    def unbounded_requests(document: dict[str, Any]) -> None:
        document["limits"]["maxRequestBytes"] = 1024 * 1024 * 1024

    def no_process_limit(document: dict[str, Any]) -> None:
        del document["limits"]["processes"]

    def invented_metric(document: dict[str, Any]) -> None:
        document["observability"]["instruments"].append("loomd.rpc.tenant_detail")

    def unbounded_cardinality(document: dict[str, Any]) -> None:
        document["observability"]["forbiddenDimensions"].remove("tenant")

    def plaintext_telemetry(document: dict[str, Any]) -> None:
        document["observability"]["otlpEndpoint"] = "http://collector:4317"

    def telemetry_without_an_exporter(document: dict[str, Any]) -> None:
        # No `observability` feature in the build, so LOOM_OTEL_ENABLED would configure nothing.
        document["observability"]["enabled"] = True

    def exporter_linked_but_unused(document: dict[str, Any]) -> None:
        # The mirror image: attack surface carried for a pipeline that is switched off.
        document["image"]["build"] = "--no-default-features --features airgap,observability"

    def telemetry_off_without_a_reason(document: dict[str, Any]) -> None:
        del document["observability"]["disabledReason"]

    def widen_egress_to_the_front_door(document: dict[str, Any]) -> None:
        # Start from a *valid* connected profile, so this posture tests the egress rule and not the
        # telemetry coupling that would otherwise reject it first.
        document["observability"]["enabled"] = True
        document["image"]["build"] = "--no-default-features --features airgap,observability"
        document["observability"].pop("disabledReason", None)
        document["egressAllowed"].append(
            {
                "description": "oops",
                "namespace": "anywhere",
                "port": document["frontDoor"]["listenPort"],
            }
        )

    def egress_without_telemetry(document: dict[str, Any]) -> None:
        document["egressAllowed"].append(
            {"description": "unused hole", "namespace": "observability", "port": 4317}
        )

    def no_tenants(document: dict[str, Any]) -> None:
        document["tenants"] = []

    # ── the postures that would re-open the write-authenticity gap ──────────────────────────────
    #
    # Each of these renders a daemon that mounts a governance-signed actor registry and then does not
    # verify against it — writes attributable but not authenticated, which is precisely what
    # docs/host-profile.md §6 used to have to admit. None of them can be expressed.

    def mount_the_registry_but_never_enforce_it(document: dict[str, Any]) -> None:
        del document["tenants"][0]["actorRegistryFile"]

    def registry_outside_the_governed_mount(document: dict[str, Any]) -> None:
        document["tenants"][0]["actorRegistryFile"] = "/tmp/actors.json"

    def share_one_registry_between_tenants(document: dict[str, Any]) -> None:
        document["tenants"][1]["actorRegistryFile"] = document["tenants"][0]["actorRegistryFile"]

    def no_rollback_floor(document: dict[str, Any]) -> None:
        del document["tenants"][0]["actorRegistryMinGeneration"]

    def a_rollback_floor_that_accepts_everything(document: dict[str, Any]) -> None:
        document["tenants"][0]["actorRegistryMinGeneration"] = 0

    def governance_key_beside_the_registry_it_signs(document: dict[str, Any]) -> None:
        document["writeAuthentication"]["governanceKeyPath"] = (
            document["externalMounts"]["actorRegistry"]["mountPath"] + "/governance.pub"
        )

    def one_key_for_releases_and_actors(document: dict[str, Any]) -> None:
        document["writeAuthentication"]["governanceKeyPath"] = document["image"]["bundle"][
            "publicKeyPath"
        ]

    def no_write_authentication_at_all(document: dict[str, Any]) -> None:
        del document["writeAuthentication"]

    return [
        ("two tenants share one tenant id", share_tenant_id),
        ("two tenants share one data directory", share_data_dir),
        ("one tenant's store nests inside another's", nest_data_dir),
        ("two tenants share one volume claim", share_volume),
        ("two tenants share one workload name", share_name),
        ("the engine runs as root", run_as_root),
        ("the root filesystem is writable", writable_root),
        ("privilege escalation is allowed", allow_privilege_escalation),
        ("capabilities are retained", keep_capabilities),
        ("seccomp is unconfined", unconfined_seccomp),
        ("AppArmor is unconfined", unconfined_apparmor),
        ("a service-account token is mounted without justification", mount_token),
        ("a justification outlives the token it described", stale_token_justification),
        ("the front door accepts anonymous clients", anonymous_clients),
        ("any valid certificate is authorized", any_valid_certificate),
        ("TLS below 1.2 is permitted", weak_tls),
        ("the stdio bridge is exposed off-host", expose_the_bridge),
        ("the proxy admin interface is exposed", expose_admin),
        ("the engine image is a mutable tag", mutable_image),
        ("the proxy image is a mutable tag", unpinned_proxy),
        ("offline bundle verification is dropped", drop_bundle_verification),
        ("the image ships an object-storage client", ship_an_object_store_client),
        ("the policy is baked into the image", bake_in_the_policy),
        ("a mounted secret is group-writable", writable_secret),
        ("the trust root is mounted writable", writable_trust_root),
        ("two external mounts overlap", overlapping_mounts),
        ("the policy comes from outside the read-only mount", policy_outside_the_mount),
        ("a permissive policy is named", permissive_policy_file),
        ("a tenant has no policy at all", no_policy_at_all),
        ("request size is unbounded beyond the engine's range", unbounded_requests),
        ("no process limit is set", no_process_limit),
        ("a metric the daemon never emits is wired", invented_metric),
        ("tenant identity is allowed into telemetry dimensions", unbounded_cardinality),
        ("telemetry leaves in plaintext", plaintext_telemetry),
        ("telemetry is enabled with no exporter compiled in", telemetry_without_an_exporter),
        ("the exporter is linked into a build that never uses it", exporter_linked_but_unused),
        ("telemetry is disabled with no reason recorded", telemetry_off_without_a_reason),
        ("egress is opened while telemetry is disabled", egress_without_telemetry),
        ("egress is widened to the front-door port", widen_egress_to_the_front_door),
        ("no tenant is declared", no_tenants),
        ("the actor registry is mounted but never enforced", mount_the_registry_but_never_enforce_it),
        ("the actor registry comes from outside the governed mount", registry_outside_the_governed_mount),
        ("two tenants share one governance-signed actor registry", share_one_registry_between_tenants),
        ("the actor registry has no rollback floor", no_rollback_floor),
        ("the rollback floor accepts every signed generation", a_rollback_floor_that_accepts_everything),
        (
            "the governance key is delivered beside the registry it signs",
            governance_key_beside_the_registry_it_signs,
        ),
        ("one trust root signs both releases and actor registries", one_key_for_releases_and_actors),
        ("write authentication is absent from the profile", no_write_authentication_at_all),
        *backup_operations.unsafe_postures(),
    ]


def run() -> int:
    # 1. the committed profile is valid and the rendered artifacts are current
    raw = load_raw()
    profile = validate(copy.deepcopy(raw))
    artifacts = render(profile)
    stale = drift(artifacts)
    if stale:
        print(
            "host profile artifacts are stale; run "
            "`python3 scripts/render_host_profile.py --write`:",
            file=sys.stderr,
        )
        for relative in stale:
            print(f"  {relative}", file=sys.stderr)
        return 1
    for relative in sorted(artifacts):
        target = RENDER_ROOT / relative
        if target.is_symlink() or not target.is_file():
            print(f"rendered artifact is not a regular file: {relative}", file=sys.stderr)
            return 1

    # 2. the rendered output upholds the controls that live in the output
    problems = check_rendered(profile, artifacts)
    if problems:
        print("rendered host profile violates its own controls:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    # 3. the gate must fire on every unsafe posture
    accepted: list[str] = []
    for description, mutate in unsafe_postures():
        try:
            validate(with_change(mutate))
        except ProfileError:
            continue
        except (KeyError, TypeError, ValueError) as error:
            # A tamper that trips a different guard is still a rejection, but the profile gate should
            # be the thing that names it. Surface it rather than counting it as a pass.
            print(
                f"  NOTE: {description!r} was rejected by {type(error).__name__}: {error}",
                file=sys.stderr,
            )
            continue
        accepted.append(description)
    if accepted:
        print("the host-profile gate ACCEPTED unsafe postures:", file=sys.stderr)
        for description in accepted:
            print(f"  {description}", file=sys.stderr)
        return 1

    print(
        "host profile gate passed: "
        f"{len(profile['tenants'])} tenants, {len(artifacts)} rendered artifacts current, "
        f"{len(unsafe_postures())} unsafe postures rejected"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (OSError, json.JSONDecodeError, ProfileError) as error:
        print(f"host profile verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
