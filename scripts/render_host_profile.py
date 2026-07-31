#!/usr/bin/env python3
"""Validate and render the reference production host profile for loomDB.

`deploy/reference/profile.json` is the declarative source of truth. This module validates it against
the controls the profile is required to uphold, then renders the committed Kubernetes manifests and
systemd units from it. The rendered artifacts are checked in, so a reviewer reads real YAML and a
gate can prove the committed output still matches the declaration.

Two design notes, both deliberate:

* **Validation runs before rendering, and rendering never repairs a profile.** A declaration that
  would place two tenants in one process, expose an unauthenticated port, or relax the deny-by-default
  policy is rejected outright. There is no rendered configuration that expresses those postures, which
  is what makes the guarantee structural instead of advisory.
* **Standard library only.** The repository's whole air-gap posture rests on adding no dependency that
  cannot be verified offline, so the manifests are rendered rather than parsed and the drift gate
  compares bytes. Kubernetes YAML is emitted; nothing here needs a YAML parser.

Usage:
    render_host_profile.py --check    # validate, and fail on drift from the committed artifacts
    render_host_profile.py --write    # validate and rewrite the committed artifacts
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "reference" / "profile.json"
RENDER_ROOT = ROOT / "deploy" / "reference"

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
CPU = re.compile(r"^[0-9]+(\.[0-9]+)?m?$")
QUANTITY = re.compile(r"^[0-9]+(\.[0-9]+)?(Ki|Mi|Gi|Ti)?$")
SPIFFE = re.compile(r"^spiffe://[a-z0-9.-]+/\S+$")

# The instruments `loomd` actually emits (docs/operations.md). A profile may not wire a metric the
# daemon does not produce, and may not add a dimension that would make cardinality unbounded.
KNOWN_INSTRUMENTS = {
    "loomd.rpc.requests",
    "loomd.rpc.failures",
    "loomd.rpc.denied",
    "loomd.rpc.duration",
}
# Dimensions that would carry tenant data or unbounded cardinality into telemetry.
REQUIRED_FORBIDDEN_DIMENSIONS = {
    "tenant",
    "request_id",
    "arguments",
    "token",
}
# The engine's own accepted ranges (crates/loom-mcp/src/admission.rs). A profile outside them would
# not start, so rendering it would be rendering a broken deployment.
MAX_REQUEST_BYTES_RANGE = (256, 16 * 1024 * 1024)
REQUESTS_PER_SECOND_RANGE = (1, 100_000)
REQUEST_BURST_RANGE = (1, 1_000_000)

SECCOMP_PROFILES = {"RuntimeDefault", "Localhost"}
RESERVED_PORTS = {22, 80, 443}


class ProfileError(ValueError):
    """The declared profile violates a control the reference profile must uphold."""


def fail(message: str) -> None:
    raise ProfileError(message)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def require_true(value: Any, label: str) -> bool:
    if value is not True:
        fail(f"{label} must be true in the reference profile")
    return True


def require_false(value: Any, label: str) -> bool:
    if value is not False:
        fail(f"{label} must be false in the reference profile")
    return False


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{label} must be a boolean")
    return value


def require_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        fail(f"{label} must be an integer")
    if not (minimum <= value <= maximum):
        fail(f"{label} must be in {minimum}..={maximum}, got {value}")
    return value


def require_match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    text = require_text(value, label)
    if not pattern.match(text):
        fail(f"{label} does not match {pattern.pattern}: {text!r}")
    return text


def posix_parts(path: str, label: str) -> tuple[str, ...]:
    if not path.startswith("/"):
        fail(f"{label} must be an absolute path, got {path!r}")
    candidate = pathlib.PurePosixPath(path)
    if ".." in candidate.parts:
        fail(f"{label} must not contain '..': {path!r}")
    return candidate.parts


def nests(outer: tuple[str, ...], inner: tuple[str, ...]) -> bool:
    """True when one path contains the other — including when they are identical."""
    shorter, longer = (outer, inner) if len(outer) <= len(inner) else (inner, outer)
    return longer[: len(shorter)] == shorter


# ── validation ──────────────────────────────────────────────────────────────────────────────────


def validate(document: Any) -> dict[str, Any]:
    """Validate the whole profile, returning it unchanged. Raises `ProfileError` on any violation."""
    profile = require_object(document, "profile")
    if profile.get("schemaVersion") != 1:
        fail("schemaVersion must equal 1")
    require_text(profile.get("profile"), "profile.profile")
    require_text(profile.get("description"), "profile.description")
    require_match(NAME, profile.get("namespace"), "profile.namespace")

    validate_image(require_object(profile.get("image"), "image"))
    front_door = validate_front_door(require_object(profile.get("frontDoor"), "frontDoor"))
    validate_hardening(require_object(profile.get("hardening"), "hardening"))
    validate_limits(require_object(profile.get("limits"), "limits"))
    mounts = validate_external_mounts(
        require_object(profile.get("externalMounts"), "externalMounts")
    )
    validate_observability(
        require_object(profile.get("observability"), "observability"), profile["image"]["build"]
    )
    validate_egress(
        require_list(profile.get("egressAllowed"), "egressAllowed"),
        front_door,
        profile["observability"]["enabled"],
    )
    validate_tenants(require_list(profile.get("tenants"), "tenants"), mounts)
    return profile


def validate_image(image: dict[str, Any]) -> None:
    require_text(image.get("repository"), "image.repository")
    # Immutable artifact reference. A tag is mutable by definition, so the profile has no field for
    # one: the only way to name the image is by digest.
    require_match(DIGEST, image.get("digest"), "image.digest")
    require_bool(image.get("digestIsPlaceholder"), "image.digestIsPlaceholder")
    build = require_text(image.get("build"), "image.build")
    if "--no-default-features" not in build or "airgap" not in build:
        fail(
            "image.build must be the air-gap build "
            "('--no-default-features --features airgap'); the reference profile does not ship an "
            "object-storage client"
        )

    bundle = require_object(image.get("bundle"), "image.bundle")
    if bundle.get("kind") != "software":
        fail("image.bundle.kind must be 'software' for a loomd release bundle")
    require_text(bundle.get("id"), "image.bundle.id")
    require_text(bundle.get("version"), "image.bundle.version")
    # Offline bundle verification in the deployment path: the public key is a mounted trust root, not
    # a key fetched at deploy time and not a checksum published beside the artifact.
    public_key = require_text(bundle.get("publicKeyPath"), "image.bundle.publicKeyPath")
    posix_parts(public_key, "image.bundle.publicKeyPath")
    posix_parts(require_text(bundle.get("payloadPath"), "image.bundle.payloadPath"), "payloadPath")
    posix_parts(require_text(bundle.get("bundlePath"), "image.bundle.bundlePath"), "bundlePath")


def validate_front_door(front_door: dict[str, Any]) -> dict[str, Any]:
    require_text(front_door.get("kind"), "frontDoor.kind")
    require_text(front_door.get("implementation"), "frontDoor.implementation")
    # The proxy is a distinct artifact from the engine and is pinned the same immutable way.
    image = require_object(front_door.get("image"), "frontDoor.image")
    require_text(image.get("repository"), "frontDoor.image.repository")
    require_match(DIGEST, image.get("digest"), "frontDoor.image.digest")
    require_bool(image.get("digestIsPlaceholder"), "frontDoor.image.digestIsPlaceholder")
    require_match(SPIFFE, front_door.get("identity"), "frontDoor.identity")
    require_text(front_door.get("trustDomain"), "frontDoor.trustDomain")
    # Authenticated TLS in front of the engine, and no anonymous client.
    require_true(front_door.get("requireClientCertificate"), "frontDoor.requireClientCertificate")
    if front_door.get("minimumTlsVersion") not in {"TLSv1_2", "TLSv1_3"}:
        fail("frontDoor.minimumTlsVersion must be TLSv1_2 or TLSv1_3")

    identities = require_list(
        front_door.get("authorizedClientIdentities"), "frontDoor.authorizedClientIdentities"
    )
    if not identities:
        fail(
            "frontDoor.authorizedClientIdentities must name at least one client; an mTLS listener "
            "that authorizes every valid certificate is an authenticated open door"
        )
    for index, identity in enumerate(identities):
        require_match(SPIFFE, identity, f"frontDoor.authorizedClientIdentities[{index}]")
    if len(set(identities)) != len(identities):
        fail("frontDoor.authorizedClientIdentities contains duplicates")

    listen = require_int(front_door.get("listenPort"), "frontDoor.listenPort", 1024, 65535)
    health = require_int(front_door.get("healthPort"), "frontDoor.healthPort", 1024, 65535)
    bridge = require_int(front_door.get("bridgePort"), "frontDoor.bridgePort", 1024, 65535)
    if len({listen, health, bridge}) != 3:
        fail("frontDoor.listenPort, healthPort, and bridgePort must all differ")
    for label, port in (("listenPort", listen), ("healthPort", health), ("bridgePort", bridge)):
        if port in RESERVED_PORTS:
            fail(f"frontDoor.{label} must not use the well-known port {port}")

    # THE "no public unauthenticated MCP endpoint" CONTROL. `loomd` speaks JSON-RPC over stdio; the
    # bridge that adapts a socket to that stdio must never leave the pod's network namespace, so the
    # only reachable port is the mTLS listener. An admin interface is loopback-only for the same
    # reason — Envoy's admin endpoint can drain listeners and dump config.
    if front_door.get("bridgeBindAddress") != "127.0.0.1":
        fail(
            "frontDoor.bridgeBindAddress must be 127.0.0.1: the stdio bridge is the unauthenticated "
            "path to the engine and must not be reachable off-host"
        )
    if front_door.get("adminBindAddress") != "127.0.0.1":
        fail("frontDoor.adminBindAddress must be 127.0.0.1")
    return front_door


def validate_hardening(hardening: dict[str, Any]) -> None:
    for label in ("runAsUser", "runAsGroup"):
        value = require_int(hardening.get(label), f"hardening.{label}", 1, 2**31 - 1)
        if value == 0:
            fail(f"hardening.{label} must not be 0 (root)")
    require_true(hardening.get("runAsNonRoot"), "hardening.runAsNonRoot")
    require_true(hardening.get("readOnlyRootFilesystem"), "hardening.readOnlyRootFilesystem")
    require_false(hardening.get("allowPrivilegeEscalation"), "hardening.allowPrivilegeEscalation")
    if require_list(hardening.get("dropCapabilities"), "hardening.dropCapabilities") != ["ALL"]:
        fail("hardening.dropCapabilities must be exactly ['ALL']")

    if hardening.get("seccompProfile") not in SECCOMP_PROFILES:
        fail(f"hardening.seccompProfile must be one of {sorted(SECCOMP_PROFILES)}")
    require_text(hardening.get("apparmorProfile"), "hardening.apparmorProfile")
    require_text(hardening.get("seLinuxType"), "hardening.seLinuxType")
    if hardening.get("apparmorProfile") == "unconfined":
        fail("hardening.apparmorProfile must not be 'unconfined'")

    # No service-account token unless a documented integration needs one. Mounting it is allowed only
    # with a written justification, because the default posture is that loomd calls no Kubernetes API.
    automount = require_bool(
        hardening.get("automountServiceAccountToken"), "hardening.automountServiceAccountToken"
    )
    justification = hardening.get("serviceAccountTokenJustification")
    if automount:
        if not isinstance(justification, str) or not justification.strip():
            fail(
                "hardening.automountServiceAccountToken=true requires "
                "hardening.serviceAccountTokenJustification to document the integration that needs it"
            )
    elif justification is not None:
        fail(
            "hardening.serviceAccountTokenJustification must be null when no token is mounted, so a "
            "stale justification cannot outlive the integration it described"
        )


def validate_limits(limits: dict[str, Any]) -> None:
    require_match(CPU, limits.get("cpu"), "limits.cpu")
    require_match(QUANTITY, limits.get("memory"), "limits.memory")
    require_match(QUANTITY, limits.get("ephemeralStorage"), "limits.ephemeralStorage")
    require_int(limits.get("openFiles"), "limits.openFiles", 64, 1_048_576)
    require_int(limits.get("processes"), "limits.processes", 8, 65_536)
    require_int(limits.get("maxRequestBytes"), "limits.maxRequestBytes", *MAX_REQUEST_BYTES_RANGE)
    require_int(
        limits.get("requestsPerSecond"), "limits.requestsPerSecond", *REQUESTS_PER_SECOND_RANGE
    )
    require_int(limits.get("requestBurst"), "limits.requestBurst", *REQUEST_BURST_RANGE)


def validate_external_mounts(mounts: dict[str, Any]) -> dict[str, Any]:
    required = {"policy", "actorRegistry", "trustRoot", "frontDoorIdentity"}
    missing = required - set(mounts)
    if missing:
        fail(f"externalMounts is missing {sorted(missing)}")
    seen_paths: list[tuple[str, tuple[str, ...]]] = []
    for name in sorted(mounts):
        mount = require_object(mounts[name], f"externalMounts.{name}")
        require_text(mount.get("description"), f"externalMounts.{name}.description")
        # Externally managed: policy, actor registry, and trust roots arrive from a secret the
        # deploying organization owns. Baking them into the image would make a rotation a rebuild.
        if mount.get("source") != "secret":
            fail(
                f"externalMounts.{name}.source must be 'secret'; policy, actor registry, and trust "
                "roots are externally managed and must not be baked into the image"
            )
        require_match(NAME, mount.get("secretName"), f"externalMounts.{name}.secretName")
        require_true(mount.get("readOnly"), f"externalMounts.{name}.readOnly")
        mode = require_text(mount.get("mode"), f"externalMounts.{name}.mode")
        if not re.match(r"^0[0-7]{3}$", mode):
            fail(f"externalMounts.{name}.mode must be octal like '0440', got {mode!r}")
        if int(mode, 8) & 0o022:
            fail(f"externalMounts.{name}.mode must not be group- or world-writable ({mode})")
        path = require_text(mount.get("mountPath"), f"externalMounts.{name}.mountPath")
        parts = posix_parts(path, f"externalMounts.{name}.mountPath")
        for other_name, other in seen_paths:
            if nests(parts, other):
                fail(
                    f"externalMounts.{name}.mountPath {path!r} overlaps "
                    f"externalMounts.{other_name}; one mount would shadow the other"
                )
        seen_paths.append((name, parts))
    return mounts


def validate_observability(observability: dict[str, Any], build: str) -> None:
    # THE TELEMETRY/BUILD COUPLING, IN BOTH DIRECTIONS.
    #
    # `LOOM_OTEL_ENABLED=true` on a binary built without the `observability` feature is not
    # "telemetry on" — it is a setting nothing reads, because the exporter is not in the binary.
    # Rendering it would advertise a metrics pipeline that cannot exist. Conversely, linking the
    # exporter into a build that never enables it is attack surface carried for nothing.
    #
    # `validate_image` independently requires the air-gap amputation, so the two supported builds are
    # `--no-default-features --features airgap` (no exporter, no object-storage client) and
    # `--no-default-features --features airgap,observability` (exporter, still no object-storage
    # client). Telemetry is never a reason to reintroduce an S3 client.
    enabled = require_bool(observability.get("enabled"), "observability.enabled")
    exporter_compiled_in = "observability" in build
    if enabled and not exporter_compiled_in:
        fail(
            "observability.enabled is true but image.build does not enable the 'observability' "
            "feature, so no OTLP exporter is compiled in and the setting would configure nothing "
            "(use '--no-default-features --features airgap,observability')"
        )
    if not enabled:
        if exporter_compiled_in:
            fail(
                "image.build compiles the OTLP exporter in while observability.enabled is false; "
                "build without the 'observability' feature rather than carrying unused surface"
            )
        require_text(observability.get("disabledReason"), "observability.disabledReason")

    endpoint = require_text(observability.get("otlpEndpoint"), "observability.otlpEndpoint")
    if not endpoint.startswith("https://"):
        fail("observability.otlpEndpoint must use HTTPS")
    instruments = require_list(observability.get("instruments"), "observability.instruments")
    if not instruments:
        fail("observability.instruments must name the metrics wired for the host's monitoring")
    if len(set(instruments)) != len(instruments):
        fail("observability.instruments contains duplicates")
    unknown = set(instruments) - KNOWN_INSTRUMENTS
    if unknown:
        fail(
            f"observability.instruments names metrics loomd does not emit: {sorted(unknown)} "
            f"(known: {sorted(KNOWN_INSTRUMENTS)})"
        )
    forbidden = require_list(
        observability.get("forbiddenDimensions"), "observability.forbiddenDimensions"
    )
    absent = REQUIRED_FORBIDDEN_DIMENSIONS - set(forbidden)
    if absent:
        fail(
            "observability.forbiddenDimensions must list every unbounded or tenant-bearing "
            f"dimension; missing {sorted(absent)}"
        )


def validate_egress(
    rules: list[Any], front_door: dict[str, Any], telemetry_enabled: bool
) -> None:
    if rules and not telemetry_enabled:
        fail(
            "egressAllowed opens outbound traffic while observability.enabled is false; a "
            "default-deny posture must not carry an exception nothing uses"
        )
    for index, rule in enumerate(rules):
        entry = require_object(rule, f"egressAllowed[{index}]")
        require_text(entry.get("description"), f"egressAllowed[{index}].description")
        require_match(NAME, entry.get("namespace"), f"egressAllowed[{index}].namespace")
        port = require_int(entry.get("port"), f"egressAllowed[{index}].port", 1, 65535)
        if port == front_door["listenPort"]:
            fail(
                f"egressAllowed[{index}] re-opens the front-door port outbound; the default-deny "
                "policy must not be widened to the engine's own listener"
            )


def validate_tenants(tenants: list[Any], mounts: dict[str, Any]) -> None:
    if not tenants:
        fail("tenants must not be empty")
    policy_root = posix_parts(mounts["policy"]["mountPath"], "externalMounts.policy.mountPath")

    names: set[str] = set()
    tenant_ids: set[str] = set()
    claims: set[str] = set()
    data_dirs: list[tuple[str, tuple[str, ...]]] = []
    policy_files: set[str] = set()

    for index, item in enumerate(tenants):
        tenant = require_object(item, f"tenants[{index}]")
        name = require_match(NAME, tenant.get("name"), f"tenants[{index}].name")
        tenant_id = require_match(TENANT_ID, tenant.get("tenantId"), f"tenants[{index}].tenantId")
        claim = require_match(NAME, tenant.get("volumeClaim"), f"tenants[{index}].volumeClaim")
        require_match(QUANTITY, tenant.get("storage"), f"tenants[{index}].storage")
        data_dir = require_text(tenant.get("dataDir"), f"tenants[{index}].dataDir")
        parts = posix_parts(data_dir, f"tenants[{index}].dataDir")
        policy_file = require_text(tenant.get("policyFile"), f"tenants[{index}].policyFile")
        policy_parts = posix_parts(policy_file, f"tenants[{index}].policyFile")

        # ── THE ONE-TENANT-PER-PROCESS-AND-DIRECTORY CONTROL ────────────────────────────────────
        # Every one of these is a way two tenants could end up sharing a process or a store. A
        # duplicate name collapses two StatefulSets into one; a duplicate tenant id points two
        # workloads at one substrate pool; a shared or nested data directory puts two single-writer
        # engines on one tree. None of them can be rendered.
        if name in names:
            fail(f"tenants[{index}].name {name!r} is declared twice; one tenant, one workload")
        if tenant_id in tenant_ids:
            fail(
                f"tenants[{index}].tenantId {tenant_id!r} is declared twice; two workloads would "
                "share one substrate pool and cross-tenant isolation would become a runtime filter"
            )
        if claim in claims:
            fail(
                f"tenants[{index}].volumeClaim {claim!r} is declared twice; two engines would write "
                "one volume"
            )
        for other_name, other in data_dirs:
            if nests(parts, other):
                fail(
                    f"tenants[{index}].dataDir {data_dir!r} overlaps tenant {other_name!r}'s data "
                    "directory; one tenant per process means one tenant per store"
                )
        if policy_file in policy_files:
            fail(f"tenants[{index}].policyFile {policy_file!r} is declared twice")
        # Deny-by-default is only real if the policy comes from the read-only external mount.
        if not nests(policy_parts, policy_root) or len(policy_parts) <= len(policy_root):
            fail(
                f"tenants[{index}].policyFile {policy_file!r} must live under the read-only policy "
                f"mount {mounts['policy']['mountPath']!r}"
            )
        if "permissive" in policy_file:
            fail(f"tenants[{index}].policyFile must not name a permissive policy: {policy_file!r}")

        names.add(name)
        tenant_ids.add(tenant_id)
        claims.add(claim)
        data_dirs.append((name, parts))
        policy_files.add(policy_file)


# ── rendering ───────────────────────────────────────────────────────────────────────────────────

HEADER = (
    "# GENERATED by scripts/render_host_profile.py from deploy/reference/profile.json.\n"
    "# Do not edit by hand: `python3 scripts/verify_host_profile.py` fails on drift.\n"
)

# Which secret each container may see. Least privilege is per-container, not per-pod: the bundle
# verifier needs only the trust root, the engine never needs the proxy's private key, and the proxy
# never needs the policy or the actor registry.
MOUNTS_BY_CONTAINER = {
    "verify-release-bundle": ("trustRoot",),
    "loomd": ("policy", "actorRegistry", "trustRoot"),
    "front-door": ("frontDoorIdentity",),
}


def volume_name(key: str) -> str:
    """A DNS-1123 volume name for an external mount key (`actorRegistry` -> `actor-registry`)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", key).lower()


def cpu_quota_percent(cpu: str) -> int:
    """systemd `CPUQuota=` for a Kubernetes CPU quantity, millicores included."""
    if cpu.endswith("m"):
        return max(1, round(int(cpu[:-1]) / 10))
    return max(1, round(float(cpu) * 100))


def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    # Quote every string. Envoy type URLs, SPIFFE URIs, and paths all contain characters that are
    # legal in a plain scalar only by accident; quoting removes the question.
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def to_yaml(value: Any, indent: int = 0) -> list[str]:
    """Emit deterministic block YAML for dict/list/scalar trees.

    The front-door configuration is security-critical and deeply nested, and hand-indenting it in a
    template is how you ship a proxy that authorizes the wrong thing — or does not parse at all. It is
    built as a structure and emitted here, so the indentation cannot be wrong by construction.
    """
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = f'"{key}"' if key.startswith("@") else key
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{name}:")
                lines.extend(to_yaml(item, indent + 2))
            elif isinstance(item, dict):
                lines.append(f"{pad}{name}: {{}}")
            elif isinstance(item, list):
                lines.append(f"{pad}{name}: []")
            else:
                lines.append(f"{pad}{name}: {yaml_scalar(item)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item:
                nested = to_yaml(item, indent + 2)
                # Hoist the first key onto the dash so the block reads like hand-written YAML.
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
            elif isinstance(item, list) and item:
                nested = to_yaml(item, indent + 2)
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
    else:
        lines.append(f"{pad}{yaml_scalar(value)}")
    return lines


def render_telemetry_env(profile: dict[str, Any], indent: str) -> str:
    """The OTLP environment, or an explanation of why there is none."""
    observability = profile["observability"]
    if not observability["enabled"]:
        return (
            f"{indent}# No telemetry environment: this is the air-gap build and the OTLP exporter is\n"
            f"{indent}# not compiled in. Setting LOOM_OTEL_ENABLED here would configure nothing.\n"
            f"{indent}# Health is served by the front door; see docs/host-profile.md."
        ).rstrip()
    return "\n".join(
        [
            f"{indent}- name: LOOM_OTEL_ENABLED",
            f'{indent}  value: "true"',
            f"{indent}- name: OTEL_EXPORTER_OTLP_ENDPOINT",
            f"{indent}  value: {observability['otlpEndpoint']}",
        ]
    )


def render_volume_mounts(profile: dict[str, Any], container: str, indent: str) -> str:
    mounts = profile["externalMounts"]
    lines = []
    for key in MOUNTS_BY_CONTAINER[container]:
        lines.extend(
            [
                f"{indent}- name: {volume_name(key)}",
                f"{indent}  mountPath: {mounts[key]['mountPath']}",
                f"{indent}  readOnly: true",
            ]
        )
    return "\n".join(lines)


def render(profile: dict[str, Any]) -> dict[str, str]:
    """Render every committed artifact. Keys are paths relative to `deploy/reference`."""
    artifacts = {
        "kubernetes/00-namespace.yaml": render_namespace(profile),
        "kubernetes/10-network-policy.yaml": render_network_policy(profile),
        "kubernetes/20-front-door-config.yaml": render_front_door_config(profile),
        "systemd/loomd@.service": render_systemd_unit(profile),
    }
    for tenant in profile["tenants"]:
        artifacts[f"kubernetes/30-tenant-{tenant['name']}.yaml"] = render_tenant(profile, tenant)
        artifacts[f"systemd/loomd-{tenant['name']}.env"] = render_systemd_env(profile, tenant)
    return artifacts


def render_namespace(profile: dict[str, Any]) -> str:
    namespace = profile["namespace"]
    hardening = profile["hardening"]
    return f"""{HEADER}apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    # Pod Security Admission at `restricted`: the cluster refuses a workload that drops the
    # non-root, no-privilege-escalation, seccomp, or capability posture below the profile.
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: loomd
  namespace: {namespace}
# loomd calls no Kubernetes API. Without a mounted token there is no credential in the pod for a
# compromised agent input to reach the control plane with.
automountServiceAccountToken: {str(hardening['automountServiceAccountToken']).lower()}
"""


def render_network_policy(profile: dict[str, Any]) -> str:
    namespace = profile["namespace"]
    front_door = profile["frontDoor"]
    lines = [
        HEADER,
        "apiVersion: networking.k8s.io/v1",
        "kind: NetworkPolicy",
        "metadata:",
        "  name: loomd-default-deny",
        f"  namespace: {namespace}",
        "spec:",
        "  # An empty podSelector selects every pod; naming both policy types with no rules below",
        "  # denies all ingress and all egress in this namespace, including DNS.",
        "  podSelector: {}",
        "  policyTypes:",
        "    - Ingress",
        "    - Egress",
        "---",
        "apiVersion: networking.k8s.io/v1",
        "kind: NetworkPolicy",
        "metadata:",
        "  name: loomd-front-door",
        f"  namespace: {namespace}",
        "spec:",
        "  podSelector:",
        "    matchLabels:",
        "      app.kubernetes.io/name: loomd",
        "  policyTypes:",
        "    - Ingress",
        "    - Egress",
        "  ingress:",
        "    # Only the mTLS front door and the kubelet health port are reachable. The stdio bridge",
        f"    # binds {front_door['bridgeBindAddress']} and so has no ingress rule at all.",
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        "              kubernetes.io/metadata.name: agent-runtime",
        "      ports:",
        "        - protocol: TCP",
        f"          port: {front_door['listenPort']}",
        "    # The kubelet probe port. It answers a static 200 and carries no engine data, no tenant",
        "    # identifier, and no path into the MCP surface — the only unauthenticated response here.",
        "    - ports:",
        "        - protocol: TCP",
        f"          port: {front_door['healthPort']}",
    ]
    egress = profile["egressAllowed"]
    if egress:
        lines.append("  egress:")
        for rule in egress:
            lines.extend(
                [
                    f"    # {rule['description']}",
                    "    - to:",
                    "        - namespaceSelector:",
                    "            matchLabels:",
                    f"              kubernetes.io/metadata.name: {rule['namespace']}",
                    "      ports:",
                    "        - protocol: TCP",
                    f"          port: {rule['port']}",
                ]
            )
    else:
        lines.append("  egress: []")
    return "\n".join(lines) + "\n"


def envoy_config(profile: dict[str, Any]) -> dict[str, Any]:
    """The front-door proxy configuration, as a structure."""
    front_door = profile["frontDoor"]
    identity = profile["externalMounts"]["frontDoorIdentity"]["mountPath"]
    rbac = "type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC"
    tcp_proxy = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"
    hcm = (
        "type.googleapis.com/envoy.extensions.filters.network."
        "http_connection_manager.v3.HttpConnectionManager"
    )
    downstream_tls = (
        "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
    )
    router = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"

    # Authorize the client's *authenticated* SPIFFE identity, not merely a valid certificate.
    authorized = [
        {"authenticated": {"principal_name": {"exact": name}}}
        for name in front_door["authorizedClientIdentities"]
    ]
    return {
        "admin": {
            "address": {
                "socket_address": {
                    "address": front_door["adminBindAddress"],
                    "port_value": 9901,
                }
            }
        },
        "static_resources": {
            "listeners": [
                {
                    "name": "loomd_mtls",
                    "address": {
                        "socket_address": {
                            "address": "0.0.0.0",
                            "port_value": front_door["listenPort"],
                        }
                    },
                    "filter_chains": [
                        {
                            "filters": [
                                {
                                    "name": "envoy.filters.network.rbac",
                                    "typed_config": {
                                        "@type": rbac,
                                        "stat_prefix": "loomd_authz",
                                        "rules": {
                                            "action": "ALLOW",
                                            "policies": {
                                                "authorized_agents": {
                                                    "permissions": [{"any": True}],
                                                    "principals": [
                                                        {"or_ids": {"ids": authorized}}
                                                    ],
                                                }
                                            },
                                        },
                                    },
                                },
                                {
                                    "name": "envoy.filters.network.tcp_proxy",
                                    "typed_config": {
                                        "@type": tcp_proxy,
                                        "stat_prefix": "loomd",
                                        "cluster": "loomd_stdio_bridge",
                                    },
                                },
                            ],
                            "transport_socket": {
                                "name": "envoy.transport_sockets.tls",
                                "typed_config": {
                                    "@type": downstream_tls,
                                    "require_client_certificate": True,
                                    "common_tls_context": {
                                        "tls_params": {
                                            "tls_minimum_protocol_version": front_door[
                                                "minimumTlsVersion"
                                            ]
                                        },
                                        "tls_certificates": [
                                            {
                                                "certificate_chain": {
                                                    "filename": f"{identity}/tls.crt"
                                                },
                                                "private_key": {
                                                    "filename": f"{identity}/tls.key"
                                                },
                                            }
                                        ],
                                        "validation_context": {
                                            "trusted_ca": {
                                                "filename": f"{identity}/client-ca.crt"
                                            },
                                            "match_typed_subject_alt_names": [
                                                {
                                                    "san_type": "URI",
                                                    "matcher": {
                                                        "prefix": (
                                                            f"spiffe://"
                                                            f"{front_door['trustDomain']}/"
                                                        )
                                                    },
                                                }
                                            ],
                                        },
                                    },
                                },
                            },
                        }
                    ],
                },
                {
                    "name": "health",
                    "address": {
                        "socket_address": {
                            "address": "0.0.0.0",
                            "port_value": front_door["healthPort"],
                        }
                    },
                    "filter_chains": [
                        {
                            "filters": [
                                {
                                    "name": "envoy.filters.network.http_connection_manager",
                                    "typed_config": {
                                        "@type": hcm,
                                        "stat_prefix": "health",
                                        "route_config": {
                                            "virtual_hosts": [
                                                {
                                                    "name": "health",
                                                    "domains": ["*"],
                                                    "routes": [
                                                        {
                                                            "match": {"path": "/healthz"},
                                                            "direct_response": {
                                                                "status": 200,
                                                                "body": {
                                                                    "inline_string": "ok"
                                                                },
                                                            },
                                                        }
                                                    ],
                                                }
                                            ]
                                        },
                                        "http_filters": [
                                            {
                                                "name": "envoy.filters.http.router",
                                                "typed_config": {"@type": router},
                                            }
                                        ],
                                    },
                                }
                            ]
                        }
                    ],
                },
            ],
            "clusters": [
                {
                    "name": "loomd_stdio_bridge",
                    "type": "STATIC",
                    "load_assignment": {
                        "cluster_name": "loomd_stdio_bridge",
                        "endpoints": [
                            {
                                "lb_endpoints": [
                                    {
                                        "endpoint": {
                                            "address": {
                                                "socket_address": {
                                                    "address": front_door["bridgeBindAddress"],
                                                    "port_value": front_door["bridgePort"],
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ],
                    },
                }
            ],
        },
    }


def render_front_door_config(profile: dict[str, Any]) -> str:
    namespace = profile["namespace"]
    front_door = profile["frontDoor"]
    body = "\n".join(f"    {line}" for line in to_yaml(envoy_config(profile)))
    return f"""{HEADER}apiVersion: v1
kind: ConfigMap
metadata:
  name: loomd-front-door
  namespace: {namespace}
data:
  # The host owns the front door. loomDB ships no network listener: `loomd` speaks newline-delimited
  # JSON-RPC over stdio, and this proxy is the only thing bound to the pod's address. It terminates
  # mTLS on {front_door['listenPort']}, authorizes the client's authenticated SPIFFE identity (a valid
  # certificate is not enough), and forwards to the loopback stdio bridge on
  # {front_door['bridgeBindAddress']}:{front_door['bridgePort']}. The admin interface is loopback-only
  # because it can drain listeners and dump the running config; the health listener answers a static
  # 200 on {front_door['healthPort']} and carries no engine data.
  #
  # Generated from a structure, not a template — see to_yaml() in scripts/render_host_profile.py.
  envoy.yaml: |
{body}
"""


def render_tenant(profile: dict[str, Any], tenant: dict[str, Any]) -> str:
    namespace = profile["namespace"]
    image = profile["image"]
    front_door = profile["frontDoor"]
    hardening = profile["hardening"]
    limits = profile["limits"]
    mounts = profile["externalMounts"]
    name = tenant["name"]
    reference = f"{image['repository']}@{image['digest']}"
    proxy_reference = f"{front_door['image']['repository']}@{front_door['image']['digest']}"
    bundle = image["bundle"]

    init_mounts = render_volume_mounts(profile, "verify-release-bundle", " " * 12)
    engine_mounts = render_volume_mounts(profile, "loomd", " " * 12)
    proxy_mounts = render_volume_mounts(profile, "front-door", " " * 12)
    volume_yaml = "\n".join(
        f"""        - name: {volume_name(key)}
          secret:
            secretName: {mount['secretName']}
            defaultMode: 0{int(mount['mode'], 8):o}"""
        for key, mount in sorted(mounts.items())
    )

    return f"""{HEADER}# Tenant {name!r} — one tenant, one process, one store.
#
# There is no field on this object that names a second tenant. Isolation is the shape of the
# deployment, not a filter inside a shared server: a second tenant is a second StatefulSet with its
# own volume, rendered from its own entry in profile.json.
apiVersion: v1
kind: Service
metadata:
  name: loomd-{name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: loomd
    loomdb.io/tenant: {name}
spec:
  clusterIP: None
  selector:
    app.kubernetes.io/name: loomd
    loomdb.io/tenant: {name}
  ports:
    - name: mtls
      port: {front_door['listenPort']}
      targetPort: {front_door['listenPort']}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: loomd-{name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: loomd
    loomdb.io/tenant: {name}
spec:
  serviceName: loomd-{name}
  # One writer. substrate is a single-writer engine per pool, so this is not a scaling knob.
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: loomd
      loomdb.io/tenant: {name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: loomd
        loomdb.io/tenant: {name}
      annotations:
        container.apparmor.security.beta.kubernetes.io/loomd: {hardening['apparmorProfile']}
    spec:
      serviceAccountName: loomd
      automountServiceAccountToken: {str(hardening['automountServiceAccountToken']).lower()}
      securityContext:
        runAsNonRoot: {str(hardening['runAsNonRoot']).lower()}
        runAsUser: {hardening['runAsUser']}
        runAsGroup: {hardening['runAsGroup']}
        fsGroup: {hardening['runAsGroup']}
        seccompProfile:
          type: {hardening['seccompProfile']}
        seLinuxOptions:
          type: {hardening['seLinuxType']}
      initContainers:
        # Offline bundle verification in the deployment path. The signature is checked against the
        # independently distributed trust root before the engine ever runs, and the exact kind, id,
        # and version are required — an authentic build that was not the approved one still fails.
        # A storage vendor's checksum is not a substitute for this signature.
        - name: verify-release-bundle
          image: {reference}
          command:
            - loom-bundle-tool
            - verify
            - --public
            - {bundle['publicKeyPath']}
            - --require-kind
            - {bundle['kind']}
            - --require-id
            - {bundle['id']}
            - --require-version
            - {bundle['version']}
            - --in
            - {bundle['bundlePath']}
          securityContext:
            allowPrivilegeEscalation: {str(hardening['allowPrivilegeEscalation']).lower()}
            readOnlyRootFilesystem: {str(hardening['readOnlyRootFilesystem']).lower()}
            capabilities:
              drop: {json.dumps(hardening['dropCapabilities'])}
          volumeMounts:
{init_mounts}
      containers:
        - name: loomd
          image: {reference}
          # Built {image['build']}: no object-storage client is compiled in.
          env:
            # One tenant. One store. Both are process-scoped, so there is no request on which this
            # process could reach another tenant's data.
            - name: LOOM_TENANT
              value: {tenant['tenantId']}
            - name: LOOM_DATA_DIR
              value: {tenant['dataDir']}
            # Deny-by-default, from the read-only externally managed mount. LOOM_ALLOW_PERMISSIVE_POLICY
            # is deliberately absent: it is mutually exclusive with LOOM_POLICY_FILE and would refuse
            # to start alongside it.
            - name: LOOM_POLICY_FILE
              value: {tenant['policyFile']}
            - name: LOOM_MAX_REQUEST_BYTES
              value: "{limits['maxRequestBytes']}"
            - name: LOOM_REQUESTS_PER_SECOND
              value: "{limits['requestsPerSecond']}"
            - name: LOOM_REQUEST_BURST
              value: "{limits['requestBurst']}"
{render_telemetry_env(profile, " " * 12)}
          securityContext:
            allowPrivilegeEscalation: {str(hardening['allowPrivilegeEscalation']).lower()}
            readOnlyRootFilesystem: {str(hardening['readOnlyRootFilesystem']).lower()}
            capabilities:
              drop: {json.dumps(hardening['dropCapabilities'])}
          resources:
            requests:
              cpu: {limits['cpu']}
              memory: {limits['memory']}
              ephemeral-storage: {limits['ephemeralStorage']}
            limits:
              cpu: {limits['cpu']}
              memory: {limits['memory']}
              ephemeral-storage: {limits['ephemeralStorage']}
          volumeMounts:
            # The one writable path in an otherwise read-only root filesystem.
            - name: data
              mountPath: {tenant['dataDir']}
{engine_mounts}
        - name: front-door
          image: {proxy_reference}
          # The mTLS terminator and stdio bridge — the host's component, not loomDB's. Substitute the
          # organization's own proxy or mesh sidecar; the contract it must meet is in
          # docs/host-profile.md. loomDB ships no network listener.
          args:
            - --config-path
            - /etc/envoy/envoy.yaml
          ports:
            - name: mtls
              containerPort: {front_door['listenPort']}
            - name: health
              containerPort: {front_door['healthPort']}
          livenessProbe:
            httpGet:
              path: /healthz
              port: {front_door['healthPort']}
          readinessProbe:
            httpGet:
              path: /healthz
              port: {front_door['healthPort']}
          securityContext:
            allowPrivilegeEscalation: {str(hardening['allowPrivilegeEscalation']).lower()}
            readOnlyRootFilesystem: {str(hardening['readOnlyRootFilesystem']).lower()}
            capabilities:
              drop: {json.dumps(hardening['dropCapabilities'])}
          volumeMounts:
            - name: front-door-config
              mountPath: /etc/envoy
              readOnly: true
{proxy_mounts}
      volumes:
        - name: front-door-config
          configMap:
            name: loomd-front-door
{volume_yaml}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes:
          # One writer, enforced by the volume as well as by the replica count.
          - ReadWriteOnce
        resources:
          requests:
            storage: {tenant['storage']}
"""


def render_systemd_unit(profile: dict[str, Any]) -> str:
    hardening = profile["hardening"]
    limits = profile["limits"]
    front_door = profile["frontDoor"]
    return f"""{HEADER}# Templated unit: one instance per tenant, `systemctl start loomd@alpha`. The instance name selects
# the per-tenant environment file, so a tenant's identity and store are fixed by the unit the host
# starts and cannot be redirected by a request.
[Unit]
Description=loomDB engine for tenant %i
Documentation=file:///usr/share/doc/loomdb/host-profile.md
After=network-online.target
# The engine must not start without its store mounted; an unmounted data directory stops startup.
RequiresMountsFor=/var/lib/loomd/%i

[Service]
Type=simple
User=loomd
Group=loomd
EnvironmentFile=/etc/loomd/loomd-%i.env
ExecStart=/usr/local/bin/loomd
# Verify the signed release bundle against the trust root before serving. A non-zero exit here means
# the unit never starts.
ExecStartPre=/usr/local/bin/loom-bundle-tool verify \\
    --public /etc/loomd/trust/loom-release.pub \\
    --require-kind {profile['image']['bundle']['kind']} \\
    --require-id {profile['image']['bundle']['id']} \\
    --require-version {profile['image']['bundle']['version']} \\
    --in /etc/loomd/trust/loomd.bundle
Restart=on-failure
RestartSec=5s

# ── filesystem ─────────────────────────────────────────────────────────────────────────────────
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
# The single writable path. Everything else, including /etc/loomd, is read-only to this process.
ReadWritePaths=/var/lib/loomd/%i
StateDirectory=loomd/%i
StateDirectoryMode=0700
UMask=0077

# ── privilege ──────────────────────────────────────────────────────────────────────────────────
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount @swap @reboot @module @debug
# SELinux: hardening.seLinuxType is {hardening['seLinuxType']!r}, which is the *container* type the
# Kubernetes flavour applies. A systemd service on a host needs a type from the site's own policy, and
# an incorrect SELinuxContext= stops the unit from starting — so this is left for you to set rather
# than rendered wrong. Confine the unit with your own module, or rely on the AppArmor profile
# ({hardening['apparmorProfile']}) where that is the host's MAC system.
# SELinuxContext=system_u:system_r:<your_type>:s0

# ── network ────────────────────────────────────────────────────────────────────────────────────
# Default deny. loomd itself speaks stdio and needs no address; the bridge in front of it listens on
# loopback only, so nothing here is reachable off-host. Add an IPAddressAllow line only for the
# telemetry collector, and only on the deployment that enables it.
IPAddressDeny=any
IPAddressAllow=localhost
RestrictAddressFamilies=AF_UNIX

# ── resource limits ────────────────────────────────────────────────────────────────────────────
CPUQuota={cpu_quota_percent(limits['cpu'])}%
MemoryMax={limits['memory'].replace('Gi', 'G').replace('Mi', 'M')}
MemoryswapMax=0
LimitNOFILE={limits['openFiles']}
TasksMax={limits['processes']}
LimitCORE=0

[Install]
WantedBy=multi-user.target

# The front door is a separate unit the organization supplies. It must bind
# {front_door['bridgeBindAddress']}:{front_door['bridgePort']} toward this engine, terminate mTLS on
# {front_door['listenPort']}, and authorize client identities explicitly. See docs/host-profile.md.
"""


def render_systemd_env(profile: dict[str, Any], tenant: dict[str, Any]) -> str:
    limits = profile["limits"]
    observability = profile["observability"]
    if observability["enabled"]:
        telemetry = (
            f"LOOM_OTEL_ENABLED=true\n"
            f"OTEL_EXPORTER_OTLP_ENDPOINT={observability['otlpEndpoint']}\n"
        )
    else:
        telemetry = (
            "# No telemetry: the air-gap build has no OTLP exporter compiled in, and the unit denies\n"
            "# all outbound addresses. Enabling it needs the connected build, an IPAddressAllow line\n"
            "# for the collector, and AF_INET in RestrictAddressFamilies.\n"
        )
    return f"""{HEADER}# Tenant {tenant['name']!r}. One tenant, one store, one process.
LOOM_TENANT={tenant['tenantId']}
LOOM_DATA_DIR={tenant['dataDir']}
# Deny-by-default from the externally managed, read-only policy mount.
LOOM_POLICY_FILE={tenant['policyFile']}
LOOM_MAX_REQUEST_BYTES={limits['maxRequestBytes']}
LOOM_REQUESTS_PER_SECOND={limits['requestsPerSecond']}
LOOM_REQUEST_BURST={limits['requestBurst']}
{telemetry}"""


# ── entry point ─────────────────────────────────────────────────────────────────────────────────


def load(path: pathlib.Path = PROFILE) -> dict[str, Any]:
    return validate(json.loads(path.read_text(encoding="utf-8")))


def drift(artifacts: dict[str, str]) -> list[str]:
    """Relative paths whose committed bytes differ from the rendered bytes."""
    stale = []
    for relative, expected in sorted(artifacts.items()):
        target = RENDER_ROOT / relative
        if not target.is_file() or target.read_text(encoding="utf-8") != expected:
            stale.append(relative)
    return stale


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail on drift")
    mode.add_argument("--write", action="store_true", help="rewrite the committed artifacts")
    parser.add_argument("--profile", type=pathlib.Path, default=PROFILE)
    arguments = parser.parse_args(argv)

    profile = load(arguments.profile)
    artifacts = render(profile)

    if arguments.write:
        for relative, content in sorted(artifacts.items()):
            target = RENDER_ROOT / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        print(f"host profile rendered: {len(artifacts)} artifacts")
        return 0

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
    print(
        f"host profile valid and rendered artifacts current: {len(profile['tenants'])} tenants, "
        f"{len(artifacts)} artifacts"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, json.JSONDecodeError, ProfileError) as error:
        print(f"host profile verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
