#!/usr/bin/env python3
"""Backup scheduling, retention, verification, and rehearsal for the reference host profile.

This is the deployment half of the signed-backup mechanism. The mechanism itself lives in the engine
and in `loomctl` — a signed manifest, an atomic publish, a restore that refuses to overwrite — and
nothing here weakens it. What is added is *when* it runs, *who* runs it, *how long copies are kept*,
and *what the host can see*.

Three things shape every decision below.

**A backup cannot read a live volume.** `FileRefStore::open` holds an exclusive advisory lock for the
store's lifetime, so a job that mounted the tenant's live volume would fail every night — proven in
`crates/loomctl/tests/backup_operations.rs`. So the profile declares a platform-provided
point-in-time source and the renderer refuses to emit a job that mounts the live claim.

**The verifier must not be the writer.** A signature is only worth the independence of the party
checking it. The writer holds the signing key and nothing else; the verifier holds the public trust
root and nothing else; neither can do the other's job, and this is enforced by which secret each
container may mount, not by convention.

**loomDB never touches the immutable target.** No build links an object-storage client. The
immutable, off-account copy is declared as a host responsibility with a named mechanism, and the
declaration is checked for the properties that make it worth having.
"""

from __future__ import annotations

import re
from typing import Any, Callable

CRON_FIELD = re.compile(r"^[0-9*/,\-]+$")

# Signals `loomctl` actually writes (crates/loomctl/src/metrics.rs `ALL`). A profile that alerts on a
# metric nothing emits is a profile whose monitoring is decoration, so the list is closed.
KNOWN_BACKUP_SIGNALS = {
    "loomdb_backup_last_success_timestamp_seconds",
    "loomdb_backup_last_verified_timestamp_seconds",
    "loomdb_backup_last_verified_recovery_point_seconds",
    "loomdb_backup_duration_seconds",
    "loomdb_backup_bytes",
    "loomdb_backup_files",
    "loomdb_backup_failures_total",
    "loomdb_backup_scrub_damaged_objects",
    "loomdb_backup_retained_copies",
    "loomdb_backup_pruned_total",
    "loomdb_backup_legal_hold_retained",
}

# The signals the rendered alerts read. Declaring the pipeline without them would leave a stale or
# failing backup silent, which is the whole failure this increment exists to make loud.
REQUIRED_BACKUP_SIGNALS = {
    "loomdb_backup_last_success_timestamp_seconds",
    "loomdb_backup_last_verified_timestamp_seconds",
    "loomdb_backup_failures_total",
    "loomdb_backup_scrub_damaged_objects",
}

# WORM mechanisms whose retention a deployment-account compromise cannot shorten. `object-lock`
# *governance* mode is deliberately absent: a principal with the bypass permission can delete under
# it, which is exactly the adversary an immutable copy exists to survive.
IMMUTABLE_KINDS = {"object-lock-compliance", "worm-appliance", "tape-vault"}

POINT_IN_TIME_KINDS = {"csi-volume-snapshot-clone", "storage-array-clone", "filesystem-snapshot"}

SCHEDULE_ROLES = ("backup", "verify", "prune", "rehearsal")

# Least privilege per job, the same way MOUNTS_BY_CONTAINER works for the engine pod. The writer
# holds the signing key and cannot verify; the verifier and the rehearsal hold the public trust root
# and cannot sign; retention holds the legal-hold register and neither signs nor verifies.
JOB_MOUNTS = {
    "backup": ("backupSigningKey",),
    "verify": ("backupTrustRoot",),
    "prune": ("retentionHolds",),
    "rehearsal": ("backupTrustRoot",),
}

# Which service account each job runs as. The verifier and the rehearsal are a *different* identity
# from the writer, so a compromise of the thing that makes backups cannot also mint the verification
# that says they are fine.
JOB_IDENTITY = {
    "backup": "loomd-backup",
    "verify": "loomd-backup-verifier",
    "prune": "loomd-backup",
    "rehearsal": "loomd-backup-verifier",
}


def validate(
    block: dict[str, Any],
    mounts: dict[str, Any],
    tenants: list[dict[str, Any]],
    helpers: dict[str, Callable[..., Any]],
) -> None:
    """Validate `backupOperations`. `helpers` carries the shared require_*/posix_parts/nests/fail."""
    fail = helpers["fail"]
    require_text = helpers["require_text"]
    require_int = helpers["require_int"]
    require_true = helpers["require_true"]
    require_object = helpers["require_object"]
    require_list = helpers["require_list"]
    posix_parts = helpers["posix_parts"]
    nests = helpers["nests"]

    require_text(block.get("description"), "backupOperations.description")
    require_text(block.get("keyId"), "backupOperations.keyId")

    # A private key is the one mounted secret that must not be *readable* beyond its owner, not
    # merely un-writable. `loomctl` refuses a signing key with any group or other bit set
    # (`signing_key` in crates/loomctl/src/main.rs), so a profile that mounted 0440 would render a
    # job that cannot start.
    signing_mode = int(mounts["backupSigningKey"]["mode"], 8)
    if signing_mode & 0o077:
        fail(
            "externalMounts.backupSigningKey.mode must be owner-only (0400 or 0600); loomctl "
            f"refuses a signing key any group or other identity can read, and 0{signing_mode:o} "
            "is readable beyond its owner"
        )

    # The signing key and the trust root live on *different* mounts, because the whole point is that
    # no single compromised secret both writes and blesses a backup.
    _under_mount(
        helpers,
        require_text(block.get("signingKeyPath"), "backupOperations.signingKeyPath"),
        mounts["backupSigningKey"],
        "backupOperations.signingKeyPath",
        "externalMounts.backupSigningKey",
    )
    _under_mount(
        helpers,
        require_text(block.get("trustRootPath"), "backupOperations.trustRootPath"),
        mounts["backupTrustRoot"],
        "backupOperations.trustRootPath",
        "externalMounts.backupTrustRoot",
    )

    staging = require_text(block.get("stagingPath"), "backupOperations.stagingPath")
    staging_parts = posix_parts(staging, "backupOperations.stagingPath")
    metrics = require_text(block.get("metricsPath"), "backupOperations.metricsPath")
    metrics_parts = posix_parts(metrics, "backupOperations.metricsPath")

    schedules = require_object(block.get("schedules"), "backupOperations.schedules")
    missing = set(SCHEDULE_ROLES) - set(schedules)
    if missing:
        fail(f"backupOperations.schedules is missing {sorted(missing)}")
    for role in SCHEDULE_ROLES:
        _cron(helpers, schedules[role], f"backupOperations.schedules.{role}")
    # A verify that starts in the same minute as the write races the atomic publish and will
    # intermittently report a backup that is not there yet.
    if len(set(schedules[role] for role in SCHEDULE_ROLES)) != len(SCHEDULE_ROLES):
        fail(
            "backupOperations.schedules must give each job its own time; a verify or a prune that "
            "runs in the same minute as the write races the atomic publish"
        )

    interval = require_int(
        block.get("backupIntervalSeconds"), "backupOperations.backupIntervalSeconds", 60, 30 * 86_400
    )
    max_age = require_int(
        block.get("maxAgeSeconds"), "backupOperations.maxAgeSeconds", 60, 90 * 86_400
    )
    # THE STALE-BACKUP ALERT MUST BE ACTIONABLE. Below the period it fires forever and gets muted;
    # far above it, days of silence pass unnoticed. One missed run must be visible.
    if max_age <= interval:
        fail(
            f"backupOperations.maxAgeSeconds ({max_age}) must exceed backupIntervalSeconds "
            f"({interval}); an alert threshold below the backup period fires permanently and will "
            "be muted"
        )
    if max_age > 4 * interval:
        fail(
            f"backupOperations.maxAgeSeconds ({max_age}) allows more than four missed backups "
            f"before anyone is told (period {interval}s)"
        )

    _point_in_time(helpers, require_object(block.get("pointInTimeSource"), "pointInTimeSource"), tenants)
    _retention(helpers, require_object(block.get("retention"), "backupOperations.retention"), mounts)
    rehearsal = require_object(block.get("rehearsal"), "backupOperations.rehearsal")
    require_text(rehearsal.get("description"), "backupOperations.rehearsal.description")
    restore_path = require_text(
        rehearsal.get("restorePath"), "backupOperations.rehearsal.restorePath"
    )
    restore_parts = posix_parts(restore_path, "backupOperations.rehearsal.restorePath")

    # ── A REHEARSAL MUST NOT BE ABLE TO LAND ON PRODUCTION ──────────────────────────────────────
    # `restore-signed` already refuses an existing destination, so a rehearsal aimed at a live store
    # fails rather than overwrites. That is the mechanism's floor; this is the deployment's: there is
    # no rendered configuration in which the rehearsal path, the staging root, or the metrics
    # directory overlaps a tenant's data directory at all.
    for name, parts in (
        ("rehearsal.restorePath", restore_parts),
        ("stagingPath", staging_parts),
        ("metricsPath", metrics_parts),
    ):
        for tenant in tenants:
            data_parts = posix_parts(tenant["dataDir"], "tenants[].dataDir")
            if nests(parts, data_parts):
                fail(
                    f"backupOperations.{name} {'/'.join(('',) + parts)!r} overlaps tenant "
                    f"{tenant['name']!r}'s data directory; a backup job must never be able to write "
                    "into a live store"
                )
    if nests(restore_parts, staging_parts):
        fail(
            "backupOperations.rehearsal.restorePath must not sit inside the staging root, or a "
            "rehearsal would land where retention prunes"
        )

    signals = require_list(block.get("signals"), "backupOperations.signals")
    if not signals:
        fail("backupOperations.signals must name the operational signals the host collects")
    if len(set(signals)) != len(signals):
        fail("backupOperations.signals contains duplicates")
    unknown = set(signals) - KNOWN_BACKUP_SIGNALS
    if unknown:
        fail(
            f"backupOperations.signals names signals loomctl never writes: {sorted(unknown)} "
            f"(known: {sorted(KNOWN_BACKUP_SIGNALS)})"
        )
    absent = REQUIRED_BACKUP_SIGNALS - set(signals)
    if absent:
        fail(
            "backupOperations.signals must carry the signals the rendered alerts read; missing "
            f"{sorted(absent)}. Without them a stale or failing backup is silent"
        )
    # A signal name is a metric name, and a metric with a tenant in it is tenant data leaving through
    # the monitoring pipeline. `loomctl` emits no labels at all; this refuses a declaration that
    # pretends otherwise.
    for signal in signals:
        if "{" in signal or "tenant" in signal:
            fail(
                f"backupOperations.signals[{signal!r}] carries a label or a tenant identifier; "
                "these signals are unlabelled by construction and the collector attaches workload "
                "labels itself"
            )
    # `require_true` is used inside `_retention` for the off-account property; referenced here so the
    # helper set this module needs stays explicit.
    _ = require_true


def _under_mount(
    helpers: dict[str, Callable[..., Any]],
    path: str,
    mount: dict[str, Any],
    label: str,
    mount_label: str,
) -> None:
    parts = helpers["posix_parts"](path, label)
    root = helpers["posix_parts"](mount["mountPath"], f"{mount_label}.mountPath")
    if not helpers["nests"](parts, root) or len(parts) <= len(root):
        helpers["fail"](
            f"{label} {path!r} must live under the read-only mount {mount['mountPath']!r}"
        )


def _cron(helpers: dict[str, Callable[..., Any]], value: Any, label: str) -> None:
    """A schedule both flavours can express *identically*.

    The Kubernetes flavour renders a cron expression and the systemd flavour renders an
    `OnCalendar=`. A schedule that translates only approximately would mean two different things on
    two deployments of the same profile, so the accepted grammar is deliberately the intersection:
    a literal minute and hour, at most one of day-of-month or day-of-week, and no month restriction.
    A richer schedule is not silently approximated — it is refused.
    """
    fail = helpers["fail"]
    text = helpers["require_text"](value, label)
    fields = text.split()
    if len(fields) != 5 or not all(CRON_FIELD.match(field) for field in fields):
        fail(
            f"{label} must be a five-field cron expression over digits, '*', '/', ',', and '-', "
            f"got {text!r}"
        )
    minute, hour, day, month, weekday = fields
    if not minute.isdigit() or not (0 <= int(minute) <= 59):
        fail(f"{label} must name a literal minute 0-59 so both flavours agree, got {minute!r}")
    if not hour.isdigit() or not (0 <= int(hour) <= 23):
        fail(f"{label} must name a literal hour 0-23 so both flavours agree, got {hour!r}")
    if month != "*":
        fail(f"{label} must not restrict the month; a backup that skips months is not a backup")
    if day != "*" and weekday != "*":
        fail(
            f"{label} sets both day-of-month and day-of-week, which cron and systemd interpret "
            "differently; set at most one"
        )
    if day != "*" and not (day.isdigit() and 1 <= int(day) <= 31):
        fail(f"{label} day-of-month must be a literal 1-31, got {day!r}")
    if weekday != "*" and not (weekday.isdigit() and 0 <= int(weekday) <= 7):
        fail(f"{label} day-of-week must be a literal 0-7, got {weekday!r}")


def _point_in_time(
    helpers: dict[str, Callable[..., Any]], source: dict[str, Any], tenants: list[dict[str, Any]]
) -> None:
    fail = helpers["fail"]
    kind = helpers["require_text"](source.get("kind"), "pointInTimeSource.kind")
    if kind not in POINT_IN_TIME_KINDS:
        fail(f"backupOperations.pointInTimeSource.kind must be one of {sorted(POINT_IN_TIME_KINDS)}")
    helpers["require_text"](source.get("description"), "pointInTimeSource.description")
    template = helpers["require_text"](
        source.get("claimTemplate"), "backupOperations.pointInTimeSource.claimTemplate"
    )
    if "{tenant}" not in template:
        fail(
            "backupOperations.pointInTimeSource.claimTemplate must contain '{tenant}'; one source "
            "shared by two tenants would put two tenants' bytes in one backup"
        )

    # ── THE LIVE-VOLUME REFUSAL ─────────────────────────────────────────────────────────────────
    # The engine holds an exclusive lock on its store for the process lifetime. A job pointed at the
    # live claim cannot read it — it would fail every night — so the profile cannot name one.
    claims = {tenant["volumeClaim"] for tenant in tenants}
    rendered = {template.replace("{tenant}", tenant["name"]) for tenant in tenants}
    collision = rendered & claims
    if collision:
        fail(
            f"backupOperations.pointInTimeSource.claimTemplate renders {sorted(collision)}, which "
            "is a live tenant volume. loomd holds an exclusive lock on its store, so a backup job "
            "cannot read the volume the engine is serving; snapshot it and bind the clone"
        )
    if len(rendered) != len(tenants):
        fail(
            "backupOperations.pointInTimeSource.claimTemplate does not give each tenant its own "
            "source"
        )


def _retention(
    helpers: dict[str, Callable[..., Any]], retention: dict[str, Any], mounts: dict[str, Any]
) -> None:
    fail = helpers["fail"]
    keep_days = helpers["require_int"](
        retention.get("keepDays"), "backupOperations.retention.keepDays", 1, 3650
    )
    # A retention policy that can empty the shelf will, on the day the schedule quietly stopped.
    helpers["require_int"](
        retention.get("minimumCopies"), "backupOperations.retention.minimumCopies", 1, 10_000
    )
    _under_mount(
        helpers,
        helpers["require_text"](
            retention.get("legalHoldFile"), "backupOperations.retention.legalHoldFile"
        ),
        mounts["retentionHolds"],
        "backupOperations.retention.legalHoldFile",
        "externalMounts.retentionHolds",
    )

    target = helpers["require_object"](
        retention.get("immutableTarget"), "backupOperations.retention.immutableTarget"
    )
    helpers["require_text"](target.get("description"), "immutableTarget.description")
    kind = helpers["require_text"](target.get("kind"), "immutableTarget.kind")
    if kind not in IMMUTABLE_KINDS:
        fail(
            f"backupOperations.retention.immutableTarget.kind must be one of "
            f"{sorted(IMMUTABLE_KINDS)}; a mechanism a privileged principal can bypass — "
            "object-lock governance mode, an ordinary bucket with a lifecycle rule — is not "
            "immutable against the adversary an immutable copy exists to survive"
        )
    # Off-account is not optional. An immutable copy in the account that was compromised is a copy
    # the attacker can wait out or delete with the credentials they already hold.
    helpers["require_true"](
        target.get("offAccount"), "backupOperations.retention.immutableTarget.offAccount"
    )
    retain_days = helpers["require_int"](
        target.get("retainDays"), "backupOperations.retention.immutableTarget.retainDays", 1, 3650
    )
    if retain_days < keep_days:
        fail(
            f"backupOperations.retention.immutableTarget.retainDays ({retain_days}) is shorter than "
            f"retention.keepDays ({keep_days}); the immutable copy would expire before the local "
            "one it exists to outlive"
        )


# ── rendering ───────────────────────────────────────────────────────────────────────────────────


def job_command(profile: dict[str, Any], role: str, tenant: dict[str, Any]) -> list[str]:
    """The exact `loomctl` invocation each scheduled role runs."""
    backup = profile["backupOperations"]
    staging = f"{backup['stagingPath']}/{tenant['name']}"
    metrics = f"{backup['metricsPath']}/{tenant['name']}-{role}.prom"
    retention = backup["retention"]
    if role == "backup":
        return [
            "loomctl",
            "backup-signed",
            # The point-in-time clone, never the live volume: loomd holds an exclusive lock on the
            # store it is serving, so this job could not read it.
            "--path",
            "/var/lib/loomd-source",
            "--tenant",
            tenant["tenantId"],
            # `--root` mints a fresh `<tenant>-<unix>` destination. Neither flavour has a portable
            # per-run identifier to interpolate, and the publish refuses to overwrite anyway, so a
            # repeated name would be a failed job rather than a lost backup.
            "--root",
            staging,
            "--signing-key-file",
            backup["signingKeyPath"],
            "--key-id",
            backup["keyId"],
            "--metrics-file",
            metrics,
        ]
    if role == "verify":
        return [
            "loomctl",
            "verify-backup-signed",
            # The newest backup on the shelf. The verifier runs later than the writer, as a
            # different identity, and shares no state with it beyond the shelf itself.
            "--root",
            staging,
            "--public-key-file",
            backup["trustRootPath"],
            "--key-id",
            backup["keyId"],
            "--metrics-file",
            metrics,
        ]
    if role == "prune":
        return [
            "loomctl",
            "backup-prune",
            "--root",
            staging,
            "--keep-days",
            str(retention["keepDays"]),
            "--minimum-copies",
            str(retention["minimumCopies"]),
            "--legal-hold-file",
            retention["legalHoldFile"],
            "--metrics-file",
            metrics,
            "--apply",
        ]
    return [
        "loomctl",
        "restore-signed",
        "--root",
        staging,
        "--expected-tenant",
        tenant["tenantId"],
        # A fresh path every rehearsal, minted under the rehearsal volume. `restore-signed` refuses
        # an existing destination, so a rehearsal can neither overwrite a store nor quietly reuse
        # last week's.
        "--out-root",
        f"{backup['rehearsal']['restorePath']}/{tenant['name']}",
        "--public-key-file",
        backup["trustRootPath"],
        "--key-id",
        backup["keyId"],
        "--metrics-file",
        metrics,
    ]


def render_cronjobs(
    profile: dict[str, Any], tenant: dict[str, Any], helpers: dict[str, Callable[..., Any]]
) -> str:
    """The four scheduled jobs for one tenant."""
    header = helpers["HEADER"]
    volume_name = helpers["volume_name"]
    namespace = profile["namespace"]
    image = profile["image"]
    backup = profile["backupOperations"]
    mounts = profile["externalMounts"]
    hardening = profile["hardening"]
    reference = f"{image['repository']}@{image['digest']}"
    source_claim = backup["pointInTimeSource"]["claimTemplate"].replace(
        "{tenant}", tenant["name"]
    )

    blocks = [
        f"""{header}# Backup operations for tenant {tenant['name']!r}.
#
# THE SOURCE IS A CLONE, NOT THE LIVE VOLUME. loomd holds an exclusive advisory lock on its store
# for the process lifetime, so a job that mounted {tenant['volumeClaim']!r} could not read it. The
# platform snapshots that volume and binds the result as {source_claim!r}; only the backup job
# mounts it, read-only.
#
# THE WRITER AND THE VERIFIER ARE DIFFERENT IDENTITIES. The backup job runs as
# {JOB_IDENTITY['backup']!r} and mounts the signing key. The verifier and the rehearsal run as
# {JOB_IDENTITY['verify']!r} and mount the public trust root. Neither can do the other's job, so a
# compromise of the thing that writes backups cannot also mint the verification that blesses them.
"""
    ]

    for role in SCHEDULE_ROLES:
        command = job_command(profile, role, tenant)
        mount_keys = JOB_MOUNTS[role]
        volume_mounts = [
            f"                - name: {volume_name(key)}\n"
            f"                  mountPath: {mounts[key]['mountPath']}\n"
            "                  readOnly: true"
            for key in mount_keys
        ]
        volumes = [
            f"            - name: {volume_name(key)}\n"
            "              secret:\n"
            f"                secretName: {mounts[key]['secretName']}\n"
            f"                defaultMode: 0{int(mounts[key]['mode'], 8):o}"
            for key in mount_keys
        ]
        def mount(name: str, path: str, read_only: bool) -> str:
            suffix = "\n                  readOnly: true" if read_only else ""
            return f"                - name: {name}\n                  mountPath: {path}{suffix}"

        def claim(name: str, claim_name: str, read_only: bool) -> str:
            suffix = "\n                readOnly: true" if read_only else ""
            return (
                f"            - name: {name}\n"
                "              persistentVolumeClaim:\n"
                f"                claimName: {claim_name}{suffix}"
            )

        if role == "backup":
            # The clone, read-only. Never the live claim: the engine holds an exclusive lock on it.
            volume_mounts.insert(0, mount("source", "/var/lib/loomd-source", True))
            volumes.insert(0, claim("source", source_claim, True))
        if role == "rehearsal":
            # A rehearsal reads the shelf and writes only to its own rehearsal volume.
            volume_mounts.append(mount("staging", backup["stagingPath"], True))
            volume_mounts.append(mount("rehearsal", backup["rehearsal"]["restorePath"], False))
            volumes.append(claim("staging", "loomd-backup-staging", True))
            volumes.append(claim("rehearsal", "loomd-rehearsal", False))
        else:
            volume_mounts.append(mount("staging", backup["stagingPath"], False))
            volumes.append(claim("staging", "loomd-backup-staging", False))
        volume_mounts.append(mount("metrics", backup["metricsPath"], False))
        volumes.append(claim("metrics", "loomd-backup-metrics", False))

        arguments = "\n".join(f"                - {part}" for part in command[1:])
        blocks.append(
            f"""---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: loomd-{role}-{tenant['name']}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: loomd
    loomdb.io/tenant: {tenant['name']}
    loomdb.io/role: {role}
spec:
  schedule: "{backup['schedules'][role]}"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        metadata:
          labels:
            app.kubernetes.io/name: loomd
            loomdb.io/tenant: {tenant['name']}
            loomdb.io/role: {role}
        spec:
          serviceAccountName: {JOB_IDENTITY[role]}
          automountServiceAccountToken: false
          restartPolicy: Never
          securityContext:
            runAsNonRoot: {str(hardening['runAsNonRoot']).lower()}
            runAsUser: {hardening['runAsUser']}
            runAsGroup: {hardening['runAsGroup']}
            fsGroup: {hardening['runAsGroup']}
            seccompProfile:
              type: {hardening['seccompProfile']}
            seLinuxOptions:
              type: {hardening['seLinuxType']}
          containers:
            - name: {role}
              image: {reference}
              command:
                - {command[0]}
              args:
{arguments}
              securityContext:
                allowPrivilegeEscalation: {str(hardening['allowPrivilegeEscalation']).lower()}
                readOnlyRootFilesystem: {str(hardening['readOnlyRootFilesystem']).lower()}
                capabilities:
                  drop: ["ALL"]
              volumeMounts:
{chr(10).join(volume_mounts)}
          volumes:
{chr(10).join(volumes)}
"""
        )
    return "".join(blocks)


def render_alerts(profile: dict[str, Any], helpers: dict[str, Callable[..., Any]]) -> str:
    """The alerts that make a missing, failing, or unverified backup loud.

    A backup pipeline nobody is told about is a backup pipeline that stopped in March. These rules
    read only signals `loomctl` actually writes, and carry no tenant identifier — the collector
    attaches workload labels from the job it scraped.
    """
    backup = profile["backupOperations"]
    hours = backup["maxAgeSeconds"] / 3600
    return f"""{helpers['HEADER']}# Alerts over the signals loomctl publishes. No rule here names a tenant: these series are
# unlabelled by construction and the collector attaches the workload labels itself.
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: loomd-backup
  namespace: {profile['namespace']}
  labels:
    app.kubernetes.io/name: loomd
spec:
  groups:
    - name: loomd-backup
      rules:
        # THE STALE-BACKUP ALERT. Threshold {backup['maxAgeSeconds']}s ({hours:g}h) against a
        # {backup['backupIntervalSeconds']}s period: one missed run is visible, and the rule does
        # not fire permanently just because the period has not elapsed.
        - alert: LoomdBackupStale
          expr: >-
            time() - loomdb_backup_last_success_timestamp_seconds > {backup['maxAgeSeconds']}
            or absent(loomdb_backup_last_success_timestamp_seconds)
          for: 15m
          labels:
            severity: critical
          annotations:
            summary: No successful loomDB backup within {hours:g}h
            description: >-
              The last successful signed backup is older than the allowed recovery-point window, or
              no backup has ever reported. `absent()` is deliberate: a job that never ran emits
              nothing, and silence must not read as health.
        # A backup nobody verified is a backup nobody has evidence for. Verification runs from a
        # different trust domain than the writer, so this going quiet is its own failure.
        - alert: LoomdBackupUnverified
          expr: >-
            time() - loomdb_backup_last_verified_timestamp_seconds > {backup['maxAgeSeconds'] * 2}
            or absent(loomdb_backup_last_verified_timestamp_seconds)
          for: 30m
          labels:
            severity: warning
          annotations:
            summary: No independent verification of a loomDB backup
            description: >-
              Independent verification against the trust root has not completed recently. The
              signature is the authenticity check; a storage vendor checksum does not substitute.
        - alert: LoomdBackupJobFailing
          expr: loomdb_backup_failures_total > 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: A loomDB backup job reported failure
            description: >-
              The last run of a backup, verification, or retention job failed. The signal is written
              on the failure path too, so this is the job telling you, not an inference from silence.
        - alert: LoomdBackupDamaged
          expr: loomdb_backup_scrub_damaged_objects > 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: A loomDB integrity scrub found damage
            description: >-
              Verification found a backup whose signature or digests no longer hold, or a store scrub
              found damaged objects. Treat the affected copy as unusable and verify the next one.
"""


def render_units(
    profile: dict[str, Any], tenant_names: list[str], helpers: dict[str, Callable[..., Any]]
) -> dict[str, str]:
    """The systemd flavour: one templated service and timer per role.

    Same posture without Kubernetes. `%i` is the tenant, so `systemctl enable --now
    loomd-backup@alpha.timer` schedules exactly one tenant's backup from that tenant's environment
    file — the same one-tenant-per-unit shape the engine uses.
    """
    header = helpers["HEADER"]
    backup = profile["backupOperations"]
    units: dict[str, str] = {}
    intent = {
        "backup": "Signed backup of the point-in-time clone",
        "verify": "Independent verification against the trust root",
        "prune": "Retention with legal hold",
        "rehearsal": "Restore rehearsal to a fresh path",
    }
    for role in SCHEDULE_ROLES:
        # One tenant is enough to render the templated command: the tenant-specific values arrive
        # from the environment file, so `%i` is what varies at runtime.
        sample = {"name": "%i", "tenantId": "${LOOM_TENANT}"}
        command = job_command(profile, role, sample)
        # `loomctl <subcommand>` on the first line, then one `--flag value` pair per continuation, so
        # the unit reads the way the documented command does.
        lines = [f"{command[0]} {command[1]}"]
        lines.extend(_shell_pair(command, index) for index in range(2, len(command), 2))
        rendered = " \\\n    ".join(lines)
        identity = "loomd-backup" if role in {"backup", "prune"} else "loomd-verifier"
        # The writer and the verifier are different Unix users for the same reason they are
        # different service accounts: file modes on the signing key are what keeps them apart.
        units[f"systemd/loomd-{role}@.service"] = f"""{header}# {intent[role]} for tenant %i.
#
# Runs as {identity}: the writer is the only identity that can read the signing key, and the
# verifier is the only identity that reads the trust root. A single account doing both would make
# the independent check a formality.
[Unit]
Description=loomDB {intent[role].lower()} for tenant %i
Documentation=file:///usr/share/doc/loomdb/backup-restore.md
{_requires_mounts(profile, role)}

[Service]
Type=oneshot
User={identity}
Group={identity}
EnvironmentFile=/etc/loomd/loomd-%i.env
EnvironmentFile=/etc/loomd/backup.env
ExecStart=/usr/local/bin/{rendered}

# Same hardening as the engine unit. A backup job reads a database and writes a signed copy; it
# needs no privilege, no network, and no path outside what it was given.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths={backup['stagingPath']} {backup['metricsPath']}{_rehearsal_path(profile, role)}
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
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
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
"""
        units[f"systemd/loomd-{role}@.timer"] = f"""{header}# Schedule for {intent[role].lower()}, tenant %i.
#
# OnCalendar mirrors the Kubernetes flavour's cron expression {backup['schedules'][role]!r}. Persistent=true
# so a host that was down over the window runs the job when it comes back rather than skipping it
# silently — a missed backup nobody was told about is the failure this whole increment exists to
# make loud.
[Unit]
Description=Schedule loomDB {intent[role].lower()} for tenant %i

[Timer]
OnCalendar={_calendar(backup['schedules'][role])}
Persistent=true
RandomizedDelaySec=300
Unit=loomd-{role}@%i.service

[Install]
WantedBy=timers.target
"""

    units["systemd/backup.env"] = f"""{header}# Shared backup-operations environment for every tenant's backup units.
# Tenant identity and store come from /etc/loomd/loomd-<tenant>.env; nothing here names a tenant.
LOOM_BACKUP_KEY_ID={backup['keyId']}
LOOM_BACKUP_STAGING={backup['stagingPath']}
LOOM_BACKUP_METRICS={backup['metricsPath']}
# Destinations are minted by loomctl as <tenant>-<unix> under the shelf, so neither flavour needs a
# per-run identifier of its own. The publish refuses to overwrite, so a repeated name would be a
# failed job rather than a lost backup.
# Tenants rendered by this profile: {', '.join(tenant_names)}
"""
    return units


def _shell_pair(command: list[str], index: int) -> str:
    if index + 1 < len(command):
        return f"{command[index]} {command[index + 1]}"
    return command[index]


def _requires_mounts(profile: dict[str, Any], role: str) -> str:
    backup = profile["backupOperations"]
    if role == "backup":
        return (
            "# The point-in-time clone must be mounted; an absent source stops the unit rather than\n"
            "# signing an empty backup. The live store is deliberately not named here: loomd holds an\n"
            "# exclusive lock on it and this job could not read it.\n"
            "RequiresMountsFor=/var/lib/loomd-source"
        )
    if role == "rehearsal":
        return f"RequiresMountsFor={backup['stagingPath']} {backup['rehearsal']['restorePath']}"
    return f"RequiresMountsFor={backup['stagingPath']}"


def _rehearsal_path(profile: dict[str, Any], role: str) -> str:
    if role != "rehearsal":
        return ""
    return f" {profile['backupOperations']['rehearsal']['restorePath']}"


def _calendar(cron: str) -> str:
    """Render a five-field cron expression as a systemd OnCalendar value.

    Only the shapes the profile's validation admits are translated, and anything else is emitted as
    an explicit refusal rather than a guess — a schedule that silently means something other than
    what the Kubernetes flavour does is worse than no schedule at all.
    """
    minute, hour, day, month, weekday = cron.split()
    if month != "*" or (day != "*" and weekday != "*"):
        return f"INVALID({cron})"
    if weekday != "*":
        names = {
            "0": "Sun",
            "1": "Mon",
            "2": "Tue",
            "3": "Wed",
            "4": "Thu",
            "5": "Fri",
            "6": "Sat",
            "7": "Sun",
        }
        if weekday not in names:
            return f"INVALID({cron})"
        return f"{names[weekday]} *-*-* {int(hour):02d}:{int(minute):02d}:00"
    if day != "*":
        return f"*-*-{int(day):02d} {int(hour):02d}:{int(minute):02d}:00"
    return f"*-*-* {int(hour):02d}:{int(minute):02d}:00"


# ── the postures this profile must refuse ───────────────────────────────────────────────────────


def unsafe_postures() -> list[tuple[str, Callable[[dict[str, Any]], None]]]:
    """Every backup-operations posture the reference profile must refuse to express."""

    def backup_the_live_volume(document: dict[str, Any]) -> None:
        document["backupOperations"]["pointInTimeSource"]["claimTemplate"] = "loomd-data-{tenant}"

    def one_source_for_every_tenant(document: dict[str, Any]) -> None:
        document["backupOperations"]["pointInTimeSource"]["claimTemplate"] = "loomd-snapshot-shared"

    def unknown_point_in_time_mechanism(document: dict[str, Any]) -> None:
        document["backupOperations"]["pointInTimeSource"]["kind"] = "copy-the-files"

    def rehearse_onto_a_live_store(document: dict[str, Any]) -> None:
        document["backupOperations"]["rehearsal"]["restorePath"] = document["tenants"][0]["dataDir"]

    def rehearse_inside_a_live_store(document: dict[str, Any]) -> None:
        document["backupOperations"]["rehearsal"]["restorePath"] = (
            document["tenants"][0]["dataDir"] + "/rehearsal"
        )

    def stage_backups_inside_a_live_store(document: dict[str, Any]) -> None:
        document["backupOperations"]["stagingPath"] = document["tenants"][0]["dataDir"] + "/backups"

    def rehearse_where_retention_prunes(document: dict[str, Any]) -> None:
        document["backupOperations"]["rehearsal"]["restorePath"] = (
            document["backupOperations"]["stagingPath"] + "/rehearsal"
        )

    def sign_and_verify_with_one_secret(document: dict[str, Any]) -> None:
        document["backupOperations"]["trustRootPath"] = document["backupOperations"][
            "signingKeyPath"
        ]

    def a_bypassable_immutable_target(document: dict[str, Any]) -> None:
        document["backupOperations"]["retention"]["immutableTarget"][
            "kind"
        ] = "object-lock-governance"

    def keep_the_immutable_copy_in_the_same_account(document: dict[str, Any]) -> None:
        document["backupOperations"]["retention"]["immutableTarget"]["offAccount"] = False

    def let_the_immutable_copy_expire_first(document: dict[str, Any]) -> None:
        document["backupOperations"]["retention"]["immutableTarget"]["retainDays"] = 1

    def a_retention_policy_that_can_empty_the_shelf(document: dict[str, Any]) -> None:
        document["backupOperations"]["retention"]["minimumCopies"] = 0

    def a_legal_hold_register_outside_its_mount(document: dict[str, Any]) -> None:
        document["backupOperations"]["retention"]["legalHoldFile"] = "/tmp/legal-hold.json"

    def an_alert_that_fires_forever(document: dict[str, Any]) -> None:
        document["backupOperations"]["maxAgeSeconds"] = document["backupOperations"][
            "backupIntervalSeconds"
        ]

    def an_alert_that_never_fires_in_time(document: dict[str, Any]) -> None:
        document["backupOperations"]["maxAgeSeconds"] = (
            10 * document["backupOperations"]["backupIntervalSeconds"]
        )

    def verify_races_the_write(document: dict[str, Any]) -> None:
        document["backupOperations"]["schedules"]["verify"] = document["backupOperations"][
            "schedules"
        ]["backup"]

    def an_invented_backup_signal(document: dict[str, Any]) -> None:
        document["backupOperations"]["signals"].append("loomdb_backup_probably_fine")

    def drop_the_stale_backup_signal(document: dict[str, Any]) -> None:
        document["backupOperations"]["signals"].remove(
            "loomdb_backup_last_success_timestamp_seconds"
        )

    def a_tenant_bearing_backup_signal(document: dict[str, Any]) -> None:
        document["backupOperations"]["signals"] = [
            signal.replace("loomdb_backup_bytes", 'loomdb_backup_bytes{tenant="alpha-corp"}')
            for signal in document["backupOperations"]["signals"]
        ]

    def no_backup_operations_at_all(document: dict[str, Any]) -> None:
        del document["backupOperations"]

    def a_group_readable_backup_signing_key(document: dict[str, Any]) -> None:
        document["externalMounts"]["backupSigningKey"]["mode"] = "0440"

    return [
        ("the backup job reads the live tenant volume", backup_the_live_volume),
        ("one point-in-time source serves every tenant", one_source_for_every_tenant),
        ("the point-in-time source is an unnamed mechanism", unknown_point_in_time_mechanism),
        ("the restore rehearsal targets a live store", rehearse_onto_a_live_store),
        ("the restore rehearsal lands inside a live store", rehearse_inside_a_live_store),
        ("backups are staged inside a live store", stage_backups_inside_a_live_store),
        ("the rehearsal restores where retention prunes", rehearse_where_retention_prunes),
        ("one secret both signs and verifies backups", sign_and_verify_with_one_secret),
        ("the immutable target can be bypassed by a privileged principal", a_bypassable_immutable_target),
        ("the immutable copy lives in the account that was compromised", keep_the_immutable_copy_in_the_same_account),
        ("the immutable copy expires before the local one", let_the_immutable_copy_expire_first),
        ("retention can empty the shelf", a_retention_policy_that_can_empty_the_shelf),
        ("the legal-hold register comes from outside its mount", a_legal_hold_register_outside_its_mount),
        ("the stale-backup alert fires permanently", an_alert_that_fires_forever),
        ("the stale-backup alert tolerates ten missed backups", an_alert_that_never_fires_in_time),
        ("verification races the write it verifies", verify_races_the_write),
        ("an alert is wired to a signal loomctl never writes", an_invented_backup_signal),
        ("the stale-backup signal is not collected", drop_the_stale_backup_signal),
        ("a backup signal carries a tenant identifier", a_tenant_bearing_backup_signal),
        ("backup operations are absent from the profile", no_backup_operations_at_all),
        ("the backup signing key is readable beyond its owner", a_group_readable_backup_signing_key),
    ]
