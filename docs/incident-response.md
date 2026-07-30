# Product security incident response

This runbook covers a vulnerability or integrity incident in loomDB source, dependencies, released
artifacts, update bundles, actor trust roots, or backup signatures. The deploying organization owns
host/network incidents and customer communications, but the product team must provide the technical
facts and corrected artifacts needed for containment.

## Intake and severity

Use GitHub private vulnerability reporting as directed by [`SECURITY.md`](../SECURITY.md). Do not put
exploit details, customer data, private keys, tokens, bundle payloads, or unreleased fixes in public
issues or logs. Record the affected source revision, artifact digest, feature set, deployment mode,
reproduction, impact, known exploitation, and reporter contact.

- **Critical:** active compromise, signature/trust-root bypass, cross-tenant access, remote code
  execution, silent corruption, or an unauthenticated path to privileged action.
- **High:** credible confidentiality/integrity/availability loss requiring preconditions.
- **Medium/Low:** bounded impact without a practical critical/high path.

Follow the acknowledgement and remediation targets in `SECURITY.md`. Severity changes require a
written reason in the private incident record.

## Containment

1. Freeze releases and preserve the exact source, CI run, SBOM, checksums, provenance, logs, and
   affected bundles. Do not destroy evidence while eradicating.
2. Identify affected versions and deployment postures. Air-gap, default remote, observability, and
   host-wrapper paths may have different exposure.
3. If a signing key or trust root may be compromised, stop signing, remove its release-environment
   authority, distribute a deny/revocation decision through the established out-of-band channel, and
   require exact kind/id/version at every update door. Never replace trust by publishing a new key
   beside an untrusted artifact.
4. If actor authority is compromised, reject new writes from the affected key and preserve historical
   verification material for prior records. Run provenance and taint analysis to identify derived
   claims and already-executed actions.
5. If backup authenticity is in doubt, quarantine affected backups and restore only from a separately
   verified signed manifest and approved trust root.

## Eradication, recovery, and disclosure

Develop the fix under the normal review, DCO, test, audit, reproducibility, SBOM, signature, and
provenance gates. Add a regression test that fails on the vulnerable revision and passes on the fix.
Re-verify the release from a clean environment and publish checksums plus upgrade/rollback guidance.

The deployment owner validates recovery on a non-production copy, runs `loomctl verify`, known-answer
reads, provenance/taint queries, and—when storage is affected—a signed backup/restore drill. Promote
only after the approved trust root, tenant identity, branch heads, and integrity results match.

Coordinate disclosure with the reporter and affected customers. State impacted versions, severity,
exploitability, indicators, mitigations, fixed artifact digests, trust-root actions, and any residual
risk. A third-party or customer notification exercise remains a required external readiness gate.
