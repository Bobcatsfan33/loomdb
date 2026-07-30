# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting for this repository. Include the affected revision, reproduction steps, impact, and any
suggested mitigation.

The maintainers will acknowledge a report within three business days, provide an initial severity
assessment within seven business days, and coordinate disclosure after a fix is available. Critical
issues that affect released artifacts are targeted for remediation within seven calendar days; high
severity issues within thirty days.

## Supported versions

Until the project reaches 1.0, only the latest tagged release receives security fixes. Release notes
will identify any required on-disk migration. Consumers should verify signed release artifacts and
their accompanying checksums before installation.

## Security boundary

loomDB is an embedded engine. The host application remains responsible for network authentication,
authorization, TLS, process isolation, backup access, resource quotas, and operating-system hardening.
The repository threat model documents the controls provided by the engine and the threats that remain
outside that boundary.
