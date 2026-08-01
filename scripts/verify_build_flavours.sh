#!/usr/bin/env bash
# Compile every supported build flavour, reject every forbidden one, and inspect what each links.
#
# WHY THIS EXISTS
#
# P6 documented a "connected air-gap" flavour — telemetry to an in-enclave collector, still with no
# object-storage client — and `scripts/render_host_profile.py` accepted that build string. But a
# blanket `compile_error!` in `crates/loom-mcp/src/lib.rs` rejected exactly that combination, so the
# documented build could not be produced. Nothing caught it: CI compiled the pure air-gap flavour
# and the default connected flavour, and never the fourth corner.
#
# That is the class of failure this script closes. A flavour nobody compiles is a flavour that is
# broken the moment someone touches a feature, and a claim about what a binary links is only worth
# the check that could have falsified it.
#
#   bash scripts/verify_build_flavours.sh
#
# Every check prints what it proved. A failure names the flavour and the offending crate.

set -euo pipefail

cd "$(dirname "$0")/.."

FAILURES=0

note() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  OK   %s\n' "$*"; }
fail() {
    printf '  FAIL %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

# ── 1. every supported flavour compiles ─────────────────────────────────────────────────────────
#
# Storage posture and telemetry are orthogonal, so all four corners are supported and all four are
# built here. Omitting one is how the P6 contradiction survived.

compiles() {
    local label="$1"
    shift
    if cargo check --quiet -p loom-mcp "$@" 2>/dev/null; then
        pass "$label compiles"
    else
        fail "$label does NOT compile: cargo check -p loom-mcp $*"
    fi
}

note "1. supported flavours compile"
compiles "connected (remote)" --no-default-features --features remote
compiles "connected + telemetry" --no-default-features --features remote,observability
compiles "air-gap" --no-default-features --features airgap
compiles "air-gap + telemetry (the documented connected flavour)" \
    --no-default-features --features airgap,observability

# ── 2. every forbidden flavour is rejected, by name ─────────────────────────────────────────────
#
# A guard nobody has watched fire is not a guard. Each of these must fail to compile *and* the
# failure must name the invariant, so a future refactor cannot quietly turn the error into a
# different one — or into nothing.

rejects() {
    local label="$1" expected="$2"
    shift 2
    local output
    if output=$(cargo check --quiet -p loom-mcp "$@" 2>&1); then
        fail "$label was ACCEPTED; it must not compile"
    # Substring match in the shell, never `printf | grep -q`: see the note above `absent`.
    elif [ "${output#*"$expected"}" != "$output" ]; then
        pass "$label is rejected, naming: ${expected}"
    else
        fail "$label failed for the wrong reason (expected '$expected' in the error)"
    fi
}

note "2. forbidden flavours are rejected"
rejects "both storage postures at once" "mutually exclusive" \
    --no-default-features --features remote,airgap
rejects "no storage posture declared" "exactly one storage posture" \
    --no-default-features
rejects "no posture, telemetry only" "exactly one storage posture" \
    --no-default-features --features observability

# ── 3. what each flavour actually links ─────────────────────────────────────────────────────────
#
# THE DISCRIMINATING CHECK. `cargo tree` over the non-dev graph is reproducible on any machine and
# distinguishes the flavours; a symbol check cannot, because link-time dead-code elimination can
# strip an unused client from a connected binary too (docs/operations.md says so).

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Graphs are written to files, and every check greps the FILE.
#
# Not `printf '%s' "$graph" | grep -q …`: `grep -q` exits at the first match and closes the pipe, so
# `printf` takes EPIPE and — under `set -o pipefail` — the pipeline reports failure even though the
# pattern *was* found. In `present` that shows up as a spurious FAIL; in `absent` it would have shown
# up as a spurious **OK**, quietly blessing a leaked object-storage client. This checker exists to
# make that class of thing impossible, so it must not contain a fail-open path of its own.
graph() {
    local package="$1" features="$2" out="$WORK/$3"
    cargo tree -p "$package" --no-default-features --features "$features" -e no-dev >"$out" 2>/dev/null
    printf '%s' "$out"
}

absent() {
    local label="$1" pattern="$2" file="$3"
    if grep -qiE "$pattern" "$file"; then
        printf '  FAIL %s links %s:\n' "$label" "$pattern" >&2
        grep -iE "$pattern" "$file" | sed 's/^/       /' >&2
        FAILURES=$((FAILURES + 1))
    else
        pass "$label links no $pattern"
    fi
}

present() {
    local label="$1" pattern="$2" file="$3"
    if grep -qiE "$pattern" "$file"; then
        pass "$label links $pattern, as its flavour claims"
    else
        fail "$label does NOT link $pattern; the flavour advertises telemetry it cannot emit"
    fi
}

note "3. dependency graphs match what each flavour claims"

AIRGAP_GRAPH="$(graph loom-mcp airgap airgap.tree)"
AIRGAP_OTLP_GRAPH="$(graph loom-mcp airgap,observability airgap-otlp.tree)"
CONNECTED_GRAPH="$(graph loom-mcp remote connected.tree)"

# The property an enclave actually needs, in BOTH air-gap flavours. Telemetry is never a reason to
# reintroduce an object-storage client.
absent "air-gap" 'object_store|substrate-store' "$AIRGAP_GRAPH"
absent "air-gap + telemetry" 'object_store|substrate-store' "$AIRGAP_OTLP_GRAPH"

# The pure air-gap flavour carries no exporter at all — not "configured off", not compiled.
absent "air-gap" 'opentelemetry|reqwest|prost' "$AIRGAP_GRAPH"

# ...and the connected air-gap flavour does carry one, or it is advertising a pipeline it cannot
# serve. This is the assertion that would have caught the contradiction from the other direction.
present "air-gap + telemetry" 'opentelemetry' "$AIRGAP_OTLP_GRAPH"

# The default connected build carries no exporter either, until observability is asked for.
absent "connected" 'opentelemetry' "$CONNECTED_GRAPH"

# loomctl performs local diagnostics and signed backups and never sleeps or wakes a tenant, so it
# has no business linking an object-storage client in any profile — including its ordinary build.
LOOMCTL_GRAPH="$WORK/loomctl.tree"
cargo tree -p loomctl -e no-dev >"$LOOMCTL_GRAPH" 2>/dev/null
absent "loomctl" 'object_store|substrate-store' "$LOOMCTL_GRAPH"

# ── 4. the shipped air-gap binaries build, not just check ───────────────────────────────────────

note "4. the shipped air-gap binaries build"
if cargo build --quiet -p loom-mcp --no-default-features --features airgap 2>/dev/null &&
    cargo build --quiet -p loomctl 2>/dev/null; then
    pass "loomd (air-gap) and loomctl build"
else
    fail "the air-gap operator binaries do not build"
fi

note "result"
if [ "$FAILURES" -eq 0 ]; then
    echo "build flavours verified: 4 supported flavours compile, 3 forbidden combinations rejected,"
    echo "and every dependency graph matches what its flavour claims."
    exit 0
fi
echo "build-flavour verification FAILED: $FAILURES problem(s) above." >&2
exit 1
