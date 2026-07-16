//! **AT-039 through the REAL multi-tenant surface — not two separate engines.**
//!
//! The scoreboard test proved cross-tenant isolation with two independent `Loom`s (no shared surface).
//! This proves it through a single [`Tenancy`] router over many tenants — the front door where a
//! `WHERE tenant = ?` would leak if it existed. It does not: the token carries its tenant in the
//! signature, so cross-tenant is structural, and the failure modes a real router introduces (a token
//! re-pointed at another tenant, an unregistered tenant) all return the SAME uniform refusal.

use std::sync::Arc;

use loom_branch::{Loom, Tenancy};
use loom_core::{
    ActorId, IndexHint, LoomError, Observation, ObservationId, Record, SourceRef, TenantId,
    Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;

fn obs() -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(b"x"),
        source: SourceRef::new("erp", "secret"),
        trust: TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: b"exists".to_vec(),
    }))
}

/// **A tenant cannot read, name, or confirm the existence of another tenant's identifiers.**
#[test]
fn at_039_through_the_router_no_cross_tenant_and_no_existence_oracle() {
    let tenancy = Tenancy::new();

    // Two tenants, registered by the operator.
    let a = tenancy.register(
        TenantId::new("tenant-a"),
        Arc::new(
            Loom::in_memory(TenantId::new("tenant-a"))
                .unwrap()
                .with_clock(|| NOW),
        ),
    );
    let b = tenancy.register(
        TenantId::new("tenant-b"),
        Arc::new(
            Loom::in_memory(TenantId::new("tenant-b"))
                .unwrap()
                .with_clock(|| NOW),
        ),
    );

    // Each opens a session (getting a token bound to its tenant).
    let (sa, ta) = a.open_session().unwrap();
    let (sb, tb) = b.open_session().unwrap();

    // B writes a record under a known-good key.
    b.write_indexed(
        &tb,
        &sb.branch,
        b"secret/exists".to_vec(),
        obs(),
        IndexHint::text("b secret"),
        &WriteEnvelope::new(ActorId::new("b"), sb.id.clone(), sb.branch.clone(), "write"),
    )
    .unwrap();

    // ── AT-039, through the router ──────────────────────────────────────────

    // A, using its own valid token, asks the ROUTER for B's known-good key. It routes to A's engine
    // (the token's tenant is A), which does not have the key → not found. Same as a nonexistent key.
    let b_known_good = tenancy.read(&ta, &sa.branch, b"secret/exists").unwrap();
    let never_existed = tenancy.read(&ta, &sa.branch, b"secret/never").unwrap();
    assert!(
        b_known_good.is_none(),
        "B's key must be invisible to A through the router"
    );
    assert!(never_existed.is_none());
    assert_eq!(
        b_known_good.is_none(),
        never_existed.is_none(),
        "AT-039: 'B's real key' and 'a key that never existed' must be indistinguishable from A"
    );

    // A takes its valid token and TAMPERS the tenant field to B, to try to route into B's engine.
    let mut forged = ta.clone();
    forged.claims.tenant = TenantId::new("tenant-b");
    let tampered = tenancy.read(&forged, &sa.branch, b"secret/exists");
    assert!(
        matches!(tampered, Err(LoomError::Unauthorized)),
        "a token re-pointed at another tenant must be refused (its signature no longer verifies): {tampered:?}"
    );

    // A token naming a tenant that was NEVER registered returns the SAME error — no existence oracle.
    let mut ghost = ta.clone();
    ghost.claims.tenant = TenantId::new("tenant-zzz-does-not-exist");
    let unregistered = tenancy.read(&ghost, &sa.branch, b"secret/exists");
    assert!(
        matches!(unregistered, Err(LoomError::Unauthorized)),
        "an unregistered tenant must return the SAME refusal as a rejected one — no way to probe existence"
    );

    // The two refusals are byte-identical messages: a caller cannot tell "exists but forbidden" from
    // "does not exist".
    assert_eq!(
        tampered.unwrap_err().to_string(),
        unregistered.unwrap_err().to_string(),
        "AT-039: the refusal for a tampered-into-existing-tenant token and an unregistered-tenant token \
         must be IDENTICAL, or the difference is an existence oracle"
    );
}

/// **B's own token still works through the router — isolation is not a blanket denial.**
#[test]
fn the_router_still_serves_a_tenants_own_valid_token() {
    let tenancy = Tenancy::new();
    let b = tenancy.register(
        TenantId::new("tenant-b"),
        Arc::new(
            Loom::in_memory(TenantId::new("tenant-b"))
                .unwrap()
                .with_clock(|| NOW),
        ),
    );
    let (sb, tb) = b.open_session().unwrap();
    b.write_indexed(
        &tb,
        &sb.branch,
        b"mine".to_vec(),
        obs(),
        IndexHint::text("m"),
        &WriteEnvelope::new(ActorId::new("b"), sb.id.clone(), sb.branch.clone(), "w"),
    )
    .unwrap();

    let got = tenancy.read(&tb, &sb.branch, b"mine").unwrap();
    assert!(
        matches!(got, Some(Record::Observation(_))),
        "B reads its own record through the router"
    );
}
