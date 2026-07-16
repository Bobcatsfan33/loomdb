//! Persistence: AT-046 and AT-047.
//!
//! The gate on everything in L2. A derivation DAG built on refs that vanish is a derivation DAG that
//! vanishes, and a taint report that cannot walk the history it is tainting is not a report — it is a
//! guess.
//!
//! The question that has to have an answer: **"where is branch h2 after a restart?"**
//!
//! This whole file exercises the **remote** sleep/wake path, so it is compiled only with the `remote`
//! feature (on by default). An airgap build (`--no-default-features`) has no object-storage client, so
//! there is nothing here to test — the file is compiled out, not skipped-with-a-lie (CLAUDE.md rule 8:
//! the reason is written down, here).
#![cfg(feature = "remote")]

use loom_branch::{Loom, LoomWakeToken, MergePolicy};
use loom_core::{ActorId, BranchId, Record, Result, SessionId, TenantId, Value, WriteEnvelope};
use object_store::memory::InMemory;
use std::sync::Arc;
use substrate_pager::StoreConfig;
use substrate_store::{RemoteTier, TieredStore};

fn envelope(branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent-1"),
        SessionId::new("s1"),
        branch.clone(),
        "investigating",
    )
}

fn counter(n: i64) -> Record {
    Record::Value(Value::Counter(n))
}

/// **AT-046 — deterministic replay, at the LoomDB level.**
///
/// Kill the process. Restart. Everything is exactly where it was: the data, the branch *names*, and
/// the commit DAG — including the merge edges substrate cannot store and which, if lost, silently
/// restore the double-counting bug (merge twice, and a `+3` becomes a `+6`, and the merge reports
/// success).
#[test]
fn at_046_a_restart_finds_the_branches_the_data_and_the_merge_edges() -> Result<()> {
    let home = tempfile::tempdir().expect("tempdir");
    let tenant = TenantId::new("acme");

    // ── the process that dies ──────────────────────────────────────────────
    let (h2_before, session_name) = {
        let db = Loom::open(home.path(), tenant.clone())?;
        let (session, token) = db.open_session_named(SessionId::new("investigation-1"))?;

        db.write(
            &token,
            &session.branch,
            b"tally".to_vec(),
            counter(10),
            &envelope(&session.branch),
        )?;

        let (h1, token) = db.branch(&token, &session.branch, "h1")?;
        let (h2, token) = db.branch(&token, &session.branch, "h2")?;

        db.write(&token, &h1, b"tally".to_vec(), counter(13), &envelope(&h1))?; // +3
        db.write(&token, &h2, b"tally".to_vec(), counter(15), &envelope(&h2))?; // +5

        // Merge h1 into h2. The merge edge — h1's head as h2's SECOND parent — exists only in
        // LoomDB's own DAG, and it has to survive.
        let merged = db.merge(&token, &h1, &h2, &MergePolicy::Conflict, &envelope(&h2))?;
        assert!(merged.is_merged(), "{merged:?}");
        assert_eq!(db.read(&token, &h2, b"tally")?, Some(counter(18)));

        (db.head(&h2)?, session.id)
    }; // the process is gone. Nothing was closed cleanly.

    // ── the process that comes back ────────────────────────────────────────
    let db = Loom::open(home.path(), tenant)?;

    // THE QUESTION. It has an answer.
    let h2 = BranchId::new("h2");
    assert_eq!(
        db.head(&h2)?,
        h2_before,
        "branch h2 is not where we left it — a restart lost the refs"
    );

    let names = db.branch_names();
    for expected in ["main", session_name.as_str(), "h1", "h2"] {
        assert!(
            names.iter().any(|n| n == expected),
            "branch {expected:?} did not survive the restart. Found: {names:?}"
        );
    }

    // The data is there. A capability for an existing branch has to be MINTED — the old session's
    // token died with the process it was issued in, which is the correct behaviour for a capability.
    let token = db.issue_capability(
        SessionId::new("after-restart"),
        &[h2.clone(), BranchId::new("h1")],
        3_600_000,
    )?;
    assert_eq!(db.read(&token, &h2, b"tally")?, Some(counter(18)));

    // AND THE MERGE EDGE SURVIVED. Merging h1 into h2 again must be a NO-OP — because h2 already
    // absorbed it. If the DAG were lost, the merge base would revert to the fork point, h1's +3 would
    // be applied a second time, and 18 would silently become 21.
    let again = db.merge(
        &token,
        &BranchId::new("h1"),
        &h2,
        &MergePolicy::Conflict,
        &envelope(&h2),
    )?;
    assert!(again.is_merged(), "{again:?}");

    assert_eq!(
        db.read(&token, &h2, b"tally")?,
        Some(counter(18)),
        "re-merging after a restart DOUBLE-COUNTED: the commit DAG's merge edge did not survive, so \
         the merge base reverted to the fork point and h1's delta was applied twice. This is the bug \
         the model oracle caught, coming back through the front door."
    );
    Ok(())
}

/// A second restart, with no work in between, changes nothing. Recovery is idempotent.
#[test]
fn at_046_reopening_twice_is_idempotent() -> Result<()> {
    let home = tempfile::tempdir().expect("tempdir");
    let tenant = TenantId::new("acme");

    {
        let db = Loom::open(home.path(), tenant.clone())?;
        let (session, token) = db.open_session_named(SessionId::new("s1"))?;
        db.write(
            &token,
            &session.branch,
            b"k".to_vec(),
            counter(1),
            &envelope(&session.branch),
        )?;
    }

    let first = {
        let db = Loom::open(home.path(), tenant.clone())?;
        (db.branch_names(), db.head(&BranchId::new("s1"))?)
    };
    let second = {
        let db = Loom::open(home.path(), tenant)?;
        (db.branch_names(), db.head(&BranchId::new("s1"))?)
    };

    assert_eq!(
        first, second,
        "opening the database twice produced two different databases"
    );
    Ok(())
}

/// **AT-047 — session sleep and wake.**
///
/// Sleep the tenant into object storage. **Wipe the local disk entirely** — not evict, delete. Wake
/// somewhere else. Identical results, and the branch names come back with the data.
#[tokio::test(flavor = "multi_thread")]
async fn at_047_sleep_wipe_wake_and_the_branches_come_back() -> Result<()> {
    let backend = Arc::new(InMemory::new());
    let remote = RemoteTier::new(backend, "acme");
    let tenant = TenantId::new("acme");

    let first_home = tempfile::tempdir().expect("tempdir");

    // ── awake ──────────────────────────────────────────────────────────────
    let token_json = {
        let tiered = TieredStore::open(
            first_home.path(),
            remote.clone(),
            StoreConfig {
                pool: "acme".into(),
                ..Default::default()
            },
        )
        .await
        .expect("tiered store");

        let db = Loom::on(
            Arc::clone(tiered.pager()),
            Arc::new(loom_branch::MemRefStore::new()),
            tenant.clone(),
        )?;

        let (session, token) = db.open_session_named(SessionId::new("investigation-1"))?;

        // Enough writes, across enough commits, that the head is an OVERLAY on a base — which is
        // exactly the case that used to wake up broken.
        for round in 0..12u64 {
            db.write(
                &token,
                &session.branch,
                format!("key-{round:04}").into_bytes(),
                counter(round as i64),
                &envelope(&session.branch),
            )?;
        }

        let (h2, token) = db.branch(&token, &session.branch, "h2")?;
        db.write(
            &token,
            &h2,
            b"hypothesis".to_vec(),
            counter(999),
            &envelope(&h2),
        )?;

        let wake_token = db.sleep(&tiered).await?;
        wake_token.to_json()?
    };

    // ── destroy the machine ────────────────────────────────────────────────
    std::fs::remove_dir_all(first_home.path()).expect("wipe the disk");

    // ── wake, on a different disk, from nothing but object storage ─────────
    let token: LoomWakeToken = LoomWakeToken::from_json(&token_json)?;
    let new_home = tempfile::tempdir().expect("tempdir");

    let started = std::time::Instant::now();
    let tiered = TieredStore::open(
        new_home.path(),
        remote,
        StoreConfig {
            pool: "acme".into(),
            ..Default::default()
        },
    )
    .await
    .expect("tiered store");

    let db = Loom::wake(&tiered, &token)?;
    let cap = db.issue_capability(
        SessionId::new("after-wake"),
        &[BranchId::new("h2"), BranchId::new("investigation-1")],
        3_600_000,
    )?;

    // The first read, from a cold cache, on a different disk.
    let first_read = db.read(&cap, &BranchId::new("investigation-1"), b"key-0000")?;
    let wake_latency = started.elapsed();

    assert_eq!(first_read, Some(counter(0)));

    // The target is p99 < 250ms (substrate docs/02 §7). In memory this is microseconds; the
    // assertion is a guard against a catastrophic regression — someone making wake fetch everything
    // eagerly — not a published benchmark. The real number is measured against MinIO.
    assert!(
        wake_latency.as_millis() < 250,
        "wake-to-first-read took {wake_latency:?}"
    );

    // EVERY page, including ones the top overlay does not hold — the case that used to break.
    for round in 0..12u64 {
        assert_eq!(
            db.read(
                &cap,
                &BranchId::new("investigation-1"),
                format!("key-{round:04}").as_bytes()
            )?,
            Some(counter(round as i64)),
            "key-{round:04} did not survive sleep and wake"
        );
    }

    // AND THE BRANCH NAMES CAME BACK WITH IT.
    assert_eq!(
        db.read(&cap, &BranchId::new("h2"), b"hypothesis")?,
        Some(counter(999)),
        "branch h2 did not survive sleep and wake — the token carried the data and lost the refs"
    );
    assert!(db.branch_names().iter().any(|n| n == "h2"));

    // The token itself answers "where is branch h2" without opening anything at all.
    assert!(token.branches().any(|(name, _)| name == "h2"));
    Ok(())
}
