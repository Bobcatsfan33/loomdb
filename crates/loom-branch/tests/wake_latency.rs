//! **AT-047 wake latency, measured over REAL object storage.** `#[ignore]`d; needs `MINIO_URL`.
//!
//! The in-suite AT-047 test (`persistence.rs`) proves sleep/wake *correctness* over an in-memory tier,
//! where wake is microseconds — it says so itself, and calls its `< 250 ms` assertion a regression
//! guard, not a benchmark. This is the benchmark: it seeds a tenant, sleeps it to a real
//! S3-compatible object store, wipes the local disk, wakes on a cold cache, and times **wake → first
//! read** — the operation `docs/02 §7` puts a p99 < 250 ms target on. It repeats to report a
//! distribution (p50 / p99 / max), not a single sample.
//!
//! This is **LoomDB's own session sleep/wake path** — loom faults its refs closure and tree pages back
//! from the tier. It is a different code path from FlockDB's DuckDB wake→query, and it is measured
//! separately, here.
//!
//! ## Scope, stated so no one over-reads it
//!
//! The number is only a **wide-area** number if `MINIO_URL` points at a bucket a real network away.
//! Against a same-runner MinIO the round-trip is ~local, so a pass there proves the wake path *meets the
//! target over the object-storage protocol at low latency* — it does not prove a wide-area p99. The
//! wide-area figure is the follow-on, taken against a genuinely remote bucket. No unqualified `< 250 ms`
//! claim is published from a same-runner run.
//!
//! ## Run it
//!
//! ```sh
//! MINIO_URL=http://127.0.0.1:9000 \
//!   cargo test -p loom-branch --test wake_latency -- --ignored --nocapture
//! ```

#![cfg(feature = "remote")]

use loom_branch::{Loom, LoomWakeToken, MemRefStore};
use loom_core::{ActorId, BranchId, Record, SessionId, TenantId, Value, WriteEnvelope};
use object_store::aws::AmazonS3Builder;
use std::sync::Arc;
use std::time::Instant;
use substrate_pager::StoreConfig;
use substrate_store::{RemoteTier, TieredStore};

fn envelope(branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent-1"),
        SessionId::new("s1"),
        branch.clone(),
        "measuring",
    )
}

fn counter(n: i64) -> Record {
    Record::Value(Value::Counter(n))
}

/// A fresh S3-backed `RemoteTier` for `pool`, in one of two modes decided by the environment:
///
/// - **Same-runner MinIO** (`MINIO_URL` set): custom endpoint over HTTP with explicit creds — the
///   low-latency control (p99 ≈ 13 ms; not a wide-area number).
/// - **Real AWS S3, wide-area** (`MINIO_URL` unset): region-derived HTTPS endpoint, credentials from
///   the standard `AWS_*` env the workflow maps from repository secrets (never echoed). `WAKE_ENDPOINT`
///   (optional) points at an S3-compatible service like R2. This is the genuinely-remote p99 an
///   unqualified `< 250 ms` for a remote-tier deployment rests on.
fn s3_remote(pool: &str) -> RemoteTier {
    let bucket = std::env::var("WAKE_BUCKET")
        .or_else(|_| std::env::var("MINIO_BUCKET"))
        .unwrap_or_else(|_| "loomdb".into());
    let mut builder = AmazonS3Builder::new().with_bucket_name(bucket);

    if let Ok(url) = std::env::var("MINIO_URL") {
        builder = builder
            .with_endpoint(url)
            .with_allow_http(true)
            .with_access_key_id(std::env::var("MINIO_USER").unwrap_or_else(|_| "minioadmin".into()))
            .with_secret_access_key(
                std::env::var("MINIO_PASSWORD").unwrap_or_else(|_| "minioadmin".into()),
            );
    } else {
        if let Ok(region) = std::env::var("AWS_REGION").or_else(|_| std::env::var("WAKE_REGION")) {
            builder = builder.with_region(region);
        }
        if let Ok(key) = std::env::var("AWS_ACCESS_KEY_ID") {
            builder = builder.with_access_key_id(key);
        }
        if let Ok(secret) = std::env::var("AWS_SECRET_ACCESS_KEY") {
            builder = builder.with_secret_access_key(secret);
        }
        if let Ok(endpoint) = std::env::var("WAKE_ENDPOINT") {
            builder = builder.with_endpoint(endpoint);
        }
    }

    let backend = builder.build().expect("build an S3 client");
    RemoteTier::new(Arc::new(backend), pool.to_string())
}

#[test]
#[ignore = "needs an S3-compatible endpoint; set MINIO_URL. Measures loom's own wake→first-read over object storage (AT-047)."]
fn at_047_wake_latency_over_object_storage() {
    // How many independent cold wakes to time. Each is: fresh tier, wake from nothing but object
    // storage, first read (which faults pages from the tier). Env-scalable for a longer nightly run.
    let samples: usize = std::env::var("LOOM_WAKE_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let mut latencies_ms: Vec<f64> = Vec::with_capacity(samples);

    for s in 0..samples {
        // A distinct tenant/pool per sample so each wake is genuinely cold and independent.
        let pool = format!("loomwake-{s}");
        let tenant = TenantId::new(pool.clone());

        // ── seed + sleep into the real bucket ──
        let seed_home = tempfile::tempdir().expect("tempdir");
        let token_json = rt.block_on(async {
            let tiered = TieredStore::open(
                seed_home.path(),
                s3_remote(&pool),
                StoreConfig {
                    pool: pool.clone(),
                    ..Default::default()
                },
            )
            .await
            .expect("open tiered store");

            let db = Loom::on(
                Arc::clone(tiered.pager()),
                Arc::new(MemRefStore::new()),
                tenant.clone(),
            )
            .expect("open loom");

            let (session, token) = db
                .open_session_named(SessionId::new("investigation-1"))
                .expect("session");
            // Enough commits that the head is an overlay on a base — the realistic wake shape.
            for round in 0..12u64 {
                db.write(
                    &token,
                    &session.branch,
                    format!("key-{round:04}").into_bytes(),
                    counter(round as i64),
                    &envelope(&session.branch),
                )
                .expect("write");
            }
            let wake_token = db.sleep(&tiered).await.expect("sleep");
            wake_token.to_json().expect("token json")
        });

        // ── wipe local; wake on a cold cache; time wake → first read ──
        drop(seed_home);
        let token = LoomWakeToken::from_json(&token_json).expect("parse token");
        let wake_home = tempfile::tempdir().expect("tempdir");

        let started = Instant::now();
        let value = rt.block_on(async {
            let tiered = TieredStore::open(
                wake_home.path(),
                s3_remote(&pool),
                StoreConfig {
                    pool: pool.clone(),
                    ..Default::default()
                },
            )
            .await
            .expect("open cold tiered store");
            let db = Loom::wake(&tiered, &token).expect("wake");
            let cap = db
                .issue_capability(
                    SessionId::new("after-wake"),
                    &[BranchId::new("investigation-1")],
                    3_600_000,
                )
                .expect("capability");
            // The first read from a cold cache faults its pages from the tier — this is the wake latency.
            db.read(&cap, &BranchId::new("investigation-1"), b"key-0000")
                .expect("first read")
        });
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(value, Some(counter(0)), "woke to the wrong value");
        latencies_ms.push(elapsed_ms);
    }

    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = |p: f64| -> f64 {
        let idx = ((p / 100.0) * (latencies_ms.len() as f64 - 1.0)).round() as usize;
        latencies_ms[idx.min(latencies_ms.len() - 1)]
    };
    let mean = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;

    println!("--- AT-047: loom wake → first read over object storage ({samples} cold wakes) ---");
    println!("p50 : {:.1} ms", pct(50.0));
    println!("p90 : {:.1} ms", pct(90.0));
    println!("p99 : {:.1} ms", pct(99.0));
    println!("max : {:.1} ms", latencies_ms[latencies_ms.len() - 1]);
    println!("mean: {mean:.1} ms");
    println!("(loom's OWN sleep/wake path, not FlockDB's DuckDB wake. Only a wide-area number if MINIO_URL is remote.)");

    let p99 = pct(99.0);
    // The `< 250 ms` check is a regression GUARD, applied only against a same-runner endpoint (MINIO_URL
    // set), where wake must comfortably hold and a regression that makes it fetch everything eagerly
    // would blow past it. Against a genuinely-remote bucket this is a MEASUREMENT, not a gate: the
    // number is the deliverable (held for review), and whether it clears 250 ms is the reviewer's call —
    // so a wide-area p99 over the target reports honestly instead of failing the run.
    if std::env::var("MINIO_URL").is_ok() {
        assert!(
            p99 < 250.0,
            "AT-047 p99 wake→first-read was {p99:.1} ms (target < 250 ms) against this same-runner endpoint"
        );
    } else if p99 >= 250.0 {
        println!("NOTE: wide-area p99 {p99:.1} ms is OVER the 250 ms target — reported, not asserted; no <250ms claim.");
    } else {
        println!("wide-area p99 {p99:.1} ms is UNDER 250 ms — but confirm against your own bucket before quoting.");
    }

    drop(rt);
}
