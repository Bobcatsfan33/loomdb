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
use object_store::ObjectStore;
use std::sync::Arc;
use std::time::Instant;
use substrate_pager::{PageId, StoreConfig};
use substrate_store::{RemoteTier, TieredStore};

/// Build the object-storage client once — its connection pool is what "warm" means. Sharing ONE client
/// across a run's wakes (via [`RemoteTier::new`] with `Arc::clone`) models the production loomd server:
/// a persistent client whose keep-alive connections stay open between wakes, so a wake reuses them
/// instead of paying a fresh TLS handshake per GET. Env logic identical to [`s3_remote`].
fn s3_client() -> Arc<dyn ObjectStore> {
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
    Arc::new(builder.build().expect("build an S3 client"))
}

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

/// **AT-047, the latency phase: loom's wake COALESCED through substrate's `get_batch`.**
///
/// The serial test above faults the point read's pages one round-trip at a time. This one maps that
/// read's actual page fault set to page ids and fetches them in a single concurrent, deduped
/// `get_batch` — the "hot tenant re-wake" case, where the fault set is known (here, learned from a
/// probe wake via `cas().list()`; in production, from a warm set). It reports a BREAKDOWN, because the
/// honest question is *where the time goes*: `get_batch` coalesces the PAGE fetches, but loom's read
/// also walks the overlay MANIFEST chain, and those manifest fetches are a different object type that
/// `get_batch` does not touch. The number — not the intention — says whether coalescing the pages is
/// enough to clear 250 ms, or whether the manifest chain is the next thing to batch.
#[test]
#[ignore = "needs an S3-compatible endpoint; set MINIO_URL. Measures loom's wake COALESCED via get_batch (AT-047 latency phase)."]
fn at_047_wake_latency_batched_over_object_storage() {
    let samples: usize = std::env::var("LOOM_WAKE_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let mut total_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut batch_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut read_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut rtt_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut fault_pages_n: Vec<usize> = Vec::with_capacity(samples);
    let branch = BranchId::new("investigation-1");

    // ONE shared client for the whole run — its connection pool warms on the first wake and stays warm
    // (keep-alive), so the measured wakes reuse connections instead of paying a fresh TLS handshake per
    // GET. This is the pooling lever: it re-baselines BOTH components (get_batch pages AND the manifest
    // walk), since both go through this same client to the same store.
    let backend = s3_client();

    for s in 0..samples {
        let pool = format!("loombatch-{s}");
        let tenant = TenantId::new(pool.clone());

        // ── seed + sleep (same shape as the serial test: 12 writes → head is an overlay on a base) ──
        let seed_home = tempfile::tempdir().expect("tempdir");
        let token_json = rt.block_on(async {
            let tiered = TieredStore::open(
                seed_home.path(),
                RemoteTier::new(Arc::clone(&backend), pool.clone()),
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
            db.sleep(&tiered)
                .await
                .expect("sleep")
                .to_json()
                .expect("json")
        });
        drop(seed_home);
        let token = LoomWakeToken::from_json(&token_json).expect("parse token");

        // ── Probe wake (cold): serial point read, then LEARN the pages it faulted (the fault set). ──
        let probe_home = tempfile::tempdir().expect("tempdir");
        let fault_pages: Vec<PageId> = rt.block_on(async {
            let tiered = TieredStore::open(
                probe_home.path(),
                RemoteTier::new(Arc::clone(&backend), pool.clone()),
                StoreConfig {
                    pool: pool.clone(),
                    ..Default::default()
                },
            )
            .await
            .expect("open probe tier");
            let db = Loom::wake(&tiered, &token).expect("wake");
            let cap = db
                .issue_capability(
                    SessionId::new("probe"),
                    std::slice::from_ref(&branch),
                    3_600_000,
                )
                .expect("cap");
            db.read(&cap, &branch, b"key-0000").expect("probe read");
            // The local CAS now holds exactly the PAGES that first read faulted — its fault set.
            tiered.pager().cas().list().expect("list faulted pages")
        });
        drop(probe_home);

        // ── RTT probe: time ONE warm GET, so every component below can be reported in RTT-multiples.
        //    This is the only thing that cuts through the wild run-to-run network variance (the serial
        //    baseline alone swings 2x between runs) — 450 ms means nothing until you know if that is one
        //    round-trip or two. Uses the shared, already-warm client; a raw remote GET, not through the
        //    tier cache. ──
        let rtt = rt.block_on(async {
            let remote = RemoteTier::new(Arc::clone(&backend), pool.clone());
            let key = remote.page_key(fault_pages[0]);
            let t = Instant::now();
            remote.get(&key).await.expect("rtt probe get");
            t.elapsed().as_secs_f64() * 1000.0
        });
        rtt_ms.push(rtt);

        // ── Measured wake (cold cache, warm client): get_batch the fault set, then read. Timed + broken down. ──
        let wake_home = tempfile::tempdir().expect("tempdir");
        let started = Instant::now();
        let (value, this_batch_ms, this_read_ms) = rt.block_on(async {
            let tiered = TieredStore::open(
                wake_home.path(),
                RemoteTier::new(Arc::clone(&backend), pool.clone()),
                StoreConfig {
                    pool: pool.clone(),
                    ..Default::default()
                },
            )
            .await
            .expect("open cold tier");
            let db = Loom::wake(&tiered, &token).expect("wake");

            // Coalesce the page fault set into ONE concurrent, deduped batch.
            let t_batch = Instant::now();
            tiered.get_batch(&fault_pages).expect("get_batch");
            let batch = t_batch.elapsed().as_secs_f64() * 1000.0;

            // The read now serves those pages warm; what remains on this path is the manifest chain.
            let t_read = Instant::now();
            let cap = db
                .issue_capability(
                    SessionId::new("after"),
                    std::slice::from_ref(&branch),
                    3_600_000,
                )
                .expect("cap");
            let v = db.read(&cap, &branch, b"key-0000").expect("read");
            let read = t_read.elapsed().as_secs_f64() * 1000.0;
            (v, batch, read)
        });
        let total = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(value, Some(counter(0)), "woke to the wrong value");
        total_ms.push(total);
        batch_ms.push(this_batch_ms);
        read_ms.push(this_read_ms);
        fault_pages_n.push(fault_pages.len());
    }

    total_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = |v: &[f64], p: f64| -> f64 {
        let idx = ((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
        v[idx.min(v.len() - 1)]
    };
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let mean_u = |v: &[usize]| v.iter().sum::<usize>() as f64 / v.len() as f64;

    let rtt = mean(&rtt_ms).max(0.001);
    println!("--- AT-047 BATCHED: loom wake COALESCED via get_batch, warm pool ({samples} cold wakes) ---");
    println!(
        "fault set size          : mean {:.1} pages (deduped to objects by get_batch)",
        mean_u(&fault_pages_n)
    );
    println!(
        "1 RTT (warm GET)        : mean {rtt:.1} ms  ← the unit; absolute ms below are noisy, RTT-multiples are not"
    );
    println!(
        "wake → first read TOTAL : p50 {:.1} / p99 {:.1} ms   = {:.2} RTT (p50)",
        pct(&total_ms, 50.0),
        pct(&total_ms, 99.0),
        pct(&total_ms, 50.0) / rtt
    );
    println!(
        "  ├ get_batch(pages)     : mean {:.1} ms = {:.2} RTT  (concurrent, deduped — the coalesced part)",
        mean(&batch_ms),
        mean(&batch_ms) / rtt
    );
    println!(
        "  └ read (manifest chain + warm pages) : mean {:.1} ms = {:.2} RTT  (serial manifests get_batch does NOT touch)",
        mean(&read_ms),
        mean(&read_ms) / rtt
    );
    println!("(loom's OWN wake, not DuckDB. Only a wide-area number if MINIO_URL is remote.)");

    let p99 = pct(&total_ms, 99.0);
    if std::env::var("MINIO_URL").is_ok() {
        // Same-runner: informational only (RTT ≈ 0, so batching shows little). No gate here.
        println!("(same-runner endpoint — informational; batching's payoff only shows wide-area.)");
    } else if p99 < 250.0 {
        println!("RESULT: batched wide-area p99 {p99:.1} ms is UNDER 250 ms — AT-047 wide-area limit can be RETIRED (batched path).");
    } else {
        println!("RESULT: batched wide-area p99 {p99:.1} ms is still OVER 250 ms — coalescing the pages helped, but the breakdown shows what dominates (likely the serial manifest chain — the next thing to batch). Reported honestly; no <250ms claim.");
    }

    drop(rt);
}

/// **AT-047, hot vs cold — the warm set through LoomDB's REAL wake path.**
///
/// The batched test above *simulates* a warm re-wake by learning the fault set with a probe and calling
/// `get_batch` by hand — and its own breakdown flags that it coalesces the pages but leaves the overlay
/// MANIFEST chain serial ("the next thing to batch"). substrate v1.4.x makes that automatic: a session's
/// faulted objects (chain **and** pages) are learned into the warm set, `sleep()` carries it in the
/// token, and `Loom::wake` hands it to `TieredStore::prefetch`, which hydrates the whole chain in one
/// concurrent round-trip before the first read arrives. This test measures **that**, end to end, with no
/// hand-built batch — the number is loom's actual wake, not a harness stand-in.
///
/// Two paths against the same point read, same tenant shape:
///
/// - **cold** — first-ever wake, empty warm set: the serial overlay-chain walk. The `~2–4 RTT` baseline.
/// - **hot**  — re-wake carrying the warm set the cold session learned: the prefetch collapses the walk.
///   The `< 250 ms` target lives here.
///
/// The hot token is the cold token with the warm set the cold wake learned grafted on (nothing was
/// written between them, so the refs are identical) — exactly what a real working session's `sleep()`
/// persists, without needing a read-only re-sleep to resolve a history closure it never faulted.
///
/// Wide-area (no `MINIO_URL`): the hot p99 is the deliverable, and whether it clears 250 ms is the
/// AT-047 verdict. Same-runner: informational (RTT ≈ 0 hides the gap).
#[test]
#[ignore = "needs an S3-compatible endpoint; set MINIO_URL. Measures loom's warm-set hot re-wake vs cold first-ever (AT-047)."]
fn at_047_hot_vs_cold_rewake_over_object_storage() {
    let samples: usize = std::env::var("LOOM_WAKE_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let branch = BranchId::new("investigation-1");
    let backend = s3_client(); // one warm, pooled client for the whole run — see the batched test.

    let mut cold_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut hot_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut rtt_ms: Vec<f64> = Vec::with_capacity(samples);
    let mut warm_manifests_n: Vec<usize> = Vec::with_capacity(samples);
    let mut warm_pages_n: Vec<usize> = Vec::with_capacity(samples);
    let mut hot_read_faults_n: Vec<u64> = Vec::with_capacity(samples);
    let mut hot_hydrate_ms: Vec<f64> = Vec::with_capacity(samples);

    let open = |home: &std::path::Path, pool: &str| {
        rt.block_on(TieredStore::open(
            home,
            RemoteTier::new(Arc::clone(&backend), pool.to_string()),
            StoreConfig {
                pool: pool.to_string(),
                ..Default::default()
            },
        ))
        .expect("open tier")
    };

    for s in 0..samples {
        let pool = format!("loomhotcold-{s}");
        let tenant = TenantId::new(pool.clone());

        // ── seed + sleep: 12 writes so the head is an overlay on a base (the realistic wake shape). The
        //    seed never faults, so this cold token's warm set is empty — a true first-ever token. ──
        let seed_home = tempfile::tempdir().expect("tempdir");
        let token_cold = rt.block_on(async {
            let tiered = TieredStore::open(
                seed_home.path(),
                RemoteTier::new(Arc::clone(&backend), pool.clone()),
                StoreConfig {
                    pool: pool.clone(),
                    ..Default::default()
                },
            )
            .await
            .expect("open seed tier");
            let db = Loom::on(
                Arc::clone(tiered.pager()),
                Arc::new(MemRefStore::new()),
                tenant.clone(),
            )
            .expect("open loom");
            let (session, token) = db
                .open_session_named(SessionId::new("investigation-1"))
                .expect("session");
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
            db.sleep(&tiered).await.expect("sleep")
        });
        drop(seed_home);
        assert!(
            token_cold.warm_set.is_empty(),
            "a first-ever token should carry no warm set"
        );

        // ── COLD: first-ever wake, empty warm set → serial chain walk. Also learns the warm set. ──
        let cold_home = tempfile::tempdir().expect("tempdir");
        let (cold_elapsed, warm) = {
            let tiered = open(cold_home.path(), &pool);
            let started = Instant::now();
            let value = {
                let db = Loom::wake(&tiered, &token_cold).expect("cold wake");
                let cap = db
                    .issue_capability(
                        SessionId::new("cold"),
                        std::slice::from_ref(&branch),
                        3_600_000,
                    )
                    .expect("cap");
                db.read(&cap, &branch, b"key-0000").expect("cold read")
            };
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(value, Some(counter(0)), "cold woke to the wrong value");
            (elapsed, tiered.warm_set())
        };
        drop(cold_home);
        cold_ms.push(cold_elapsed);
        assert!(
            !warm.is_empty(),
            "the cold read learned no warm set — nothing for the hot path to prefetch"
        );

        // ── RTT probe: one warm GET of a known-durable object (a page the cold read faulted), so both
        //    paths can be read in RTT-multiples through the wild run-to-run network variance. Raw remote
        //    GET, not through a tier cache. ──
        let rtt = rt.block_on(async {
            let remote = RemoteTier::new(Arc::clone(&backend), pool.clone());
            let key = match warm.pages.first() {
                Some(&p) => remote.page_key(p),
                None => remote.manifest_key(warm.manifests[0]),
            };
            let t = Instant::now();
            let _ = remote.get(&key).await;
            t.elapsed().as_secs_f64() * 1000.0
        });
        rtt_ms.push(rtt);

        // Warm-set composition — how much of each object type the cold read learned, so we can see
        // whether the manifest chain (the serial bottleneck) is actually being hydrated.
        warm_manifests_n.push(warm.manifests.len());
        warm_pages_n.push(warm.pages.len());

        // The hot token: same refs (nothing was written), with the learned warm set grafted on.
        let token_hot = LoomWakeToken {
            warm_set: warm,
            ..token_cold.clone()
        };

        // ── HOT: re-wake carrying the warm set → hydrate (awaited), then wake+read on the warm cache. ──
        // We split the two costs: hydrate in isolation, then wake+read. Loom::wake also hydrates, but by
        // then everything is resident so its hydrate is a cheap no-op — so this attributes the round-trips
        // honestly (hydrate vs. everything-else) without changing the total a production single-wake pays.
        let hot_home = tempfile::tempdir().expect("tempdir");
        let (hot_elapsed, hydrate_only_ms, read_faults) = {
            let tiered = open(hot_home.path(), &pool);
            let started = Instant::now();

            // 1. Hydrate in isolation, timed.
            let t_h = Instant::now();
            tiered.hydrate(&token_hot.warm_set);
            let hydrate_ms = t_h.elapsed().as_secs_f64() * 1000.0;
            let misses_after_hydrate = tiered.stats().misses;

            // 2. Wake (its internal hydrate is now a warm no-op) + read.
            let db = Loom::wake(&tiered, &token_hot).expect("hot wake");
            let value = {
                let cap = db
                    .issue_capability(
                        SessionId::new("hot"),
                        std::slice::from_ref(&branch),
                        3_600_000,
                    )
                    .expect("cap");
                db.read(&cap, &branch, b"key-0000").expect("hot read")
            };
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            let read_faults = tiered.stats().misses.saturating_sub(misses_after_hydrate);
            assert_eq!(value, Some(counter(0)), "hot woke to the wrong value");
            (elapsed, hydrate_ms, read_faults)
        };
        drop(hot_home);
        hot_ms.push(hot_elapsed);
        hot_hydrate_ms.push(hydrate_only_ms);
        hot_read_faults_n.push(read_faults);
    }

    let sort =
        |v: &mut Vec<f64>| v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sort(&mut cold_ms);
    sort(&mut hot_ms);
    let pct = |v: &[f64], p: f64| -> f64 {
        let idx = ((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
        v[idx.min(v.len() - 1)]
    };
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let mean_u = |v: &[usize]| v.iter().sum::<usize>() as f64 / v.len() as f64;
    let mean_u64 = |v: &[u64]| v.iter().sum::<u64>() as f64 / v.len() as f64;
    let rtt = mean(&rtt_ms).max(0.001);

    println!(
        "--- AT-047 HOT vs COLD: loom's real wake path, warm set via token ({samples} samples) ---"
    );
    println!("1 RTT (warm GET)   : mean {rtt:.1} ms  ← the unit");
    println!(
        "warm set learned   : mean {:.1} manifests + {:.1} pages   |   hot read faulted mean {:.2} objects AFTER hydrate",
        mean_u(&warm_manifests_n),
        mean_u(&warm_pages_n),
        mean_u64(&hot_read_faults_n),
    );
    println!(
        "hot breakdown      : hydrate mean {:.1} ms = {:.2} RTT   |   wake+read (warm) = the rest",
        mean(&hot_hydrate_ms),
        mean(&hot_hydrate_ms) / rtt,
    );
    println!(
        "COLD (first-ever)  : p50 {:.1} / p99 {:.1} ms   = {:.2} / {:.2} RTT   (serial overlay-chain walk)",
        pct(&cold_ms, 50.0),
        pct(&cold_ms, 99.0),
        pct(&cold_ms, 50.0) / rtt,
        pct(&cold_ms, 99.0) / rtt,
    );
    println!(
        "HOT  (warm re-wake): p50 {:.1} / p99 {:.1} ms   = {:.2} / {:.2} RTT   (prefetch collapses the chain)",
        pct(&hot_ms, 50.0),
        pct(&hot_ms, 99.0),
        pct(&hot_ms, 50.0) / rtt,
        pct(&hot_ms, 99.0) / rtt,
    );
    println!(
        "speedup (p50)      : {:.2}x",
        pct(&cold_ms, 50.0) / pct(&hot_ms, 50.0).max(1e-9)
    );
    println!("(loom's OWN wake through the warm set, not DuckDB. Only a wide-area number if MINIO_URL is remote.)");

    let hot_p99 = pct(&hot_ms, 99.0);
    if std::env::var("MINIO_URL").is_ok() {
        println!("(same-runner endpoint — informational; the warm set's payoff only shows wide-area where RTT is real.)");
    } else if hot_p99 < 250.0 {
        println!(
            "RESULT: hot re-wake wide-area p99 {hot_p99:.1} ms is UNDER 250 ms — AT-047 wide-area limit RETIRES for the hot-tenant re-wake (cold first-ever stays the serial {:.2}-RTT baseline).",
            pct(&cold_ms, 50.0) / rtt
        );
    } else {
        println!("RESULT: hot re-wake wide-area p99 {hot_p99:.1} ms is still OVER 250 ms — reported honestly; no <250ms claim, AT-047 limit stands and its number is UPDATED to this measurement.");
    }

    drop(rt);
}
