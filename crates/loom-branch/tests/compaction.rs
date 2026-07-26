//! **The ANN live-index gates — buffer + fold + union-search, and the concurrency it survives.**
//!
//! Slice 2c's decision (compaction, on the number) is only *resolved* when the index is **live**: a
//! freshly-written vector is searchable immediately, with **0 staleness**, and stays searchable across
//! the background fold that moves it from the write buffer into the graph. These are the gates that hold
//! that claim to evidence rather than hope.
//!
//! - **0 staleness** — a vector is found the instant it is written, before any fold (via the union's
//!   buffer scan).
//! - **The handoff invariant** — a vector is searchable *continuously* across a fold: in the buffer
//!   before, in the graph after, with no window where a search would miss it, and never counted twice.
//! - **Recall on the union** — recall holds against brute force with the index in its realistic mixed
//!   state (some vectors folded into the graph, some still in the buffer).
//! - **The concurrency gate** — the same class of care as wake-piece-2: the fold racing live appends and
//!   union-searches under randomized interleavings loses no item, double-indexes none, and never
//!   deadlocks.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;
const DIM: usize = 48;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32
    }
}
fn rv(r: &mut Rng, d: usize) -> Embedding {
    Embedding::new((0..d).map(|_| r.unit() * 2.0 - 1.0).collect::<Vec<_>>())
}

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "index",
    )
}
fn obs(i: usize) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(format!("s{i}").as_bytes()),
        source: SourceRef::new("web", format!("s{i}")),
        trust: TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: format!("fact {i}").into_bytes(),
    }))
}

fn key_of(i: usize) -> Vec<u8> {
    format!("obs/{i:08}").into_bytes()
}

/// **0 staleness: a written vector is searchable immediately, before any fold.** The graph does not yet
/// contain it — the union's buffer scan does.
#[test]
fn a_written_vector_is_searchable_before_any_fold() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();
    let mut rng = Rng(1);

    let mut vecs = Vec::new();
    for i in 0..40usize {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &token,
            &branch,
            key_of(i),
            obs(i),
            IndexHint::text(format!("f{i}")).with_embedding(v.clone()),
            &env(&session.id, &branch),
        )
        .unwrap();
        vecs.push(v);
    }

    // No build/fold has happened, so the graph is empty. Every vector must still retrieve itself, from
    // the buffer, via the union search.
    for (i, v) in vecs.iter().enumerate() {
        let hits = db.search_ann(&token, &branch, v, 5).unwrap();
        assert!(
            hits.contains(&key_of(i)),
            "vector {i} was not searchable before a fold — the buffer is not being unioned into search"
        );
    }
}

/// **The handoff never drops a vector and never double-counts it.** Search the same vector before and
/// after a fold: found both times, and exactly once (no duplicate key) — the buffer→graph handoff is
/// atomic and the buffer is cleared on commit.
#[test]
fn the_handoff_never_drops_a_vector_and_never_double_counts() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();
    let mut rng = Rng(2);

    let mut vecs = Vec::new();
    for i in 0..60usize {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &token,
            &branch,
            key_of(i),
            obs(i),
            IndexHint::text(format!("f{i}")).with_embedding(v.clone()),
            &env(&session.id, &branch),
        )
        .unwrap();
        vecs.push(v);
    }

    let check_all = |label: &str| {
        for (i, v) in vecs.iter().enumerate() {
            let hits = db.search_ann(&token, &branch, v, 5).unwrap();
            assert!(hits.contains(&key_of(i)), "{label}: vector {i} not found");
            // No key appears twice in a single result (the union dedups by record key).
            let mut sorted = hits.clone();
            sorted.sort();
            let mut deduped = sorted.clone();
            deduped.dedup();
            assert_eq!(
                sorted, deduped,
                "{label}: a key was returned twice for vector {i}"
            );
        }
    };

    check_all("before fold (buffer only)");
    let folded = db.ann_fold(&token, &branch).unwrap();
    assert_eq!(
        folded,
        vecs.len(),
        "the fold should have indexed every buffered vector"
    );
    check_all("after fold (graph only, buffer cleared)");

    // A second fold with nothing new buffered is a no-op that still holds.
    db.ann_fold(&token, &branch).unwrap();
    check_all("after a redundant fold");
}

/// **Recall holds on the union** with the index in a realistic mixed state: half the vectors folded into
/// the graph, half still in the buffer. Recall@10 vs the exact brute-force top-10 must clear the floor.
#[test]
fn recall_holds_across_the_union_of_graph_and_buffer() {
    const K: usize = 10;
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();
    let mut rng = Rng(3);

    let n = 400usize;
    let mut items: Vec<(Vec<u8>, Embedding)> = Vec::new();
    // First half → written then folded into the graph.
    for i in 0..n / 2 {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &token,
            &branch,
            key_of(i),
            obs(i),
            IndexHint::text("f").with_embedding(v.clone()),
            &env(&session.id, &branch),
        )
        .unwrap();
        items.push((key_of(i), v));
    }
    db.ann_fold(&token, &branch).unwrap();
    // Second half → written after the fold, so they live in the buffer at search time.
    for i in n / 2..n {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &token,
            &branch,
            key_of(i),
            obs(i),
            IndexHint::text("f").with_embedding(v.clone()),
            &env(&session.id, &branch),
        )
        .unwrap();
        items.push((key_of(i), v));
    }

    let mut hits = 0usize;
    let mut possible = 0usize;
    for _ in 0..20 {
        let q = rv(&mut rng, DIM);
        let mut exact: Vec<(&Vec<u8>, f32)> = items
            .iter()
            .filter_map(|(k, v)| q.cosine(v).map(|c| (k, c)))
            .collect();
        exact.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let truth: std::collections::HashSet<Vec<u8>> =
            exact.iter().take(K).map(|(k, _)| (*k).clone()).collect();
        let got: std::collections::HashSet<Vec<u8>> = db
            .search_ann(&token, &branch, &q, K)
            .unwrap()
            .into_iter()
            .collect();
        hits += truth.iter().filter(|k| got.contains(*k)).count();
        possible += truth.len();
    }
    let recall = hits as f64 / possible as f64;
    assert!(
        recall >= 0.85,
        "union-search recall@{K} = {recall:.3} across graph+buffer, below floor 0.85"
    );
}

/// **AT-040 holds for the buffer too — a sibling's UNFOLDED vector is never returned.** The buffer is a
/// reserved, in-branch prefix, so a search forks only its own branch's tree and scans only its own
/// buffer. Nothing is folded here, so this exercises the *buffer* isolation specifically (the graph path
/// is covered in `ann.rs`).
#[test]
fn a_siblings_buffered_vector_is_never_returned() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (root, token) = db.open_session().unwrap();
    let (left, ltok) = db.branch(&token, &root.branch, "left").unwrap();
    let (right, rtok) = db.branch(&token, &root.branch, "right").unwrap();
    let mut rng = Rng(9);
    for i in 0..50usize {
        db.write_indexed(
            &ltok,
            &left,
            format!("L/{i}").into_bytes(),
            obs(i),
            IndexHint::text("l").with_embedding(rv(&mut rng, DIM)),
            &env(&root.id, &left),
        )
        .unwrap();
        db.write_indexed(
            &rtok,
            &right,
            format!("R/{i}").into_bytes(),
            obs(i),
            IndexHint::text("r").with_embedding(rv(&mut rng, DIM)),
            &env(&root.id, &right),
        )
        .unwrap();
    }
    // NO fold — every vector is in the buffer. Search must still be branch-isolated.
    let q = rv(&mut rng, DIM);
    for key in db.search_ann(&ltok, &left, &q, 20).unwrap() {
        let s = String::from_utf8_lossy(&key);
        assert!(
            s.starts_with("L/"),
            "LEAK: left's buffer search returned {s}, a sibling's vector — the buffer is not isolated"
        );
    }
    for key in db.search_ann(&rtok, &right, &q, 20).unwrap() {
        let s = String::from_utf8_lossy(&key);
        assert!(
            s.starts_with("R/"),
            "LEAK: right's buffer search returned {s}, a sibling's vector — the buffer is not isolated"
        );
    }
}

/// **The concurrency gate — the fold racing live appends and union-searches.**
///
/// One thread writes `N` distinct vectors; one thread folds in a tight loop the whole time; three
/// threads union-search vectors already written. Under these randomized interleavings it proves:
/// - **no lost item** — after the run, every written vector retrieves itself (buffer or graph);
/// - **no double-index** — no search ever returns a record key twice;
/// - **no deadlock** — every thread finishes (the test simply returns; a hang is a failure).
///
/// Each vector is near-orthogonal to the others, so self-retrieval is exact and a miss is a real loss,
/// not approximation noise.
#[test]
fn fold_racing_writes_and_searches_never_loses_or_doubles_an_item() {
    const N: usize = 160;
    let db = Arc::new(
        Loom::in_memory(TenantId::new("acme"))
            .unwrap()
            .with_clock(|| NOW),
    );
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    let mut rng = Rng(4);
    let vecs: Arc<Vec<Embedding>> = Arc::new((0..N).map(|_| rv(&mut rng, DIM)).collect());
    let written = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Folder: fold in a tight loop, racing the writer, until told to stop.
    let folder = {
        let (db, token, branch, stop) = (db.clone(), token.clone(), branch.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                db.ann_fold(&token, &branch).expect("fold");
                // A realistic cadence rather than a spin: each fold rebuilds the whole graph, so a tight
                // loop just burns CPU on redundant rebuilds. This still overlaps folds heavily with the
                // writes and searches — the race we are gating — without hundreds of full rebuilds.
                std::thread::sleep(std::time::Duration::from_micros(500));
            }
        })
    };

    // Searchers: continuously search a vector already written and assert no duplicate key comes back.
    let searchers: Vec<_> = (0..3)
        .map(|s| {
            let (db, token, branch, vecs, written, stop) = (
                db.clone(),
                token.clone(),
                branch.clone(),
                vecs.clone(),
                written.clone(),
                stop.clone(),
            );
            std::thread::spawn(move || {
                let mut r = Rng(0xBEEF ^ s as u64);
                while !stop.load(Ordering::Relaxed) {
                    let w = written.load(Ordering::Acquire);
                    if w == 0 {
                        std::thread::yield_now();
                        continue;
                    }
                    let i = (r.next() as usize) % w; // a vector guaranteed already committed
                    let hits = db.search_ann(&token, &branch, &vecs[i], 5).expect("search");
                    let mut sorted = hits.clone();
                    sorted.sort();
                    let mut deduped = sorted.clone();
                    deduped.dedup();
                    assert_eq!(sorted, deduped, "a key was returned twice under the race");
                    // A committed vector must be findable at all times, mid-race.
                    assert!(
                        hits.contains(&key_of(i)),
                        "vector {i} vanished mid-race — the handoff dropped it"
                    );
                }
            })
        })
        .collect();

    // Writer (this thread): write every vector, publishing the count AFTER each commit lands.
    for i in 0..N {
        db.write_indexed(
            &token,
            &branch,
            key_of(i),
            obs(i),
            IndexHint::text(format!("f{i}")).with_embedding(vecs[i].clone()),
            &env(&session.id, &branch),
        )
        .expect("write");
        written.store(i + 1, Ordering::Release);
    }

    stop.store(true, Ordering::Release);
    folder
        .join()
        .expect("folder thread panicked (deadlock or assertion)");
    for h in searchers {
        h.join()
            .expect("searcher thread panicked (deadlock or assertion)");
    }

    // A final fold to drain the buffer, then the whole-set invariant: every item present exactly once.
    db.ann_fold(&token, &branch).expect("final fold");
    for i in 0..N {
        let hits = db
            .search_ann(&token, &branch, &vecs[i], 5)
            .expect("final search");
        assert!(
            hits.contains(&key_of(i)),
            "LOST: vector {i} is in neither buffer nor graph after the race"
        );
        let mut sorted = hits.clone();
        sorted.sort();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(
            sorted, deduped,
            "DOUBLE: key returned twice for vector {i} after the race"
        );
    }
}
