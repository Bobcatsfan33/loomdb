//! **The ANN index in a real branch: recall against the brute-force scan, and isolation.**
//!
//! Slice 2a proved the graph against the recall oracle in memory. This proves it end to end through the
//! branch tree: build the index on a real branch, and (1) it recovers the same nearest neighbours a
//! full scan would, and (2) — the load-bearing property — a search on one branch NEVER returns a
//! sibling branch's vectors, because the graph lives in the branch's own tree (invariant I-11).

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;

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

fn obs(source: &str) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(source.as_bytes()),
        source: SourceRef::new("web", source),
        trust: TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: source.as_bytes().to_vec(),
    }))
}

/// Write `n` indexed observations with random vectors on `branch`. Returns the (key, vector) list.
fn seed(
    db: &Loom,
    token: &loom_branch::CapabilityToken,
    branch: &BranchId,
    sid: &SessionId,
    rng: &mut Rng,
    n: usize,
    dim: usize,
) -> Vec<(Vec<u8>, Embedding)> {
    let mut out = Vec::new();
    for i in 0..n {
        let key = format!("obs/{i}").into_bytes();
        let v = rv(rng, dim);
        db.write_indexed(
            token,
            branch,
            key.clone(),
            obs(&format!("s{i}")),
            IndexHint::text(format!("fact {i}")).with_embedding(v.clone()),
            &env(sid, branch),
        )
        .unwrap();
        out.push((key, v));
    }
    out
}

/// **The branch ANN index recovers the same near neighbours a full scan would — recall through the
/// real tree.**
#[test]
fn ann_index_in_a_branch_matches_the_brute_force_scan() {
    const DIM: usize = 24;
    const K: usize = 10;
    let n: usize = if std::env::var("RECALL_FULL").is_ok() {
        400
    } else {
        120
    };

    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();
    let mut rng = Rng(7);
    let items = seed(&db, &token, &branch, &session.id, &mut rng, n, DIM);

    let indexed = db.build_ann_index(&token, &branch).unwrap();
    assert_eq!(indexed, n, "every vector on the branch is indexed");

    // 15 queries, recall@K vs the exact top-K.
    let mut hits = 0usize;
    let mut possible = 0usize;
    for _ in 0..15 {
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
        "branch ANN recall@{K} = {recall:.3}, below floor 0.85"
    );
}

/// **AT-040 through the ANN index: a sibling branch's vectors are never returned.**
///
/// Each branch builds its own graph in its own tree. A query on `left` can only reach `left`'s graph —
/// a different head manifest is a different tree. This is the same structural isolation as the scan,
/// preserved by keeping the index IN the branch (invariant I-11) rather than in a shared store.
#[test]
fn ann_search_never_returns_a_siblings_vectors() {
    const DIM: usize = 16;

    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (root, token) = db.open_session().unwrap();
    let (left, ltok) = db.branch(&token, &root.branch, "left").unwrap();
    let (right, rtok) = db.branch(&token, &root.branch, "right").unwrap();

    let mut rng = Rng(99);
    // Distinct, non-overlapping key spaces so a leak is unmistakable.
    for i in 0..80 {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &ltok,
            &left,
            format!("L/{i}").into_bytes(),
            obs(&format!("l{i}")),
            IndexHint::text("left").with_embedding(v),
            &env(&root.id, &left),
        )
        .unwrap();
    }
    for i in 0..80 {
        let v = rv(&mut rng, DIM);
        db.write_indexed(
            &rtok,
            &right,
            format!("R/{i}").into_bytes(),
            obs(&format!("r{i}")),
            IndexHint::text("right").with_embedding(v),
            &env(&root.id, &right),
        )
        .unwrap();
    }
    db.build_ann_index(&ltok, &left).unwrap();
    db.build_ann_index(&rtok, &right).unwrap();

    // A query on left must return only L/ keys — never an R/ key. Both retrieval surfaces are checked:
    // the ANN graph search AND the exact scan, since each is a distinct path that reads the branch fork.
    let q = rv(&mut rng, DIM);
    for search in ["ann", "scan"] {
        let left_hits = match search {
            "ann" => db.search_ann(&ltok, &left, &q, 20).unwrap(),
            _ => db.search_scan(&ltok, &left, &q, 20).unwrap(),
        };
        for key in left_hits {
            let s = String::from_utf8_lossy(&key);
            assert!(
                s.starts_with("L/"),
                "LEAK ({search}): left's search returned {s}, a sibling's vector. Not isolated."
            );
        }
        let right_hits = match search {
            "ann" => db.search_ann(&rtok, &right, &q, 20).unwrap(),
            _ => db.search_scan(&rtok, &right, &q, 20).unwrap(),
        };
        for key in right_hits {
            let s = String::from_utf8_lossy(&key);
            assert!(
                s.starts_with("R/"),
                "LEAK ({search}): right's search returned {s}"
            );
        }
    }
}

/// **`search_scan` is exact — it returns precisely the brute-force top-k, and needs no built index.**
///
/// The exact fallback the ANN is measured against (`benches/ann_vs_scan.rs`). It scores every index
/// entry, so it is correct-by-construction; this pins that down against an independent in-RAM brute force
/// (set-equality, not merely recall ≥ floor) and confirms it works with no `build_ann_index` first —
/// index entries carry their embedding whether or not a graph was ever folded.
#[test]
fn search_scan_returns_the_exact_top_k() {
    const DIM: usize = 24;
    const K: usize = 10;
    let n = 200;

    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();
    let mut rng = Rng(4242);
    let items = seed(&db, &token, &branch, &session.id, &mut rng, n, DIM);

    // No build_ann_index: search_scan reads the index entries directly.
    for _ in 0..15 {
        let q = rv(&mut rng, DIM);
        let mut exact: Vec<(&Vec<u8>, f32)> = items
            .iter()
            .filter_map(|(k, v)| q.cosine(v).map(|c| (k, c)))
            .collect();
        exact.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let truth: std::collections::HashSet<Vec<u8>> =
            exact.iter().take(K).map(|(k, _)| (*k).clone()).collect();

        let got: std::collections::HashSet<Vec<u8>> = db
            .search_scan(&token, &branch, &q, K)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(got, truth, "search_scan did not return the exact top-{K}");
    }
}
