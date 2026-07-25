//! Embeddings, and the one similarity we compute over them.
//!
//! # The engine does not embed. It stores what it is handed.
//!
//! There is no model in here. A caller that has an embedding model hands us the vector; we store it,
//! and we compare it. This is the same stance as AT-002's read-set: the engine is the place vectors
//! *live and are searched*, not the place they are *made*. Baking a specific model in would pin the
//! whole database to one vendor's dimensionality and one moment's idea of what "similar" means, and
//! make deterministic replay depend on a network service. So: the caller's vector, verbatim.

use serde::{Deserialize, Serialize};

/// A dense vector, as produced by whatever model the caller used.
///
/// The dimensionality is the caller's; we only require that two vectors compared against each other
/// agree on it, and we say so rather than returning a quietly-wrong number when they do not.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Embedding(pub Vec<f32>);

impl Embedding {
    /// Wrap a vector.
    pub fn new(v: impl Into<Vec<f32>>) -> Self {
        Embedding(v.into())
    }

    /// The dimensionality.
    pub fn dim(&self) -> usize {
        self.0.len()
    }

    /// **Cosine similarity, in `[-1, 1]`** — or `None` when the two vectors cannot be compared.
    ///
    /// Returns `None` rather than a number when the dimensions differ or a vector is all-zeros. A
    /// zero vector has no direction, so its cosine to anything is undefined; returning `0.0` there
    /// would silently rank an un-embeddable item as "somewhat unrelated to everything" instead of
    /// "not comparable", and it would pollute a retrieval with items that were never really scored.
    /// The caller decides what an incomparable candidate is worth; we do not decide it for them by
    /// picking a plausible-looking zero.
    pub fn cosine(&self, other: &Embedding) -> Option<f32> {
        if self.0.len() != other.0.len() || self.0.is_empty() {
            return None;
        }

        let mut dot = 0.0f32;
        let mut na = 0.0f32;
        let mut nb = 0.0f32;
        for (a, b) in self.0.iter().zip(&other.0) {
            dot += a * b;
            na += a * a;
            nb += b * b;
        }

        if na == 0.0 || nb == 0.0 {
            return None;
        }

        Some(dot / (na.sqrt() * nb.sqrt()))
    }

    /// **The bare dot product** — `None` when the two cannot be compared (differing dims, or empty).
    ///
    /// On **unit-length** vectors this *is* cosine similarity: `dot(â, b̂) = cos(a, b)`, because the
    /// norms are 1. That identity is the whole point of [`normalized`](Self::normalized): normalize once,
    /// then compare with a single-accumulator dot instead of [`cosine`](Self::cosine)'s three
    /// accumulators and two square roots — a large constant saving in a graph build that computes the
    /// same distances thousands of times, and **recall-neutral by construction** because it preserves
    /// the cosine ranking exactly.
    pub fn dot(&self, other: &Embedding) -> Option<f32> {
        if self.0.len() != other.0.len() || self.0.is_empty() {
            return None;
        }
        Some(self.0.iter().zip(&other.0).map(|(a, b)| a * b).sum())
    }

    /// **A unit-length copy** of this vector — `None` for a zero or empty vector (no direction, so no
    /// unit form), the same "not comparable" cases [`cosine`](Self::cosine) refuses.
    ///
    /// Normalizing is a **load-time** conversion, never a storage one: the persisted bytes stay the
    /// caller's verbatim vector (no format change, no migration, `as-of` reproducibility intact), and we
    /// normalize into the build buffer / query path so distance can be a bare [`dot`](Self::dot). Because
    /// `dot(â, b̂) = cos(a, b)`, building the graph on normalized vectors yields the *same* graph as
    /// building it on the raw vectors with cosine — the normalization changes the cost, never the
    /// ranking.
    pub fn normalized(&self) -> Option<Embedding> {
        if self.0.is_empty() {
            return None;
        }
        let norm_sq: f32 = self.0.iter().map(|x| x * x).sum();
        if norm_sq == 0.0 {
            return None;
        }
        let inv = 1.0 / norm_sq.sqrt();
        Some(Embedding(self.0.iter().map(|x| x * inv).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors_are_maximally_similar() {
        let a = Embedding::new([1.0, 2.0, 3.0]);
        assert!((a.cosine(&a).unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn orthogonal_vectors_are_zero() {
        let a = Embedding::new([1.0, 0.0]);
        let b = Embedding::new([0.0, 1.0]);
        assert!(a.cosine(&b).unwrap().abs() < 1e-6);
    }

    #[test]
    fn mismatched_dimensions_are_not_comparable() {
        let a = Embedding::new([1.0, 2.0]);
        let b = Embedding::new([1.0, 2.0, 3.0]);
        assert_eq!(
            a.cosine(&b),
            None,
            "comparing across dimensions must be refused, not guessed"
        );
    }

    #[test]
    fn a_zero_vector_has_no_similarity() {
        let a = Embedding::new([0.0, 0.0]);
        let b = Embedding::new([1.0, 1.0]);
        assert_eq!(
            a.cosine(&b),
            None,
            "a zero vector has no direction; its cosine is undefined, not zero"
        );
    }

    #[test]
    fn dot_of_normalized_equals_cosine() {
        // The identity the fast build rests on: normalizing then taking the dot product reproduces
        // cosine exactly, so the graph built on unit vectors is the graph cosine would have built.
        let pairs = [
            (vec![3.0f32, 1.0, -2.0, 5.0], vec![-1.0f32, 4.0, 2.0, 0.5]),
            (vec![1.0, 0.0, 0.0], vec![0.0, 1.0, 0.0]),
            (vec![0.1, 0.2, 0.3, 0.4], vec![0.4, 0.3, 0.2, 0.1]),
        ];
        for (a, b) in pairs {
            let a = Embedding::new(a);
            let b = Embedding::new(b);
            let cos = a.cosine(&b).unwrap();
            let dot_norm = a
                .normalized()
                .unwrap()
                .dot(&b.normalized().unwrap())
                .unwrap();
            assert!(
                (cos - dot_norm).abs() < 1e-6,
                "dot(normalized) = {dot_norm} must equal cosine = {cos}"
            );
        }
    }

    #[test]
    fn normalized_is_unit_length_and_refuses_zero() {
        let n = Embedding::new([3.0, 4.0]).normalized().unwrap();
        let len: f32 = n.0.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (len - 1.0).abs() < 1e-6,
            "normalized vector must be unit length, got {len}"
        );
        assert_eq!(Embedding::new([0.0, 0.0]).normalized(), None);
        assert_eq!(Embedding::new(Vec::<f32>::new()).normalized(), None);
    }
}
