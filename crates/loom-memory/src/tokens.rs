//! Counting tokens, for the budget the packer spends.
//!
//! # Why this is deliberately crude, and says so
//!
//! A real deployment tokenises with the *model's* tokeniser, because the budget is that model's
//! context window and nobody else's. We do not have that model here (see `embedding.rs` for the same
//! reason), so this estimates. The estimate is intentionally a **slight over-count** — closer to a
//! byte-pair budget than a whitespace one — because the failure that matters is *over*-filling a
//! context window, and an estimate that runs a little high fills it a little less. Under-counting
//! would let the packer promise an item fits and then blow the real budget.
//!
//! The number is not the point. The *shape* is: token cost is monotonic in text length, an item's
//! cost is fixed and known before packing, and the packer never has to split one. That is what AT-042
//! leans on when it packs 100,000 candidates into 50 tokens without truncating a single item in half.

/// Roughly how many tokens a string will cost, over-counting on purpose.
///
/// ~4 characters per token is the usual rule of thumb for English BPE tokenisers; we use it, and add
/// one so that even the empty string and one-word items cost something (an item that costs zero tokens
/// would let the packer include unbounded numbers of them and call the budget satisfied).
pub fn estimate(text: &str) -> u32 {
    (text.chars().count() as u32).div_ceil(4) + 1
}

/// A token budget the packer spends down. Total is fixed at construction; the rest is arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    total: u32,
    spent: u32,
}

impl Budget {
    /// A budget of `total` tokens.
    pub fn new(total: u32) -> Self {
        Budget { total, spent: 0 }
    }

    /// Does `cost` still fit? A **whole-item** question — the packer never asks "how much of this
    /// fits", because half a fact is not a fact, it is a fact with the evidence cut off.
    pub fn fits(&self, cost: u32) -> bool {
        self.spent.saturating_add(cost) <= self.total
    }

    /// Spend `cost`. Returns whether it fit; if it did not, nothing is spent — the caller was told
    /// no, and a `no` that still charges you is a bug.
    pub fn spend(&mut self, cost: u32) -> bool {
        if !self.fits(cost) {
            return false;
        }
        self.spent += cost;
        true
    }

    /// Tokens spent so far.
    pub fn spent(&self) -> u32 {
        self.spent
    }

    /// The ceiling.
    pub fn total(&self) -> u32 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_monotonic_in_length() {
        assert!(estimate("a longer piece of text here") > estimate("short"));
    }

    #[test]
    fn nothing_costs_zero_tokens() {
        assert!(
            estimate("") >= 1,
            "a zero-cost item would let the packer include unbounded items"
        );
    }

    #[test]
    fn a_refused_spend_charges_nothing() {
        let mut b = Budget::new(10);
        assert!(b.spend(8));
        assert!(!b.spend(5), "5 does not fit in the remaining 2");
        assert_eq!(
            b.spent(),
            8,
            "a refused spend must not have charged the budget"
        );
        assert!(b.spend(2), "and the 2 that does fit still fits");
    }
}
