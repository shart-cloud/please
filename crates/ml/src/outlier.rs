//! How unlike its siblings is each segment.
//!
//! # What this is for, after T008
//!
//! Read `docs/research/embedding-separation-results.md` before giving this number a job. It measures two
//! things, and only one of them survived Phase 0:
//!
//! * **Ranking** — *given* a document with a payload in it, which segment is the payload? Measured at
//!   55.6% top-1 and 80.3% top-3 over 951 generated rows (T006). Useful.
//! * **Detection** — is there a payload in this document at all? Measured at **3.1%** true-positive rate
//!   at zero false positives, against `document-map.md` §6's kill criterion of 25% (T008). Not useful,
//!   and not close.
//!
//! The reason the second fails is worth keeping next to the code: *every* document has a
//! most-unlike-its-siblings segment, including a grocery list. The magnitude of that oddness carries no
//! information about whether anybody injected anything. §6's instruction for a failed M2 is *abandon
//! rather than tune*, and the corroboration rule that would have consumed this score as a gate was
//! dropped rather than given a threshold nobody could defend.
//!
//! So: these scores are **reported, never gating**. They ride along in `MlSegmentResult` because a human
//! reading a verdict can use a ranking, and nothing in `please-ml` or `please-core` compares one against a
//! threshold. If a future feature wants to, the number it has to beat is 25%.

/// Per-mille distance from the mean of a segment's siblings — `1000 - mean_cosine * 1000`.
///
/// # The range is `0..=2000`, and that is not a bug
///
/// Cosine similarity over these embeddings runs `[-1, 1]`, not `[0, 1]`: `all-MiniLM-L6-v2` produces
/// genuinely anti-correlated vectors for unrelated text — T004 measured -0.0014 and -0.0058 for an
/// unrelated sentence, and pairs below zero occur. Clamping at 1000 would collapse "unrelated" and
/// "opposite" into one value, which is exactly the distinction a ranker needs.
///
/// Returns one score per input vector, in the same order. Fewer than two vectors yields an empty result:
/// a segment with no siblings has nothing to be unlike, and inventing a score for it would put every
/// one-paragraph document at the top of a ranking. T006 excluded 57 rows on this basis and reported the
/// denominator rather than implying it.
pub fn scores(vectors: &[Vec<f32>]) -> Vec<u16> {
    if vectors.len() < 2 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(vectors.len());
    for (index, vector) in vectors.iter().enumerate() {
        let mut total = 0.0f32;
        let mut count = 0usize;
        for (other_index, other) in vectors.iter().enumerate() {
            if other_index == index {
                continue;
            }
            match cosine(vector, other) {
                Some(similarity) => {
                    total += similarity;
                    count += 1;
                }
                // A dimension mismatch means two vectors from different models, which is a caller bug
                // rather than a document property. Skipped rather than panicking, and if every pair is
                // skipped the segment scores as maximally ordinary — the direction that produces no
                // finding, since nothing here gates anyway.
                None => continue,
            }
        }
        let mean = if count == 0 {
            1.0
        } else {
            total / count as f32
        };
        let score = (1000.0 - mean * 1000.0).round().clamp(0.0, u16::MAX as f32) as u16;
        out.push(score);
    }
    out
}

/// Cosine similarity, or `None` if the vectors cannot be compared.
///
/// The vectors arriving here are already L2-normalised by the embedder, which would make this a plain dot
/// product — the norms are recomputed anyway. A vector that is normalised is cheap to divide by 1.0, and a
/// function that silently returns garbage when handed an un-normalised input is a trap for the next caller.
fn cosine(left: &[f32], right: &[f32]) -> Option<f32> {
    if left.len() != right.len() || left.is_empty() {
        return None;
    }
    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;
    for (a, b) in left.iter().zip(right.iter()) {
        dot += a * b;
        left_norm += a * a;
        right_norm += b * b;
    }
    if left_norm <= 0.0 || right_norm <= 0.0 {
        return None;
    }
    let similarity = dot / (left_norm.sqrt() * right_norm.sqrt());
    if !similarity.is_finite() {
        return None;
    }
    Some(similarity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Orthogonal unit vectors, one of which is the odd one out.
    fn group() -> Vec<Vec<f32>> {
        vec![
            vec![1.0, 0.0, 0.0],
            vec![0.99, 0.14, 0.0],
            vec![0.98, 0.20, 0.0],
            vec![0.97, 0.24, 0.0],
            vec![0.0, 0.0, 1.0],
        ]
    }

    #[test]
    fn the_semantic_odd_one_out_ranks_first() {
        // T014's stated acceptance: five segments, four similar and one different, and the different one
        // is the top outlier.
        let scores = scores(&group());
        let top = scores
            .iter()
            .enumerate()
            .max_by_key(|(_, score)| **score)
            .map(|(index, _)| index);
        assert_eq!(top, Some(4));
    }

    #[test]
    fn an_orthogonal_vector_scores_exactly_a_thousand() {
        // The formula's anchor point, worth pinning because it is what makes the number readable: 1000 is
        // "shares nothing with its siblings", below 1000 is "resembles them", above is "opposes them".
        let scores = scores(&[vec![1.0, 0.0], vec![0.0, 1.0]]);
        assert_eq!(scores, vec![1000, 1000]);
    }

    #[test]
    fn anti_correlation_exceeds_a_thousand_rather_than_clamping() {
        let scores = scores(&[vec![1.0, 0.0], vec![-1.0, 0.0]]);
        assert!(
            scores[0] > 1000,
            "opposite vectors must outrank merely unrelated ones, got {}",
            scores[0]
        );
    }

    #[test]
    fn a_lone_segment_has_no_siblings_and_so_no_score() {
        assert!(scores(&[vec![1.0, 0.0]]).is_empty());
        assert!(scores(&[]).is_empty());
    }

    #[test]
    fn mismatched_dimensions_do_not_panic() {
        let scores = scores(&[vec![1.0, 0.0], vec![1.0, 0.0, 0.0]]);
        assert_eq!(scores.len(), 2);
    }
}
