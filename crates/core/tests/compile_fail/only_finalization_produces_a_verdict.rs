//! SC-108 / FR-120: `finalize` is the only producer of a `Verdict`.
//!
//! 001 had three producers, all in `engine.rs` — the size gate, the main path, and the unreadable target —
//! each calling a public `Verdict::assemble` with a `VerdictParts` it built itself. Three producers means
//! the FR-004 clean-means-examined invariant is decided in three places that have to agree, and it means
//! privacy on `Verdict`'s own fields bought nothing: a caller could hand in whatever evidence it liked.
//!
//! The parts struct is deleted and the constructor is `pub(super)`. The combination below is the one worth
//! forbidding: a coverage gap recorded *and* an outcome of `Clean` asserted by a caller who never had to
//! consider that those two are contradictory.
//!
//! The legitimate spellings are `finalize::finalize`, `finalize::oversized`, and
//! `finalize::unreadable_target`, none of which can express this.

use please_core::verdict::{
    EngineId, IncompleteCause, Outcome, RiskLevel, RulesetId, TargetRef, Verdict,
};

fn main() {
    let _verdict = Verdict::new(
        Outcome::Clean,
        0,
        RiskLevel::None,
        Vec::new(),
        false,
        Vec::new(),
        TargetRef::buffer("forged", 0),
        RulesetId {
            name: "forged".to_string(),
            version: "0.0.0".to_string(),
            digest: "0000000000000000".to_string(),
        },
        EngineId::current(),
    );

    // Named so the import is used even though the call above is the point of the file. `IncompleteCause`
    // is what a forged verdict would need in order to claim a gap it never had.
    let _ = IncompleteCause::InputSize;
}
