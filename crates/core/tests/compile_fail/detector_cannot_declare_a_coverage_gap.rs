//! SC-108 / FR-122: nothing outside finalization can put an `Incompleteness` into a verdict.
//!
//! A detector records coverage gaps — it must, since only the code that hit a bound knows it hit one — but
//! it records them as a `CoverageGap` through the evidence accumulator, and finalization is what turns
//! those into the `Incompleteness` values a verdict reports. The two types carry the same information and
//! differ only in who may create one; `finalize::evidence` explains why that is the right shape.
//!
//! Sealing this matters because `Incompleteness` is what the FR-004 clean-means-examined invariant is
//! checked against. A module that could mint one could also mint zero of them.
//!
//! The legitimate spelling of what this file attempts is:
//!
//! ```ignore
//! evidence.record_gap(CoverageGap::bound(IncompleteCause::DecodeDepth, 3, "two layers remained"));
//! ```

use please_core::verdict::{IncompleteCause, Incompleteness};

fn main() {
    let _gap = Incompleteness {
        cause: IncompleteCause::DecodeDepth,
        configured: Some(3),
        detail: Some("invented, with no decoder involved".to_string()),
    };
}
