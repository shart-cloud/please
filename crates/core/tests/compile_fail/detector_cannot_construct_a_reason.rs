//! SC-108 / FR-121 / FR-126: nothing outside finalization can construct a `Reason`.
//!
//! 001's `detect::Hit::into_reason` built this struct literal, so the decision about what a finding *says*
//! — including whether its excerpt had been neutralised — lived in the module that found it. There was a
//! helper that did the neutralising, and every detector used it, which is not the same thing as being
//! unable to skip it.
//!
//! What this protects is `matched`. A `Reason` that exists is a `Reason` whose excerpt is safe to print
//! (FR-021), and that holds only while the single site that builds one is the site that sanitises.
//!
//! **One assertion per file.** A case with several forbidden statements in it proves less than it appears
//! to: `rustc` stops at the first name-resolution failure, so an earlier error hides whether the later
//! statements would have been rejected at all.

use please_core::verdict::{DetectionClass, Reason, Span};

fn main() {
    let _reason = Reason {
        rule_id: "attacker.controlled".to_string(),
        class: DetectionClass::Override,
        span: Span::new(0, 4),
        matched: "raw \u{1b}[2J unneutralised bytes".to_string(),
        severity: 100,
        chain: Vec::new(),
        description: "built outside finalization".to_string(),
        suppressed_by: None,
    };
}
