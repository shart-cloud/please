//! Detection: turning input into reasons.
//!
//! One module per detection class, plus the dispatch that runs the active ones and applies quoting
//! suppression. Each class is independently addressable so it can be reported on, scored, and disabled
//! in isolation (FR-015).
//!
//! Class-specific detectors — concealment, confusables — and the quoting pre-pass arrive with User
//! Story 1 (T044–T052). Pattern evaluation, which every rule-driven class is built on, is here now.

pub mod concealment;
pub mod pattern;
