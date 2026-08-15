//! Rule preparation — the only route from rule *text* to scanning capability (FR-101).
//!
//! **Skeleton (T005).** The contents arrive in Phase 3: `provenance` (T033), `prepared` (T036, T037,
//! T042), `validate` (T038, T039), and the three entry points (T040).
//!
//! Feature 001 let a caller build an `Engine` from a `Ruleset` and *then* offered
//! `Ruleset::validate_compiled` as a separate courtesy. That makes safety a property of call order,
//! and a caller who never makes the second call gets a scanner driven by rules nobody proved could
//! compile within budget. A resource bomb in a rule file is a rule file that parses.
//!
//! This module exists so the transition has an owner. `PreparedRuleset` is a newtype over a validated
//! rule set whose only constructors validate, and `Engine` will accept nothing else — so the unsafe
//! state stops being reachable rather than being documented as discouraged (FR-102, FR-103).
