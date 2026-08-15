//! What this scan will examine, resolved once (FR-129).
//!
//! A [`ScanPlan`] is built at the top of a scan from the policy and the rule set, and is read-only
//! afterwards. Nothing derives it from scanned content — a policy inferred from the text under analysis
//! is a policy the attacker writes (FR-020).
//!
//! # The point of resolving classes here
//!
//! 001 asked `policy.is_active(..)` at two separate places in `Engine::scan`: once for rules matched
//! against the input, once for rules matched against decoded content. Two sites reading the same `Vec`
//! sounds harmless, and would be, except that the decode path *changed the class* between the two
//! checks — it tested the rule's declared class and then labelled the observation `Encoding`. So a
//! decoded finding had to satisfy two different filters, and selecting only `override` found the
//! override rules in the clear and lost the identical payload delivered base-64. That is the US2 defect,
//! and it is a defect of arithmetic on classes happening between two filter applications rather than of
//! either filter.
//!
//! One resolution, in one place, applied once per observation to the one class that observation carries
//! (T051). Four sites reading a resolved answer was not itself the bug — the bug was that two of them saw
//! different classes for the same finding. A single application cannot disagree with itself.

use crate::finalize::types::DetectionClass;
use crate::policy::ScanPolicy;

/// The resolved bounds for one scan.
///
/// Gathered into their own struct so a stage can be handed the limits it must respect without also being
/// handed the class selection and the suppression setting, which are none of its business. Counted rather
/// than timed throughout: a wall-clock deadline needs a clock, and this crate does not have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_input_bytes: u64,
    pub max_decode_depth: u8,
    pub max_matches_per_rule: u32,
    pub max_reasons: u32,
    pub max_excerpt_bytes: u32,
}

/// What one scan will examine.
///
/// Borrows the rule slice rather than owning it: the rules belong to the engine and outlive any single
/// scan, and copying them per scan would make the cheap part of the design expensive.
#[derive(Debug, Clone, Copy)]
pub struct ScanPlan<'a> {
    classes: &'a [DetectionClass],
    bounds: Bounds,
    suppress_in_quotes: bool,
}

impl<'a> ScanPlan<'a> {
    /// Resolve a policy into a plan.
    ///
    /// Carries no rules, since T074. It held a slice in order to hand it to the matching loops in
    /// `Engine::scan`, and [`crate::matcher`] now owns the rule set outright — a plan holding one too would
    /// make two holders of the thing FR-140 says has exactly one.
    pub fn resolve(policy: &'a ScanPolicy) -> Self {
        Self {
            classes: &policy.classes,
            bounds: Bounds {
                max_input_bytes: policy.max_input_bytes,
                max_decode_depth: policy.max_decode_depth,
                max_matches_per_rule: policy.max_matches_per_rule,
                max_reasons: policy.max_reasons,
                max_excerpt_bytes: policy.max_excerpt_bytes,
            },
            suppress_in_quotes: policy.suppress_in_quotes,
        }
    }

    /// True when an observation of `class` is reported by this scan.
    ///
    /// The **single** resolution of the active set, and since T051 the single *application* of it too: it is
    /// called once per observation, in `Engine::scan`, on the one class that observation carries. 001 called
    /// the equivalent from four places and changed an observation's class between two of them.
    ///
    /// Named `admits` rather than `is_active` deliberately. "Is this class active?" is a question anywhere in
    /// the pipeline can reasonably ask, and four places did; "does this scan admit this observation?" is a
    /// question with one natural asking point — the boundary where observations are recorded.
    pub fn admits(&self, class: DetectionClass) -> bool {
        self.classes.contains(&class)
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    pub fn suppress_in_quotes(&self) -> bool {
        self.suppress_in_quotes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_carries_the_policys_bounds_verbatim() {
        let policy = ScanPolicy::default();
        let plan = ScanPlan::resolve(&policy);
        assert_eq!(plan.bounds().max_input_bytes, policy.max_input_bytes);
        assert_eq!(plan.bounds().max_decode_depth, policy.max_decode_depth);
        assert_eq!(plan.bounds().max_reasons, policy.max_reasons);
        assert_eq!(plan.suppress_in_quotes(), policy.suppress_in_quotes);
    }

    #[test]
    fn deselecting_a_class_deselects_it_for_every_reader() {
        // The property the double gate broke. Two stages asking the plan the same question must get the
        // same answer, no matter which stage asks or when.
        let policy = ScanPolicy {
            classes: vec![DetectionClass::Override],
            ..Default::default()
        };
        let plan = ScanPlan::resolve(&policy);
        assert!(plan.admits(DetectionClass::Override));
        assert!(!plan.admits(DetectionClass::Concealment));
        assert!(!plan.admits(DetectionClass::Confusable));
    }

    #[test]
    fn an_empty_selection_activates_nothing() {
        // Not the same as "activates everything". A caller who selected no classes asked for no
        // rule-driven detection, and guessing otherwise would override an explicit choice.
        let policy = ScanPolicy {
            classes: Vec::new(),
            ..Default::default()
        };
        let plan = ScanPlan::resolve(&policy);
        for class in crate::policy::ALL_CLASSES {
            assert!(!plan.admits(class), "{class:?} must not be admitted");
        }
    }
}
