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
//! One resolution, in one place, read by everything, removes the possibility of two answers. T051
//! finishes the job by making this the only *application* site as well.

use crate::finalize::types::DetectionClass;
use crate::policy::ScanPolicy;
use crate::ruleset::Rule;

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
    rules: &'a [Rule],
    bounds: Bounds,
    suppress_in_quotes: bool,
}

impl<'a> ScanPlan<'a> {
    /// Resolve a policy and a rule set into a plan.
    pub fn resolve(policy: &'a ScanPolicy, rules: &'a [Rule]) -> Self {
        Self {
            classes: &policy.classes,
            rules,
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

    /// True when `class` is selected for this scan.
    ///
    /// The **single** resolution of the active set. Still read from more than one place in `engine.rs`
    /// until T051 collapses those into the participating-rule list — but reading one resolved answer
    /// twice cannot produce two answers, which is what the defect required.
    pub fn is_active(&self, class: DetectionClass) -> bool {
        self.classes.contains(&class)
    }

    /// Every rule in the resolved set, whether or not its class is selected.
    ///
    /// The class filter is applied by the caller for now; T051 replaces this with a participating-rules
    /// view that has already applied it.
    pub fn rules(&self) -> &'a [Rule] {
        self.rules
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
        let plan = ScanPlan::resolve(&policy, &[]);
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
        let plan = ScanPlan::resolve(&policy, &[]);
        assert!(plan.is_active(DetectionClass::Override));
        assert!(!plan.is_active(DetectionClass::Concealment));
        assert!(!plan.is_active(DetectionClass::Confusable));
    }

    #[test]
    fn an_empty_selection_activates_nothing() {
        // Not the same as "activates everything". A caller who selected no classes asked for no
        // rule-driven detection, and guessing otherwise would override an explicit choice.
        let policy = ScanPolicy {
            classes: Vec::new(),
            ..Default::default()
        };
        let plan = ScanPlan::resolve(&policy, &[]);
        for class in crate::policy::ALL_CLASSES {
            assert!(!plan.is_active(class), "{class:?} must not be active");
        }
    }
}
