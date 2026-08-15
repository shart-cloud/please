//! [`PreparedRuleset`] — the only thing a scanner can be built from, and the record proving it.

use regex::bytes::Regex;

use crate::finalize::types::RulesetId;
use crate::ruleset::{Bands, Rule, Ruleset, RulesetLimits};

/// Evidence that resource validation succeeded, and what it succeeded **against** (FR-108).
///
/// 001 had no such thing. `validate_compiled` returned `Result<(), _>`, so the outcome of the check was a
/// control-flow event and nothing recorded that it had happened. "Validated" was a state of the
/// programmer's mind rather than of the rule set.
///
/// # The staleness rule
///
/// A record is usable only for constructing a capability whose limits are **no stricter** than
/// [`limits`](Self::limits). Tightening forces revalidation. Without that, "validated" is decoration: a
/// caller could validate at a 1 MiB compiled budget, construct at 4 KiB, and carry a record asserting a
/// guarantee that was never established at the limits actually in force.
///
/// Relaxing is free in the other direction, which is what keeps the fast path fast — a pattern that fits a
/// small budget fits a larger one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRecord {
    limits: RulesetLimits,
    compiled_here: usize,
    covered_by_ci: usize,
}

impl ValidationRecord {
    pub(super) fn new(limits: RulesetLimits, compiled_here: usize, covered_by_ci: usize) -> Self {
        Self {
            limits,
            compiled_here,
            covered_by_ci,
        }
    }

    /// The limits validation was performed against.
    pub fn limits(&self) -> &RulesetLimits {
        &self.limits
    }

    /// How many patterns were compiled during this preparation.
    ///
    /// Counts rather than rule ids, which is a deliberate narrowing of what `data-model.md` calls
    /// `covered`. The ids are already in the rule set, each beside its own provenance, so recording them
    /// again would be a second copy of the same fact that could disagree with the first. What the count
    /// adds is the thing no other field carries: **how much work this preparation actually did**, which is
    /// exactly the quantity SC-105 constrains and the bench measures.
    pub fn compiled_here(&self) -> usize {
        self.compiled_here
    }

    /// How many rules were accepted on the strength of the CI check rather than a run-time compile.
    ///
    /// Non-zero only for built-in rules under limits no stricter than the defaults. If the CI check in
    /// `.github/workflows/ci.yml` were ever removed, this number would be the count of rules trusted for
    /// no reason.
    pub fn covered_by_ci(&self) -> usize {
        self.covered_by_ci
    }

    /// Whether this record covers construction at `limits` (FR-108).
    ///
    /// True when `limits` is **no stricter** than the limits this record was established at. The direction
    /// is easy to get backwards, so: a pattern proven to compile within 1 MiB is still safe under a 4 MiB
    /// budget, and is *not* known to be safe under a 4 KiB one — under the tighter budget it might fail to
    /// compile, which at scan time is a coverage gap rather than a rejected configuration. So relaxing
    /// reuses the record and tightening revalidates.
    pub fn covers(&self, limits: &RulesetLimits) -> bool {
        limits.permits_at_least(&self.limits)
    }
}

/// A rule set proven to compile within its resource budget, with its compiled patterns retained.
///
/// **Every constructor validates** (FR-102, FR-103). There is no path to one of these that skips
/// validation, so "the caller forgot" stops being expressible rather than being documented against — which
/// is the entire difference between this and 001's `validate_compiled`.
///
/// # A newtype, not a type-state
///
/// The type-state spelling — `Ruleset<Unvalidated>` and `Ruleset<Validated>` with the transition as the
/// only way between them — is the more fashionable answer and was rejected (research P2). It puts a type
/// parameter on a type that appears in `Engine`, in every error, and in the public surface, to express one
/// bit that a private field already expresses; and the compiler diagnostics it produces when a caller gets
/// it wrong are markedly worse than "no such function". The guarantee is identical because in both cases
/// the transition is the only constructor.
#[derive(Debug)]
pub struct PreparedRuleset {
    /// Private. The whole mechanism: this cannot be assembled from outside `crate::prepare`, so it cannot
    /// exist without having gone through validation.
    ruleset: Ruleset,
    record: ValidationRecord,
    id: RulesetId,
    /// Compiled patterns retained from validation, one slot per rule in rule order. `None` for rules the
    /// CI record covered, which the matcher compiles lazily on first literal hit (FR-109).
    compiled: Vec<Option<Regex>>,
}

impl PreparedRuleset {
    /// Assemble from validated parts. Visible to `crate::prepare` only.
    pub(super) fn new(
        ruleset: Ruleset,
        record: ValidationRecord,
        compiled: Vec<Option<Regex>>,
    ) -> Self {
        debug_assert_eq!(
            compiled.len(),
            ruleset.all_rules().len(),
            "one compiled slot per rule, or the matcher's indices mean nothing",
        );
        let id = identity(&ruleset, &record);
        Self {
            ruleset,
            record,
            id,
            compiled,
        }
    }

    /// Identity covering content **and** provenance **and** validation state (FR-111).
    ///
    /// Distinct from `self.ruleset().id()`, which covers content alone. Both are worth having: the content
    /// digest answers "were these the same rules?", and this one answers "were these the same rules, from
    /// the same origins, proven to the same standard?" — which is the question an auditor asks about a
    /// finding somebody disputes.
    pub fn id(&self) -> &RulesetId {
        &self.id
    }

    /// The validated rule set.
    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    /// Every rule, enabled or not, each carrying its provenance.
    pub fn rules(&self) -> &[Rule] {
        self.ruleset.all_rules()
    }

    pub fn bands(&self) -> &Bands {
        self.ruleset.bands()
    }

    /// What was validated, and against which limits.
    pub fn record(&self) -> &ValidationRecord {
        &self.record
    }

    pub fn warnings(&self) -> &[String] {
        self.ruleset.warnings()
    }

    /// Take the retained compiled patterns, consuming this rule set.
    ///
    /// Consuming rather than borrowing because the matcher takes ownership of the slots: a `Regex` held in
    /// two places would be either a clone — re-paying the compilation this exists to avoid — or a shared
    /// borrow that ties the engine's lifetime to the prepared set for no reason.
    pub(crate) fn into_parts(self) -> (Ruleset, RulesetId, Vec<Option<Regex>>, RulesetLimits) {
        let limits = self.record.limits;
        (self.ruleset, self.id, self.compiled, limits)
    }
}

/// The prepared identity: content, then trust, then the standard it was proven to (FR-111).
///
/// Built from the content digest rather than over the rules again, so there is one definition of what
/// content identity means and this extends it rather than competing with it.
fn identity(ruleset: &Ruleset, record: &ValidationRecord) -> RulesetId {
    use sha2::{Digest, Sha256};

    let content = ruleset.id();
    let mut hasher = Sha256::new();
    hasher.update(content.digest.as_bytes());
    hasher.update([0]);

    // Per rule, because provenance is per rule. A set differing only in which half is caller-supplied
    // must land on a different digest.
    for rule in ruleset.all_rules() {
        hasher.update(rule.id.as_bytes());
        hasher.update([0]);
        hasher.update(rule.provenance.as_str().as_bytes());
        hasher.update([0]);
    }

    // The limits are part of the claim. Two preparations of identical rules, one proven at a 1 MiB
    // compiled budget and one at 4 KiB, have not established the same thing.
    hasher.update(
        format!(
            "{}:{}:{}",
            record.limits.max_pattern_bytes,
            record.limits.max_compiled_bytes,
            record.limits.max_rules,
        )
        .as_bytes(),
    );

    let full = hasher.finalize();
    RulesetId {
        name: content.name.clone(),
        version: content.version.clone(),
        digest: full.iter().take(8).map(|b| format!("{b:02x}")).collect(),
    }
}
