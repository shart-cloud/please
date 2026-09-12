//! Shipping composition: structural analysis → optional local classifier → optional review.
//! Core remains deterministic and free of I/O. A session resolves caller policy once and can scan
//! many inputs. Optional capabilities are absent from the default dependency graph.
use please_core::{Engine, Outcome, RiskLevel, ScanPolicy, TargetRef, Verdict};

mod rules;
pub use rules::{load_engine, RuleLoadError};

#[cfg(feature = "judge")]
pub use please_judge::{Judge, Resolution, ReviewAuthority};
#[cfg(feature = "ml-candle")]
pub use please_ml::MlLoadResult;
#[cfg(feature = "ml-candle")]
mod config;
#[cfg(feature = "ml-candle")]
pub use config::load as load_classifier;

/// The shared interpretation of a verdict at the caller's action threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDecision {
    Clean,
    BelowThreshold,
    AtOrAboveThreshold,
    Inconclusive,
}
impl ScanDecision {
    pub fn from_verdict(verdict: &Verdict, threshold: RiskLevel) -> Self {
        match verdict.outcome() {
            Outcome::Clean => Self::Clean,
            Outcome::Inconclusive => Self::Inconclusive,
            Outcome::RiskFound if verdict.is_at_or_above(threshold) => Self::AtOrAboveThreshold,
            Outcome::RiskFound => Self::BelowThreshold,
        }
    }
}

pub struct ScanSession<'a> {
    engine: &'a Engine,
    policy: ScanPolicy,
    #[cfg(feature = "ml-candle")]
    model: Option<&'a MlLoadResult>,
    #[cfg(feature = "judge")]
    judge: Option<&'a Judge>,
}
impl<'a> ScanSession<'a> {
    pub fn new(engine: &'a Engine, policy: ScanPolicy) -> Self {
        Self {
            engine,
            policy,
            #[cfg(feature = "ml-candle")]
            model: None,
            #[cfg(feature = "judge")]
            judge: None,
        }
    }
    pub fn policy(&self) -> &ScanPolicy {
        &self.policy
    }
    #[cfg(feature = "ml-candle")]
    pub fn with_model(mut self, model: &'a MlLoadResult) -> Self {
        self.model = Some(model);
        self
    }
    #[cfg(feature = "judge")]
    pub fn with_judge(mut self, judge: &'a Judge) -> Self {
        self.judge = Some(judge);
        self
    }

    pub fn scan(&self, input: &[u8], target: TargetRef) -> Verdict {
        let verdict = self.engine.scan(input, &self.policy, target);
        // The same acquisition/analysis limit gates every optional tier, including library callers.
        if input.len() as u64 > self.policy.max_input_bytes {
            return verdict;
        }
        #[cfg(feature = "ml-candle")]
        let verdict = match self.model {
            Some(model) => {
                please_ml::scan(model, verdict, input, &self.policy, self.engine.bands())
            }
            None => verdict,
        };
        #[cfg(feature = "judge")]
        let verdict = match self.judge {
            Some(judge) => judge.review(verdict, input, self.engine.bands()),
            None => verdict,
        };
        verdict
    }
    pub fn decision(&self, verdict: &Verdict) -> ScanDecision {
        ScanDecision::from_verdict(verdict, self.policy.threshold)
    }
}
