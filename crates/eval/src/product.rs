//! Configuration for measuring the shipping pipeline. Experimental model probes remain separate.
use crate::Result;
use clap::{Args, ValueEnum};
use please_core::{InputProvenance, ScanPolicy, ScanProfile};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Mode {
    #[default]
    Product,
    Mechanism,
}

#[derive(Debug, Args)]
pub struct ProductOptions {
    /// Product uses shipping defaults. Mechanism preserves the historical structural/reference baseline.
    #[arg(long, value_enum, default_value = "product")]
    pub mode: Mode,
    #[arg(long)]
    pub profile: Option<ScanProfile>,
    #[arg(long)]
    pub provenance: Option<InputProvenance>,
    #[arg(long)]
    pub threshold: Option<String>,
    #[cfg(feature = "shipping-ml")]
    #[arg(long)]
    pub ml_config: Option<std::path::PathBuf>,
    #[cfg(feature = "shipping-ml")]
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100), default_value_t = 75)]
    pub ml_impact: u8,
    #[cfg(feature = "shipping-judge")]
    #[arg(long)]
    pub judge: bool,
    #[cfg(feature = "shipping-judge")]
    #[arg(long, requires = "judge")]
    pub judge_allow_release: bool,
    #[cfg(feature = "shipping-judge")]
    #[arg(long, requires = "judge")]
    pub review_context: Option<std::path::PathBuf>,
}

pub struct Runtime {
    pub policy: ScanPolicy,
    pub mode: &'static str,
    #[cfg(feature = "shipping-ml")]
    model: Option<please_scan::MlLoadResult>,
    #[cfg(feature = "shipping-judge")]
    judge: Option<please_scan::Judge>,
}
impl ProductOptions {
    pub fn resolve(&self, historical_floor: please_core::RiskLevel) -> Result<Runtime> {
        let mechanism = matches!(self.mode, Mode::Mechanism);
        if mechanism
            && (self.profile.is_some() || self.provenance.is_some() || self.threshold.is_some())
        {
            return Err("mechanism mode fixes the historical reference profile and detection floor; use product mode to configure policy".into());
        }
        let mut policy = if mechanism {
            ScanPolicy {
                threshold: historical_floor,
                ..ScanPolicy::reference_analysis()
            }
        } else {
            ScanPolicy::default()
        };
        if let Some(profile) = self.profile {
            policy.profile = profile;
            policy.suppress_in_quotes = profile == ScanProfile::ReferenceAnalysis;
        }
        if let Some(provenance) = self.provenance {
            policy.provenance = provenance;
        }
        if let Some(threshold) = &self.threshold {
            policy.threshold = crate::metrics::parse_floor(threshold)?;
        }
        #[cfg(feature = "shipping-ml")]
        let model = {
            if mechanism && self.ml_config.is_some() {
                return Err("mechanism mode is structural-only".into());
            }
            policy.ml_impact = please_core::MlImpact::new(self.ml_impact)?;
            self.ml_config
                .as_ref()
                .map(|path| please_scan::load_classifier(path))
                .transpose()?
        };
        #[cfg(feature = "shipping-judge")]
        let judge = {
            if mechanism && self.judge {
                return Err("mechanism mode does not run a judge".into());
            }
            if let Some(path) = &self.review_context {
                policy.caller_context = Some(serde_json::from_slice(&std::fs::read(path)?)?);
            }
            if self.judge {
                let resolution = please_scan::Resolution::from_env();
                for warning in resolution.warnings() {
                    eprintln!("please-eval: {warning}");
                }
                Some(please_scan::Judge::new(resolution).with_authority(
                    if self.judge_allow_release {
                        please_scan::ReviewAuthority::MayRelease
                    } else {
                        please_scan::ReviewAuthority::Advisory
                    },
                ))
            } else {
                None
            }
        };
        Ok(Runtime {
            policy,
            mode: if mechanism { "mechanism" } else { "product" },
            #[cfg(feature = "shipping-ml")]
            model,
            #[cfg(feature = "shipping-judge")]
            judge,
        })
    }
}
impl Runtime {
    /// Construct the structural-only runtime shared by first-party callers such as the bench.
    pub fn structural(
        mode: Mode,
        profile: ScanProfile,
        threshold: please_core::RiskLevel,
    ) -> Result<Self> {
        if matches!(mode, Mode::Mechanism) && profile != ScanProfile::ReferenceAnalysis {
            return Err("mechanism mode requires the reference_analysis profile".into());
        }
        ProductOptions {
            mode,
            profile: matches!(mode, Mode::Product).then_some(profile),
            provenance: None,
            threshold: matches!(mode, Mode::Product).then(|| threshold.as_str().to_string()),
            #[cfg(feature = "shipping-ml")]
            ml_config: None,
            #[cfg(feature = "shipping-ml")]
            ml_impact: 75,
            #[cfg(feature = "shipping-judge")]
            judge: false,
            #[cfg(feature = "shipping-judge")]
            judge_allow_release: false,
            #[cfg(feature = "shipping-judge")]
            review_context: None,
        }
        .resolve(threshold)
    }

    pub fn session<'a>(&'a self, engine: &'a please_core::Engine) -> please_scan::ScanSession<'a> {
        self.session_with_policy(engine, self.policy.clone())
    }

    pub fn session_with_provenance<'a>(
        &'a self,
        engine: &'a please_core::Engine,
        provenance: InputProvenance,
    ) -> please_scan::ScanSession<'a> {
        let mut policy = self.policy.clone();
        policy.provenance = provenance;
        self.session_with_policy(engine, policy)
    }

    fn session_with_policy<'a>(
        &'a self,
        engine: &'a please_core::Engine,
        policy: ScanPolicy,
    ) -> please_scan::ScanSession<'a> {
        let session = please_scan::ScanSession::new(engine, policy);
        #[cfg(feature = "shipping-ml")]
        let session = match &self.model {
            Some(model) => session.with_model(model),
            None => session,
        };
        #[cfg(feature = "shipping-judge")]
        let session = match &self.judge {
            Some(judge) => session.with_judge(judge),
            None => session,
        };
        session
    }
    pub fn metadata(&self, engine: &please_core::Engine, description: &str) -> serde_json::Value {
        let mut tiers = serde_json::json!({});
        #[cfg(feature = "shipping-ml")]
        if let Some(model) = &self.model {
            tiers["ml"] = match model {
                please_scan::MlLoadResult::Loaded(model) => serde_json::json!({
                    "model": model.config().model_id, "revision": model.config().revision,
                    "weights_digest": model.digest(), "threshold": model.config().threshold,
                    "assessed_impact": self.policy.ml_impact,
                    "inference": model.identity(), "windowing": model.config().windowing,
                }),
                please_scan::MlLoadResult::Unavailable(detail) => {
                    serde_json::json!({"unavailable":detail})
                }
            };
        }
        #[cfg(feature = "shipping-judge")]
        if let Some(judge) = &self.judge {
            tiers["judge"] = judge.inference_metadata();
        }
        // Keep the default build free of optional capabilities while allowing the cfg branches above to mutate.
        let _ = &mut tiers;
        serde_json::json!({"format_version":3, "mode":self.mode, "policy":self.policy,
            "ruleset":description, "ruleset_digest":engine.ruleset_id().digest,
            "engine_version":please_core::ENGINE_VERSION, "tiers":tiers})
    }
}
