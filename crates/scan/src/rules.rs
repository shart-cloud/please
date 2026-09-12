//! Acquire ordered rule files, then delegate whole-set preparation to the offline core.
//! No partially loaded engine is returned. Presentation and process exit codes belong to callers.

use please_core::{Engine, Ruleset, RulesetError};
use std::{error::Error, fmt, io, path::PathBuf};

/// The stage and source of a rule acquisition failure.
#[derive(Debug)]
pub enum RuleLoadError {
    /// The embedded default failed to load; this is an installation/build defect.
    Builtin(RulesetError),
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: RulesetError,
    },
    /// Layer resolution or compiled validation failed. Core supplies rule IDs where applicable;
    /// a failure concerning the resolved set cannot always be attributed to one file.
    Prepare(RulesetError),
}

impl fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(source) => write!(f, "the built-in rule set failed to load: {source}"),
            Self::Read { path, source } => {
                write!(f, "cannot read rule set {}: {source}", path.display())
            }
            Self::Parse { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Prepare(source) => source.fmt(f),
        }
    }
}

impl Error for RuleLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Read { source, .. } => source,
            Self::Builtin(source) | Self::Parse { source, .. } | Self::Prepare(source) => source,
        })
    }
}

/// Load the built-in base plus files in caller order, then disable the supplied IDs.
/// Later files replace earlier rules with the same ID; replacement warnings remain on the engine.
/// Files are parsed before the resolved set is prepared, preserving core's validation sequence.
/// With no files or disabled IDs, use the built-in fast path.
pub fn load_engine(files: &[PathBuf], disabled: &[String]) -> Result<Engine, RuleLoadError> {
    if files.is_empty() && disabled.is_empty() {
        return Engine::builtin().map_err(RuleLoadError::Builtin);
    }
    let mut builder = Engine::builder();
    for path in files {
        let source = std::fs::read_to_string(path).map_err(|source| RuleLoadError::Read {
            path: path.clone(),
            source,
        })?;
        let ruleset = Ruleset::from_toml(&source).map_err(|source| RuleLoadError::Parse {
            path: path.clone(),
            source,
        })?;
        builder = builder.add_ruleset(ruleset);
    }
    for id in disabled {
        builder = builder.disable(id.clone());
    }
    builder.build().map_err(RuleLoadError::Prepare)
}
