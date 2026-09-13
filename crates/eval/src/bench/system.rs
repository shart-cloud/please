use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::bench::identity::{
    canonical_digest, nonempty, read_verified_file, require_sha256, safe_relative,
};
use crate::bench::model::{
    AdapterManifest, ExecutionMode, NormalizerKind, Surface, SystemManifest,
};
use crate::Result;

pub const SYSTEM_SCHEMA: &str = "please-bench-system/v1";
const MANIFEST_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VerifiedSystem {
    pub manifest: SystemManifest,
    pub digest: String,
    pub manifest_path: PathBuf,
    pub root: PathBuf,
    pub resolved_program: Option<PathBuf>,
    pub resolved_rules: Vec<PathBuf>,
}

pub fn check(path: &Path, execution_mode: ExecutionMode) -> Result<VerifiedSystem> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a regular non-symbolic system manifest",
            path.display()
        )
        .into());
    }
    if metadata.len() > MANIFEST_LIMIT {
        return Err("system manifest exceeds 2 MiB".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let manifest: SystemManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != SYSTEM_SCHEMA {
        return Err(format!("unsupported system schema {}", manifest.schema_version).into());
    }
    for (value, field) in [
        (&manifest.system_id, "system_id"),
        (&manifest.version, "system version"),
        (&manifest.adapter_version, "adapter_version"),
        (&manifest.configuration_identity, "configuration_identity"),
        (&manifest.review_authority, "review_authority"),
        (&manifest.operating_point.threshold, "operating threshold"),
        (
            &manifest.operating_point.description,
            "operating-point description",
        ),
    ] {
        nonempty(value, field)?;
    }
    if manifest.supported_surfaces.is_empty() {
        return Err("system supports no evaluation surface".into());
    }
    let surfaces: BTreeSet<_> = manifest.supported_surfaces.iter().copied().collect();
    if surfaces.len() != manifest.supported_surfaces.len() {
        return Err("supported_surfaces contains duplicates".into());
    }
    if manifest.requires_trusted_context && !surfaces.contains(&Surface::ContextualAlignment) {
        return Err("requires_trusted_context is true without contextual_alignment support".into());
    }
    let mut normalized = BTreeSet::new();
    for normalizer in &manifest.normalizers {
        nonempty(&normalizer.normalizer_id, "normalizer_id")?;
        nonempty(&normalizer.version, "normalizer version")?;
        if !surfaces.contains(&normalizer.surface) {
            return Err("normalizer targets an unsupported surface".into());
        }
        if !normalized.insert(normalizer.surface) {
            return Err("system declares more than one normalizer for a surface".into());
        }
        if let NormalizerKind::NativeV1 {
            positive_labels,
            negative_labels,
        } = &normalizer.mapping
        {
            validate_labels(positive_labels, "positive_labels")?;
            validate_labels(negative_labels, "negative_labels")?;
            if positive_labels
                .iter()
                .any(|label| negative_labels.contains(label))
            {
                return Err("native positive and negative labels overlap".into());
            }
        }
    }
    if normalized != surfaces {
        return Err("each supported surface needs exactly one normalizer".into());
    }

    let root = crate::bench::identity::manifest_root(path)?;
    let mut resolved_program = None;
    let mut resolved_rules = Vec::new();
    match &manifest.adapter {
        AdapterManifest::Please {
            profile,
            threshold,
            provenance_mapping,
            rules,
            disabled_rules,
            ..
        } => {
            if surfaces != BTreeSet::from([Surface::ArtifactDetection]) {
                return Err("the PLEASE adapter supports only artifact_detection".into());
            }
            if manifest.adapter_version != "please-in-process/v1" {
                return Err("unsupported PLEASE adapter_version".into());
            }
            if !matches!(profile.as_str(), "enforcement" | "reference_analysis") {
                return Err("PLEASE profile must be enforcement or reference_analysis".into());
            }
            crate::metrics::parse_floor(threshold)?;
            for (source, mapped) in provenance_mapping {
                nonempty(source, "provenance mapping source")?;
                if !matches!(
                    mapped.as_str(),
                    "unspecified" | "caller_provided" | "user_input" | "tool_response"
                ) {
                    return Err(format!("invalid PLEASE provenance mapping target {mapped}").into());
                }
            }
            if disabled_rules.iter().any(|rule| rule.trim().is_empty()) {
                return Err("disabled_rules contains an empty id".into());
            }
            for rule in rules {
                safe_relative(rule, "PLEASE rule path")?;
                let resolved = root.join(rule);
                let metadata = fs::symlink_metadata(&resolved)?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(format!("{} is not a regular rule file", resolved.display()).into());
                }
                resolved_rules.push(resolved);
            }
            if !manifest
                .normalizers
                .iter()
                .all(|normalizer| matches!(normalizer.mapping, NormalizerKind::PleaseArtifactV1))
            {
                return Err("the PLEASE adapter requires please_artifact_v1 normalization".into());
            }
        }
        AdapterManifest::Subprocess {
            program,
            executable_sha256,
            environment,
            network_capable,
            sandbox_command,
            ..
        } => {
            if manifest.adapter_version != "please-bench-jsonl/v1" {
                return Err("unsupported subprocess adapter_version".into());
            }
            if *network_capable && execution_mode == ExecutionMode::Offline {
                return Err("network-capable adapter selected by an offline experiment".into());
            }
            require_sha256(executable_sha256, "executable_sha256")?;
            let resolved = if program.is_absolute() {
                program.clone()
            } else {
                safe_relative(program, "subprocess program")?;
                root.join(program)
            };
            let metadata = fs::symlink_metadata(&resolved)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(format!("{} is not a regular executable", resolved.display()).into());
            }
            read_verified_file(
                &resolved,
                metadata.len(),
                executable_sha256,
                256 * 1024 * 1024,
            )?;
            if sandbox_command.len() > 32
                || sandbox_command
                    .iter()
                    .any(|argument| argument.is_empty() || argument.len() > 4096)
            {
                return Err(
                    "sandbox_command accepts at most 32 bounded non-empty arguments".into(),
                );
            }
            for key in environment.keys() {
                if key.is_empty()
                    || !key.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(format!("unsafe environment key {key:?}").into());
                }
            }
            resolved_program = Some(resolved);
        }
    }
    let digest = canonical_digest("please-bench-system/v1", &manifest)?;
    Ok(VerifiedSystem {
        manifest,
        digest,
        manifest_path: path.canonicalize()?,
        root,
        resolved_program,
        resolved_rules,
    })
}

fn validate_labels(values: &[String], field: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| value.trim().is_empty())
    {
        return Err(format!("{field} must be sorted, unique, and non-empty").into());
    }
    Ok(())
}
