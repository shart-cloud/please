use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::bench::identity::{
    canonical_digest, collect_regular_files, nonempty, normalized_digest, read_verified_file,
    require_sha256, safe_relative, sha256,
};
use crate::bench::model::{
    CasePackManifest, ExposureRecord, GroundTruth, Split, Surface, TaxonomyManifest,
};
use crate::Result;

pub const PACK_SCHEMA: &str = "please-bench-case-pack/v2";
pub const TAXONOMY_SCHEMA: &str = "please-bench-taxonomy/v1";
// 75k compact case records measured at roughly 39 MiB. Keep explicit headroom without allowing an
// unbounded manifest; candidate assets retain their independent, much smaller per-input limit.
const MANIFEST_LIMIT: u64 = 64 * 1024 * 1024;
const EXPOSURE_LIMIT: u64 = 64 * 1024 * 1024;
pub const MAX_CASE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct VerifiedPack {
    pub manifest: CasePackManifest,
    pub taxonomy: TaxonomyManifest,
    pub digest: String,
    pub root: PathBuf,
    pub normalized_case_digests: Vec<String>,
}

impl VerifiedPack {
    pub fn case_digest(&self, index: usize) -> Result<String> {
        canonical_digest("please-bench-case/v1", &self.manifest.cases[index])
    }

    pub fn read_case(&self, index: usize, max_bytes: u64) -> Result<Vec<u8>> {
        let case = &self.manifest.cases[index];
        read_verified_file(
            &self.root.join(&case.asset_path),
            case.byte_length,
            &case.asset_sha256,
            max_bytes,
        )
    }
}

pub fn expected_digest(path: &Path) -> Result<String> {
    let mut manifest: CasePackManifest =
        serde_json::from_slice(&read_bounded(path, MANIFEST_LIMIT)?)?;
    manifest.content_digest.clear();
    canonical_digest("please-bench-case-pack/v2", &manifest)
}

pub fn check(path: &Path, exposure_paths: &[PathBuf]) -> Result<VerifiedPack> {
    let bytes = read_bounded(path, MANIFEST_LIMIT)?;
    let manifest: CasePackManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != PACK_SCHEMA {
        return Err(format!("unsupported case-pack schema {}", manifest.schema_version).into());
    }
    for (value, field) in [
        (&manifest.pack_id, "pack_id"),
        (&manifest.version, "version"),
        (&manifest.created_at, "created_at"),
        (&manifest.creation_provenance, "creation_provenance"),
        (&manifest.license_summary, "license_summary"),
    ] {
        nonempty(value, field)?;
    }
    require_sha256(&manifest.content_digest, "content_digest")?;
    require_sha256(&manifest.taxonomy_sha256, "taxonomy_sha256")?;
    if manifest.cases.is_empty() {
        return Err("case pack is empty".into());
    }
    let mut without_digest = manifest.clone();
    without_digest.content_digest.clear();
    let digest = canonical_digest("please-bench-case-pack/v2", &without_digest)?;
    if digest != manifest.content_digest {
        return Err(format!("case-pack content_digest mismatch; expected {digest}").into());
    }

    let root = crate::bench::identity::manifest_root(path)?;
    safe_relative(&manifest.taxonomy_path, "taxonomy_path")?;
    let taxonomy_path = root.join(&manifest.taxonomy_path);
    let taxonomy_bytes = read_bounded(&taxonomy_path, MANIFEST_LIMIT)?;
    if sha256(&taxonomy_bytes) != manifest.taxonomy_sha256 {
        return Err("taxonomy bytes do not match taxonomy_sha256".into());
    }
    let taxonomy: TaxonomyManifest = serde_json::from_slice(&taxonomy_bytes)?;
    validate_taxonomy(&taxonomy)?;
    let normalized_case_digests = validate_cases(&manifest, &taxonomy, &root)?;
    validate_exposure(&manifest, &root, exposure_paths)?;
    Ok(VerifiedPack {
        manifest,
        taxonomy,
        digest,
        root,
        normalized_case_digests,
    })
}

fn validate_taxonomy(taxonomy: &TaxonomyManifest) -> Result<()> {
    if taxonomy.schema_version != TAXONOMY_SCHEMA {
        return Err(format!("unsupported taxonomy schema {}", taxonomy.schema_version).into());
    }
    nonempty(&taxonomy.taxonomy_id, "taxonomy_id")?;
    nonempty(&taxonomy.version, "taxonomy version")?;
    validate_sorted_unique(&taxonomy.techniques, "taxonomy techniques")?;
    validate_sorted_unique(&taxonomy.delivery_vectors, "taxonomy delivery_vectors")?;
    if taxonomy.delivery_vectors.is_empty() {
        return Err("taxonomy needs at least one delivery vector".into());
    }
    Ok(())
}

fn validate_sorted_unique(values: &[String], field: &str) -> Result<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{field} contains an empty value").into());
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{field} must be sorted and unique").into());
    }
    Ok(())
}

fn validate_cases(
    manifest: &CasePackManifest,
    taxonomy: &TaxonomyManifest,
    root: &Path,
) -> Result<Vec<String>> {
    let techniques: BTreeSet<_> = taxonomy.techniques.iter().map(String::as_str).collect();
    let vectors: BTreeSet<_> = taxonomy
        .delivery_vectors
        .iter()
        .map(String::as_str)
        .collect();
    let mut ids = BTreeSet::new();
    let mut expected_assets = BTreeSet::new();
    let mut family_splits = BTreeMap::new();
    let mut exact_splits = BTreeMap::new();
    let mut normalized_splits = BTreeMap::new();
    let mut labels_by_digest = BTreeMap::new();
    let mut contextual_groups: BTreeMap<&str, (&str, usize)> = BTreeMap::new();
    let mut normalized_case_digests = Vec::with_capacity(manifest.cases.len());

    for (index, case) in manifest.cases.iter().enumerate() {
        for (value, field) in [
            (&case.case_id, "case_id"),
            (&case.source, "source"),
            (&case.provenance, "provenance"),
            (&case.label_provenance, "label_provenance"),
            (&case.group_id, "group_id"),
            (&case.family_id, "family_id"),
            (&case.delivery_vector, "delivery_vector"),
            (&case.presentation_context, "presentation_context"),
        ] {
            nonempty(value, field)?;
        }
        if let Some(disagreement) = &case.label_disagreement {
            nonempty(disagreement, "label_disagreement")?;
        }
        if !ids.insert(case.case_id.as_str()) {
            return Err(format!("duplicate case_id {}", case.case_id).into());
        }
        require_sha256(&case.asset_sha256, "asset_sha256")?;
        if case.byte_length > MAX_CASE_BYTES {
            return Err(format!(
                "case {} byte_length exceeds the 16 MiB case ceiling",
                case.case_id
            )
            .into());
        }
        safe_relative(&case.asset_path, "asset_path")?;
        if case
            .asset_path
            .components()
            .next()
            .and_then(|part| part.as_os_str().to_str())
            != Some("assets")
        {
            return Err("case assets must live below assets/".into());
        }
        if !vectors.contains(case.delivery_vector.as_str()) {
            return Err(format!("case {} uses an unknown delivery vector", case.case_id).into());
        }
        validate_sorted_unique(&case.techniques, "case techniques")?;
        if let Some(unknown) = case
            .techniques
            .iter()
            .find(|value| !techniques.contains(value.as_str()))
        {
            return Err(format!("case {} uses unknown technique {unknown}", case.case_id).into());
        }
        match (&case.surface, &case.ground_truth, &case.trusted_context) {
            (Surface::ArtifactDetection, GroundTruth::Artifact { .. }, None) => {}
            (Surface::ContextualAlignment, GroundTruth::Contextual { .. }, Some(context)) => {
                nonempty(&context.context_id, "trusted context id")?;
                nonempty(&context.task, "trusted task")?;
                for permission in &context.permissions {
                    nonempty(&permission.resource, "permission resource")?;
                    nonempty(&permission.action, "permission action")?;
                }
                let entry = contextual_groups
                    .entry(&case.group_id)
                    .or_insert((&case.asset_sha256, index));
                if entry.0 != case.asset_sha256 {
                    return Err(format!(
                        "paired contextual group {} changes candidate bytes",
                        case.group_id
                    )
                    .into());
                }
            }
            _ => {
                return Err(format!(
                    "case {} has a surface, label, or trusted-context mismatch",
                    case.case_id
                )
                .into())
            }
        }

        for previous in [
            family_splits.insert(case.family_id.clone(), case.split),
            exact_splits.insert(case.asset_sha256.clone(), case.split),
        ]
        .into_iter()
        .flatten()
        {
            if previous != case.split {
                return Err("family or exact bytes cross development/holdout splits".into());
            }
        }
        expected_assets.insert(case.asset_path.clone());
        let bytes = read_verified_file(
            &root.join(&case.asset_path),
            case.byte_length,
            &case.asset_sha256,
            MAX_CASE_BYTES,
        )?;
        let normalized = normalized_digest(&bytes);
        if let Some(previous) = normalized_splits.insert(normalized.clone(), case.split) {
            if previous != case.split {
                return Err("normalized-equivalent bytes cross development/holdout splits".into());
            }
        }
        normalized_case_digests.push(normalized);
        if case.surface == Surface::ArtifactDetection {
            let label = serde_json::to_string(&case.ground_truth)?;
            if let Some(previous) =
                labels_by_digest.insert(case.asset_sha256.clone(), label.clone())
            {
                if previous != label {
                    return Err(format!(
                        "identical artifact bytes have conflicting labels at case {}",
                        case.case_id
                    )
                    .into());
                }
            }
        }
    }

    let asset_root = root.join("assets");
    if !asset_root.is_dir() {
        return Err("case pack has no assets directory".into());
    }
    let actual: BTreeSet<_> = collect_regular_files(&asset_root)?
        .into_iter()
        .map(|path| Path::new("assets").join(path))
        .collect();
    if actual != expected_assets {
        let extra: Vec<_> = actual.difference(&expected_assets).collect();
        let missing: Vec<_> = expected_assets.difference(&actual).collect();
        return Err(
            format!("asset inventory mismatch; extra={extra:?}, missing={missing:?}").into(),
        );
    }
    for (group_id, baseline_case_id) in &manifest.group_baselines {
        nonempty(group_id, "group baseline group_id")?;
        nonempty(baseline_case_id, "baseline_case_id")?;
        if !contextual_groups.contains_key(group_id.as_str()) {
            return Err(
                format!("group baseline {group_id} does not name a contextual group").into(),
            );
        }
        let Some(baseline) = manifest
            .cases
            .iter()
            .find(|case| case.case_id == *baseline_case_id)
        else {
            return Err(
                format!("group baseline {group_id} names missing case {baseline_case_id}").into(),
            );
        };
        if baseline.group_id != *group_id || baseline.surface != Surface::ContextualAlignment {
            return Err(format!(
                "baseline case {baseline_case_id} is not contextual member of group {group_id}"
            )
            .into());
        }
    }
    Ok(normalized_case_digests)
}

fn validate_exposure(
    manifest: &CasePackManifest,
    root: &Path,
    exposure_paths: &[PathBuf],
) -> Result<()> {
    let holdout: Vec<_> = manifest
        .cases
        .iter()
        .filter(|case| case.split == Split::Holdout)
        .collect();
    if holdout.is_empty() {
        return Ok(());
    }
    if exposure_paths.is_empty() {
        return Err("holdout pack verification requires exposure history".into());
    }
    let mut exact = BTreeSet::new();
    let mut normalized = BTreeSet::new();
    let mut families = BTreeSet::new();
    for relative in exposure_paths {
        let path = if relative.is_absolute() {
            relative.clone()
        } else {
            safe_relative(relative, "exposure path")?;
            root.join(relative)
        };
        let bytes = read_bounded(&path, EXPOSURE_LIMIT)?;
        for (line_number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let record: ExposureRecord = serde_json::from_slice(line)
                .map_err(|error| format!("{}:{}: {error}", path.display(), line_number + 1))?;
            if record.schema_version != "please-bench-exposure/v1" {
                return Err("unsupported exposure record schema".into());
            }
            for (digest, field) in [
                (&record.pack_digest, "exposure pack_digest"),
                (&record.input_sha256, "exposure input_sha256"),
                (&record.normalized_sha256, "exposure normalized_sha256"),
            ] {
                require_sha256(digest, field)?;
            }
            exact.insert(record.input_sha256);
            normalized.insert(record.normalized_sha256);
            families.insert(record.family_id);
        }
    }
    for case in holdout {
        let bytes = read_verified_file(
            &root.join(&case.asset_path),
            case.byte_length,
            &case.asset_sha256,
            case.byte_length,
        )?;
        if exact.contains(&case.asset_sha256)
            || normalized.contains(&normalized_digest(&bytes))
            || families.contains(&case.family_id)
        {
            return Err(format!(
                "holdout case {} is present in exposure history",
                case.case_id
            )
            .into());
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular non-symbolic file", path.display()).into());
    }
    if metadata.len() > limit {
        return Err(format!("{} exceeds its size limit", path.display()).into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} exceeds its size limit", path.display()).into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_digest_ignores_only_its_declared_digest() {
        let mut manifest = CasePackManifest {
            schema_version: PACK_SCHEMA.into(),
            pack_id: "p".into(),
            version: "1".into(),
            content_digest: "x".into(),
            created_at: "now".into(),
            creation_provenance: "test".into(),
            license_summary: "first-party fixture".into(),
            purpose: crate::bench::model::PackPurpose::Instrument,
            taxonomy_path: "taxonomy.json".into(),
            taxonomy_sha256: "0".repeat(64),
            group_baselines: BTreeMap::new(),
            cases: vec![],
        };
        manifest.content_digest.clear();
        let one = canonical_digest("please-bench-case-pack/v2", &manifest).unwrap();
        manifest.pack_id = "q".into();
        let two = canonical_digest("please-bench-case-pack/v2", &manifest).unwrap();
        assert_ne!(one, two);
    }
}
