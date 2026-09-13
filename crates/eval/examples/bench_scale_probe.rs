//! Manual instrument-scale probe. Generates first-party synthetic metadata and one shared benign asset.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use please_eval::bench::identity::{canonical_digest, sha256};
use please_eval::bench::model::*;
use please_eval::bench::{pack, report, runner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: bench_scale_probe OUT [CASES]")?,
    );
    let count: usize = std::env::args()
        .nth(2)
        .as_deref()
        .unwrap_or("10000")
        .parse()?;
    if root.exists() {
        return Err(format!("{} exists", root.display()).into());
    }
    let pack_root = root.join("pack");
    fs::create_dir_all(pack_root.join("assets"))?;
    let candidate = b"Ordinary synthetic instrument control.";
    fs::write(pack_root.join("assets/control.txt"), candidate)?;
    let taxonomy = TaxonomyManifest {
        schema_version: pack::TAXONOMY_SCHEMA.into(),
        taxonomy_id: "scale-instrument".into(),
        version: "1".into(),
        techniques: vec![],
        delivery_vectors: vec!["synthetic".into()],
    };
    let taxonomy_bytes = serde_json::to_vec_pretty(&taxonomy)?;
    fs::write(pack_root.join("taxonomy.json"), &taxonomy_bytes)?;
    let cases = (0..count)
        .map(|index| BenchCase {
            case_id: format!("scale-{index:08}"),
            surface: Surface::ArtifactDetection,
            source: "first_party_scale_instrument".into(),
            provenance: "caller_provided".into(),
            ground_truth: GroundTruth::Artifact {
                label: ArtifactLabel::Benign,
            },
            label_provenance: "synthetic instrument control".into(),
            label_disagreement: None,
            group_id: format!("scale-{index:08}"),
            family_id: format!("scale-{index:08}"),
            split: Split::Development,
            delivery_vector: "synthetic".into(),
            techniques: vec![],
            presentation_context: "plain".into(),
            asset_path: "assets/control.txt".into(),
            asset_sha256: sha256(candidate),
            byte_length: candidate.len() as u64,
            trusted_context: None,
        })
        .collect();
    let mut case_pack = CasePackManifest {
        schema_version: pack::PACK_SCHEMA.into(),
        pack_id: "scale-instrument".into(),
        version: "1".into(),
        content_digest: String::new(),
        created_at: "2026-09-12T00:00:00Z".into(),
        creation_provenance: "generated first-party scale probe".into(),
        license_summary: "MIT OR Apache-2.0".into(),
        purpose: PackPurpose::Instrument,
        taxonomy_path: "taxonomy.json".into(),
        taxonomy_sha256: sha256(&taxonomy_bytes),
        group_baselines: BTreeMap::new(),
        cases,
    };
    case_pack.content_digest = canonical_digest("please-bench-case-pack/v2", &case_pack)?;
    fs::write(pack_root.join("pack.json"), serde_json::to_vec(&case_pack)?)?;
    let system = SystemManifest {
        schema_version: "please-bench-system/v1".into(),
        system_id: "please-scale-control".into(),
        version: "006-frozen".into(),
        adapter_version: "please-in-process/v1".into(),
        configuration_identity: "builtin/reference-analysis/low".into(),
        supported_surfaces: vec![Surface::ArtifactDetection],
        requires_trusted_context: false,
        deterministic: true,
        review_authority: "none".into(),
        operating_point: OperatingPoint {
            threshold: "low".into(),
            description: "scale instrument only".into(),
        },
        identities: SystemIdentities {
            model: None,
            prompt: None,
            rule_set: Some("builtin".into()),
            runtime: Some("in-process".into()),
        },
        adapter: AdapterManifest::Please {
            mode: PleaseMode::Mechanism,
            profile: "reference_analysis".into(),
            threshold: "low".into(),
            provenance_mapping: BTreeMap::from([(
                "caller_provided".into(),
                "caller_provided".into(),
            )]),
            rules: vec![],
            disabled_rules: vec![],
        },
        normalizers: vec![NormalizerManifest {
            normalizer_id: "please-artifact".into(),
            version: "1".into(),
            surface: Surface::ArtifactDetection,
            mapping: NormalizerKind::PleaseArtifactV1,
        }],
    };
    fs::write(root.join("system.json"), serde_json::to_vec(&system)?)?;
    let experiment = ExperimentManifest {
        schema_version: runner::EXPERIMENT_SCHEMA.into(),
        experiment_id: "scale-probe".into(),
        version: "1".into(),
        pack_path: "pack/pack.json".into(),
        system_paths: vec!["system.json".into()],
        exposure_paths: vec![],
        repetitions: 1,
        execution_mode: ExecutionMode::Offline,
        limits: RunLimits {
            max_input_bytes: 1024,
            max_request_bytes: 4096,
            max_stdout_bytes: 4096,
            max_stderr_bytes: 1024,
            startup_timeout_ms: 1000,
            case_timeout_ms: 1000,
            max_restarts: 0,
            max_in_flight: 1,
        },
    };
    fs::write(
        root.join("experiment.json"),
        serde_json::to_vec(&experiment)?,
    )?;
    let started = Instant::now();
    pack::check(&pack_root.join("pack.json"), &[])?;
    let verified_ms = started.elapsed().as_millis();
    let started = Instant::now();
    runner::run(&root.join("experiment.json"), &root.join("run"))?;
    let run_ms = started.elapsed().as_millis();
    let started = Instant::now();
    report::build(&root.join("run"))?;
    let report_ms = started.elapsed().as_millis();
    println!("cases={count} verify_ms={verified_ms} run_ms={run_ms} report_ms={report_ms} max_in_flight=1");
    Ok(())
}
