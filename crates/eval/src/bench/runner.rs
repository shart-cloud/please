use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::bench::adapter::NativeExecution;
use crate::bench::identity::{canonical_digest, hex_encode, nonempty, sha256};
use crate::bench::model::{
    AdapterManifest, BenchResult, CoverageState, ExecutionTelemetry, ExperimentManifest,
    NormalizedDecision, NormalizerManifest, PlannedSystem, ProcessTelemetry, RawOutput, RunLimits,
    RunManifest, SavedFile, StagedExecutable,
};
use crate::bench::normalize;
use crate::bench::pack::{self, VerifiedPack};
use crate::bench::please::PleaseAdapter;
#[cfg(unix)]
use crate::bench::process::ProcessAdapter;
use crate::bench::system::{self, VerifiedSystem};
use crate::Result;

pub const EXPERIMENT_SCHEMA: &str = "please-bench-experiment/v1";
pub const RUN_SCHEMA: &str = "please-bench-run/v1";
pub const RESULT_SCHEMA: &str = "please-bench-result/v1";
const MANIFEST_LIMIT: u64 = 4 * 1024 * 1024;

pub struct VerifiedExperiment {
    pub manifest: ExperimentManifest,
    pub digest: String,
    pub pack: VerifiedPack,
    pub systems: Vec<VerifiedSystem>,
}

enum LiveAdapter {
    Please(Box<PleaseAdapter>),
    #[cfg(unix)]
    Process(Box<ProcessAdapter>),
    #[cfg(not(unix))]
    ProcessUnsupported,
}

pub fn check_experiment(path: &Path) -> Result<VerifiedExperiment> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular experiment manifest", path.display()).into());
    }
    if metadata.len() > MANIFEST_LIMIT {
        return Err("experiment manifest exceeds 4 MiB".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let manifest: ExperimentManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != EXPERIMENT_SCHEMA {
        return Err(format!("unsupported experiment schema {}", manifest.schema_version).into());
    }
    nonempty(&manifest.experiment_id, "experiment_id")?;
    nonempty(&manifest.version, "experiment version")?;
    validate_limits(&manifest.limits)?;
    if manifest.repetitions == 0 || manifest.repetitions > 1000 {
        return Err("repetitions must be in 1..=1000".into());
    }
    if manifest.system_paths.is_empty() {
        return Err("experiment selects no systems".into());
    }
    let root = crate::bench::identity::manifest_root(path)?;
    let pack_path = resolve_manifest_path(&root, &manifest.pack_path, "pack_path")?;
    let exposure_paths = manifest
        .exposure_paths
        .iter()
        .map(|path| resolve_exposure_path(&root, path))
        .collect::<Result<Vec<_>>>()?;
    let pack = pack::check(&pack_path, &exposure_paths)?;
    let mut systems = Vec::new();
    let mut ids = BTreeSet::new();
    for system_path in &manifest.system_paths {
        let path = resolve_manifest_path(&root, system_path, "system_path")?;
        let verified = system::check(&path, manifest.execution_mode)?;
        if !ids.insert(verified.manifest.system_id.clone()) {
            return Err(format!("duplicate system id {}", verified.manifest.system_id).into());
        }
        systems.push(verified);
    }
    for case in &pack.manifest.cases {
        if case.byte_length > manifest.limits.max_input_bytes {
            return Err(format!(
                "case {} byte_length {} exceeds max_input_bytes {}",
                case.case_id, case.byte_length, manifest.limits.max_input_bytes
            )
            .into());
        }
    }
    if systems
        .iter()
        .any(|system| matches!(system.manifest.adapter, AdapterManifest::Subprocess { .. }))
    {
        let request_id = "0".repeat(64);
        for (index, case) in pack.manifest.cases.iter().enumerate() {
            let candidate = pack.read_case(index, manifest.limits.max_input_bytes)?;
            let request = crate::bench::protocol::encode_case_request(
                &request_id,
                case.surface,
                &candidate,
                &case.asset_sha256,
                &case.provenance,
                case.trusted_context.as_ref(),
            )?;
            if request.len() as u64 > manifest.limits.max_request_bytes {
                return Err(format!(
                    "case {} encoded request is {} bytes, exceeding max_request_bytes {}",
                    case.case_id,
                    request.len(),
                    manifest.limits.max_request_bytes
                )
                .into());
            }
        }
    }
    let digest = canonical_digest("please-bench-experiment/v1", &manifest)?;
    Ok(VerifiedExperiment {
        manifest,
        digest,
        pack,
        systems,
    })
}

pub fn run(experiment_path: &Path, out: &Path) -> Result<RunManifest> {
    let verified = check_experiment(experiment_path)?;
    if out.exists() {
        return Err(format!(
            "{} already exists; bench runs never overwrite",
            out.display()
        )
        .into());
    }

    let runtime_identities: Vec<_> = verified
        .systems
        .iter()
        .map(runtime_identity)
        .collect::<Result<_>>()?;
    let case_digests: Vec<_> = (0..verified.pack.manifest.cases.len())
        .map(|index| verified.pack.case_digest(index))
        .collect::<Result<_>>()?;
    let normalized_case_digests = verified.pack.normalized_case_digests.clone();
    let semantic_identity = serde_json::json!({
        "experiment_digest": verified.digest,
        "pack_digest": verified.pack.digest,
        "ordered_case_digests": case_digests,
        "systems": verified.systems.iter().map(|system| &system.digest).collect::<Vec<_>>(),
        "runtime_identities": runtime_identities,
        "repetitions": verified.manifest.repetitions,
        "execution_mode": verified.manifest.execution_mode,
        "limits": verified.manifest.limits,
    });
    let run_id = canonical_digest("please-bench-run-identity/v1", &semantic_identity)?;
    let systems: Vec<_> = verified
        .systems
        .iter()
        .zip(runtime_identities)
        .map(|(system, runtime_identity)| PlannedSystem {
            sandbox_command: match &system.manifest.adapter {
                AdapterManifest::Please { .. } => None,
                AdapterManifest::Subprocess {
                    sandbox_command, ..
                } => Some(sandbox_command.clone()),
            },
            system_id: system.manifest.system_id.clone(),
            system_digest: system.digest.clone(),
            manifest_path: system.manifest_path.clone(),
            adapter_version: system.manifest.adapter_version.clone(),
            normalizers: system.manifest.normalizers.clone(),
            operating_point: system.manifest.operating_point.clone(),
            runtime_identity,
            staged_executable: None,
        })
        .collect();
    let mut manifest = RunManifest {
        schema_version: RUN_SCHEMA.into(),
        run_id: run_id.clone(),
        status: "incomplete".into(),
        experiment_id: verified.manifest.experiment_id.clone(),
        experiment_digest: verified.digest.clone(),
        pack_id: verified.pack.manifest.pack_id.clone(),
        pack_digest: verified.pack.digest.clone(),
        group_baselines: verified.pack.manifest.group_baselines.clone(),
        ordered_case_digests: case_digests.clone(),
        systems,
        repetitions: verified.manifest.repetitions,
        execution_mode: verified.manifest.execution_mode,
        limits: verified.manifest.limits.clone(),
        max_observed_in_flight: 0,
        processes: Vec::new(),
        host: host_metadata(),
        results: None,
    };

    fs::create_dir(out)?;
    fs::create_dir(out.join("work"))?;
    for (system_index, (planned, system)) in manifest
        .systems
        .iter_mut()
        .zip(&verified.systems)
        .enumerate()
    {
        planned.staged_executable = stage_executable(out, system_index, system)?;
    }
    write_manifest(out, &manifest)?;
    let results_path = out.join("results.jsonl");
    let results_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&results_path)?;
    let mut writer = BufWriter::new(results_file);
    let mut results_digest = Sha256::new();
    let mut result_bytes = 0u64;
    let mut rows = 0u64;
    let mut in_flight = 0u32;
    let mut max_observed_in_flight = 0u32;

    for (system_index, system) in verified.systems.iter().enumerate() {
        let work_dir = out.join("work").join(format!("system-{system_index:04}"));
        let staged_program = manifest.systems[system_index]
            .staged_executable
            .as_ref()
            .map(|executable| out.join(&executable.path));
        let mut adapter = make_adapter(
            system,
            staged_program.as_deref(),
            &work_dir,
            verified.manifest.limits.clone(),
        )?;
        for (case_index, case) in verified.pack.manifest.cases.iter().enumerate() {
            for repetition in 0..verified.manifest.repetitions {
                let case_digest = &case_digests[case_index];
                let request_id = canonical_digest(
                    "please-bench-request/v1",
                    &(
                        run_id.as_str(),
                        system.digest.as_str(),
                        case_digest.as_str(),
                        repetition,
                    ),
                )?;
                let row_id = canonical_digest(
                    "please-bench-row/v1",
                    &(request_id.as_str(), system.digest.as_str()),
                )?;
                let normalizer = system
                    .manifest
                    .normalizers
                    .iter()
                    .find(|normalizer| normalizer.surface == case.surface);
                let execution = if !system.manifest.supported_surfaces.contains(&case.surface) {
                    NativeExecution::unsupported()
                } else {
                    match verified
                        .pack
                        .read_case(case_index, verified.manifest.limits.max_input_bytes)
                    {
                        Ok(candidate) => {
                            in_flight += 1;
                            max_observed_in_flight = max_observed_in_flight.max(in_flight);
                            if in_flight > verified.manifest.limits.max_in_flight {
                                return Err("runner exceeded the frozen in-flight limit".into());
                            }
                            let outcome = execute(
                                &mut adapter,
                                &request_id,
                                case,
                                &candidate,
                                &system.digest,
                            );
                            in_flight -= 1;
                            outcome
                        }
                        Err(error) => NativeExecution::unavailable(format!(
                            "case input unavailable at execution: {error}"
                        )),
                    }
                };
                let row = build_row(
                    &manifest,
                    system,
                    case,
                    case_digest,
                    &normalized_case_digests[case_index],
                    &row_id,
                    &request_id,
                    repetition,
                    normalizer,
                    execution,
                )?;
                let mut bytes = serde_json::to_vec(&row)?;
                bytes.push(b'\n');
                writer.write_all(&bytes)?;
                results_digest.update(&bytes);
                result_bytes += bytes.len() as u64;
                rows += 1;
            }
        }
        manifest.processes.extend(finish_adapter(adapter));
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    manifest.status = "complete".into();
    manifest.max_observed_in_flight = max_observed_in_flight;
    manifest.results = Some(SavedFile {
        rows,
        bytes: result_bytes,
        sha256: format!("{:x}", results_digest.finalize()),
    });
    write_manifest(out, &manifest)?;
    Ok(manifest)
}

fn stage_executable(
    out: &Path,
    system_index: usize,
    system: &VerifiedSystem,
) -> Result<Option<StagedExecutable>> {
    let AdapterManifest::Subprocess {
        executable_sha256, ..
    } = &system.manifest.adapter
    else {
        return Ok(None);
    };
    let source = system
        .resolved_program
        .as_ref()
        .ok_or("verified subprocess has no resolved program")?;
    let relative = PathBuf::from("programs")
        .join(format!("system-{system_index:04}"))
        .join("adapter");
    let destination = out.join(&relative);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or("staged executable has no parent")?,
    )?;
    fs::copy(source, &destination)?;
    let length = fs::symlink_metadata(&destination)?.len();
    crate::bench::identity::read_verified_file(
        &destination,
        length,
        executable_sha256,
        256 * 1024 * 1024,
    )?;
    let mut permissions = fs::metadata(&destination)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&destination, permissions)?;
    Ok(Some(StagedExecutable {
        path: relative,
        sha256: executable_sha256.clone(),
    }))
}

fn validate_limits(limits: &RunLimits) -> Result<()> {
    if limits.max_input_bytes == 0 || limits.max_input_bytes > 16 * 1024 * 1024 {
        return Err("max_input_bytes must be in 1..=16777216".into());
    }
    if limits.max_request_bytes < limits.max_input_bytes
        || limits.max_request_bytes > 40 * 1024 * 1024
    {
        return Err("max_request_bytes must cover max_input_bytes and stay below 40 MiB".into());
    }
    if limits.max_stdout_bytes == 0 || limits.max_stdout_bytes > 16 * 1024 * 1024 {
        return Err("max_stdout_bytes must be in 1..=16 MiB".into());
    }
    if limits.max_stderr_bytes == 0 || limits.max_stderr_bytes > 4 * 1024 * 1024 {
        return Err("max_stderr_bytes must be in 1..=4 MiB".into());
    }
    if limits.startup_timeout_ms == 0
        || limits.case_timeout_ms == 0
        || limits.startup_timeout_ms > 300_000
        || limits.case_timeout_ms > 300_000
    {
        return Err("startup and case timeouts must be in 1..=300000 ms".into());
    }
    if limits.max_restarts > 100 {
        return Err("max_restarts must be in 0..=100".into());
    }
    if limits.max_in_flight != 1 {
        return Err("version 1 schedules exactly one in-flight request".into());
    }
    Ok(())
}

fn resolve_manifest_path(root: &Path, path: &Path, field: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(format!("{field} must be a non-empty relative path").into());
    }
    Ok(root.join(path))
}

fn resolve_exposure_path(root: &Path, path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err("exposure_path must not be empty".into());
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    })
}

fn runtime_identity(system: &VerifiedSystem) -> Result<serde_json::Value> {
    match &system.manifest.adapter {
        AdapterManifest::Please { .. } => crate::bench::please::runtime_identity(system),
        AdapterManifest::Subprocess {
            executable_sha256,
            args,
            environment,
            network_capable,
            sandbox_command,
            ..
        } => Ok(serde_json::json!({
            "protocol": "please-bench-jsonl/v1",
            "executable_sha256": executable_sha256,
            "args": args,
            "sandbox_command": sandbox_command,
            "environment_names": environment.keys().collect::<Vec<_>>(),
            "network_capable": network_capable,
            "platform": "linux",
        })),
    }
}

fn make_adapter(
    system: &VerifiedSystem,
    staged_program: Option<&Path>,
    work_dir: &Path,
    limits: RunLimits,
) -> Result<LiveAdapter> {
    match system.manifest.adapter {
        AdapterManifest::Please { .. } => {
            Ok(LiveAdapter::Please(Box::new(PleaseAdapter::new(system)?)))
        }
        AdapterManifest::Subprocess { .. } => {
            #[cfg(unix)]
            {
                let program = staged_program.ok_or("subprocess has no staged executable")?;
                Ok(LiveAdapter::Process(Box::new(ProcessAdapter::new(
                    system, program, work_dir, limits,
                )?)))
            }
            #[cfg(not(unix))]
            {
                let _ = (system, staged_program, work_dir, limits);
                Ok(LiveAdapter::ProcessUnsupported)
            }
        }
    }
}

fn execute(
    adapter: &mut LiveAdapter,
    request_id: &str,
    case: &crate::bench::model::BenchCase,
    candidate: &[u8],
    _system_digest: &str,
) -> NativeExecution {
    match adapter {
        LiveAdapter::Please(adapter) => adapter.execute(&case.case_id, &case.provenance, candidate),
        #[cfg(unix)]
        LiveAdapter::Process(adapter) => adapter.execute(
            request_id,
            case.surface,
            candidate,
            &case.asset_sha256,
            &case.provenance,
            case.trusted_context.clone(),
        ),
        #[cfg(not(unix))]
        LiveAdapter::ProcessUnsupported => {
            NativeExecution::unavailable("subprocess adapters currently require Linux or WSL")
        }
    }
}

fn finish_adapter(adapter: LiveAdapter) -> Vec<ProcessTelemetry> {
    match adapter {
        LiveAdapter::Please(_) => Vec::new(),
        #[cfg(unix)]
        LiveAdapter::Process(adapter) => adapter.finish(),
        #[cfg(not(unix))]
        LiveAdapter::ProcessUnsupported => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_row(
    run: &RunManifest,
    system: &VerifiedSystem,
    case: &crate::bench::model::BenchCase,
    case_digest: &str,
    normalized_input_sha256: &str,
    row_id: &str,
    request_id: &str,
    repetition: u32,
    normalizer: Option<&NormalizerManifest>,
    mut execution: NativeExecution,
) -> Result<BenchResult> {
    let normalized: Option<NormalizedDecision> =
        if let (Some(normalizer), Some(native)) = (normalizer, execution.native.as_ref()) {
            if execution.coverage == CoverageState::Abstained {
                None
            } else {
                match normalize::normalize(normalizer, case.surface, native, case.byte_length) {
                    Ok(decision) => Some(decision),
                    Err(error) => {
                        execution.coverage = CoverageState::InvalidOutput;
                        execution
                            .diagnostics
                            .push(format!("normalization failed: {error}"));
                        None
                    }
                }
            }
        } else {
            None
        };
    let normalizer_id = normalizer
        .map(|normalizer| normalizer.normalizer_id.clone())
        .unwrap_or_else(|| "unsupported".into());
    let normalizer_version = normalizer
        .map(|normalizer| normalizer.version.clone())
        .unwrap_or_else(|| "0".into());
    let native_bytes = execution
        .native
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    let raw_output = if execution.native.is_some()
        || !execution.stdout.is_empty()
        || !execution.stderr.is_empty()
        || execution.exit_status.is_some()
    {
        Some(RawOutput {
            transport: execution.transport.into(),
            native_sha256: if native_bytes.is_empty() {
                sha256(&execution.stdout)
            } else {
                sha256(&native_bytes)
            },
            native: execution.native.clone(),
            stdout_sha256: (!execution.stdout.is_empty()).then(|| sha256(&execution.stdout)),
            stdout_hex: (!execution.stdout.is_empty()).then(|| hex_encode(&execution.stdout)),
            stderr_sha256: (!execution.stderr.is_empty()).then(|| sha256(&execution.stderr)),
            stderr_hex: (!execution.stderr.is_empty()).then(|| hex_encode(&execution.stderr)),
            exit_status: execution.exit_status,
        })
    } else {
        None
    };
    let remote_requests = execution
        .native
        .as_ref()
        .map_or(0, |native| native.remote_requests);
    let declared_cost_microusd = execution
        .native
        .as_ref()
        .map_or(0, |native| native.declared_cost_microusd);
    Ok(BenchResult {
        schema_version: RESULT_SCHEMA.into(),
        row_id: row_id.into(),
        run_id: run.run_id.clone(),
        request_id: request_id.into(),
        pack_digest: run.pack_digest.clone(),
        case_id: case.case_id.clone(),
        case_digest: case_digest.into(),
        input_sha256: case.asset_sha256.clone(),
        normalized_input_sha256: normalized_input_sha256.into(),
        system_id: system.manifest.system_id.clone(),
        system_digest: system.digest.clone(),
        normalizer_id,
        normalizer_version,
        repetition,
        surface: case.surface,
        source: case.source.clone(),
        provenance: case.provenance.clone(),
        group_id: case.group_id.clone(),
        family_id: case.family_id.clone(),
        split: case.split,
        delivery_vector: case.delivery_vector.clone(),
        techniques: case.techniques.clone(),
        ground_truth: case.ground_truth.clone(),
        trusted_context_id: case
            .trusted_context
            .as_ref()
            .map(|context| context.context_id.clone()),
        coverage: execution.coverage,
        raw_output,
        normalized,
        telemetry: ExecutionTelemetry {
            elapsed_micros: duration_micros(execution.elapsed),
            runner_overhead_micros: duration_micros(execution.runner_overhead),
            stdout_bytes: execution.stdout.len() as u64,
            stderr_bytes: execution.stderr.len() as u64,
            peak_memory_bytes: None,
            remote_requests,
            declared_cost_microusd,
        },
        diagnostics: execution.diagnostics,
    })
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

fn host_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("os".into(), std::env::consts::OS.into()),
        ("arch".into(), std::env::consts::ARCH.into()),
        (
            "please_eval_version".into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
    ])
}

fn write_manifest(directory: &Path, manifest: &RunManifest) -> Result<()> {
    let pending = directory.join(".run.json.pending");
    let target = directory.join("run.json");
    let bytes = serde_json::to_vec_pretty(manifest)?;
    {
        let mut file = File::create(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(pending, target)?;
    Ok(())
}

pub fn verify_saved_run(directory: &Path) -> Result<RunManifest> {
    let manifest: RunManifest = serde_json::from_slice(&fs::read(directory.join("run.json"))?)?;
    if manifest.schema_version != RUN_SCHEMA || manifest.status != "complete" {
        return Err("bench run is missing a complete version-1 manifest".into());
    }
    let saved = manifest
        .results
        .as_ref()
        .ok_or("complete run has no results identity")?;
    let mut file = File::open(directory.join("results.jsonl"))?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut rows = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        bytes += count as u64;
        rows += buffer[..count]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count() as u64;
    }
    if bytes != saved.bytes
        || rows != saved.rows
        || format!("{:x}", digest.finalize()) != saved.sha256
    {
        return Err("bench results do not match their completion identity".into());
    }
    let systems: BTreeMap<_, _> = manifest
        .systems
        .iter()
        .map(|system| (system.system_id.as_str(), system.system_digest.as_str()))
        .collect();
    let mut process_ids = BTreeSet::new();
    for system in &manifest.systems {
        if let Some(executable) = &system.staged_executable {
            crate::bench::identity::safe_relative(&executable.path, "staged executable path")?;
            crate::bench::identity::require_sha256(&executable.sha256, "staged executable sha256")?;
            let path = directory.join(&executable.path);
            let length = fs::symlink_metadata(&path)?.len();
            crate::bench::identity::read_verified_file(
                &path,
                length,
                &executable.sha256,
                256 * 1024 * 1024,
            )?;
        }
    }
    for process in &manifest.processes {
        crate::bench::identity::require_sha256(&process.stderr_sha256, "process stderr_sha256")?;
        crate::bench::identity::require_sha256(
            &process.retained_stderr_sha256,
            "process retained_stderr_sha256",
        )?;
        if systems.get(process.system_id.as_str()).copied() != Some(process.system_digest.as_str())
            || process.spawn_index == 0
            || !process_ids.insert((process.system_id.as_str(), process.spawn_index))
        {
            return Err(
                "process telemetry identity is not in the run plan or is duplicated".into(),
            );
        }
        let retained = crate::bench::identity::hex_decode(&process.retained_stderr_hex)?;
        if retained.len() as u64 > process.stderr_bytes
            || retained.len() as u64 > manifest.limits.max_stderr_bytes
            || sha256(&retained) != process.retained_stderr_sha256
        {
            return Err("process retained stderr identity is invalid".into());
        }
        if !process.stderr_overflow
            && (retained.len() as u64 != process.stderr_bytes
                || process.stderr_sha256 != process.retained_stderr_sha256)
        {
            return Err("bounded process stderr does not match its full-stream identity".into());
        }
        if process.stderr_overflow && process.stderr_bytes <= manifest.limits.max_stderr_bytes {
            return Err("process stderr overflow flag disagrees with its byte count".into());
        }
    }
    Ok(manifest)
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}
