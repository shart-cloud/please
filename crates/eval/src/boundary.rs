//! Frozen tokenizer-verified placement suites, measured through the shipping ScanSession.
use crate::{
    replay::{Capture, Label},
    Result,
};
use please_ml::{config::WindowSettings, WindowLayout, WindowPlanner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

const VERSION: u32 = 2;
const CARRIER: &str = "The quarterly inventory report lists completed deliveries. Items are counted and stored in the warehouse. ";
const MAX_CASES: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Development,
    Holdout,
}

/// Same capture metadata and group/split convention as owner-reviewed capture collections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub capture: Capture,
    pub group: String,
    pub split: Split,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub capture: Capture,
    pub group: String,
    pub split: Split,
    pub placement: String,
    pub payload_start: usize,
    pub payload_end: usize,
    pub token_start: usize,
    pub token_end: usize,
    pub zero_overlap_windows: Vec<WindowLayout>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub version: u32,
    pub seeds_sha256: String,
    pub tokenizer_sha256: String,
    pub max_tokens: usize,
    pub carrier: String,
    pub cases: Vec<Case>,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err("boundary input exceeds 1 MiB".into());
    }
    Ok(bytes)
}
fn local(root: &Path, path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("input path must be relative without traversal".into());
    }
    Ok(root.join(path))
}
fn payload_range(offsets: &[(usize, usize)], start: usize, end: usize) -> Result<(usize, usize)> {
    let first = offsets
        .iter()
        .position(|(s, e)| *s < end && *e > start)
        .ok_or("payload produced no tokens")?;
    let last = offsets
        .iter()
        .rposition(|(s, e)| *s < end && *e > start)
        .unwrap();
    Ok((first, last + 1))
}

/// Generate all positions from each seed; a family never crosses the development/holdout split.
/// No inference, labels are inherited from the supplied capture and must be appropriate to padding.
pub fn generate(
    seeds_path: &Path,
    tokenizer_path: &Path,
    max_tokens: usize,
    out: &Path,
) -> Result<String> {
    if out.exists() {
        return Err("boundary output already exists".into());
    }
    if !(4..=8192).contains(&max_tokens) {
        return Err("boundary context must be 4..=8192 tokens".into());
    }
    let seed_bytes = read(seeds_path)?;
    let seeds: Vec<Seed> = serde_json::from_slice(&seed_bytes)?;
    if seeds.is_empty() || seeds.len() > MAX_CASES / 7 {
        return Err("invalid boundary seed count".into());
    }
    // Tokenizer JSON may be larger than input documents; it is a caller-owned model artifact.
    let tokenizer = std::fs::read(tokenizer_path)?;
    let planner = WindowPlanner::new(&tokenizer, max_tokens, WindowSettings::default())?;
    let mut groups = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut cases = Vec::new();
    let mut files = Vec::new();
    for seed in seeds {
        if seed.group.trim().is_empty() || !ids.insert(seed.capture.id.clone()) {
            return Err("empty group or duplicate seed id".into());
        }
        crate::replay::source(&seed.capture.source)?;
        for prior in [
            groups.insert(seed.group.clone(), seed.split),
            hashes.insert(seed.capture.input_sha256.clone(), seed.split),
        ] {
            if prior.is_some_and(|s| s != seed.split) {
                return Err("related group or identical input crosses splits".into());
            }
        }
        let bytes = read(&local(
            seeds_path.parent().unwrap_or(Path::new(".")),
            &seed.capture.input_path,
        )?)?;
        if digest(&bytes) != seed.capture.input_sha256 {
            return Err("seed input digest mismatch".into());
        }
        let payload = std::str::from_utf8(&bytes)?;
        if payload.trim().is_empty() {
            return Err("empty boundary payload".into());
        }
        // Realized boundaries come from production windows, not an assumption about special tokens.
        let probe = "word ".repeat(
            max_tokens
                .checked_mul(3)
                .filter(|n| *n <= MAX_BYTES / 5)
                .ok_or("invalid context size")?,
        );
        let layout = planner.layout(&probe)?;
        let capacity = layout.first().ok_or("no probe window")?.token_end;
        if capacity < 2 {
            return Err("boundary suite requires payload capacity >= 2".into());
        }
        let payload_tokens = planner.payload_offsets(payload)?.len();
        let carrier = CARRIER.repeat(max_tokens);
        let carrier_offsets = planner.payload_offsets(&carrier)?;
        let mut positions = vec![
            ("first", 0, capacity * 2),
            ("inside", capacity / 4, capacity * 2),
            ("before", capacity.saturating_sub(payload_tokens), capacity),
            ("crossing", capacity - 1, capacity),
            ("after", capacity, capacity),
            ("last", capacity * 2, 0),
            ("later_crossing", capacity * 2 - 1, capacity),
        ];
        if payload_tokens > capacity / 2 {
            positions.retain(|(name, _, _)| {
                ["first", "after", "last", "crossing", "later_crossing"].contains(name)
            });
        }
        for (placement, requested_start, suffix_tokens) in positions {
            // Search bounded padding adjustments, validating token positions after joining all text.
            let mut chosen = None;
            let lo = requested_start.saturating_sub(16);
            let hi = requested_start.saturating_add(16);
            for prefix_tokens in lo..=hi {
                let prefix_end = carrier_offsets
                    .get(prefix_tokens)
                    .ok_or("carrier too short")?
                    .0;
                let suffix_end = carrier_offsets
                    .get(suffix_tokens)
                    .ok_or("carrier too short")?
                    .0;
                let prefix = &carrier[..prefix_end];
                let suffix = &carrier[..suffix_end];
                let text = format!("{prefix}\n{payload}\n{suffix}");
                if text.len() > MAX_BYTES {
                    return Err("generated boundary input exceeds byte limit".into());
                }
                let start = prefix.len() + 1;
                let end = start + payload.len();
                let offsets = planner.payload_offsets(&text)?;
                let (ts, te) = payload_range(&offsets, start, end)?;
                let placement_matches = match placement {
                    "before" => te == capacity,
                    "crossing" => ts == requested_start && te > capacity,
                    "later_crossing" => ts == requested_start && te > capacity * 2,
                    "inside" => ts == requested_start && te <= capacity,
                    _ => ts == requested_start,
                };
                if placement_matches {
                    let windows = planner.layout(&text)?;
                    chosen = Some((text, start, end, ts, te, windows));
                    break;
                }
            }
            let (text, start, end, token_start, token_end, windows) = chosen.ok_or_else(|| format!("cannot realize {placement} for seed {}; payload may be too short/long for this placement", seed.capture.id))?;
            let index = cases.len();
            let path = PathBuf::from(format!("inputs/{index:04}.txt"));
            let mut capture = seed.capture.clone();
            capture.id = format!("{}/{placement}", capture.id);
            capture.input_path = path.clone();
            capture.input_sha256 = digest(text.as_bytes());
            cases.push(Case {
                capture,
                group: seed.group.clone(),
                split: seed.split,
                placement: placement.into(),
                payload_start: start,
                payload_end: end,
                token_start,
                token_end,
                zero_overlap_windows: windows,
            });
            files.push((path, text));
        }
    }
    let suite = Suite {
        version: VERSION,
        seeds_sha256: digest(&seed_bytes),
        tokenizer_sha256: digest(&tokenizer),
        max_tokens,
        carrier: CARRIER.into(),
        cases,
    };
    let manifest = serde_json::to_vec_pretty(&suite)?;
    std::fs::create_dir(out)?;
    std::fs::create_dir(out.join("inputs"))?;
    for (path, text) in files {
        std::fs::write(out.join(path), text)?;
    }
    std::fs::write(out.join("suite.json"), &manifest)?;
    Ok(digest(&manifest))
}

fn verified(suite_path: &Path, expected: &str) -> Result<(Suite, Vec<Vec<u8>>)> {
    // Suite manifests can exceed the document cap because they contain all layouts.
    let bytes = std::fs::read(suite_path)?;
    if digest(&bytes) != expected {
        return Err("suite digest mismatch".into());
    }
    let suite: Suite = serde_json::from_slice(&bytes)?;
    if suite.version != VERSION || suite.cases.is_empty() || suite.cases.len() > MAX_CASES {
        return Err("invalid suite version/count".into());
    }
    let mut inputs = Vec::new();
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::new();
    for case in &suite.cases {
        if !ids.insert(&case.capture.id) {
            return Err("duplicate boundary case id".into());
        }
        if groups
            .insert(&case.group, case.split)
            .is_some_and(|s| s != case.split)
        {
            return Err("suite group crosses splits".into());
        }
        let input = read(&local(
            suite_path.parent().unwrap_or(Path::new(".")),
            &case.capture.input_path,
        )?)?;
        if digest(&input) != case.capture.input_sha256 {
            return Err("boundary input digest mismatch".into());
        }
        inputs.push(input);
    }
    Ok((suite, inputs))
}

/// Tokenizer-only verification also independently rechecks realized positions in frozen bytes.
pub fn check(suite_path: &Path, expected: &str, tokenizer_path: &Path) -> Result<()> {
    let (suite, inputs) = verified(suite_path, expected)?;
    let tokenizer = std::fs::read(tokenizer_path)?;
    if digest(&tokenizer) != suite.tokenizer_sha256 {
        return Err("suite tokenizer mismatch".into());
    }
    let planner = WindowPlanner::new(&tokenizer, suite.max_tokens, WindowSettings::default())?;
    for (case, input) in suite.cases.iter().zip(inputs) {
        verify_layout(&planner, case, &input)?;
    }
    Ok(())
}
fn verify_layout(planner: &WindowPlanner, case: &Case, input: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(input)?;
    if text
        .get(case.payload_start..case.payload_end)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err("invalid payload byte range".into());
    }
    if planner.layout(text)? != case.zero_overlap_windows
        || payload_range(
            &planner.payload_offsets(text)?,
            case.payload_start,
            case.payload_end,
        )? != (case.token_start, case.token_end)
    {
        return Err("frozen placement no longer matches tokenizer".into());
    }
    Ok(())
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub total: usize,
    pub injections: usize,
    pub benign: usize,
    pub uncertain: usize,
    pub ml_hits: usize,
    pub ml_false_positives: usize,
    pub ml_misses: usize,
    pub product_hits: usize,
    pub product_false_positives: usize,
    pub blocks: usize,
    pub reviews: usize,
    pub allows: usize,
    pub incomplete: usize,
}
impl Counts {
    pub fn record(
        &mut self,
        label: Label,
        admitted: Option<bool>,
        decision: &str,
        incomplete: bool,
    ) {
        self.total += 1;
        self.incomplete += usize::from(incomplete);
        match decision {
            "block" => self.blocks += 1,
            "allow" => self.allows += 1,
            _ => self.reviews += 1,
        }
        match label {
            Label::Benign => {
                self.benign += 1;
                self.product_false_positives += usize::from(decision == "block");
                self.ml_false_positives += usize::from(admitted == Some(true));
            }
            Label::Injection => {
                self.injections += 1;
                self.product_hits += usize::from(decision == "block");
                self.ml_hits += usize::from(admitted == Some(true));
                self.ml_misses += usize::from(admitted != Some(true));
            }
            Label::Uncertain => self.uncertain += 1,
        }
    }
}

#[cfg(feature = "shipping-ml")]
pub fn run(
    suite_path: &Path,
    expected: &str,
    config_path: &Path,
    out: &Path,
    repeats: usize,
    split: Split,
) -> Result<()> {
    use please_core::{Engine, ScanPolicy, TargetRef};
    use please_scan::{MlLoadResult, ScanDecision, ScanSession};
    use std::time::Instant;
    if out.exists() {
        return Err("boundary run output already exists".into());
    }
    if repeats == 0 || repeats > 100 {
        return Err("repeats must be 1..=100".into());
    }
    let (suite, inputs) = verified(suite_path, expected)?;
    let started = Instant::now();
    let loaded = please_scan::load_classifier(config_path)?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.;
    let model = match &loaded {
        MlLoadResult::Loaded(m) => m,
        MlLoadResult::Unavailable(d) => {
            return Err(format!("boundary model unavailable: {d}").into())
        }
    };
    if model.identity().fields()["tokenizer_sha256"] != suite.tokenizer_sha256
        || model.config().max_tokens != suite.max_tokens
    {
        return Err("run model tokenizer/context differs from frozen suite".into());
    }
    // Recheck all selected geometry before inference; use the loaded tokenizer's immutable bytes digest.
    let tokenizer = std::fs::read(model.config().model_path.join("tokenizer.json"))?;
    if digest(&tokenizer) != suite.tokenizer_sha256 {
        return Err("tokenizer changed after load".into());
    }
    let planner = WindowPlanner::new(&tokenizer, suite.max_tokens, WindowSettings::default())?;
    for (case, input) in suite.cases.iter().zip(&inputs) {
        verify_layout(&planner, case, input)?;
    }
    let warmup = Instant::now();
    if let please_ml::Outcome::Failed(detail) = model.classify_detailed("Warmup.") {
        return Err(format!("boundary warmup failed: {detail}").into());
    }
    let warmup_ms = warmup.elapsed().as_secs_f64() * 1000.;
    let engine = Engine::builtin()?;
    let mut rows = Vec::new();
    let mut totals = Counts::default();
    let mut strata: BTreeMap<String, Counts> = BTreeMap::new();
    let mut groups: BTreeMap<String, Counts> = BTreeMap::new();
    let mut latencies = Vec::new();
    let selected = suite.cases.iter().filter(|c| c.split == split).count();
    let measured = Instant::now();
    for (case, input) in suite
        .cases
        .iter()
        .zip(&inputs)
        .filter(|(c, _)| c.split == split)
    {
        let source = crate::replay::source(&case.capture.source)?;
        let policy = ScanPolicy {
            provenance: ScanPolicy::for_source(source).provenance,
            ..Default::default()
        };
        let session = ScanSession::new(&engine, policy).with_model(&loaded);
        let mut verdict = None;
        let mut times = Vec::new();
        for _ in 0..repeats {
            let start = Instant::now();
            let next = session.scan(input, TargetRef::buffer(&case.capture.id, input.len()));
            times.push(start.elapsed().as_secs_f64() * 1000.);
            verdict = Some(next);
        }
        let verdict = verdict.unwrap();
        let decision = match session.decision(&verdict) {
            ScanDecision::Clean | ScanDecision::BelowThreshold => "allow",
            ScanDecision::AtOrAboveThreshold => "block",
            ScanDecision::Inconclusive => "review",
        };
        let ml = verdict.ml();
        let raw = ml
            .and_then(|m| m.segments().first())
            .and_then(|s| s.raw_score());
        let admitted = raw.map(|s| s >= model.config().threshold);
        let incomplete = verdict.is_incomplete();
        totals.record(case.capture.label, admitted, decision, incomplete);
        let length = if input.len() < 4096 {
            "under_4k"
        } else {
            "4k_or_more"
        };
        for key in [
            format!("source/{}", case.capture.source),
            format!("placement/{}", case.placement),
            format!("length/{length}"),
        ] {
            strata.entry(key).or_default().record(
                case.capture.label,
                admitted,
                decision,
                incomplete,
            );
        }
        groups.entry(case.group.clone()).or_default().record(
            case.capture.label,
            admitted,
            decision,
            incomplete,
        );
        latencies.extend(&times);
        rows.push(serde_json::json!({"capture":case.capture,"group":case.group,"split":case.split,"placement":case.placement,
            "payload_span":[case.payload_start,case.payload_end],"payload_token_range":[case.token_start,case.token_end],
            "latency_ms":times,"ml_admitted":admitted,"decision":decision,"incomplete":incomplete,
            "windows_processed":ml.map(|m|m.windows().len()),"model_tokens_processed":ml.map(|m|m.windows().iter().map(|w|w.model_tokens).sum::<usize>()),"verdict":verdict}));
        if rows.len() % 10 == 0 || rows.len() == selected {
            eprintln!(
                "boundary: {}/{} cases completed in {:.1}s",
                rows.len(),
                selected,
                measured.elapsed().as_secs_f64()
            );
        }
    }
    if rows.is_empty() {
        return Err("selected split has no cases".into());
    }
    latencies.sort_by(f64::total_cmp);
    let quantile = |percent: usize| latencies[((latencies.len() - 1) * percent) / 100];
    let executable_digest = {
        use std::io::Read;
        let mut file = std::fs::File::open(std::env::current_exe()?)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        format!("{:x}", hash.finalize())
    };
    let metadata = serde_json::json!({"format_version":VERSION,"suite_sha256":expected,"split":split,
        "inference":model.identity(),"threshold":model.config().threshold,"windowing":model.config().windowing,
        "policy":ScanPolicy::default(),"ruleset":engine.ruleset_id(),"repeats":repeats,
        "judge":false,"load_ms":load_ms,"warmup_ms":warmup_ms,"scan_latency_ms":{"p50":quantile(50),"p95":quantile(95)},
        "runtime":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"available_parallelism":std::thread::available_parallelism().map(|n|n.get()).ok(),"peak_rss_kib":peak_rss_kib(),"executable_sha256":executable_digest},
        "totals":totals,"strata":strata,"uncertainty_by_group":group_intervals(&groups),"groups":groups,
        "uncertainty":"Descriptive paired development results; related placements are not independent. No shipping acceptance or population confidence claim."});
    std::fs::create_dir(out)?;
    std::fs::write(out.join("run.json"), serde_json::to_vec_pretty(&metadata)?)?;
    let lines = rows
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(out.join("results.jsonl"), lines)?;
    std::fs::write(
        out.join("report.md"),
        format!(
            "# Boundary evaluation\n\nSuite: `{expected}`\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&metadata)?
        ),
    )?;
    Ok(())
}
#[cfg(feature = "shipping-ml")]
fn peak_rss_kib() -> Option<u64> {
    // Linux process high-water RSS; unavailable on other hosts, never invented as zero.
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
        })
}

/// Paired placements share a group. Resample whole groups; never treat placements as independent.
#[cfg(feature = "shipping-ml")]
fn group_intervals(groups: &BTreeMap<String, Counts>) -> serde_json::Value {
    let all: Vec<_> = groups.values().collect();
    if all.len() < 2 {
        return serde_json::json!({"groups":all.len(),"intervals":null,"reason":"fewer than two independent groups"});
    }
    let mut state = 0x52a68b4d912a77efu64;
    let mut tpr = Vec::new();
    let mut fpr = Vec::new();
    for _ in 0..2000 {
        let (mut hits, mut positives, mut fp, mut negatives) = (0, 0, 0, 0);
        for _ in 0..all.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let g = all[(state % all.len() as u64) as usize];
            hits += g.ml_hits;
            positives += g.injections;
            fp += g.ml_false_positives;
            negatives += g.benign;
        }
        if positives > 0 {
            tpr.push(hits as f64 / positives as f64);
        }
        if negatives > 0 {
            fpr.push(fp as f64 / negatives as f64);
        }
    }
    let interval = |mut values: Vec<f64>| {
        values.sort_by(f64::total_cmp);
        if values.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::json!({"low":values[(values.len()-1)*25/1000],"high":values[(values.len()-1)*975/1000],"valid_resamples":values.len()})
        }
    };
    serde_json::json!({"method":"deterministic whole-group percentile bootstrap, 2000 draws, 95% interval", "groups":all.len(),"ml_tpr":interval(tpr),"ml_fpr":interval(fpr),"limit":"Degenerate/small-sample intervals do not establish a population ceiling or the 1% target."})
}
