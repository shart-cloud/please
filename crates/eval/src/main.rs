//! `please-eval` — the evaluation harness's command line.
//!
//! Corpus commands, plus an isolated phase-0 model feasibility workflow:
//!
//! ```text
//! please-eval generate            build the span-labelled corpus (no network)
//! please-eval fetch               materialise the public slices into the cache (needs `hf`)
//! please-eval manifest --check    verify the cache against the committed manifests
//! please-eval run                 scan every slice
//! please-eval report              per-source stratified metrics
//! please-eval gate                the false-positive gate, as an exit code
//!
//! please-eval model fetch         explicit networked acquisition of pinned model assets
//! please-eval model check         cache-only integrity and attribution
//! please-eval model smoke         real Candle inference (`--features ml`)
//! ```
//!
//! `run`, `report` and `gate` all take `--offline`, which restricts them to the committed corpora.
//! That is the configuration CI uses, and `README.md` states plainly what it proves and what it does
//! not: the gate over hand-written negatives, generated matched carriers and this repository's own
//! prose is real, and the public-corpus half needs an approved dataset gate and a human.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use please_eval::metrics::{parse_floor, Gate, Report, SliceMetrics};
use please_eval::models::ModelManifest;
use please_eval::rows::Row;
use please_eval::scan::RuleSelection;
use please_eval::slice::{Origin, Slice, SliceSet};
use please_eval::{cases, fetch, generate, manifest, models, scan, Result};

/// Exit code for a gate failure.
///
/// Distinct from the code for a broken invocation. A caller — a CI job, a person — has to be able to
/// tell "the tool ran and the corpus is worse than it was" from "the tool did not run", and a single
/// non-zero code makes those the same event.
const EXIT_GATE_FAILED: u8 = 2;
const EXIT_ERROR: u8 = 1;

#[derive(Parser)]
#[command(
    name = "please-eval",
    about = "Evaluation harness for PLEASE: corpus adapters, a span-labelled generator, and per-source stratified metrics.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build `corpus/generated.jsonl` from the committed carriers, payloads and positions.
    Generate {
        /// Verify the committed file matches what the inputs generate, and change nothing.
        #[arg(long)]
        check: bool,
    },
    /// Materialise public-corpus slices into the cache and write their manifests.
    Fetch {
        /// Slice ids. Omit for every query slice.
        #[arg(long = "slice")]
        slices: Vec<String>,
    },
    /// Verify cached corpus text against the committed manifests.
    Manifest {
        #[arg(long = "slice")]
        slices: Vec<String>,
    },
    /// Scan slices and write per-row results.
    Run {
        #[arg(long = "slice")]
        slices: Vec<String>,
        /// Only the slices that need no network.
        #[arg(long)]
        offline: bool,
        /// Additional rule sets, layered on the built-in base.
        #[arg(long = "rules")]
        rules: Vec<PathBuf>,
        /// Rules to disable, by id.
        #[arg(long = "disable-rule")]
        disable_rule: Vec<String>,
        /// Label for this run's results directory.
        #[arg(long, default_value = "builtin")]
        run: String,
    },
    /// Per-source stratified metrics over a run's results.
    Report {
        #[arg(long, default_value = "builtin")]
        run: String,
        #[arg(long)]
        offline: bool,
        /// `md` or `json`.
        #[arg(long, default_value = "md")]
        format: String,
        /// Write here instead of to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// The false-positive gate. Exits 2 when it fails.
    Gate {
        #[arg(long, default_value = "builtin")]
        run: String,
        #[arg(long)]
        offline: bool,
        /// Also enforce SC-003's criterion, not only the regression floor.
        #[arg(long)]
        strict: bool,
        /// Permit gate-eligible slices with no committed baseline. For the measurement that establishes
        /// the baselines, and nothing else.
        #[arg(long)]
        allow_unpinned: bool,
    },
    /// Acquire, verify, and probe revision-pinned ML candidates without touching shipping crates.
    Model {
        #[command(subcommand)]
        action: ModelCommand,
    },
}

#[derive(Subcommand)]
enum ModelCommand {
    /// Show the committed candidates and whether their pinned revision is present locally.
    List,
    /// Download pinned runtime assets with `hf`, then verify every digest.
    Fetch {
        /// Model ids. Omit for every committed candidate.
        models: Vec<String>,
    },
    /// Verify cached byte lengths/digests without accessing the network.
    Check {
        /// Model ids. Omit for every committed candidate.
        models: Vec<String>,
    },
    /// Run real CPU inference and emit measured JSON. Requires `--features ml`.
    Smoke {
        /// Model ids. Omit for every committed candidate.
        models: Vec<String>,
        /// Timed inferences per model; the reported latency is the median.
        #[arg(long, default_value_t = 10)]
        runs: usize,
    },
    /// M2 / M7: document-level separation, and the held-out check on it.
    ///
    /// Freezes the zero-false-positive threshold on the generated matched negatives and applies it
    /// unchanged to the hand-written fixtures and this repository's own prose — `document-map.md`
    /// §5.1's mitigation for measuring our own imagination. Requires `--features ml`.
    Holdout {
        /// The embedder to measure with. Defaults to the manifest's only embedder.
        #[arg(long)]
        model: Option<String>,
        /// Cut prose into sentences rather than paragraphs.
        #[arg(long)]
        sentences: bool,
        /// Write the markdown report here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also write one JSON object per document here.
        #[arg(long)]
        docs: Option<PathBuf>,
    },
    /// T006 / SC-603: rank each generated row's injected segment against its siblings.
    ///
    /// The kill-criterion measurement for the embedding half of `specs/006-local-ml-tier/`. Requires
    /// `--features ml` unless `--dry-run` is passed.
    Outlier {
        /// The embedder to measure with. Defaults to the manifest's only embedder.
        #[arg(long)]
        model: Option<String>,
        /// Segment the corpus and report what would be scored, without loading a model. Answers
        /// "what can this segmentation even see?" for the price of no inference at all.
        #[arg(long)]
        dry_run: bool,
        /// Cut prose into sentences rather than paragraphs. The first run measured 68.9% top-1 on
        /// payloads that became their own segment against 13.2% on those that did not; this is the
        /// knob that tests whether granularity is what bounds the metric.
        #[arg(long)]
        sentences: bool,
        /// Minimum sibling-group size. SC-603's wording is three.
        #[arg(long, default_value_t = please_eval::outlier::MIN_SIBLINGS)]
        min_siblings: usize,
        /// Write the markdown report here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also write one JSON object per scored row here, for chasing a surprising stratum back to
        /// the document that produced it.
        #[arg(long)]
        rows: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("please-eval: {error}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { check } => generate_corpus(check),
        Command::Fetch { slices } => fetch_slices(&slices),
        Command::Manifest { slices } => check_manifests(&slices),
        Command::Run {
            slices,
            offline,
            rules,
            disable_rule,
            run,
        } => scan_slices(
            &slices,
            offline,
            RuleSelection {
                rules,
                disable: disable_rule,
            },
            &run,
        ),
        Command::Report {
            run,
            offline,
            format,
            out,
        } => write_report(&run, offline, &format, out.as_deref()),
        Command::Gate {
            run,
            offline,
            strict,
            allow_unpinned,
        } => check_gate(&run, offline, strict, allow_unpinned),
        Command::Model { action } => match action {
            ModelCommand::List => list_models(),
            ModelCommand::Fetch { models } => fetch_models(&models),
            ModelCommand::Check { models } => check_models(&models),
            ModelCommand::Smoke { models, runs } => smoke_models(&models, runs),
            ModelCommand::Holdout {
                model,
                sentences,
                out,
                docs,
            } => measure_holdout(
                model.as_deref(),
                if sentences {
                    please_eval::segment::Granularity::Sentence
                } else {
                    please_eval::segment::Granularity::Paragraph
                },
                out.as_deref(),
                docs.as_deref(),
            ),
            ModelCommand::Outlier {
                model,
                dry_run,
                sentences,
                min_siblings,
                out,
                rows,
            } => measure_outlier(
                model.as_deref(),
                dry_run,
                if sentences {
                    please_eval::segment::Granularity::Sentence
                } else {
                    please_eval::segment::Granularity::Paragraph
                },
                min_siblings,
                out.as_deref(),
                rows.as_deref(),
            ),
        },
    }
}

fn list_models() -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    for model in &manifest.models {
        let directory = models::directory(model)?;
        println!(
            "{:<30} {:<10} {:<8} {}",
            model.id,
            model.kind.as_str(),
            if directory.is_dir() {
                "cached"
            } else {
                "missing"
            },
            directory.display()
        );
        if !model.license_note.is_empty() {
            println!("  {}", model.license_note);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn fetch_models(wanted: &[String]) -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    for model in manifest.select(wanted)? {
        eprintln!("fetching {}@{}", model.repo, &model.revision[..12]);
        let installed = models::fetch(model)?;
        print_installed(model, &installed);
    }
    Ok(ExitCode::SUCCESS)
}

fn check_models(wanted: &[String]) -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    for model in manifest.select(wanted)? {
        let directory = models::directory(model)?;
        let installed = models::inspect(model, &directory)?;
        print_installed(model, &installed);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_installed(model: &models::ModelSpec, installed: &models::InstalledModel) {
    println!(
        "{}  {}  {}",
        model.id,
        human_bytes(installed.bytes),
        installed.directory.display()
    );
    println!("  weights sha256  {}", installed.weights_sha256);
    println!("  bundle  sha256  {}", installed.bundle_sha256);
}

#[cfg(feature = "ml")]
fn smoke_models(wanted: &[String], runs: usize) -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    for model in manifest.select(wanted)? {
        let directory = models::directory(model)?;
        let installed = models::inspect(model, &directory)?;
        eprintln!(
            "probing {} (bundle {})",
            model.id,
            &installed.bundle_sha256[..12]
        );
        let report = please_eval::ml::smoke(model, &directory, runs)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "ml"))]
fn smoke_models(_wanted: &[String], _runs: usize) -> Result<ExitCode> {
    Err(
        "model smoke requires Candle. Re-run with `cargo run --release --manifest-path \
         crates/eval/Cargo.toml --features ml -- model smoke`"
            .into(),
    )
}

/// The five slices M2 and M7 need, and which of them carry a payload.
///
/// `repo_prose` is a negative and belongs here for the reason `document-map.md` §5.2 gives: the false
/// positive that matters is not a carrier without a payload — that is a perfect negative and it
/// flatters the metric — it is security prose *about* payloads, which has a payload and no seam. This
/// repository is made of that.
fn holdout_slices() -> Result<Vec<(&'static str, bool, Vec<please_eval::rows::Row>)>> {
    use please_eval::slice::LocalReader::*;
    Ok(vec![
        ("gen_positive", true, cases::read(GeneratedPositive)?),
        (
            "gen_matched_negative",
            false,
            cases::read(GeneratedMatchedNegative)?,
        ),
        ("fix_positive", true, cases::read(FixturesPositive)?),
        ("fix_benign", false, cases::read(FixturesBenign)?),
        ("repo_prose", false, cases::read(RepositoryProse)?),
    ])
}

fn measure_holdout(
    model: Option<&str>,
    granularity: please_eval::segment::Granularity,
    out: Option<&Path>,
    docs_out: Option<&Path>,
) -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    let spec = embedder_for(&manifest, model)?;
    let directory = models::directory(spec)?;
    let installed = models::inspect(spec, &directory)?;
    let slices = holdout_slices()?;
    eprintln!(
        "measuring M2/M7 with {} (bundle {}) over {} documents",
        spec.id,
        &installed.bundle_sha256[..12],
        slices.iter().map(|(_, _, rows)| rows.len()).sum::<usize>()
    );

    let docs = run_holdout(spec, &directory, &slices, granularity)?;

    if let Some(path) = docs_out {
        let mut jsonl = String::new();
        for doc in &docs {
            jsonl.push_str(&serde_json::to_string(doc)?);
            jsonl.push('\n');
        }
        std::fs::write(path, jsonl).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        eprintln!("per-document scores: {}", path.display());
    }

    let rendered =
        please_eval::outlier::render_holdout(&spec.id, &spec.revision, granularity, &docs);
    match out {
        Some(path) => {
            std::fs::write(path, &rendered)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            eprintln!("report: {}", path.display());
        }
        None => print!("{rendered}"),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "ml")]
fn run_holdout(
    spec: &models::ModelSpec,
    directory: &Path,
    slices: &[(&str, bool, Vec<please_eval::rows::Row>)],
    granularity: please_eval::segment::Granularity,
) -> Result<Vec<please_eval::outlier::DocScore>> {
    please_eval::ml::holdout_experiment(spec, directory, slices, granularity, true)
}

#[cfg(not(feature = "ml"))]
fn run_holdout(
    _spec: &models::ModelSpec,
    _directory: &Path,
    _slices: &[(&str, bool, Vec<please_eval::rows::Row>)],
    _granularity: please_eval::segment::Granularity,
) -> Result<Vec<please_eval::outlier::DocScore>> {
    Err(
        "model holdout requires Candle. Re-run with `cargo run --release --manifest-path \
         crates/eval/Cargo.toml --features ml -- model holdout`"
            .into(),
    )
}

/// The embedder to measure SC-603 with: the one named, or the manifest's only embedder.
///
/// Defaulting rather than requiring the id, because the manifest has exactly one embedder and a
/// command whose invocation differs between the memo and the terminal is a command that drifts. If a
/// second embedder is ever pinned, this stops guessing and says so.
fn embedder_for<'a>(
    manifest: &'a ModelManifest,
    wanted: Option<&str>,
) -> Result<&'a models::ModelSpec> {
    if let Some(id) = wanted {
        return manifest.get(id);
    }
    let embedders: Vec<_> = manifest
        .models
        .iter()
        .filter(|model| model.kind == models::ModelKind::Embedder)
        .collect();
    match embedders.as_slice() {
        [only] => Ok(only),
        [] => Err("the model manifest pins no embedder".into()),
        many => Err(format!(
            "the manifest pins {} embedders; name one with --model. Known: {}",
            many.len(),
            many.iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into()),
    }
}

fn measure_outlier(
    model: Option<&str>,
    dry_run: bool,
    granularity: please_eval::segment::Granularity,
    min_siblings: usize,
    out: Option<&Path>,
    rows_out: Option<&Path>,
) -> Result<ExitCode> {
    let manifest = ModelManifest::load()?;
    let spec = embedder_for(&manifest, model)?;
    let rows = cases::read(please_eval::slice::LocalReader::GeneratedPositive)?;

    if dry_run {
        return dry_run_outlier(&rows, min_siblings, granularity);
    }

    let directory = models::directory(spec)?;
    let installed = models::inspect(spec, &directory)?;
    eprintln!(
        "measuring SC-603 with {} (bundle {}) over {} rows",
        spec.id,
        &installed.bundle_sha256[..12],
        rows.len()
    );
    let (outcomes, excluded) = run_outlier(spec, &directory, &rows, min_siblings, granularity)?;

    if let Some(path) = rows_out {
        let mut jsonl = String::new();
        for outcome in &outcomes {
            jsonl.push_str(&serde_json::to_string(outcome)?);
            jsonl.push('\n');
        }
        std::fs::write(path, jsonl).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        eprintln!("per-row outcomes: {}", path.display());
    }

    let report = please_eval::outlier::aggregate(
        &spec.id,
        &spec.revision,
        granularity,
        rows.len(),
        &outcomes,
        excluded,
    );
    let rendered = please_eval::outlier::render(&report);
    match out {
        Some(path) => {
            std::fs::write(path, &rendered)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            eprintln!("report: {}", path.display());
        }
        None => print!("{rendered}"),
    }

    // The exit code is the kill criterion, so it can be a job rather than a reading exercise — and
    // `abandon` uses the gate's code rather than the error's for the reason EXIT_GATE_FAILED already
    // gives: "the measurement ran and the answer is no" must not look like "the measurement did not
    // run". `continue` is not a failure. SC-603 puts 50-60% at keep-experimenting, and a command that
    // went red there would be red every day until somebody routed around it.
    Ok(match report.verdict {
        please_eval::outlier::Verdict::Ship | please_eval::outlier::Verdict::Continue => {
            ExitCode::SUCCESS
        }
        please_eval::outlier::Verdict::Abandon => ExitCode::from(EXIT_GATE_FAILED),
    })
}

/// What the segmentation can see, with no model involved.
///
/// This is worth a command of its own because it separates the two ways SC-603 can come out low. A
/// weak signal and a segmentation that never produced a candidate look identical in the top-1 rate
/// and completely different here.
fn dry_run_outlier(
    rows: &[please_eval::rows::Row],
    min_siblings: usize,
    granularity: please_eval::segment::Granularity,
) -> Result<ExitCode> {
    use please_eval::outlier::{prepare, Excluded};
    use std::collections::BTreeMap;

    let mut excluded: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_placement: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_position: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut groups = 0usize;
    let mut scored = 0usize;

    for row in rows {
        let position = row.position.clone().unwrap_or_else(|| "-".to_string());
        let entry = by_position.entry(position).or_default();
        entry.1 += 1;
        match prepare(row, min_siblings, granularity) {
            Ok(candidate) => {
                scored += 1;
                entry.0 += 1;
                groups += candidate.siblings.len();
                *by_placement
                    .entry(match candidate.placement {
                        please_eval::segment::Placement::Isolated => "isolated",
                        please_eval::segment::Placement::Diluted => "diluted",
                        please_eval::segment::Placement::Split => "split",
                    })
                    .or_default() += 1;
                *by_kind
                    .entry(candidate.segments[candidate.injected].kind.as_str())
                    .or_default() += 1;
            }
            Err(reason) => {
                *excluded.entry(Excluded::as_str(reason)).or_default() += 1;
            }
        }
    }

    println!("rows read           {}", rows.len());
    println!("scoreable           {scored}");
    println!(
        "mean sibling group  {:.1}",
        if scored == 0 {
            0.0
        } else {
            groups as f64 / scored as f64
        }
    );
    for (title, map) in [
        ("excluded", &excluded),
        ("placement", &by_placement),
        ("segment kind", &by_kind),
    ] {
        println!("\n{title}:");
        for (key, count) in map.iter() {
            println!("  {key:<28} {count}");
        }
    }
    println!("\nscoreable by position:");
    for (key, (ok, total)) in &by_position {
        println!("  {key:<28} {ok}/{total}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "ml")]
fn run_outlier(
    spec: &models::ModelSpec,
    directory: &Path,
    rows: &[please_eval::rows::Row],
    min_siblings: usize,
    granularity: please_eval::segment::Granularity,
) -> Result<(
    Vec<please_eval::outlier::Outcome>,
    std::collections::BTreeMap<&'static str, usize>,
)> {
    please_eval::ml::outlier_experiment(spec, directory, rows, min_siblings, granularity, true)
}

#[cfg(not(feature = "ml"))]
fn run_outlier(
    _spec: &models::ModelSpec,
    _directory: &Path,
    _rows: &[please_eval::rows::Row],
    _min_siblings: usize,
    _granularity: please_eval::segment::Granularity,
) -> Result<(
    Vec<please_eval::outlier::Outcome>,
    std::collections::BTreeMap<&'static str, usize>,
)> {
    Err(
        "model outlier requires Candle. Re-run with `cargo run --release --manifest-path \
         crates/eval/Cargo.toml --features ml -- model outlier`, or pass --dry-run to see what the \
         segmentation can reach without a model"
            .into(),
    )
}

fn human_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn generate_corpus(check: bool) -> Result<ExitCode> {
    let generated = generate::build()?;
    let serialised = generate::serialise(&generated.rows)?;
    let path = generate::output_path();

    if check {
        let committed = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if committed != serialised {
            return Err(format!(
                "{} is not what the committed inputs generate. Either an input changed without the \
                 corpus being regenerated, or generation is not deterministic. Run `please-eval \
                 generate` and review the diff",
                path.display()
            )
            .into());
        }
        println!(
            "generated corpus matches its inputs: {} positives, {} matched negatives",
            generated.positives, generated.negatives
        );
        return Ok(ExitCode::SUCCESS);
    }

    std::fs::write(&path, &serialised)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!(
        "{}: {} positives, {} matched negatives",
        path.display(),
        generated.positives,
        generated.negatives
    );

    // Skipped pairs are printed, never merely omitted. A position a carrier cannot host is expected;
    // a corpus quietly missing a third of its cross-product is not, and the two look identical in a
    // row count.
    if !generated.skipped.is_empty() {
        println!(
            "\n{} carrier/position pairs were skipped because the carrier declares no such anchor:",
            generated.skipped.len()
        );
        let mut by_position: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for (carrier, position) in &generated.skipped {
            by_position
                .entry(position.as_str())
                .or_default()
                .push(carrier.as_str());
        }
        for (position, carriers) in by_position {
            println!("  {position:<16} {}", carriers.join(", "));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn fetch_slices(wanted: &[String]) -> Result<ExitCode> {
    let set = SliceSet::load()?;
    let targets = select(&set, wanted, false)?
        .into_iter()
        .filter(|slice| slice.needs_network())
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err("no query slices selected. Local slices need no fetch".into());
    }

    for slice in targets {
        eprintln!("fetching {} — {}", slice.id, slice.label);
        let fetched = fetch::slice(&set, slice)?;
        println!("{:<24} {} rows", fetched.slice_id, fetched.rows);
        if fetched.decode_failures > 0 {
            // Never silent. A previous run lost five LLMail rows to a line-based reader and the loss
            // reached a published document as a parenthesis.
            println!(
                "{:<24} WARNING: {} row(s) could not be decoded and are absent from the slice. The \
                 metric's denominator is short by that many",
                "", fetched.decode_failures
            );
        }
        if fetched.digest_disagreements > 0 {
            return Err(format!(
                "{}: DuckDB and sha2 disagreed on {} digest(s). Row identity is the content hash, so \
                 this invalidates the manifest scheme rather than the slice — do not publish anything \
                 measured from this cache",
                fetched.slice_id, fetched.digest_disagreements
            )
            .into());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn check_manifests(wanted: &[String]) -> Result<ExitCode> {
    let set = SliceSet::load()?;
    let mut checked = 0usize;
    for slice in select(&set, wanted, false)? {
        if !slice.needs_network() {
            continue;
        }
        let cached = fetch::read_cache(&slice.id)?;
        let committed = manifest::Manifest::read(&slice.id)?;
        committed.verify(&slice.id, &cached)?;
        println!("{:<24} {} rows verified", slice.id, cached.len());
        checked += 1;
    }
    if checked == 0 {
        return Err("no query slices selected; nothing to verify".into());
    }
    Ok(ExitCode::SUCCESS)
}

fn scan_slices(
    wanted: &[String],
    offline: bool,
    selection: RuleSelection,
    run_label: &str,
) -> Result<ExitCode> {
    let set = SliceSet::load()?;
    let floor = parse_floor(&set.gate.floor)?;
    let engine = selection.engine()?;
    for warning in engine.warnings() {
        eprintln!("please-eval: rule set warning: {warning}");
    }

    let mut any = false;
    for slice in select(&set, wanted, offline)? {
        let rows = load_rows(slice)?;
        let results = scan::rows(&engine, floor, &rows);
        scan::write_results(run_label, &slice.id, &results)?;
        let hits = results.iter().filter(|r| r.detected).count();
        println!(
            "{:<24} {:>6} rows  {:>6} at or above {}",
            slice.id,
            results.len(),
            hits,
            set.gate.floor
        );
        any = true;
    }
    if !any {
        return Err("no slices selected".into());
    }
    println!(
        "\nresults under {}",
        please_eval::cache::results_dir(run_label)?.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn write_report(
    run_label: &str,
    offline: bool,
    format: &str,
    out: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let report = assemble(run_label, offline)?;
    let rendered = match format {
        "md" | "markdown" => report.to_markdown(),
        "json" => serde_json::to_string_pretty(&report.to_json())?,
        other => return Err(format!("unknown --format {other:?}; expected md or json").into()),
    };
    match out {
        Some(path) => {
            std::fs::write(path, &rendered)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{rendered}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn check_gate(
    run_label: &str,
    offline: bool,
    strict: bool,
    allow_unpinned: bool,
) -> Result<ExitCode> {
    let report = assemble(run_label, offline)?;
    let gate = &report.gate;

    println!(
        "false-positive gate — criterion {}, floor `{}`",
        please_eval::metrics::pct(gate.max_fp_permille),
        report.floor
    );
    for slice in &gate.slices {
        println!(
            "  {:<24} {:>5}/{:<6} {:>7}   baseline {:<8} {}",
            slice.slice_id,
            slice.gated.hits,
            slice.gated.n,
            please_eval::metrics::pct(slice.permille),
            slice
                .baseline
                .map(please_eval::metrics::pct)
                .unwrap_or_else(|| "unpinned".to_string()),
            if slice.regressed {
                "REGRESSION"
            } else if !slice.criterion_met {
                "criterion not met (recorded)"
            } else {
                "ok"
            }
        );
    }
    if !gate.unpinned.is_empty() && !allow_unpinned {
        eprintln!(
            "\n{} gate-eligible slice(s) have no baseline_permille in corpus/slices.toml: {}.\nA slice \
             with no floor cannot detect a regression. Record today's rate there, or pass \
             --allow-unpinned for the run that establishes it.",
            gate.unpinned.len(),
            gate.unpinned.join(", ")
        );
    }

    if gate.failed(strict, allow_unpinned) {
        eprintln!("\ngate FAILED");
        return Ok(ExitCode::from(EXIT_GATE_FAILED));
    }
    println!("\ngate passed");
    Ok(ExitCode::SUCCESS)
}

/// Load a run's results and compute everything over them.
fn assemble(run_label: &str, offline: bool) -> Result<Report> {
    let set = SliceSet::load()?;
    let mut metrics = Vec::new();
    for slice in select(&set, &[], offline)? {
        let Ok(results) = scan::read_results(run_label, &slice.id) else {
            // A slice with no results is a slice this run did not scan — a `--offline` run, or a fetch
            // that has not happened. Skipped quietly here and visible by its absence from the report,
            // rather than failing a report over results the operator did not ask for.
            continue;
        };
        metrics.push(SliceMetrics::compute(slice, &results));
    }
    if metrics.is_empty() {
        return Err(format!(
            "no results under run `{run_label}`. Run `please-eval run --run {run_label}` first"
        )
        .into());
    }
    let gate = Gate::evaluate(&set, &metrics);

    // The rule set is re-derived rather than recorded in the results, so the digest in a report is the
    // digest of the rule set that is on disk NOW. That is the honest attribution: a report rendered
    // against a moved rule set should say so, and `run` is cheap enough to repeat.
    let engine = RuleSelection::default().engine()?;
    Ok(Report {
        run: run_label.to_string(),
        ruleset: RuleSelection::default().describe(),
        ruleset_digest: engine.ruleset_id().digest.clone(),
        floor: set.gate.floor.clone(),
        dataset: set.dataset.url(),
        metrics,
        gate,
    })
}

/// The slices a command should act on.
fn select<'a>(set: &'a SliceSet, wanted: &[String], offline: bool) -> Result<Vec<&'a Slice>> {
    if !wanted.is_empty() {
        return wanted.iter().map(|id| set.get(id)).collect();
    }
    Ok(if offline {
        set.offline().collect()
    } else {
        set.slices.iter().collect()
    })
}

/// Read a slice's rows, from the cache or from the committed corpora.
fn load_rows(slice: &Slice) -> Result<Vec<Row>> {
    match &slice.origin {
        Origin::Query { .. } => fetch::read_cache(&slice.id),
        Origin::Local { reader } => cases::read(*reader),
    }
}
