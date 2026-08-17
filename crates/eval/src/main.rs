//! `please-eval` — the evaluation harness's command line.
//!
//! Six subcommands, in the order a run uses them:
//!
//! ```text
//! please-eval generate            build the span-labelled corpus (no network)
//! please-eval fetch               materialise the public slices into the cache (needs `hf`)
//! please-eval manifest --check    verify the cache against the committed manifests
//! please-eval run                 scan every slice
//! please-eval report              per-source stratified metrics
//! please-eval gate                the false-positive gate, as an exit code
//! ```
//!
//! `run`, `report` and `gate` all take `--offline`, which restricts them to the committed corpora.
//! That is the configuration CI uses, and `README.md` states plainly what it proves and what it does
//! not: the gate over hand-written negatives, generated matched carriers and this repository's own
//! prose is real, and the public-corpus half needs an approved dataset gate and a human.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use please_eval::metrics::{parse_floor, Gate, Report, SliceMetrics};
use please_eval::rows::Row;
use please_eval::scan::RuleSelection;
use please_eval::slice::{Origin, Slice, SliceSet};
use please_eval::{cases, fetch, generate, manifest, scan, Result};

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
