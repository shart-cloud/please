//! Reading what to scan (FR-026, FR-032a).
//!
//! All the I/O lives here, because the core does none: it takes bytes. That split is what lets the same
//! engine run in a browser, and it means the unreadable-target case is *this* module's responsibility.
//!
//! # An unreadable file is inconclusive, not an error
//!
//! During a directory walk, a file that cannot be read produces an inconclusive verdict for that target and
//! the walk continues (FR-032a). Not a usage error, because one locked file must not suppress findings in
//! the hundreds beside it; and not a silent skip, because a file nobody examined must not be absorbed into
//! a clean summary. That is the FR-004 fail-open reproduced one level up.
//!
//! # Deciding what to scan, and reading it, are two phases
//!
//! [`plan`] enumerates targets and reads **no content**; [`load`] reads exactly one target's bytes. They
//! were one function returning `Vec<Target>`, which meant a directory walk held every file's contents in
//! memory before the first scan ran — peak memory tracked the corpus, and `contracts/cli.md` promises
//! *"no input causes a crash, a hang, or unbounded memory"*. Split, the caller loads, scans, renders and
//! drops one target at a time, so what is resident is the largest single file rather than the sum.
//!
//! The path list is still built eagerly, and deliberately: a `PathBuf` is a couple of hundred bytes against
//! a file's kilobytes-to-megabytes, and materialising it is what lets the walk be sorted once — which is
//! what makes output reproducible (SC-011) and what tells the JSON renderer whether it is writing an object
//! or an array before the first verdict exists.

use std::io::Read;
use std::path::{Path, PathBuf};

use please_core::verdict::TargetRef;

/// One thing to scan, named but not yet read.
///
/// Ordered by path, and carries the spelling the caller used alongside it — output must not vary with the
/// working directory it was produced from (SC-011), so the path is never absolutised.
pub enum Source {
    /// Standard input.
    Stdin,
    /// A file to read.
    File { path: PathBuf, as_given: String },
    /// A symbolic link to a directory, which the walk refuses to follow. See [`walk`].
    NotTraversed { path: PathBuf, as_given: String },
}

/// Something to scan, or a reason it could not be examined.
pub enum Target {
    /// Content read successfully.
    Content {
        bytes: Vec<u8>,
        reference: TargetRef,
    },
    /// A path that exists in the walk but could not be read.
    Unreadable {
        reference: TargetRef,
        detail: String,
    },
    /// A path that was read successfully but is not decodable text.
    ///
    /// Distinct from [`Target::Unreadable`] because the read worked. The bytes are here and we declined
    /// to hand them to a text analyser, which sends a reader somewhere different from a permissions
    /// problem — the same distinction [`Target::NotTraversed`] draws for a different reason.
    NotText {
        reference: TargetRef,
        detail: String,
    },
    /// A path the walk deliberately did not descend into.
    ///
    /// Distinct from [`Target::Unreadable`] because the difference is true: a symlinked directory is
    /// perfectly readable and we declined to follow it. Reporting that as unreadable would send whoever
    /// reads the verdict to look for a permissions problem that does not exist.
    NotTraversed {
        reference: TargetRef,
        detail: String,
    },
}

/// Read a rule-set file for `--rules` (FR-023).
///
/// Here rather than in `main.rs` because this module owns the filesystem: the core takes text, never a path
/// (`Ruleset::from_toml`), so somebody has to open the file and it may as well be the one place that already
/// does.
///
/// **Deliberately not [`read_file`]**, and the difference is the whole point. That function maps a read
/// failure to `Target::Unreadable`, which becomes an inconclusive verdict and lets the walk continue — right
/// for one locked file among hundreds, wrong here. A `--rules` path that cannot be read is an invocation
/// fault: the scan the operator asked for cannot be performed at all, and reporting it as inconclusive
/// coverage would describe the wrong thing. It is exit 64 (`contracts/cli.md`).
pub fn read_rules(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read rule set {}: {e}", path.display()))
}

/// Enumerate what will be scanned, in a deterministic order, **without reading any of it**.
///
/// An empty list, or `-`, means standard input, so `... | plz scan` works as a filter.
///
/// Errors here are invocation faults and abort the run (exit 64). Failures that belong to one target — a
/// file that cannot be opened, a link that will not be followed — are not errors: they surface as verdicts
/// from [`load`], so the walk continues and the target is still reported.
pub fn plan(targets: &[String]) -> Result<Vec<Source>, String> {
    if targets.is_empty() {
        return Ok(vec![Source::Stdin]);
    }

    let mut out = Vec::new();
    for raw in targets {
        if raw == "-" {
            out.push(Source::Stdin);
            continue;
        }
        let path = Path::new(raw);
        if !path.exists() {
            // An invocation fault, unlike a file that exists and cannot be read: the caller named
            // something that is not there, so there is nothing to be inconclusive about.
            return Err(format!("no such file or directory: {raw}"));
        }
        if path.is_dir() {
            // `is_dir` follows links, and that is right *here*: a link named on the command line was named
            // deliberately, and refusing to walk what the operator explicitly asked for would be obtuse.
            // Inside the walk the judgement is the opposite one — see [`walk`].
            out.extend(walk(path)?.into_iter().map(|found| found.into_source(raw)));
        } else {
            out.push(Source::File {
                path: path.to_path_buf(),
                as_given: raw.clone(),
            });
        }
    }
    Ok(out)
}

/// Read one target's content.
///
/// The counterpart to [`plan`]: called once per source, immediately before that target is scanned, so the
/// bytes can be dropped as soon as its verdict is rendered.
pub fn load(source: &Source) -> Result<Target, String> {
    match source {
        Source::Stdin => read_stdin(),
        Source::File { path, as_given } => Ok(read_file(path, as_given)),
        // Reported rather than skipped, for the same reason an unreadable file is (FR-032a): a directory
        // summarised as clean on the strength of a subtree nobody looked at is the fail-open one level up.
        Source::NotTraversed { path, as_given } => {
            let display = display_name(path, as_given);
            Ok(Target::NotTraversed {
                reference: TargetRef::path(display, 0),
                detail: "symbolic link to a directory; not followed".to_string(),
            })
        }
    }
}

fn read_stdin() -> Result<Target, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read standard input: {e}"))?;
    let reference = TargetRef::stdin(bytes.len());
    // Applied to stdin as well as to files. `curl … | plz scan` is an advertised way to use this tool and
    // is exactly as capable of delivering a PDF as a walk is. The cost is that text in a non-UTF-8 legacy
    // encoding is declined rather than scanned — recorded in `docs/limits.md`, and it fails to
    // inconclusive rather than to clean, which is the direction Principle I requires it to fail in.
    match is_text(&bytes) {
        Ok(()) => Ok(Target::Content { bytes, reference }),
        Err(detail) => Ok(Target::NotText { reference, detail }),
    }
}

/// Read one file, preserving the path exactly as the caller wrote it.
fn read_file(path: &Path, as_given: &str) -> Target {
    let display = display_name(path, as_given);

    match std::fs::read(path) {
        Ok(bytes) => {
            let reference = TargetRef::path(display, bytes.len());
            match is_text(&bytes) {
                Ok(()) => Target::Content { bytes, reference },
                Err(detail) => Target::NotText { reference, detail },
            }
        }
        Err(e) => Target::Unreadable {
            reference: TargetRef::path(display, 0),
            detail: e.to_string(),
        },
    }
}

/// How a path is named in output.
///
/// Never absolutised: output must not vary with the working directory it was produced from (SC-011).
/// Is this content decodable text?
///
/// # Why UTF-8 validity plus a NUL check, and not a heuristic
///
/// The tempting version counts printable bytes and guesses. It is the wrong instrument here, and the
/// reason is the population it would guess wrong about: dense non-English prose. This project has spent
/// more effort than anything else on not harming non-English users — the confusable analysis exists
/// partly for it, and the multilingual false-positive rate is one of the few numbers it can defend. A
/// byte-frequency test on UTF-8 Japanese or Arabic sees a great many bytes above 0x7F and, tuned by
/// anyone reasoning from English, calls it binary. The file would then be reported as unexaminable, which
/// is a quieter version of the same harm.
///
/// UTF-8 validity is not a guess. Text that decodes is text.
///
/// The NUL check is the second half, and it is what the measurements needed. A Windows
/// `Zone.Identifier` alternate data stream is *valid UTF-8* — `[ZoneTransfer]\r\nZoneId=3\0` — and
/// scored 80 on `concealment.control_characters` for its single trailing NUL. A NUL byte does not occur
/// in text anyone wrote; it occurs in text something padded.
///
/// # What this deliberately does not do
///
/// It does not extract text from a PDF, and a PDF can certainly carry a payload. Declining to parse one
/// is a scope boundary, not a solved problem, and `docs/limits.md` records it as one.
fn is_text(bytes: &[u8]) -> Result<(), String> {
    if bytes.contains(&0) {
        return Err("contains NUL bytes; not decodable text".to_string());
    }
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("not valid UTF-8 at byte {}", e.valid_up_to())),
    }
}

fn display_name(path: &Path, as_given: &str) -> String {
    if path.as_os_str() == as_given {
        as_given.to_string()
    } else {
        path.to_string_lossy().into_owned()
    }
}

/// One thing the walk found, and what kind of thing it was.
enum Found {
    File(PathBuf),
    SymlinkedDirectory(PathBuf),
}

impl Found {
    fn into_source(self, as_given: &str) -> Source {
        match self {
            Self::File(path) => Source::File {
                path,
                as_given: as_given.to_string(),
            },
            Self::SymlinkedDirectory(path) => Source::NotTraversed {
                path,
                as_given: as_given.to_string(),
            },
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::File(p) | Self::SymlinkedDirectory(p) => p,
        }
    }
}

/// Everything under `root` worth reporting, sorted.
///
/// Sorted so repeated runs produce identical output (SC-011) — a directory walk's natural order is
/// filesystem-dependent, which would make the same tree yield different reports on different machines.
///
/// A directory that cannot be listed is reported as an error rather than skipped: unlike a single
/// unreadable file, an unlistable directory means an unknown number of unexamined targets, and there is
/// nothing to attach an inconclusive verdict to.
///
/// # Symbolic links to directories are not followed
///
/// The type comes from [`std::fs::DirEntry::file_type`], which — unlike `Path::is_dir` — does **not**
/// follow links. It costs no extra syscall on any platform that returns the type from `readdir`.
///
/// This walk used to test `path.is_dir()`, which follows them, so a link to an ancestor was re-descended.
/// The kernel bounds any *single* path chain at `ELOOP` — about forty links — so **one** such link merely
/// produced forty levels of duplicate targets and a wrong exit code. **Two** in the same directory
/// produce two-to-the-fortieth paths, and the walk does not return: measured at thirty seconds with no
/// output, against a directory holding one file and two links. That is the hang `contracts/cli.md`
/// promises cannot happen, and it is why the ELOOP backstop is not a defence.
///
/// Refusing to descend removes it without canonicalising anything or carrying a visited set.
///
/// The refusal is **reported**, never silent — a link becomes an inconclusive verdict naming it. Skipping
/// it would let a tree whose real content sits behind a symlink summarise as clean, which is the FR-032a
/// fail-open one level up. A link to a *regular file* is followed normally: it cannot cycle, and reading
/// through it is what anyone would expect.
fn walk(root: &Path) -> Result<Vec<Found>, String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?;
        // Sorted at each level as well as globally below. The global sort is what fixes the reported
        // order; this one only keeps the traversal itself deterministic, which matters for the error
        // above — which unlistable directory is hit first should not depend on the filesystem.
        let mut level: Vec<(PathBuf, std::fs::FileType)> = entries
            .filter_map(Result::ok)
            // A `file_type` that fails is a target we cannot classify, so it is treated as a file: `load`
            // will attempt the read and report an unreadable target if that fails too. Dropping it is the
            // one thing that must not happen.
            .filter_map(|entry| {
                let kind = entry.file_type().ok()?;
                Some((entry.path(), kind))
            })
            .collect();
        level.sort_by(|a, b| a.0.cmp(&b.0));

        for (path, kind) in level {
            if kind.is_symlink() {
                // Only a link to a directory can cycle, so only that is refused. `path.is_dir()` here
                // resolves the link on purpose — the question being asked is what it points at.
                if path.is_dir() {
                    found.push(Found::SymlinkedDirectory(path));
                } else {
                    found.push(Found::File(path));
                }
            } else if kind.is_dir() {
                stack.push(path);
            } else {
                found.push(Found::File(path));
            }
        }
    }

    found.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(found)
}
