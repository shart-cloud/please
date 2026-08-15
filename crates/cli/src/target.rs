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

use std::io::Read;
use std::path::{Path, PathBuf};

use please_core::verdict::TargetRef;

/// Something to scan, or a reason it could not be read.
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
}

/// Resolve command-line targets into readable content, in a deterministic order.
///
/// An empty list, or `-`, means standard input, so `... | plz scan` works as a filter.
pub fn resolve(targets: &[String]) -> Result<Vec<Target>, String> {
    if targets.is_empty() {
        return Ok(vec![read_stdin()?]);
    }

    let mut out = Vec::new();
    for raw in targets {
        if raw == "-" {
            out.push(read_stdin()?);
            continue;
        }
        let path = Path::new(raw);
        if !path.exists() {
            // An invocation fault, unlike a file that exists and cannot be read: the caller named
            // something that is not there, so there is nothing to be inconclusive about.
            return Err(format!("no such file or directory: {raw}"));
        }
        if path.is_dir() {
            for file in walk(path)? {
                out.push(read_file(&file, raw));
            }
        } else {
            out.push(read_file(path, raw));
        }
    }
    Ok(out)
}

fn read_stdin() -> Result<Target, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read standard input: {e}"))?;
    let reference = TargetRef::stdin(bytes.len());
    Ok(Target::Content { bytes, reference })
}

/// Read one file, preserving the path exactly as the caller wrote it.
///
/// Never absolutised: output must not vary with the working directory it was produced from (SC-011).
fn read_file(path: &Path, as_given: &str) -> Target {
    let display = if path.as_os_str() == as_given {
        as_given.to_string()
    } else {
        path.to_string_lossy().into_owned()
    };

    match std::fs::read(path) {
        Ok(bytes) => {
            let reference = TargetRef::path(display, bytes.len());
            Target::Content { bytes, reference }
        }
        Err(e) => Target::Unreadable {
            reference: TargetRef::path(display, 0),
            detail: e.to_string(),
        },
    }
}

/// Every regular file under `root`, sorted.
///
/// Sorted so repeated runs produce identical output (SC-011) — a directory walk's natural order is
/// filesystem-dependent, which would make the same tree yield different reports on different machines.
///
/// A directory that cannot be listed is reported as an error rather than skipped: unlike a single
/// unreadable file, an unlistable directory means an unknown number of unexamined targets, and there is
/// nothing to attach an inconclusive verdict to.
fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?;
        let mut level: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        level.sort();
        for path in level {
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }

    found.sort();
    Ok(found)
}
