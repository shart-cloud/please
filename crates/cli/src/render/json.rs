//! Machine-readable output (FR-027, US2, 001 T070).
//!
//! This is what US2 is *for*: an agent harness reads it, applies its own policy, and decides whether to
//! proceed. It is the product's main distribution path, because it is how the engine reaches agents that
//! are not written in Rust.
//!
//! # This is a contract, not a rendering
//!
//! The shape is `specs/001-structural-detection-cli/contracts/verdict.schema.json`, and
//! `crates/cli/tests/contract.rs` validates real output against that file on every run. Breaking it is a
//! major version change (`contracts/cli.md`).
//!
//! Almost nothing happens here, and that is deliberate: the shape lives on the core types, next to the
//! fields it describes, so a renamed field is caught by the schema test rather than silently changing the
//! API. This module decides only **how many verdicts are in the document**.
//!
//! # One target is an object; many are an array
//!
//! ```sh
//! plz scan --format json note.md   | jq .outcome     # object
//! plz scan --format json ./skills/ | jq 'length'     # array
//! ```
//!
//! Following `quickstart.md`, which pipes a single file's output straight to `jq .ruleset` and a walked
//! directory's to an array consumer. The alternative — always an array — would be more uniform and would
//! make the overwhelmingly common case (`plz scan one-file`) require `.[0]` for no reason.
//!
//! There is **no summary object**. For several targets the answer is the array plus the exit code, which is
//! derived by the same `risk_found > inconclusive > clean` precedence a single verdict uses (FR-032b). A
//! summary field would be a second place for that precedence to live, and the two would eventually
//! disagree.
//!
//! # What is absent, on purpose
//!
//! **No timestamp** and **no absolutised path** (`cli.md`, SC-011). Either would make byte-identical repeat
//! output impossible, which is what lets a caller cache a verdict and diff it in CI — and the caller
//! already knows when they ran the scan and from where.

//! # Written incrementally
//!
//! Each verdict reaches stdout as it is produced, rather than being collected and rendered at the end.
//! That is what bounds `plz`'s memory to the largest single target instead of the whole corpus
//! (`cli.md`: *"no input causes a crash, a hang, or unbounded memory"*).
//!
//! It costs the convenience of `to_string_pretty(&verdicts)`: the array framing is written by hand here.
//! The output is **byte-identical** to what that call produced, which is not a coincidence to be trusted —
//! `tests/streaming.rs::streamed_json_is_byte_identical_to_the_batched_document` compares the two.

use std::io::Write;

use please_core::Verdict;

/// Machine-readable output, one verdict at a time.
///
/// `many` is fixed at construction from the **target count**, before a single byte of any target has been
/// read. That is what keeps "one target is an object, many are an array" decidable in a streaming writer:
/// by the time the first verdict exists the document's shape is already known, so nothing has to be
/// buffered to find out whether a second one is coming.
pub struct Emitter {
    many: bool,
    /// Whether anything has been written yet — drives `[` versus `,`, and distinguishes an empty run.
    first: bool,
}

impl Emitter {
    pub fn new(targets: usize) -> Self {
        Self {
            many: targets != 1,
            first: true,
        }
    }

    /// Write one verdict into the document.
    pub fn verdict<W: Write>(&mut self, w: &mut W, v: &Verdict) -> std::io::Result<()> {
        // Serialising a `Verdict` cannot fail: every field is a plain owned value, there is no map with
        // non-string keys, and no `Serialize` impl in this project returns an error. So this arm is
        // unreachable — but it is a `Result`, and the one thing that must never happen is a half-written
        // document on stdout that a caller parses as truth. Skipping the element and letting the caller's
        // parse fail is the safe direction.
        let body = match serde_json::to_string_pretty(v) {
            Ok(body) => body,
            Err(e) => {
                debug_assert!(false, "a verdict failed to serialise: {e}");
                eprintln!("plz: internal: a verdict failed to serialise: {e}");
                return Ok(());
            }
        };

        if !self.many {
            self.first = false;
            return w.write_all(body.as_bytes());
        }

        if self.first {
            w.write_all(b"[\n")?;
            self.first = false;
        } else {
            w.write_all(b",\n")?;
        }
        indented(w, &body)
    }

    /// Close the document.
    pub fn finish<W: Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        match (self.many, self.first) {
            // A single target whose verdict was written: it is a bare object and needs only the newline.
            (false, false) => w.write_all(b"\n"),
            // A single target that produced nothing — only reachable through the unreachable arm above.
            // Emitting nothing beats emitting a lone newline a caller would try to parse.
            (false, true) => Ok(()),
            // No targets at all: a walked directory containing no files. `[]`, as before.
            (true, true) => w.write_all(b"[]\n"),
            (true, false) => w.write_all(b"\n]\n"),
        }
    }
}

/// Write `body` with every line indented two spaces, and no trailing newline.
///
/// Two spaces because that is `serde_json`'s pretty indent, so an element written here sits at exactly the
/// depth `to_string_pretty` on the enclosing `Vec` would have put it. The trailing newline is the caller's,
/// since what follows is either `,` or the closing bracket.
fn indented<W: Write>(w: &mut W, body: &str) -> std::io::Result<()> {
    let mut lines = body.lines();
    if let Some(line) = lines.next() {
        w.write_all(b"  ")?;
        w.write_all(line.as_bytes())?;
    }
    for line in lines {
        w.write_all(b"\n  ")?;
        w.write_all(line.as_bytes())?;
    }
    Ok(())
}
