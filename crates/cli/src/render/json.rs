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

use please_core::Verdict;

/// Render every verdict as one JSON document.
///
/// Pretty-printed rather than compact. The reader is as often a person running `plz scan --format json | less`
/// while debugging a hook as it is `jq`, and `jq` does not care either way. Both are deterministic;
/// `serde_json` writes struct fields in declaration order and every collection in a verdict is a `Vec`, so
/// there is no map iteration order to vary.
pub fn render(out: &mut String, verdicts: &[Verdict]) {
    let document = match verdicts {
        [single] => serde_json::to_string_pretty(single),
        many => serde_json::to_string_pretty(many),
    };

    match document {
        Ok(json) => {
            out.push_str(&json);
            out.push('\n');
        }
        // Serialising a `Verdict` cannot fail: every field is a plain owned value, there is no map with
        // non-string keys, and no `Serialize` impl in this project returns an error. Writing into a
        // `String` cannot fail either. So this arm is unreachable — but it is a `Result`, and the one
        // thing that must never happen is a half-written document on stdout that a caller parses as
        // truth. Emitting nothing and letting the caller's parse fail is the safe direction.
        Err(e) => {
            debug_assert!(false, "a verdict failed to serialise: {e}");
            eprintln!("plz: internal: a verdict failed to serialise: {e}");
        }
    }
}
