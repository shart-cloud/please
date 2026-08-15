//! Neutralise untrusted text before it is reproduced in a report or a log (FR-021).
//!
//! Every excerpt the scanner quotes came from an attacker, and a terminal treats text as a command
//! language. `ESC [ 2 J` clears the screen; `\r` rewrites the line just printed; a bidi override
//! reorders characters after they are drawn. So an unsanitised excerpt lets a payload forge or erase
//! the very report that is exposing it — and the most valuable line to forge is the one saying a file
//! is clean.
//!
//! Sanitisation happens at the boundary where a [`crate::finalize::types::Reason`] is built, not at each
//! display site, so the guarantee holds for every consumer including the ones that forget. The
//! ordering is the whole design: **sanitise the payload, then style it.** Never the reverse — colour
//! codes added by the harness are applied to already-clean text.
//!
//! Escapes are rendered in their textual Rust form (`\x1b`, `\u{202e}`): plain ASCII, unambiguous,
//! legible in a log or a screenshot, and dependent on no font or Unicode picture glyph.
//!
//! # What is escaped, and what is deliberately not
//!
//! Escaped: C0 controls and DEL, the C1 range, zero-width and directional marks, bidi embeddings and
//! isolates, word joiner and invisible operators, the byte-order mark, the Mongolian vowel separator,
//! **the Unicode Tags block**, and **variation selectors**.
//!
//! Those last two matter because they are where most sanitizers stop short. The Tags block
//! (U+E0000–U+E007F) renders as nothing in essentially every interface, needs no terminator, and is
//! understood by models because it appears in training data — it is the current state of the art in
//! invisible prompt injection. Variation selectors can smuggle arbitrary bytes using two invisible
//! characters.
//!
//! **Not** escaped: ordinary international text. Accented Latin, Chinese, Arabic, Cyrillic, Japanese,
//! and emoji pass through byte-identical. Mangling them would break the tool for most of the world's
//! text, and the evaluation corpus cannot warn us about that failure — it holds roughly 79,000
//! non-English benign rows and zero non-English attacks, so the damage would appear only in
//! production.

/// True if `c` would be interpreted rather than drawn.
fn is_dangerous(c: char) -> bool {
    matches!(c,
        // C0 controls and DEL, then the C1 range some terminals read as CSI/OSC introducers.
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'
        // Zero-width characters and directional marks.
        | '\u{200b}'..='\u{200f}'
        // Bidi embeddings and overrides (Trojan Source, CVE-2021-42574).
        | '\u{202a}'..='\u{202e}'
        // Word joiner and invisible mathematical operators.
        | '\u{2060}'..='\u{2064}'
        // Bidi isolates.
        | '\u{2066}'..='\u{2069}'
        // Byte-order mark / zero-width no-break space.
        | '\u{feff}'
        // Mongolian vowel separator.
        | '\u{180e}'
        // Variation selectors, and their supplement.
        | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}'
        // Unicode Tags block.
        | '\u{e0000}'..='\u{e007f}'
    )
}

/// Render one dangerous character as its textual escape.
fn escape(c: char, out: &mut String) {
    match c {
        // ASCII controls and DEL read best as the byte escape an author would type.
        '\u{0}'..='\u{1f}' | '\u{7f}' => {
            out.push_str(&format!("\\x{:02x}", c as u32));
        }
        _ => {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        }
    }
}

/// Sanitise text, capping the **output** at `max_bytes`.
///
/// Returns the sanitised text and whether the cap truncated it. Truncation is reported rather than silent
/// because a limit the reader cannot see reads as complete coverage.
///
/// The boolean stays a boolean, and this function does **not** record a coverage gap itself, which is worth
/// justifying since T022 and T021 moved gap recording into the decoder and the matcher. Those two knew
/// *why* their bound mattered; this one does not. It shortens a string and has no idea whose excerpt it is
/// or what the bound is called, so a gap constructed here would carry no detail worth reading. Its single
/// caller — `finalize::into_reason` — knows both, and records it there (FR-122).
///
/// Truncation never splits a character and never splits an escape sequence: a half-written `\u{202`
/// in a log is both unreadable and a misrepresentation of what was found.
pub fn sanitize_str(input: &str, max_bytes: usize) -> (String, bool) {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut truncated = false;

    for c in input.chars() {
        // Build each unit separately so the cap is applied to whole units only.
        let mut unit = String::new();
        if is_dangerous(c) {
            escape(c, &mut unit);
        } else {
            unit.push(c);
        }

        if out.len() + unit.len() > max_bytes {
            truncated = true;
            break;
        }
        out.push_str(&unit);
    }

    (out, truncated)
}

/// Sanitise bytes that may not be valid UTF-8, capping the output at `max_bytes`.
///
/// Invalid sequences are escaped byte-by-byte as `\xNN` rather than rejected or replaced with a
/// substitution character. Scan targets are bytes and frequently are not valid text — a truncated tool
/// result, a binary file, a deliberately malformed encoding. "This was not valid text" is a fact worth
/// reporting, not a reason to refuse to look (FR-019).
pub fn sanitize_bytes(input: &[u8], max_bytes: usize) -> (String, bool) {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut truncated = false;
    let mut rest = input;

    // `from_utf8` reports how far it got and how many bytes were bad, so decoding can resume after an
    // invalid run rather than abandoning the remainder.
    loop {
        if rest.is_empty() {
            break;
        }
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                let (chunk, chunk_truncated) =
                    sanitize_str(valid, max_bytes.saturating_sub(out.len()));
                out.push_str(&chunk);
                truncated |= chunk_truncated;
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                if good > 0 {
                    // SAFETY-free: `valid_up_to` guarantees this prefix is valid UTF-8.
                    let valid = std::str::from_utf8(&rest[..good]).expect("valid_up_to prefix");
                    let (chunk, chunk_truncated) =
                        sanitize_str(valid, max_bytes.saturating_sub(out.len()));
                    out.push_str(&chunk);
                    if chunk_truncated {
                        return (out, true);
                    }
                }

                let bad_len = e.error_len().unwrap_or(rest.len() - good);
                for &byte in &rest[good..good + bad_len] {
                    let unit = format!("\\x{byte:02x}");
                    if out.len() + unit.len() > max_bytes {
                        return (out, true);
                    }
                    out.push_str(&unit);
                }

                let consumed = good + bad_len;
                if consumed >= rest.len() {
                    break;
                }
                rest = &rest[consumed..];
            }
        }
    }

    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_ranges_are_recognised() {
        for c in [
            '\u{1b}', '\u{200b}', '\u{202e}', '\u{2060}', '\u{feff}', '\u{180e}',
        ] {
            assert!(is_dangerous(c), "{c:?} should be dangerous");
        }
        for c in ['\u{fe00}', '\u{e0100}', '\u{e0041}'] {
            assert!(is_dangerous(c), "{:x} should be dangerous", c as u32);
        }
    }

    #[test]
    fn ordinary_text_is_not_dangerous() {
        for c in ['a', 'Z', '9', ' ', 'é', '中', 'م', '🔥'] {
            assert!(!is_dangerous(c), "{c:?} should be ordinary");
        }
    }

    #[test]
    fn cap_of_zero_yields_empty_and_truncated() {
        let (out, truncated) = sanitize_str("abc", 0);
        assert!(out.is_empty());
        assert!(truncated);
    }
}
