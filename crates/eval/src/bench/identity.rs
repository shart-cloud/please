use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::Result;

pub const SHA256_LEN: usize = 64;

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn require_sha256(value: &str, field: &str) -> Result<()> {
    if !valid_sha256(value) {
        return Err(format!("{field} must be a lowercase SHA-256 digest").into());
    }
    Ok(())
}

pub fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

pub fn nonempty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty").into());
    }
    Ok(())
}

pub fn safe_relative(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{field} must be a non-empty relative path without traversal").into());
    }
    Ok(())
}

pub fn manifest_root(path: &Path) -> Result<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(Into::into)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[allow(clippy::manual_is_multiple_of)] // Keep the repository's Rust 1.85 MSRV.
pub fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err("hex input has an odd length".into());
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or("hex input contains a non-hex digit")?;
        let low = hex_nibble(pair[1]).ok_or("hex input contains a non-hex digit")?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn normalized_digest(bytes: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return sha256(bytes);
    };
    let normalized = text
        .nfkc()
        .flat_map(char::to_lowercase)
        .fold(
            (String::new(), false),
            |(mut output, spacing), character| {
                if character.is_whitespace() {
                    let has_content = !output.is_empty();
                    (output, has_content)
                } else {
                    if spacing {
                        output.push(' ');
                    }
                    output.push(character);
                    (output, false)
                }
            },
        )
        .0;
    sha256(normalized.trim().as_bytes())
}

pub fn display_text(value: &str) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .take(240)
        .collect()
}

/// Open a regular file without following a final symlink and verify the exact bytes read.
pub fn read_verified_file(
    path: &Path,
    expected_len: u64,
    expected_sha256: &str,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    require_sha256(expected_sha256, "file sha256")?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        return Err(format!("{} is not a regular non-symbolic file", path.display()).into());
    }
    if before.len() != expected_len {
        return Err(format!("{} byte length changed", path.display()).into());
    }
    if expected_len > max_bytes {
        return Err(format!("{} exceeds the configured input limit", path.display()).into());
    }

    let file = open_no_follow(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() || opened.len() != expected_len {
        return Err(format!("{} changed while it was being opened", path.display()).into());
    }
    let mut bytes = Vec::with_capacity(expected_len as usize);
    let mut limited: Take<File> = file.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_len || sha256(&bytes) != expected_sha256 {
        return Err(format!("{} does not match its declared identity", path.display()).into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(Into::into)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File> {
    OpenOptions::new().read(true).open(path).map_err(Into::into)
}

pub fn collect_regular_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(
                    format!("symbolic links are forbidden in assets: {}", path.display()).into(),
                );
            }
            if metadata.is_dir() {
                visit(root, &path, files)?;
            } else if metadata.file_type().is_file() {
                files.push(path.strip_prefix(root)?.to_path_buf());
            } else {
                return Err(
                    format!("special files are forbidden in assets: {}", path.display()).into(),
                );
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_digest_is_domain_separated() {
        let value = serde_json::json!({"b": 2, "a": 1});
        assert_eq!(
            canonical_digest("a", &value).unwrap(),
            canonical_digest("a", &value).unwrap()
        );
        assert_ne!(
            canonical_digest("a", &value).unwrap(),
            canonical_digest("b", &value).unwrap()
        );
    }

    #[test]
    fn normalization_collapses_case_width_and_spacing() {
        assert_eq!(
            normalized_digest("  ＩＧＮＯＲＥ\n rules ".as_bytes()),
            normalized_digest("ignore rules".as_bytes())
        );
    }

    #[test]
    fn hex_round_trips_arbitrary_bytes() {
        let bytes = [0, 10, 13, 255, b'{', b'\n'];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
    }
}
