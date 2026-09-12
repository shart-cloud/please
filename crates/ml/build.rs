use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn collect(path: &Path, root: &Path, files: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("source directory") {
            collect(&entry.expect("source entry").path(), root, files);
        }
    } else {
        files.push(path.strip_prefix(root).expect("relative source").to_owned());
    }
}
fn main() {
    let manifest = std::path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap().parent().unwrap();
    let mut files = Vec::new();
    for name in ["ml", "core"] {
        let base = root.join("crates").join(name);
        println!("cargo:rerun-if-changed={}", base.join("src").display());
        collect(&base.join("src"), root, &mut files);
        files.push(
            base.join("Cargo.toml")
                .strip_prefix(root)
                .unwrap()
                .to_owned(),
        );
    }
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/eval/Cargo.lock",
        "crates/ml/build.rs",
    ] {
        files.push(path.into());
    }
    files.sort();
    let mut hash = Sha256::new();
    hash.update(b"please.inference-build.v1\0");
    let mut field = |key: &[u8], value: &[u8]| {
        for item in [key, value] {
            hash.update((item.len() as u64).to_be_bytes());
            hash.update(item);
        }
    };
    for path in files {
        let full = root.join(&path);
        println!("cargo:rerun-if-changed={}", full.display());
        field(
            path.to_string_lossy().as_bytes(),
            &fs::read(full).expect("build identity input"),
        );
    }
    let mut vars: Vec<_> = env::vars()
        .filter(|(k, _)| {
            k.starts_with("CARGO_FEATURE_")
                || k.starts_with("CARGO_CFG_")
                || [
                    "TARGET",
                    "PROFILE",
                    "OPT_LEVEL",
                    "DEBUG",
                    "CARGO_ENCODED_RUSTFLAGS",
                ]
                .contains(&k.as_str())
        })
        .collect();
    vars.sort();
    for (key, value) in vars {
        field(key.as_bytes(), value.as_bytes());
    }
    let rustc = std::process::Command::new(env::var_os("RUSTC").unwrap())
        .arg("-vV")
        .output()
        .expect("rustc version");
    assert!(rustc.status.success());
    field(b"rustc", &rustc.stdout);
    println!(
        "cargo:rustc-env=PLEASE_INFERENCE_BUILD={:x}",
        hash.finalize()
    );
}
