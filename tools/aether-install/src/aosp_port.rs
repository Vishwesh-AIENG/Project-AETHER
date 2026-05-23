// aosp_port.rs -- copy AETHER's AOSP device-port templates into an external
// AOSP checkout at `<aosp_root>/device/aether/arm64/` and
// `<aosp_root>/vendor/aether/`.
//
// Source tree (relative to this repo):
//   tools/aosp-device-port/device/aether/arm64/  -> <aosp_root>/device/aether/arm64/
//   tools/aosp-device-port/vendor/aether/        -> <aosp_root>/vendor/aether/
//
// Behaviour:
//   --apply       perform the recursive copy
//   without      print every file that would be written (dry run)
//
// The function returns a process exit code.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn prepare(aosp_root: &Path, apply: bool) -> i32 {
    println!("aether-install prepare-aosp-tree");
    println!("=================================");
    println!("aosp_root = {}", aosp_root.display());
    if !apply {
        println!("(dry-run -- pass --apply to perform the copy)");
    }
    println!();

    let manifest_dir = match locate_template_root() {
        Some(p) => p,
        None => {
            eprintln!(
                "error: cannot locate tools/aosp-device-port/ relative to the running binary or CWD."
            );
            return 2;
        }
    };

    if !aosp_root.is_dir() {
        eprintln!("error: aosp_root is not an existing directory: {}", aosp_root.display());
        return 2;
    }

    let mut copies: Vec<(PathBuf, PathBuf)> = Vec::new();
    let device_src = manifest_dir.join("device").join("aether").join("arm64");
    let device_dst = aosp_root.join("device").join("aether").join("arm64");
    let vendor_src = manifest_dir.join("vendor").join("aether");
    let vendor_dst = aosp_root.join("vendor").join("aether");

    if let Err(e) = walk_collect(&device_src, &device_dst, &mut copies) {
        eprintln!("error walking device template tree: {}", e);
        return 2;
    }
    if let Err(e) = walk_collect(&vendor_src, &vendor_dst, &mut copies) {
        eprintln!("error walking vendor template tree: {}", e);
        return 2;
    }

    if copies.is_empty() {
        eprintln!("error: no template files found under {}", manifest_dir.display());
        return 2;
    }

    println!("{} file(s) {}:", copies.len(), if apply { "to copy" } else { "would be copied" });
    for (src, dst) in &copies {
        let rel_dst = dst.strip_prefix(aosp_root).unwrap_or(dst.as_path());
        println!("  {} -> {}", src.display(), rel_dst.display());
    }

    if !apply {
        println!();
        println!("(dry-run; nothing written.)");
        return 0;
    }

    let mut written = 0usize;
    for (src, dst) in &copies {
        if let Some(parent) = dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("error: mkdir {}: {}", parent.display(), e);
                return 1;
            }
        }
        if let Err(e) = fs::copy(src, dst) {
            eprintln!("error: copy {} -> {}: {}", src.display(), dst.display(), e);
            return 1;
        }
        written += 1;
    }

    println!();
    println!("wrote {} file(s).", written);
    println!();
    println!("Next steps in the AOSP tree:");
    println!("  source build/envsetup.sh");
    println!("  lunch aether_arm64-user");
    println!("  m -j$(nproc)");
    0
}

fn walk_collect(src: &Path, dst: &Path, acc: &mut Vec<(PathBuf, PathBuf)>) -> io::Result<()> {
    if !src.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("template source not found: {}", src.display()),
        ));
    }
    if src.is_file() {
        acc.push((src.to_path_buf(), dst.to_path_buf()));
        return Ok(());
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = src.join(&name);
        let d = dst.join(&name);
        if s.is_dir() {
            walk_collect(&s, &d, acc)?;
        } else {
            acc.push((s, d));
        }
    }
    Ok(())
}

// Search for tools/aosp-device-port/ starting from CARGO_MANIFEST_DIR (test/dev),
// then from the current working directory walking upward (installed binary run
// from a repo checkout).
fn locate_template_root() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()? // tools/aether-install -> tools
            .parent()? // tools -> repo root
            .join("tools")
            .join("aosp-device-port"),
        std::env::current_dir().ok()?.join("tools").join("aosp-device-port"),
    ];
    for c in candidates {
        if c.join("AOSP_VERSION").is_file() {
            return Some(c);
        }
    }
    // Walk up from CWD looking for the marker.
    let mut cur = std::env::current_dir().ok()?;
    for _ in 0..6 {
        let probe = cur.join("tools").join("aosp-device-port");
        if probe.join("AOSP_VERSION").is_file() {
            return Some(probe);
        }
        cur = cur.parent()?.to_path_buf();
    }
    None
}
