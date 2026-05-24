//! AT-5 corpus run against a real ARM64 binary we already have on-hand:
//! AETHER's own `hypervisor.efi` (PE32+ AArch64 — built by `cargo build
//! --target aarch64-unknown-uefi -p hypervisor`).
//!
//! This is not an Android GSI library, but it IS real production ARM64
//! machine code from a Rust compile of substantive logic (decoders,
//! page-table setup, GIC interaction, virtio glue, etc.). It exercises
//! enough of the encoding space to be a useful gate.
//!
//! When GSI corpora become available, the dedicated Android-lib gates in
//! `at5_system_img.rs` take over; this file remains as a "always-on"
//! coverage check against a binary the repo can produce locally.

use std::path::PathBuf;

#[test]
fn at5_audit_aether_arm64_efi() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // -> repo root
    p.push("target");
    p.push("aarch64-unknown-uefi");
    p.push("release");
    p.push("hypervisor.efi");
    if !p.exists() {
        eprintln!(
            "AT-5 aether-efi corpus skipped: build it first with\n  cargo +nightly build -Z build-std=core,compiler_builtins \\\n    -Z build-std-features=compiler-builtins-mem \\\n    --release --target aarch64-unknown-uefi -p hypervisor\n  (file expected at: {})",
            p.display()
        );
        return;
    }
    let bytes = std::fs::read(&p).expect("read hypervisor.efi");
    let text = aether_translator::corpus::extract_text(&bytes)
        .expect("extract .text from hypervisor.efi");
    eprintln!(
        ".text section: {} bytes ({} instructions)",
        text.len(),
        text.len() / 4
    );
    let report = aether_translator::corpus::audit_text(&text, 0, &p);
    eprintln!(
        "AT-5 aether-efi audit: total={} lifted={} unknown={} unimpl={} decoded_unlifted={} decode_err={}",
        report.total_words,
        report.lifted,
        report.unknown.len(),
        report.unimplemented.len(),
        report.decoded_but_unlifted,
        report.decode_errors,
    );
    // Re-scan to dump first few decode errors (rejected as Reserved/Unimplemented).
    // These aren't "unknown" per spec but may indicate over-tight validation
    // worth investigating in a follow-up prompt.
    let mut err_samples = Vec::new();
    for (i, chunk) in text.chunks_exact(4).enumerate() {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        match aether_translator::decoder::decode_instruction(w) {
            Err(e) => {
                if err_samples.len() < 5 {
                    err_samples.push(format!("  +{:#06x}: {:08x} -> {:?}", i * 4, w, e));
                }
            }
            _ => {}
        }
    }
    if !err_samples.is_empty() {
        eprintln!("First decode errors (review for over-tight validation):");
        for s in &err_samples {
            eprintln!("{}", s);
        }
    }

    // Strict gate: zero Unknown encodings. The decoder should at least
    // classify every word as a recognised instruction (decoded-but-not-lifted
    // is fine for Phase A since lift is deferred).
    if !report.unknown.is_empty() {
        let preview: Vec<String> = report
            .unknown
            .iter()
            .take(10)
            .map(|(off, w)| format!("  +{:#06x}: {:08x}", off, w))
            .collect();
        panic!(
            "{} unknown encodings in hypervisor.efi .text (showing first 10):\n{}",
            report.unknown.len(),
            preview.join("\n")
        );
    }
}
