//! AT-5 gate: zero unknown encodings across the 21 AOT default libraries
//! from a real Android 14 GSI ARM64 system.img.
//!
//! Phase A skeleton: framework only. Run `scripts/fetch_gsi.sh` before
//! un-ignoring; corpus is gitignored.

use std::path::PathBuf;

const AOT_LIBS: &[&str] = &[
    "libc.so",
    "libm.so",
    "libdl.so",
    "libart.so",
    "libartbase.so",
    "libartpalette.so",
    "libhwui.so",
    "libgui.so",
    "libsurfaceflinger.so",
    "libui.so",
    "libbinder.so",
    "libbinder_ndk.so",
    "libutils.so",
    "libcutils.so",
    "libandroid_runtime.so",
    "libvulkan.so",
    "libEGL.so",
    "libGLESv2.so",
    "libsqlite.so",
    "libssl.so",
    "libcrypto.so",
];

#[test]
#[cfg_attr(not(feature = "linux_corpus"),
           ignore = "AT-5 gate: needs 21 AOT libs from a GSI extract; run \
                     scripts/fetch_gsi.sh then `cargo test --features linux_corpus`")]
fn at5_all_21_libs_zero_unknowns() {
    let mut base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.push("corpus");
    base.push("system_img");
    if !base.exists() {
        // Soft-skip in the corpus-gates CI lane when GSI fetch couldn't
        // complete (Android build ID rotated, network glitch, etc.). The
        // gate fails only when the corpus IS present and the decoder
        // misses encodings in it.
        eprintln!(
            "AT-5 corpus dir {} missing — run scripts/fetch_gsi.sh; skipping.",
            base.display()
        );
        return;
    }

    // Two-pass triage:
    //   1. Count how many libs are actually present. If ZERO are present
    //      the corpus dir was created but never populated (incomplete
    //      fetch — GSI rotated, network glitch, etc.); soft-skip the
    //      gate as we cannot audit what isn't there.
    //   2. If at least one lib is present, run the audit. A partial
    //      extract still fails — the operator should re-run fetch_gsi.
    let present: Vec<&&str> = AOT_LIBS.iter().filter(|l| base.join(l).exists()).collect();
    if present.is_empty() {
        eprintln!(
            "AT-5: corpus dir {} is empty (likely incomplete fetch_gsi.sh); skipping.",
            base.display()
        );
        return;
    }
    let mut failures = Vec::new();
    for lib in AOT_LIBS {
        let p = base.join(lib);
        if !p.exists() {
            failures.push(format!("missing: {}", lib));
            continue;
        }
        let bytes = std::fs::read(&p).expect("read lib");
        let report = aether_translator::corpus::audit_text(&bytes, 0, &p);
        if !report.passes_at5() {
            failures.push(format!(
                "{}: unknown={} unimpl={} unlifted={} decode_err={}",
                lib,
                report.unknown.len(),
                report.unimplemented.len(),
                report.decoded_but_unlifted,
                report.decode_errors,
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "AT-5 gate failures ({} of {} libs present):\n{}",
        present.len(),
        AOT_LIBS.len(),
        failures.join("\n")
    );
}
