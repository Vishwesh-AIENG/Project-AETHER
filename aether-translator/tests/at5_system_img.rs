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
#[ignore = "AT-5 gate; run scripts/fetch_gsi.sh first, then un-ignore"]
fn at5_all_21_libs_zero_unknowns() {
    let mut base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.push("corpus");
    base.push("system_img");
    assert!(
        base.exists(),
        "AT-5 corpus dir missing — run scripts/fetch_gsi.sh"
    );

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
        "AT-5 gate failures:\n{}",
        failures.join("\n")
    );
}
