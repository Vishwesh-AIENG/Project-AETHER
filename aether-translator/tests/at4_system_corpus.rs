//! AT-4 gate: decode every system / atomic / barrier instruction in a real
//! Linux GKI kernel + bionic shared libraries.
//!
//! Phase A skeleton: framework only.

use std::path::PathBuf;

#[test]
#[ignore = "AT-4 gate; un-ignore once branch_sys + LSE/LL-SC fills land"]
fn at4_vmlinux_zero_unknowns() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("corpus");
    p.push("vmlinux-gki.aarch64");
    if !p.exists() {
        eprintln!("AT-4 corpus vmlinux missing; place a decompressed GKI vmlinux here.");
        return;
    }
    let bytes = std::fs::read(&p).expect("read vmlinux");
    // Phase A uses whole-binary scan since vmlinux Image is raw .text-equivalent.
    let report = aether_translator::corpus::audit_text(&bytes, 0, &p);
    assert!(report.passes_at5(), "AT-4 vmlinux coverage failure");
}

#[test]
#[ignore = "AT-4 gate"]
fn at4_bionic_libc_zero_unknowns() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("corpus");
    p.push("libc.so.aarch64");
    if !p.exists() {
        eprintln!("AT-4 corpus libc.so.aarch64 missing.");
        return;
    }
    let bytes = std::fs::read(&p).expect("read libc");
    let report = aether_translator::corpus::audit_text(&bytes, 0, &p);
    assert!(report.passes_at5(), "AT-4 libc coverage failure");
}
