// Build script for the AETHER hypervisor crate.
//
// Wires libfex.a (FEX-Emu ARM64→x86_64 dynamic binary translator) into the
// x86_64-unknown-uefi build of hypervisor.efi. Active only when both:
//   * target == x86_64-unknown-uefi
//   * --features fex_linked
//
// Otherwise this script is a no-op. In particular, the aarch64 UEFI build,
// the host `cargo test --lib` build, and `cargo check` without the feature
// all skip every directive below — `fex_integration.rs` ships compile-time
// stubs (lines 603–627) for those cases.
//
// See third_party/fex/README.md for archive vendoring instructions.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FEX_LINKED");
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").unwrap_or_default();
    let feature_on = env::var("CARGO_FEATURE_FEX_LINKED").is_ok();

    if !feature_on {
        return;
    }
    if target != "x86_64-unknown-uefi" {
        // fex_linked is only meaningful on the x86 tier. Silently no-op on
        // other targets so cross-compilation matrices don't fail.
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = manifest_dir.join("third_party").join("fex").join("lib");

    let archive_gnu = lib_dir.join("libfex.a");
    let archive_msvc = lib_dir.join("fex.lib");

    println!("cargo:rerun-if-changed={}", archive_gnu.display());
    println!("cargo:rerun-if-changed={}", archive_msvc.display());

    if !archive_gnu.exists() && !archive_msvc.exists() {
        panic!(
            "fex_linked feature is enabled but neither {} nor {} exists. \
             See hypervisor/third_party/fex/README.md for vendoring instructions.",
            archive_gnu.display(),
            archive_msvc.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=fex");
}
