// Build script for the AETHER hypervisor crate.
//
// Step 1 of the AT integration plan removed the libfex.a static archive
// from the build path. The DBT runtime now lives in the in-tree pure-Rust
// crate `aether-translator`, pulled in via `[dependencies]` in Cargo.toml.
// No external archive lookup is performed here.
//
// `fex_linked` is preserved as a Cargo feature for compatibility with
// existing scripts, but it now forwards to `aether-translator/dbt_linked`
// and does not require any third-party binary on the filesystem.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FEX_LINKED");
}
