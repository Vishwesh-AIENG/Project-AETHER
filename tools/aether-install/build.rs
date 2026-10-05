// build.rs — embed an explicit `asInvoker` UAC manifest.
//
// Without any manifest, Windows "installer detection" force-elevates every exe
// whose name contains "install" — including `aether_install-<hash>.exe`, the
// cargo test harness, which then cannot run from an unelevated shell (os error
// 740). Read-only subcommands (`check`, `status`, dry-run `install`) need no
// admin rights. `--apply` needs an elevated shell, or inherits elevation when
// spawned by the elevated aether-setup GUI.

fn main() {
    #[cfg(target_os = "windows")]
    {
        use embed_manifest::{embed_manifest, new_manifest};
        if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
            // new_manifest() defaults to requestedExecutionLevel=asInvoker.
            embed_manifest(new_manifest("AETHER.Install"))
                .expect("failed to embed Windows manifest");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
