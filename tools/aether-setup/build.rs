// build.rs — embed a Windows UAC manifest so the installer launches elevated
// and shows the Windows admin shield on its shortcut. Only does anything on
// Windows targets; on Linux/macOS host builds (developer use) this is a no-op.

fn main() {
    #[cfg(target_os = "windows")]
    {
        use embed_manifest::manifest::ExecutionLevel;
        use embed_manifest::{embed_manifest, new_manifest};
        if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
            // new_manifest() defaults to asInvoker; the GUI must request admin
            // so its aether-install --apply child can write UEFI variables.
            embed_manifest(new_manifest("AETHER.Setup")
                .requested_execution_level(ExecutionLevel::RequireAdministrator))
                .expect("failed to embed Windows manifest");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
