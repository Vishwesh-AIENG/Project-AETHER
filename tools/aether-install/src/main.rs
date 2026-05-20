// main.rs -- aether-install CLI entry point.
//
// Dispatches the parsed subcommand to its handler module. All real work
// lives in:
//
//   cli.rs              argument parsing
//   compat_report.rs    deserialise aether-compat JSON
//   nvidia_db.rs        NVIDIA reset bug device table
//   gpu_config.rs       GPU auto-selection decision tree
//   device_path.rs      EFI device path encoding
//   boot_entry.rs       Boot#### variable encoding + BootOrder helpers
//   uefi_vars.rs        cross-platform UEFI variable I/O (Linux/Windows)
//   install_state.rs    persistent JSON state file
//   check.rs            `check` subcommand
//   install.rs          `install` subcommand
//   uninstall.rs        `uninstall` subcommand
//   update.rs           `update` subcommand
//   status.rs           `status` subcommand

mod boot_entry;
mod check;
mod cli;
mod compat_report;
mod device_path;
mod gpu_config;
mod install;
mod install_state;
mod nvidia_db;
mod status;
mod uefi_vars;
mod uninstall;
mod update;

use cli::Subcommand;

fn main() {
    let args = match cli::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!();
            eprintln!("{}", cli::HELP_TEXT);
            std::process::exit(64); // EX_USAGE
        }
    };

    let exit_code: i32 = match args.subcommand {
        Subcommand::Help    => { println!("{}", cli::HELP_TEXT); 0 }
        Subcommand::Version => {
            println!("aether-install {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Subcommand::Check     => check::run(&args),
        Subcommand::Install   => install::run(&args),
        Subcommand::Uninstall => uninstall::run(&args),
        Subcommand::Update    => update::run(&args),
        Subcommand::Status    => status::run(&args),
    };

    std::process::exit(exit_code);
}
