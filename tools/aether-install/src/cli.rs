// cli.rs -- hand-rolled argument parser for aether-install.
//
// We avoid clap to keep the dependency graph minimal. The CLI surface is small
// enough that a few hundred lines of match + iterator code is clearer than a
// derive-macro tree.
//
// Top-level grammar:
//
//   aether-install [GLOBAL_FLAGS] <subcommand> [SUBCOMMAND_FLAGS]
//
//   GLOBAL_FLAGS:
//     --apply            Actually perform destructive operations.
//                        Without --apply every subcommand runs in dry-run mode.
//     --yes              Assume yes for all confirmation prompts.
//     --json             Emit structured JSON to stdout (where applicable).
//     --quiet            Suppress non-essential output.
//     --help / -h        Show help.
//     --version / -V     Show version.
//
//   SUBCOMMANDS:
//     check              Run the compatibility checker, print report, exit.
//     install            Run the full install pipeline.
//     uninstall          Remove AETHER, restore Windows-only boot.
//     update             Upgrade an existing AETHER install to a newer version.
//     status             Show current install state.
//
//   install / update flags:
//     --hypervisor PATH       Path to hypervisor.efi (required when --apply)
//     --selector PATH         Path to selector.efi   (required when --apply)
//     --android-image PATH    Path to Android system image (required when --apply)
//     --target-disk PATH      NVMe device path (e.g. /dev/nvme0 or \\.\PHYSICALDRIVE1)
//     --esp PATH              Mount point of the EFI System Partition (e.g. /boot/efi or "S:")
//     --gpu MODE              Override auto GPU selection: sriov | passthrough | software
//     --no-gpu-prompt         Never ask for GPU choice; use --gpu or default.

use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    Check,
    Install,
    Uninstall,
    Update,
    Status,
    Help,
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuModeOverride {
    Sriov,
    Passthrough,
    Software,
}

impl GpuModeOverride {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sriov"       => Some(GpuModeOverride::Sriov),
            "passthrough" => Some(GpuModeOverride::Passthrough),
            "software"    => Some(GpuModeOverride::Software),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub subcommand: Subcommand,

    // Global flags
    pub apply:     bool,
    pub yes:       bool,
    pub json:      bool,
    pub quiet:     bool,

    // install / update flags
    pub hypervisor:     Option<String>,
    pub selector:       Option<String>,
    pub android_image:  Option<String>,
    pub target_disk:    Option<String>,
    pub esp:            Option<String>,
    pub gpu_override:   Option<GpuModeOverride>,
    pub no_gpu_prompt:  bool,

    // For error reporting
    pub raw_args: Vec<String>,
}

impl CliArgs {
    fn empty(subcommand: Subcommand) -> Self {
        CliArgs {
            subcommand,
            apply:         false,
            yes:           false,
            json:          false,
            quiet:         false,
            hypervisor:    None,
            selector:      None,
            android_image: None,
            target_disk:   None,
            esp:           None,
            gpu_override:  None,
            no_gpu_prompt: false,
            raw_args:      Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum CliError {
    UnknownSubcommand(String),
    UnknownFlag(String),
    MissingFlagValue(String),
    InvalidFlagValue { flag: String, value: String, expected: &'static str },
    MissingSubcommand,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::UnknownSubcommand(s) =>
                write!(f, "unknown subcommand: '{}'. Try `aether-install --help`.", s),
            CliError::UnknownFlag(s) =>
                write!(f, "unknown flag: '{}'", s),
            CliError::MissingFlagValue(s) =>
                write!(f, "flag '{}' requires a value", s),
            CliError::InvalidFlagValue { flag, value, expected } =>
                write!(f, "flag '{}' got '{}'; expected {}", flag, value, expected),
            CliError::MissingSubcommand =>
                write!(f, "no subcommand given. Try `aether-install --help`."),
        }
    }
}

pub fn parse() -> Result<CliArgs, CliError> {
    let argv: Vec<String> = env::args().skip(1).collect();
    parse_from(&argv)
}

pub fn parse_from(argv: &[String]) -> Result<CliArgs, CliError> {
    let mut i = 0;

    // ---- Handle global help/version before subcommand parsing -----------------
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" | "-h" => {
                let mut out = CliArgs::empty(Subcommand::Help);
                out.raw_args = argv.to_vec();
                return Ok(out);
            }
            "--version" | "-V" => {
                let mut out = CliArgs::empty(Subcommand::Version);
                out.raw_args = argv.to_vec();
                return Ok(out);
            }
            s if s.starts_with('-') => {
                // global flag before subcommand -- consume and continue
                i += 1;
                continue;
            }
            _ => break,
        }
    }

    if i >= argv.len() {
        return Err(CliError::MissingSubcommand);
    }

    // ---- Parse subcommand -----------------------------------------------------
    let subcommand = match argv[i].as_str() {
        "check"     => Subcommand::Check,
        "install"   => Subcommand::Install,
        "uninstall" => Subcommand::Uninstall,
        "update"    => Subcommand::Update,
        "status"    => Subcommand::Status,
        s => return Err(CliError::UnknownSubcommand(s.to_owned())),
    };
    i += 1;

    let mut out = CliArgs::empty(subcommand.clone());
    out.raw_args = argv.to_vec();

    // ---- Parse flags (order-independent) --------------------------------------
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--apply"          => out.apply = true,
            "--yes" | "-y"     => out.yes = true,
            "--json"           => out.json = true,
            "--quiet" | "-q"   => out.quiet = true,
            "--no-gpu-prompt"  => out.no_gpu_prompt = true,
            "--help" | "-h"    => { out.subcommand = Subcommand::Help; return Ok(out); }

            // Flags taking a value
            "--hypervisor"     => { out.hypervisor    = Some(take_value(argv, &mut i)?); }
            "--selector"       => { out.selector      = Some(take_value(argv, &mut i)?); }
            "--android-image"  => { out.android_image = Some(take_value(argv, &mut i)?); }
            "--target-disk"    => { out.target_disk   = Some(take_value(argv, &mut i)?); }
            "--esp"            => { out.esp           = Some(take_value(argv, &mut i)?); }
            "--gpu"            => {
                let v = take_value(argv, &mut i)?;
                match GpuModeOverride::parse(&v) {
                    Some(m) => out.gpu_override = Some(m),
                    None => return Err(CliError::InvalidFlagValue {
                        flag:  "--gpu".into(),
                        value: v,
                        expected: "sriov | passthrough | software",
                    }),
                }
            }

            other if other.starts_with("--") || (other.starts_with('-') && other.len() == 2) => {
                return Err(CliError::UnknownFlag(other.to_owned()));
            }

            // Positional arguments: currently none.
            _ => {
                return Err(CliError::UnknownFlag(arg.clone()));
            }
        }
        i += 1;
    }

    Ok(out)
}

fn take_value(argv: &[String], i: &mut usize) -> Result<String, CliError> {
    let flag = argv[*i].clone();
    *i += 1;
    if *i >= argv.len() {
        return Err(CliError::MissingFlagValue(flag));
    }
    Ok(argv[*i].clone())
}

// ---- Help text --------------------------------------------------------------

pub const HELP_TEXT: &str = "\
aether-install -- AETHER Installer CLI

USAGE:
    aether-install [GLOBAL_FLAGS] <SUBCOMMAND> [FLAGS]

GLOBAL FLAGS:
    --apply              Perform destructive operations. Without --apply every
                         operation runs in dry-run mode and only prints what it
                         would do.
    -y, --yes            Assume 'yes' for all confirmation prompts.
    --json               Emit structured JSON to stdout (where applicable).
    -q, --quiet          Suppress non-essential output.
    -h, --help           Show this help.
    -V, --version        Show version.

SUBCOMMANDS:
    check                Run the hardware compatibility check.
                         Wraps the aether-compat binary.
                         No admin / root required.

    install              Run the full install pipeline:
                         (1) compat check
                         (2) GPU configuration
                         (3) target disk selection
                         (4) NVMe namespace creation
                         (5) write EFI binaries to ESP
                         (6) create UEFI Boot#### entry and update BootOrder
                         (7) write Android image to NVMe namespace
                         (8) write config partition
                         Idempotent. Safe to re-run.

    uninstall            Remove AETHER:
                         (1) remove Boot#### entry, update BootOrder
                         (2) remove hypervisor.efi/selector.efi from ESP
                         (3) optionally delete Android namespace
                         Windows boot manager is not touched -- Windows
                         continues to boot exactly as before.

    update               Upgrade an existing AETHER install to a newer image:
                         (1) verify install present
                         (2) write new EFI binaries
                         (3) write new Android image to inactive A/B slot
                         (4) flip active slot
                         Original install is preserved until next install or
                         update fully succeeds.

    status               Show current install state:
                         install present yes/no, version, active A/B slot,
                         GPU configuration, last update time.

INSTALL / UPDATE FLAGS:
    --hypervisor PATH        Path to hypervisor.efi (required with --apply)
    --selector PATH          Path to selector.efi   (required with --apply)
    --android-image PATH     Path to Android system image (required with --apply)
    --target-disk PATH       NVMe device. Linux: /dev/nvme0
                                          Windows: \\\\.\\PHYSICALDRIVE1
    --esp PATH               EFI System Partition mount point.
                             Linux: /boot/efi
                             Windows: drive letter, e.g. S:
    --gpu MODE               Override the auto GPU selection.
                             MODE = sriov | passthrough | software
    --no-gpu-prompt          Skip GPU selection prompt entirely.

EXAMPLES:
    aether-install check
    aether-install install                          # dry-run; prints plan
    aether-install --apply install \\
        --hypervisor ./hypervisor.efi \\
        --selector  ./selector.efi \\
        --android-image ./android.img \\
        --target-disk /dev/nvme0 \\
        --esp /boot/efi
    aether-install status
    aether-install --apply uninstall
";

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_argv(args: &[&str]) -> Result<CliArgs, CliError> {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_from(&v)
    }

    #[test]
    fn parses_check() {
        let r = parse_argv(&["check"]).unwrap();
        assert_eq!(r.subcommand, Subcommand::Check);
        assert!(!r.apply);
        assert!(!r.json);
    }

    #[test]
    fn parses_install_with_flags() {
        let r = parse_argv(&[
            "install",
            "--apply",
            "--hypervisor", "/tmp/h.efi",
            "--selector", "/tmp/s.efi",
            "--android-image", "/tmp/a.img",
            "--target-disk", "/dev/nvme0",
            "--esp", "/boot/efi",
            "--gpu", "passthrough",
        ]).unwrap();
        assert_eq!(r.subcommand, Subcommand::Install);
        assert!(r.apply);
        assert_eq!(r.hypervisor.as_deref(), Some("/tmp/h.efi"));
        assert_eq!(r.gpu_override, Some(GpuModeOverride::Passthrough));
    }

    #[test]
    fn unknown_subcommand_rejected() {
        assert!(matches!(
            parse_argv(&["wat"]),
            Err(CliError::UnknownSubcommand(_))
        ));
    }

    #[test]
    fn unknown_flag_rejected() {
        assert!(matches!(
            parse_argv(&["install", "--lasers"]),
            Err(CliError::UnknownFlag(_))
        ));
    }

    #[test]
    fn invalid_gpu_value_rejected() {
        assert!(matches!(
            parse_argv(&["install", "--gpu", "rtx-on"]),
            Err(CliError::InvalidFlagValue { .. })
        ));
    }

    #[test]
    fn missing_flag_value_rejected() {
        assert!(matches!(
            parse_argv(&["install", "--hypervisor"]),
            Err(CliError::MissingFlagValue(_))
        ));
    }

    #[test]
    fn help_short_circuits() {
        let r = parse_argv(&["--help"]).unwrap();
        assert_eq!(r.subcommand, Subcommand::Help);
    }

    #[test]
    fn version_short_circuits() {
        let r = parse_argv(&["-V"]).unwrap();
        assert_eq!(r.subcommand, Subcommand::Version);
    }
}
