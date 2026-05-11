// ch27: The Build System
//
// AETHER is built from a unified build system that produces three distinct
// artifacts from three cooperating subsystems:
//
//   1. Hypervisor binary  — Rust/Cargo → aarch64-unknown-uefi → PE32+ EFI application
//   2. Android image      — AOSP Make/Soong → flashable Android system + boot images
//   3. Windows config     — shell scripts → Windows boot namespace on NVMe
//
// A top-level Make orchestrator invokes each subsystem in the correct order and
// packages the outputs into an installable AETHER release bundle.
//
// ── Hardware Tiers ────────────────────────────────────────────────────────────
//
// AETHER auto-detects the hardware tier at install time:
//
//   ARM Tier  — Snapdragon X Elite / X Plus.  Rust hypervisor at EL2.
//               Android runs natively; zero translation layers.
//               Cargo target: aarch64-unknown-uefi
//
//   x86 Tier  — Intel / AMD with VT-x or AMD-V.  Rust hypervisor at VMX/SVM
//               root.  FEX-Emu DBT engine (ARM64→x86) integrated inside the
//               hypervisor.  Cargo target: x86_64-unknown-uefi
//
// ── Hypervisor Binary Format ──────────────────────────────────────────────────
//
// The platform firmware loads the hypervisor as a UEFI application — a PE32+
// (Portable Executable, 64-bit) binary in EFI format.  Rust normally emits ELF,
// but the aarch64-unknown-uefi and x86_64-unknown-uefi targets emit PE32+
// directly, so no objcopy post-processing step is required.
//
//   `file hypervisor.efi` → "PE32+ executable (EFI application) Aarch64"
//
// The UEFI target requires:
//   - #![no_std]             — no standard library
//   - #![no_main]            — no automatic main()
//   - panic = "abort"        — no unwinding on bare metal
//   - -Z build-std=core,...  — rebuild core without std (nightly required)
//
// ── AOSP Build Variables ──────────────────────────────────────────────────────
//
// The Android image is built against AETHER's device configuration — a set of
// BoardConfig.mk and device.mk files that describe the virtual hardware AETHER
// presents.  Key constraints:
//
//   - ro.build.type must be "user" — never userdebug in production
//   - Partition sizes in BoardConfig.mk must match the NVMe namespace layout
//     defined in aosp.rs (default_layout::build())
//   - The GPU driver is selected at AOSP build time to match the SR-IOV VF
//     identity configured in gpu.rs
//
// ── Build Orchestration Order ─────────────────────────────────────────────────
//
// The three subsystems must be invoked in this order:
//
//   1. Build hypervisor          — no dependencies, produces hypervisor.efi
//   2. Build Android image       — depends on kernel config matching hypervisor
//                                  device-tree expectations
//   3. Prepare Windows config    — depends on NVMe namespace layout (produced
//                                  alongside the Android build)
//   4. Package release bundle    — archives all three + install script
//
// Steps 2 and 3 can be parallelized after step 1 completes.
//
// ── Cross-Compilation ─────────────────────────────────────────────────────────
//
// Development happens on x86-64 Linux workstations.  The toolchain requirements:
//
//   Rust nightly     — required for -Z build-std
//   aarch64-linux-gnu-{gcc,as,ld}  — C cross-compiler for assembly stubs
//   llvm/lld         — rust-lld with lld-link flavor for PE/COFF output
//   AOSP build env   — repo, JDK 11+, Python 3, make, ninja
//
// Primary references:
//   Cargo book: doc.rust-lang.org/cargo (workspaces, build scripts, config)
//   Rust Embedded Book: docs.rust-embedded.org/book (bare-metal patterns)
//   AOSP build docs: source.android.com/docs/setup/build

// ─────────────────────────────────────────────────────────────────────────────
// HardwareTier — the two supported hardware targets
// ─────────────────────────────────────────────────────────────────────────────

/// The two hardware tiers AETHER supports, auto-detected at install time.
///
/// Each tier determines the Cargo target triple, the virtualization mechanism,
/// and whether the FEX-Emu dynamic binary translation engine is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareTier {
    /// Snapdragon X Elite / X Plus — ARM64 native execution.
    ///
    /// AETHER runs at EL2.  Android runs natively at EL1 with Stage 2 page
    /// tables enforcing isolation.  No translation layer.
    /// Cargo target: `aarch64-unknown-uefi`.
    Arm,
    /// Intel / AMD with VT-x or AMD-V — x86 host with ARM64 translation.
    ///
    /// AETHER runs in VMX/SVM root mode.  FEX-Emu DBT engine (ARM64→x86)
    /// runs inside the hypervisor.  No host OS.
    /// Cargo target: `x86_64-unknown-uefi`.
    X86,
}

impl HardwareTier {
    /// The Rust target triple for the hypervisor binary on this tier.
    pub const fn cargo_target(self) -> &'static str {
        match self {
            HardwareTier::Arm  => "aarch64-unknown-uefi",
            HardwareTier::X86  => "x86_64-unknown-uefi",
        }
    }

    /// Return `true` when this tier requires the FEX-Emu DBT engine.
    pub const fn requires_dbt_engine(self) -> bool {
        matches!(self, HardwareTier::X86)
    }

    /// Return `true` when Android executes natively on this tier (no translation).
    pub const fn is_native_android_execution(self) -> bool {
        matches!(self, HardwareTier::Arm)
    }

    /// Return `true` when the hypervisor runs at ARM EL2 on this tier.
    pub const fn runs_at_el2(self) -> bool {
        matches!(self, HardwareTier::Arm)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CargoProfile — the Cargo build profile
// ─────────────────────────────────────────────────────────────────────────────

/// The Cargo build profile for the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoProfile {
    /// `--release`: LTO enabled, `opt-level = "s"` (size), `panic = "abort"`.
    ///
    /// Used for all installation and production builds.  The output is a
    /// size-optimized PE32+ binary suitable for UEFI loading.
    Release,
    /// Default debug profile: no optimizations, full debug symbols.
    ///
    /// Used only during development.  `panic = "abort"` still applies — there
    /// is no unwinding support on bare metal regardless of profile.
    Debug,
}

impl CargoProfile {
    /// Return the Cargo flag string for this profile.
    pub const fn cargo_flag(self) -> &'static str {
        match self {
            CargoProfile::Release => "--release",
            CargoProfile::Debug   => "",
        }
    }

    /// Return `true` when LTO is enabled for this profile.
    ///
    /// LTO is enabled only for Release to keep debug build times short.
    pub const fn lto_enabled(self) -> bool {
        matches!(self, CargoProfile::Release)
    }

    /// Return `true` when this profile is suitable for installation.
    pub const fn is_production_ready(self) -> bool {
        matches!(self, CargoProfile::Release)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypervisorBuildConfig — Cargo/Rust build configuration for the hypervisor
// ─────────────────────────────────────────────────────────────────────────────

/// The complete build configuration for the hypervisor binary.
///
/// The hypervisor is a bare-metal Rust program compiled with a nightly toolchain
/// to a UEFI target, producing a PE32+ EFI application.  All required unstable
/// flags are passed on the CLI (not in `.cargo/config.toml`) to avoid
/// duplicate-lang-item errors when running `cargo test --lib` on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypervisorBuildConfig {
    /// The hardware tier determines the Cargo target triple.
    pub tier: HardwareTier,
    /// Release or Debug profile.
    pub profile: CargoProfile,
    /// Whether `-Z build-std=core,compiler_builtins` is enabled.
    ///
    /// Must be `true` for bare-metal UEFI targets.  Rebuilds `core` without
    /// the standard library so `panic = "abort"` applies to all crate code.
    pub build_std: bool,
    /// Whether `-Z build-std-features=compiler-builtins-mem` is enabled.
    ///
    /// Provides `memcpy`/`memset`/`memcmp` implementations from
    /// `compiler-builtins` rather than relying on a C runtime.
    pub build_std_mem: bool,
}

impl HypervisorBuildConfig {
    /// The correct build configuration for an ARM-tier production build.
    pub const ARM_RELEASE: Self = Self {
        tier: HardwareTier::Arm,
        profile: CargoProfile::Release,
        build_std: true,
        build_std_mem: true,
    };

    /// The correct build configuration for an ARM-tier development build.
    pub const ARM_DEBUG: Self = Self {
        tier: HardwareTier::Arm,
        profile: CargoProfile::Debug,
        build_std: true,
        build_std_mem: true,
    };

    /// The correct build configuration for an x86-tier production build.
    pub const X86_RELEASE: Self = Self {
        tier: HardwareTier::X86,
        profile: CargoProfile::Release,
        build_std: true,
        build_std_mem: true,
    };

    /// Return the output EFI file name for this configuration.
    pub const fn output_name(self) -> &'static str {
        match self.profile {
            CargoProfile::Release => "hypervisor.efi",
            CargoProfile::Debug   => "hypervisor-debug.efi",
        }
    }

    /// Validate the build configuration.
    ///
    /// Rejects configurations that would produce an invalid or insecure binary.
    pub fn validate(&self) -> Result<(), BuildError> {
        if !self.build_std {
            return Err(BuildError::BuildStdRequired);
        }
        if !self.build_std_mem {
            return Err(BuildError::BuildStdMemRequired);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidBuildVariant — AOSP build type (ro.build.type)
// ─────────────────────────────────────────────────────────────────────────────

/// The AOSP build variant, which sets `ro.build.type` in the system image.
///
/// Production AETHER images must use `User` only.  Any other variant produces
/// a system image that fails SafetyNet and Google Play Integrity attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidBuildVariant {
    /// `ro.build.type = user` — production build.
    ///
    /// ADB disabled, SELinux enforcing, no debugging interfaces.
    /// Required by SafetyNet, Play Integrity, and AETHER's own invariant.
    User,
    /// `ro.build.type = userdebug` — developer build with root access.
    ///
    /// **Never used in production AETHER images.**  Causes attestation failure.
    Userdebug,
    /// `ro.build.type = eng` — engineering build with all debugging enabled.
    ///
    /// **Never used in production AETHER images.**  Causes attestation failure.
    Eng,
}

impl AndroidBuildVariant {
    /// Return `true` when this variant is safe for a production AETHER image.
    pub const fn is_production_safe(self) -> bool {
        matches!(self, AndroidBuildVariant::User)
    }

    /// Return the `ro.build.type` string written into the system image.
    pub const fn build_type_str(self) -> &'static str {
        match self {
            AndroidBuildVariant::User      => "user",
            AndroidBuildVariant::Userdebug => "userdebug",
            AndroidBuildVariant::Eng       => "eng",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PartitionUnit — the unit in which a partition size is expressed
// ─────────────────────────────────────────────────────────────────────────────

/// The unit used to express a partition size in `BoardConfig.mk`.
///
/// AOSP partition size variables use different units depending on the variable
/// name.  Mixing units produces wrong-sized partitions that may fail to flash
/// or boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionUnit {
    /// Size expressed in bytes.  Used by `BOARD_*IMAGE_PARTITION_SIZE`.
    Bytes,
    /// Size expressed in kibibytes (1 KiB = 1024 bytes).
    /// Used by some legacy partition variables.
    Kibibytes,
    /// Size expressed in mebibytes (1 MiB = 1024 KiB).
    /// Used by `BOARD_USERDATAIMAGE_PARTITION_SIZE` on some targets.
    Mebibytes,
}

impl PartitionUnit {
    /// Convert a value in this unit to bytes.
    ///
    /// Returns `None` on overflow.
    pub const fn to_bytes(self, value: u64) -> Option<u64> {
        match self {
            PartitionUnit::Bytes      => Some(value),
            PartitionUnit::Kibibytes  => value.checked_mul(1_024),
            PartitionUnit::Mebibytes  => value.checked_mul(1_024 * 1_024),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidBuildConfig — AOSP build configuration for AETHER's device
// ─────────────────────────────────────────────────────────────────────────────

/// The AOSP build configuration for AETHER's Android partition.
///
/// These values are encoded in `BoardConfig.mk` and `device.mk` files in the
/// AETHER device configuration tree within the AOSP fork.  They must be
/// consistent with the partition layout defined in `aosp.rs` and the hardware
/// description in the kernel device tree produced by `kernel.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidBuildConfig {
    /// The AOSP device target (e.g., `"aether_arm64"`).
    ///
    /// Selects the device configuration directory under `device/aether/`.
    pub device_target: &'static str,
    /// The build variant.  Must be `User` for production images.
    pub variant: AndroidBuildVariant,
    /// The architecture of the Android userspace (`aarch64` for ARM tier).
    pub target_arch: &'static str,
    /// The Android boot image partition size in bytes.
    ///
    /// Must match `PartitionSpec::size_bytes` for `PartitionKind::Boot` in
    /// `aosp.rs default_layout`.  Default: 64 MiB per slot.
    pub boot_partition_size_bytes: u64,
    /// The Android system partition size in bytes.
    ///
    /// Must match `PartitionSpec::size_bytes` for `PartitionKind::System`.
    /// Default: 4 GiB per slot.
    pub system_partition_size_bytes: u64,
    /// The Android userdata partition size in bytes.
    ///
    /// Must match `PartitionSpec::size_bytes` for `PartitionKind::Userdata`.
    /// Default: 80 GiB (single partition, not A/B).
    pub userdata_partition_size_bytes: u64,
}

impl AndroidBuildConfig {
    /// The production Android build configuration for the ARM tier.
    ///
    /// Partition sizes match `aosp::default_layout::build()` on a 128 GiB
    /// NVMe namespace.
    pub const ARM_PRODUCTION: Self = Self {
        device_target:                  "aether_arm64",
        variant:                        AndroidBuildVariant::User,
        target_arch:                    "aarch64",
        boot_partition_size_bytes:      64 * 1024 * 1024,        //  64 MiB
        system_partition_size_bytes:    4 * 1024 * 1024 * 1024,  //   4 GiB
        userdata_partition_size_bytes:  80 * 1024 * 1024 * 1024, //  80 GiB
    };

    /// Validate the Android build configuration.
    ///
    /// Rejects non-production build variants and obviously incorrect partition
    /// sizes (zero or misaligned).
    pub fn validate(&self) -> Result<(), BuildError> {
        if !self.variant.is_production_safe() {
            return Err(BuildError::NonProductionAndroidVariant {
                variant: self.variant,
            });
        }
        if self.boot_partition_size_bytes == 0 {
            return Err(BuildError::ZeroPartitionSize { partition: "boot" });
        }
        if self.system_partition_size_bytes == 0 {
            return Err(BuildError::ZeroPartitionSize { partition: "system" });
        }
        if self.userdata_partition_size_bytes == 0 {
            return Err(BuildError::ZeroPartitionSize { partition: "userdata" });
        }
        // Partitions must be 4 KiB aligned (NVMe LBA requirement)
        const ALIGN: u64 = 4096;
        if self.boot_partition_size_bytes % ALIGN != 0 {
            return Err(BuildError::PartitionMisaligned { partition: "boot" });
        }
        if self.system_partition_size_bytes % ALIGN != 0 {
            return Err(BuildError::PartitionMisaligned { partition: "system" });
        }
        if self.userdata_partition_size_bytes % ALIGN != 0 {
            return Err(BuildError::PartitionMisaligned { partition: "userdata" });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WindowsBuildConfig — Windows boot namespace configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for preparing the Windows partition on the NVMe namespace.
///
/// Unlike the hypervisor and Android builds, the Windows configuration is
/// produced by a set of shell scripts that write UEFI variables, configure the
/// NVMe namespace, and populate the EFI system partition with the Windows
/// bootloader.  This type records the configuration those scripts consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsBuildConfig {
    /// Windows RAM allocation in bytes.
    ///
    /// Used to size the NVMe namespace that Windows receives.  The namespace
    /// must be at least this large to hold a full crash dump (paging file ≥ RAM).
    /// See `windows.rs CrashDumpConfig::validate()`.
    pub windows_ram_bytes: u64,
    /// Windows NVMe namespace size in bytes.
    ///
    /// Must be ≥ `windows_ram_bytes` + OS footprint.  Validated by
    /// `CrashDumpConfig::validate()` in `windows.rs`.
    pub windows_namespace_bytes: u64,
    /// Whether the Windows Secure Boot chain has been populated.
    ///
    /// PK → KEK → db (with Windows Production CA) → dbx must all be present
    /// before the Windows build is considered ready.  See ch18.
    pub secure_boot_chain_populated: bool,
}

impl WindowsBuildConfig {
    /// The default Windows configuration for an 8 GiB Windows partition
    /// on a 128 GiB NVMe device.
    pub const DEFAULT: Self = Self {
        windows_ram_bytes:          8 * 1024 * 1024 * 1024,  //   8 GiB
        windows_namespace_bytes:    32 * 1024 * 1024 * 1024, //  32 GiB
        secure_boot_chain_populated: false,
    };

    /// Validate the Windows build configuration.
    pub fn validate(&self) -> Result<(), BuildError> {
        if self.windows_namespace_bytes < self.windows_ram_bytes {
            return Err(BuildError::WindowsNamespaceSmallerThanRam {
                namespace_bytes: self.windows_namespace_bytes,
                ram_bytes: self.windows_ram_bytes,
            });
        }
        if !self.secure_boot_chain_populated {
            return Err(BuildError::SecureBootChainNotPopulated);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrossCompileToolchain — toolchain requirements for a build host
// ─────────────────────────────────────────────────────────────────────────────

/// The cross-compilation toolchain requirements for building AETHER on a
/// development workstation.
///
/// All fields are booleans representing whether the required component is
/// installed and available in `$PATH`.  The `validate()` method checks all
/// requirements before starting a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossCompileToolchain {
    /// Rust nightly toolchain available (`rustup run nightly rustc --version`).
    ///
    /// Required for `-Z build-std` which is a nightly-only unstable feature.
    pub rust_nightly_available: bool,
    /// The UEFI Rust target is installed for the given hardware tier.
    ///
    /// ARM: `rustup target add aarch64-unknown-uefi`
    /// x86: `rustup target add x86_64-unknown-uefi`
    pub uefi_target_installed: bool,
    /// The ARM64 cross-compilation toolchain is installed.
    ///
    /// `aarch64-linux-gnu-gcc`, `aarch64-linux-gnu-as`, `aarch64-linux-gnu-ld`.
    /// Required for assembly stubs compiled via `build.rs`.
    pub aarch64_cross_toolchain: bool,
    /// `rust-src` component is installed (required by `-Z build-std`).
    ///
    /// `rustup component add rust-src`
    pub rust_src_component: bool,
    /// AOSP build environment is set up (for Android image builds).
    ///
    /// Requires: `repo`, JDK 17+, Python 3, `make`, `ninja`, `git`.
    pub aosp_build_env: bool,
}

impl CrossCompileToolchain {
    /// A toolchain where every component is present.
    pub const FULLY_CONFIGURED: Self = Self {
        rust_nightly_available: true,
        uefi_target_installed: true,
        aarch64_cross_toolchain: true,
        rust_src_component: true,
        aosp_build_env: true,
    };

    /// A minimal toolchain sufficient only for hypervisor builds (no AOSP).
    ///
    /// AOSP takes 4–8 hours to set up on first run; this configuration lets
    /// developers iterate on the hypervisor without a full AOSP environment.
    pub const HYPERVISOR_ONLY: Self = Self {
        rust_nightly_available: true,
        uefi_target_installed: true,
        aarch64_cross_toolchain: true,
        rust_src_component: true,
        aosp_build_env: false,
    };

    /// Return `true` when this toolchain can build all three AETHER artifacts.
    pub const fn can_build_all(self) -> bool {
        self.rust_nightly_available
            && self.uefi_target_installed
            && self.aarch64_cross_toolchain
            && self.rust_src_component
            && self.aosp_build_env
    }

    /// Return `true` when this toolchain can build at least the hypervisor binary.
    pub const fn can_build_hypervisor(self) -> bool {
        self.rust_nightly_available
            && self.uefi_target_installed
            && self.aarch64_cross_toolchain
            && self.rust_src_component
    }

    /// Validate the toolchain for a full AETHER build.
    pub fn validate(&self) -> Result<(), BuildError> {
        if !self.rust_nightly_available {
            return Err(BuildError::RustNightlyNotAvailable);
        }
        if !self.uefi_target_installed {
            return Err(BuildError::UefiTargetNotInstalled);
        }
        if !self.aarch64_cross_toolchain {
            return Err(BuildError::Aarch64CrossToolchainMissing);
        }
        if !self.rust_src_component {
            return Err(BuildError::RustSrcComponentMissing);
        }
        if !self.aosp_build_env {
            return Err(BuildError::AospBuildEnvNotConfigured);
        }
        Ok(())
    }

    /// Validate the toolchain for a hypervisor-only build.
    pub fn validate_hypervisor_only(&self) -> Result<(), BuildError> {
        if !self.rust_nightly_available {
            return Err(BuildError::RustNightlyNotAvailable);
        }
        if !self.uefi_target_installed {
            return Err(BuildError::UefiTargetNotInstalled);
        }
        if !self.aarch64_cross_toolchain {
            return Err(BuildError::Aarch64CrossToolchainMissing);
        }
        if !self.rust_src_component {
            return Err(BuildError::RustSrcComponentMissing);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildStep — the ordered stages of a full AETHER build
// ─────────────────────────────────────────────────────────────────────────────

/// The ordered stages of a complete AETHER build.
///
/// The build orchestrator invokes these in order.  Steps 2 and 3 can be
/// parallelized after step 1 completes because they have no dependency on
/// each other — only on the hypervisor build having established the final
/// device-tree and partition layout values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStep {
    /// Step 1: Build the hypervisor binary (`cargo build --release`).
    ///
    /// Must complete before any other step because the device-tree parameters
    /// and NVMe namespace layout are finalized here.
    BuildHypervisor,
    /// Step 2: Build the Android image (AOSP `m`).
    ///
    /// Depends on `BuildHypervisor` to establish the kernel device-tree
    /// expectations.  Can run in parallel with `PrepareWindowsConfig`.
    BuildAndroidImage,
    /// Step 3: Prepare the Windows boot configuration.
    ///
    /// Populates the EFI system partition, UEFI variables, and NVMe namespace
    /// for Windows.  Can run in parallel with `BuildAndroidImage`.
    PrepareWindowsConfig,
    /// Step 4: Package the release bundle.
    ///
    /// Archives all three artifacts with the installer script into a single
    /// distributable tarball.  Depends on all three prior steps.
    PackageRelease,
}

impl BuildStep {
    /// Return `true` when this step can be parallelized with the given step.
    ///
    /// Only `BuildAndroidImage` and `PrepareWindowsConfig` can run in parallel
    /// with each other (both depend on `BuildHypervisor` but not on each other).
    pub const fn can_parallelize_with(self, other: BuildStep) -> bool {
        matches!(
            (self, other),
            (BuildStep::BuildAndroidImage, BuildStep::PrepareWindowsConfig)
            | (BuildStep::PrepareWindowsConfig, BuildStep::BuildAndroidImage)
        )
    }

    /// Return the step that must complete before this step can begin.
    ///
    /// Returns `None` for `BuildHypervisor` which has no prerequisites.
    pub const fn prerequisite(self) -> Option<BuildStep> {
        match self {
            BuildStep::BuildHypervisor    => None,
            BuildStep::BuildAndroidImage  => Some(BuildStep::BuildHypervisor),
            BuildStep::PrepareWindowsConfig => Some(BuildStep::BuildHypervisor),
            BuildStep::PackageRelease     => Some(BuildStep::PrepareWindowsConfig),
        }
    }
}

/// The complete ordered sequence of build steps for a full AETHER release.
pub const BUILD_STEPS: &[BuildStep] = &[
    BuildStep::BuildHypervisor,
    BuildStep::BuildAndroidImage,
    BuildStep::PrepareWindowsConfig,
    BuildStep::PackageRelease,
];

// ─────────────────────────────────────────────────────────────────────────────
// EfiOutputFormat — verification of the hypervisor binary format
// ─────────────────────────────────────────────────────────────────────────────

/// The expected format of the hypervisor output binary.
///
/// Used as a post-build verification gate: `file hypervisor.efi` must report
/// a PE32+ EFI application for the correct architecture before the binary is
/// considered valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiOutputFormat {
    /// The binary must be PE32+ (64-bit Portable Executable).
    pub is_pe32_plus: bool,
    /// The binary must be tagged as an EFI application (subsystem = 10).
    pub is_efi_application: bool,
    /// The target architecture as reported by the `file` command.
    pub architecture: EfiArch,
}

/// The CPU architecture of a PE32+ EFI binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiArch {
    /// ARM64 / AArch64 — used by the ARM tier hypervisor.
    Aarch64,
    /// x86-64 — used by the x86 tier hypervisor.
    X86_64,
}

impl EfiOutputFormat {
    /// The expected format for an ARM-tier hypervisor binary.
    ///
    /// `file hypervisor.efi` must report:
    /// "PE32+ executable (EFI application) Aarch64"
    pub const ARM_RELEASE: Self = Self {
        is_pe32_plus: true,
        is_efi_application: true,
        architecture: EfiArch::Aarch64,
    };

    /// The expected format for an x86-tier hypervisor binary.
    pub const X86_RELEASE: Self = Self {
        is_pe32_plus: true,
        is_efi_application: true,
        architecture: EfiArch::X86_64,
    };

    /// Validate that the format is correct.
    pub fn validate(&self) -> Result<(), BuildError> {
        if !self.is_pe32_plus {
            return Err(BuildError::NotPe32Plus);
        }
        if !self.is_efi_application {
            return Err(BuildError::NotEfiApplication);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildSystemConfig — the complete AETHER build system configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The complete build system configuration for an AETHER release.
///
/// `validate()` checks every subsystem configuration and the toolchain
/// availability before a build begins.
#[derive(Debug)]
pub struct BuildSystemConfig {
    /// Hypervisor binary build configuration.
    pub hypervisor: HypervisorBuildConfig,
    /// Android image build configuration.
    pub android: AndroidBuildConfig,
    /// Windows boot configuration.
    pub windows: WindowsBuildConfig,
    /// Cross-compilation toolchain availability.
    pub toolchain: CrossCompileToolchain,
    /// Expected output binary format for post-build verification.
    pub expected_efi_format: EfiOutputFormat,
}

impl BuildSystemConfig {
    /// The production build configuration for an ARM-tier full AETHER release.
    pub const ARM_PRODUCTION: Self = Self {
        hypervisor:          HypervisorBuildConfig::ARM_RELEASE,
        android:             AndroidBuildConfig::ARM_PRODUCTION,
        windows:             WindowsBuildConfig::DEFAULT,
        toolchain:           CrossCompileToolchain::FULLY_CONFIGURED,
        expected_efi_format: EfiOutputFormat::ARM_RELEASE,
    };

    /// Validate the complete build system configuration.
    ///
    /// Checks (in order):
    ///   1. Hypervisor build configuration is valid.
    ///   2. Android build configuration is valid (user variant, aligned sizes).
    ///   3. Windows configuration is valid (namespace ≥ RAM).
    ///   4. Toolchain is fully configured.
    ///   5. Expected EFI output format is valid.
    ///   6. Hardware tier is consistent between hypervisor and EFI format.
    pub fn validate(&self) -> Result<(), BuildError> {
        self.hypervisor.validate()?;
        self.android.validate()?;
        self.windows.validate()?;
        self.toolchain.validate()?;
        self.expected_efi_format.validate()?;
        // Tier consistency: ARM hypervisor → Aarch64 EFI; x86 → X86_64 EFI
        let tier_arch_ok = match (self.hypervisor.tier, self.expected_efi_format.architecture) {
            (HardwareTier::Arm, EfiArch::Aarch64) => true,
            (HardwareTier::X86, EfiArch::X86_64)  => true,
            _                                      => false,
        };
        if !tier_arch_ok {
            return Err(BuildError::TierArchitectureMismatch);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildSummary — build readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level build readiness gate.
///
/// `build_ready()` returns `true` only when all three artifacts can be built
/// and the toolchain is fully configured.  Use this gate before starting a
/// release build.
#[derive(Debug)]
pub struct BuildSummary {
    /// True when the hypervisor build configuration is valid.
    pub hypervisor_config_valid: bool,
    /// True when the Android build configuration is valid (user variant).
    pub android_config_valid: bool,
    /// True when the Windows configuration is valid.
    pub windows_config_valid: bool,
    /// True when the full toolchain is available.
    pub toolchain_ready: bool,
}

impl BuildSummary {
    /// Return `true` when all preconditions for a release build are met.
    pub fn build_ready(&self) -> bool {
        self.hypervisor_config_valid
            && self.android_config_valid
            && self.windows_config_valid
            && self.toolchain_ready
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildError — errors returned by build configuration validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by build configuration validation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// `-Z build-std=core,compiler_builtins` is required but not enabled.
    ///
    /// Without it, `core` is not rebuilt with `panic = "abort"` and the UEFI
    /// target binary may be invalid.
    BuildStdRequired,
    /// `-Z build-std-features=compiler-builtins-mem` is required but not enabled.
    ///
    /// Without it, `memcpy`/`memset`/`memcmp` are not available on bare metal.
    BuildStdMemRequired,
    /// Android build variant is not `user`.
    ///
    /// Production images must always use the `user` variant.  Any other
    /// variant causes SafetyNet and Play Integrity attestation failures.
    NonProductionAndroidVariant {
        /// The non-production variant that was rejected.
        variant: AndroidBuildVariant,
    },
    /// A partition size is zero.
    ZeroPartitionSize {
        /// The name of the zero-sized partition (e.g., `"boot"`, `"system"`).
        partition: &'static str,
    },
    /// A partition size is not aligned to 4096 bytes (NVMe LBA requirement).
    PartitionMisaligned {
        /// The name of the misaligned partition.
        partition: &'static str,
    },
    /// Windows NVMe namespace is smaller than the Windows RAM allocation.
    ///
    /// The namespace must hold at least a full crash dump (paging file ≥ RAM).
    WindowsNamespaceSmallerThanRam {
        /// The configured namespace size in bytes.
        namespace_bytes: u64,
        /// The configured RAM size in bytes.
        ram_bytes: u64,
    },
    /// The Windows Secure Boot chain has not been populated.
    ///
    /// PK → KEK → db (Windows Production CA) → dbx must all be present.
    SecureBootChainNotPopulated,
    /// Rust nightly toolchain is not available.
    RustNightlyNotAvailable,
    /// The UEFI Rust target is not installed.
    UefiTargetNotInstalled,
    /// The `aarch64-linux-gnu-*` cross-compilation toolchain is not installed.
    Aarch64CrossToolchainMissing,
    /// The `rust-src` rustup component is not installed.
    RustSrcComponentMissing,
    /// The AOSP build environment is not configured.
    AospBuildEnvNotConfigured,
    /// The hypervisor binary is not a PE32+ executable.
    NotPe32Plus,
    /// The hypervisor binary is not tagged as an EFI application.
    NotEfiApplication,
    /// The hardware tier and EFI output architecture are inconsistent.
    ///
    /// ARM tier requires Aarch64 EFI; x86 tier requires X86_64 EFI.
    TierArchitectureMismatch,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HardwareTier ──────────────────────────────────────────────────────────

    #[test]
    fn arm_tier_cargo_target() {
        assert_eq!(HardwareTier::Arm.cargo_target(), "aarch64-unknown-uefi");
    }

    #[test]
    fn x86_tier_cargo_target() {
        assert_eq!(HardwareTier::X86.cargo_target(), "x86_64-unknown-uefi");
    }

    #[test]
    fn arm_tier_does_not_require_dbt() {
        assert!(!HardwareTier::Arm.requires_dbt_engine());
    }

    #[test]
    fn x86_tier_requires_dbt() {
        assert!(HardwareTier::X86.requires_dbt_engine());
    }

    #[test]
    fn arm_tier_native_android_execution() {
        assert!(HardwareTier::Arm.is_native_android_execution());
        assert!(!HardwareTier::X86.is_native_android_execution());
    }

    #[test]
    fn arm_tier_runs_at_el2() {
        assert!(HardwareTier::Arm.runs_at_el2());
        assert!(!HardwareTier::X86.runs_at_el2());
    }

    // ── CargoProfile ──────────────────────────────────────────────────────────

    #[test]
    fn release_profile_cargo_flag() {
        assert_eq!(CargoProfile::Release.cargo_flag(), "--release");
    }

    #[test]
    fn debug_profile_cargo_flag() {
        assert_eq!(CargoProfile::Debug.cargo_flag(), "");
    }

    #[test]
    fn release_profile_lto_enabled() {
        assert!(CargoProfile::Release.lto_enabled());
        assert!(!CargoProfile::Debug.lto_enabled());
    }

    #[test]
    fn release_profile_is_production_ready() {
        assert!(CargoProfile::Release.is_production_ready());
        assert!(!CargoProfile::Debug.is_production_ready());
    }

    // ── HypervisorBuildConfig ─────────────────────────────────────────────────

    #[test]
    fn arm_release_validates_ok() {
        assert!(HypervisorBuildConfig::ARM_RELEASE.validate().is_ok());
    }

    #[test]
    fn arm_debug_validates_ok() {
        assert!(HypervisorBuildConfig::ARM_DEBUG.validate().is_ok());
    }

    #[test]
    fn x86_release_validates_ok() {
        assert!(HypervisorBuildConfig::X86_RELEASE.validate().is_ok());
    }

    #[test]
    fn hypervisor_build_std_required() {
        let cfg = HypervisorBuildConfig {
            build_std: false,
            ..HypervisorBuildConfig::ARM_RELEASE
        };
        assert_eq!(cfg.validate(), Err(BuildError::BuildStdRequired));
    }

    #[test]
    fn hypervisor_build_std_mem_required() {
        let cfg = HypervisorBuildConfig {
            build_std_mem: false,
            ..HypervisorBuildConfig::ARM_RELEASE
        };
        assert_eq!(cfg.validate(), Err(BuildError::BuildStdMemRequired));
    }

    #[test]
    fn hypervisor_output_name_release() {
        assert_eq!(HypervisorBuildConfig::ARM_RELEASE.output_name(), "hypervisor.efi");
    }

    #[test]
    fn hypervisor_output_name_debug() {
        assert_eq!(HypervisorBuildConfig::ARM_DEBUG.output_name(), "hypervisor-debug.efi");
    }

    // ── AndroidBuildVariant ───────────────────────────────────────────────────

    #[test]
    fn user_variant_is_production_safe() {
        assert!(AndroidBuildVariant::User.is_production_safe());
    }

    #[test]
    fn userdebug_variant_not_production_safe() {
        assert!(!AndroidBuildVariant::Userdebug.is_production_safe());
    }

    #[test]
    fn eng_variant_not_production_safe() {
        assert!(!AndroidBuildVariant::Eng.is_production_safe());
    }

    #[test]
    fn android_variant_build_type_strings() {
        assert_eq!(AndroidBuildVariant::User.build_type_str(), "user");
        assert_eq!(AndroidBuildVariant::Userdebug.build_type_str(), "userdebug");
        assert_eq!(AndroidBuildVariant::Eng.build_type_str(), "eng");
    }

    // ── PartitionUnit ─────────────────────────────────────────────────────────

    #[test]
    fn partition_unit_bytes_identity() {
        assert_eq!(PartitionUnit::Bytes.to_bytes(4096), Some(4096));
    }

    #[test]
    fn partition_unit_kibibytes_conversion() {
        assert_eq!(PartitionUnit::Kibibytes.to_bytes(64), Some(64 * 1024));
    }

    #[test]
    fn partition_unit_mebibytes_conversion() {
        assert_eq!(PartitionUnit::Mebibytes.to_bytes(64), Some(64 * 1024 * 1024));
    }

    #[test]
    fn partition_unit_overflow_returns_none() {
        assert_eq!(PartitionUnit::Mebibytes.to_bytes(u64::MAX), None);
    }

    // ── AndroidBuildConfig ────────────────────────────────────────────────────

    #[test]
    fn arm_production_android_validates_ok() {
        assert!(AndroidBuildConfig::ARM_PRODUCTION.validate().is_ok());
    }

    #[test]
    fn android_userdebug_variant_rejected() {
        let cfg = AndroidBuildConfig {
            variant: AndroidBuildVariant::Userdebug,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(
            cfg.validate(),
            Err(BuildError::NonProductionAndroidVariant {
                variant: AndroidBuildVariant::Userdebug,
            })
        );
    }

    #[test]
    fn android_eng_variant_rejected() {
        let cfg = AndroidBuildConfig {
            variant: AndroidBuildVariant::Eng,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(
            cfg.validate(),
            Err(BuildError::NonProductionAndroidVariant {
                variant: AndroidBuildVariant::Eng,
            })
        );
    }

    #[test]
    fn android_zero_boot_partition_rejected() {
        let cfg = AndroidBuildConfig {
            boot_partition_size_bytes: 0,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::ZeroPartitionSize { partition: "boot" }));
    }

    #[test]
    fn android_zero_system_partition_rejected() {
        let cfg = AndroidBuildConfig {
            system_partition_size_bytes: 0,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::ZeroPartitionSize { partition: "system" }));
    }

    #[test]
    fn android_zero_userdata_partition_rejected() {
        let cfg = AndroidBuildConfig {
            userdata_partition_size_bytes: 0,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::ZeroPartitionSize { partition: "userdata" }));
    }

    #[test]
    fn android_misaligned_boot_partition_rejected() {
        let cfg = AndroidBuildConfig {
            boot_partition_size_bytes: 64 * 1024 * 1024 + 1,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::PartitionMisaligned { partition: "boot" }));
    }

    #[test]
    fn android_misaligned_system_partition_rejected() {
        let cfg = AndroidBuildConfig {
            system_partition_size_bytes: 4 * 1024 * 1024 * 1024 + 511,
            ..AndroidBuildConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::PartitionMisaligned { partition: "system" }));
    }

    // ── WindowsBuildConfig ────────────────────────────────────────────────────

    #[test]
    fn windows_default_with_secure_boot_validates_ok() {
        let cfg = WindowsBuildConfig {
            secure_boot_chain_populated: true,
            ..WindowsBuildConfig::DEFAULT
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn windows_default_without_secure_boot_fails() {
        assert_eq!(
            WindowsBuildConfig::DEFAULT.validate(),
            Err(BuildError::SecureBootChainNotPopulated)
        );
    }

    #[test]
    fn windows_namespace_smaller_than_ram_rejected() {
        let cfg = WindowsBuildConfig {
            windows_ram_bytes: 16 * 1024 * 1024 * 1024,
            windows_namespace_bytes: 8 * 1024 * 1024 * 1024,
            secure_boot_chain_populated: true,
        };
        assert_eq!(
            cfg.validate(),
            Err(BuildError::WindowsNamespaceSmallerThanRam {
                namespace_bytes: 8 * 1024 * 1024 * 1024,
                ram_bytes: 16 * 1024 * 1024 * 1024,
            })
        );
    }

    #[test]
    fn windows_namespace_equal_to_ram_validates_ok() {
        let cfg = WindowsBuildConfig {
            windows_ram_bytes: 8 * 1024 * 1024 * 1024,
            windows_namespace_bytes: 8 * 1024 * 1024 * 1024,
            secure_boot_chain_populated: true,
        };
        assert!(cfg.validate().is_ok());
    }

    // ── CrossCompileToolchain ─────────────────────────────────────────────────

    #[test]
    fn fully_configured_toolchain_validates_ok() {
        assert!(CrossCompileToolchain::FULLY_CONFIGURED.validate().is_ok());
    }

    #[test]
    fn fully_configured_can_build_all() {
        assert!(CrossCompileToolchain::FULLY_CONFIGURED.can_build_all());
    }

    #[test]
    fn hypervisor_only_toolchain_can_build_hypervisor() {
        assert!(CrossCompileToolchain::HYPERVISOR_ONLY.can_build_hypervisor());
    }

    #[test]
    fn hypervisor_only_toolchain_cannot_build_all() {
        assert!(!CrossCompileToolchain::HYPERVISOR_ONLY.can_build_all());
    }

    #[test]
    fn hypervisor_only_toolchain_fails_full_validation() {
        assert_eq!(
            CrossCompileToolchain::HYPERVISOR_ONLY.validate(),
            Err(BuildError::AospBuildEnvNotConfigured)
        );
    }

    #[test]
    fn hypervisor_only_toolchain_passes_hypervisor_validation() {
        assert!(CrossCompileToolchain::HYPERVISOR_ONLY.validate_hypervisor_only().is_ok());
    }

    #[test]
    fn missing_rust_nightly_fails_first() {
        let tc = CrossCompileToolchain {
            rust_nightly_available: false,
            ..CrossCompileToolchain::FULLY_CONFIGURED
        };
        assert_eq!(tc.validate(), Err(BuildError::RustNightlyNotAvailable));
    }

    #[test]
    fn missing_uefi_target_fails_second() {
        let tc = CrossCompileToolchain {
            uefi_target_installed: false,
            ..CrossCompileToolchain::FULLY_CONFIGURED
        };
        assert_eq!(tc.validate(), Err(BuildError::UefiTargetNotInstalled));
    }

    #[test]
    fn missing_cross_toolchain_fails() {
        let tc = CrossCompileToolchain {
            aarch64_cross_toolchain: false,
            ..CrossCompileToolchain::FULLY_CONFIGURED
        };
        assert_eq!(tc.validate(), Err(BuildError::Aarch64CrossToolchainMissing));
    }

    #[test]
    fn missing_rust_src_fails() {
        let tc = CrossCompileToolchain {
            rust_src_component: false,
            ..CrossCompileToolchain::FULLY_CONFIGURED
        };
        assert_eq!(tc.validate(), Err(BuildError::RustSrcComponentMissing));
    }

    // ── BuildStep ─────────────────────────────────────────────────────────────

    #[test]
    fn hypervisor_has_no_prerequisite() {
        assert_eq!(BuildStep::BuildHypervisor.prerequisite(), None);
    }

    #[test]
    fn android_build_depends_on_hypervisor() {
        assert_eq!(
            BuildStep::BuildAndroidImage.prerequisite(),
            Some(BuildStep::BuildHypervisor)
        );
    }

    #[test]
    fn windows_config_depends_on_hypervisor() {
        assert_eq!(
            BuildStep::PrepareWindowsConfig.prerequisite(),
            Some(BuildStep::BuildHypervisor)
        );
    }

    #[test]
    fn package_depends_on_windows_config() {
        assert_eq!(
            BuildStep::PackageRelease.prerequisite(),
            Some(BuildStep::PrepareWindowsConfig)
        );
    }

    #[test]
    fn android_and_windows_can_parallelize() {
        assert!(BuildStep::BuildAndroidImage
            .can_parallelize_with(BuildStep::PrepareWindowsConfig));
        assert!(BuildStep::PrepareWindowsConfig
            .can_parallelize_with(BuildStep::BuildAndroidImage));
    }

    #[test]
    fn hypervisor_cannot_parallelize_with_android() {
        assert!(!BuildStep::BuildHypervisor
            .can_parallelize_with(BuildStep::BuildAndroidImage));
    }

    #[test]
    fn build_steps_table_has_four_entries() {
        assert_eq!(BUILD_STEPS.len(), 4);
    }

    #[test]
    fn build_steps_starts_with_hypervisor() {
        assert_eq!(BUILD_STEPS[0], BuildStep::BuildHypervisor);
    }

    #[test]
    fn build_steps_ends_with_package() {
        assert_eq!(BUILD_STEPS[BUILD_STEPS.len() - 1], BuildStep::PackageRelease);
    }

    // ── EfiOutputFormat ───────────────────────────────────────────────────────

    #[test]
    fn arm_release_efi_format_validates_ok() {
        assert!(EfiOutputFormat::ARM_RELEASE.validate().is_ok());
    }

    #[test]
    fn x86_release_efi_format_validates_ok() {
        assert!(EfiOutputFormat::X86_RELEASE.validate().is_ok());
    }

    #[test]
    fn not_pe32_plus_rejected() {
        let fmt = EfiOutputFormat {
            is_pe32_plus: false,
            ..EfiOutputFormat::ARM_RELEASE
        };
        assert_eq!(fmt.validate(), Err(BuildError::NotPe32Plus));
    }

    #[test]
    fn not_efi_application_rejected() {
        let fmt = EfiOutputFormat {
            is_efi_application: false,
            ..EfiOutputFormat::ARM_RELEASE
        };
        assert_eq!(fmt.validate(), Err(BuildError::NotEfiApplication));
    }

    #[test]
    fn arm_efi_arch_is_aarch64() {
        assert_eq!(EfiOutputFormat::ARM_RELEASE.architecture, EfiArch::Aarch64);
    }

    #[test]
    fn x86_efi_arch_is_x86_64() {
        assert_eq!(EfiOutputFormat::X86_RELEASE.architecture, EfiArch::X86_64);
    }

    // ── BuildSystemConfig ─────────────────────────────────────────────────────

    #[test]
    fn arm_production_config_validates_ok_with_secure_boot() {
        let cfg = BuildSystemConfig {
            windows: WindowsBuildConfig {
                secure_boot_chain_populated: true,
                ..WindowsBuildConfig::DEFAULT
            },
            ..BuildSystemConfig::ARM_PRODUCTION
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn arm_production_config_fails_without_secure_boot() {
        // DEFAULT has secure_boot_chain_populated: false
        assert_eq!(
            BuildSystemConfig::ARM_PRODUCTION.validate(),
            Err(BuildError::SecureBootChainNotPopulated)
        );
    }

    #[test]
    fn tier_architecture_mismatch_rejected() {
        let cfg = BuildSystemConfig {
            hypervisor: HypervisorBuildConfig::ARM_RELEASE,
            expected_efi_format: EfiOutputFormat::X86_RELEASE,
            windows: WindowsBuildConfig {
                secure_boot_chain_populated: true,
                ..WindowsBuildConfig::DEFAULT
            },
            ..BuildSystemConfig::ARM_PRODUCTION
        };
        assert_eq!(cfg.validate(), Err(BuildError::TierArchitectureMismatch));
    }

    // ── BuildSummary ──────────────────────────────────────────────────────────

    #[test]
    fn build_summary_all_ready() {
        let s = BuildSummary {
            hypervisor_config_valid: true,
            android_config_valid: true,
            windows_config_valid: true,
            toolchain_ready: true,
        };
        assert!(s.build_ready());
    }

    #[test]
    fn build_summary_partial_fails() {
        let cases = [
            BuildSummary { hypervisor_config_valid: false, android_config_valid: true,  windows_config_valid: true,  toolchain_ready: true  },
            BuildSummary { hypervisor_config_valid: true,  android_config_valid: false, windows_config_valid: true,  toolchain_ready: true  },
            BuildSummary { hypervisor_config_valid: true,  android_config_valid: true,  windows_config_valid: false, toolchain_ready: true  },
            BuildSummary { hypervisor_config_valid: true,  android_config_valid: true,  windows_config_valid: true,  toolchain_ready: false },
        ];
        for s in &cases {
            assert!(!s.build_ready(), "expected not-ready for {:?}", s);
        }
    }
}
