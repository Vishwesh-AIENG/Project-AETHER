// ch28: The Development Workflow
//
// AETHER development follows a three-tier test loop that keeps iteration speed
// high while still validating against realistic hardware.
//
// ── Three-Tier Development Loop ───────────────────────────────────────────────
//
//   Tier 1 — QEMU + minimal bare-metal guest.  No Android, no Windows.
//             A small ARM64 test binary exercises one hypervisor feature at a
//             time.  Boot time < 5 seconds.  Used for all new feature work.
//
//   Tier 2 — QEMU + real Linux guest (Android Common Kernel).  Validates that
//             real guest software works.  10–30 minutes per cycle.  Used for
//             integration testing after Tier 1 passes.
//
//   Tier 3 — Real Snapdragon X Elite hardware.  SR-IOV testing, performance
//             measurement, hardware-specific validation.  Never used for
//             initial development.
//
// ── QEMU Configuration ────────────────────────────────────────────────────────
//
//   Required flags:
//     -machine virt,gic-version=3,virtualization=on
//       ↑ virtualization=on is mandatory — without it EL2 is inaccessible.
//     -cpu cortex-a76
//     -S -gdb tcp::1234
//       ↑ freeze at startup, wait for GDB/LLDB to connect.
//
//   Full invocation:
//     qemu-system-aarch64 \
//       -machine virt,gic-version=3,virtualization=on \
//       -cpu cortex-a76 -m 8G \
//       -bios OVMF.fd \
//       -drive file=fat:rw:efi_partition/ \
//       -nographic -serial stdio \
//       -monitor telnet::4444,server,nowait \
//       -S -gdb tcp::1234
//
// ── Debug Infrastructure ──────────────────────────────────────────────────────
//
//   Primary:   UART serial output via PL011 at 0x09000000 (QEMU virt machine).
//              AETHER maps the UART early in initialization and writes every
//              major step to serial.  This is the only debug channel available
//              before the MMU and GDB stub are set up.
//
//   Secondary: QEMU GDB remote stub (the -gdb flag).  Connect with:
//                rust-lldb
//                target remote :1234
//                add-symbol-file aether.elf
//              Gives register inspection, memory examination, hardware
//              breakpoints.  Activate after serial output is working.
//
//   Breakpoints: Use HARDWARE breakpoints (hbreak in GDB) before the MMU is
//                configured — software breakpoints overwrite instructions and
//                require write access that may not be available in early boot.
//                ARM64 typically provides 6 hardware breakpoints.
//
// ── Continuous Integration ────────────────────────────────────────────────────
//
//   Per-commit:  cargo check (hypervisor), Tier 1 QEMU test suite (<5 min).
//   Per-PR:      cargo test --lib (hypervisor unit tests), Tier 1 integration.
//   Nightly:     m checkbuild (AOSP build verification — 4+ h, 200+ GB disk).
//   Release:     Full AOSP image build + hardware validation.
//
//   NEVER run a full AOSP build on every commit.  It cannot be a per-commit
//   gate: a full build takes 4–8 hours and requires 200+ GB of disk space.
//
// ── Bisection ─────────────────────────────────────────────────────────────────
//
//   git bisect run make test-tier1
//
//   Every Tier 1 test exits 0 (pass) or non-zero (fail) with no human
//   interaction.  This invariant is required for automated bisection.
//
// ── Snapshot-Based Testing ────────────────────────────────────────────────────
//
//   After a slow initialization sequence (Android boot, 15–30 min), save a
//   QEMU snapshot:  (qemu) savevm checkpoint_post_boot
//   Future test runs restore from the snapshot:  -loadvm checkpoint_post_boot
//   This eliminates repeated boot waits and accelerates the Tier 2 loop.
//
// Primary reference:
//   QEMU docs: qemu.org/docs (System Emulation Guide, qemu-system-aarch64 man)
//   LLDB docs: lldb.llvm.org (remote debugging, ARM64 register commands)

// ─────────────────────────────────────────────────────────────────────────────
// TestTier — the three testing tiers
// ─────────────────────────────────────────────────────────────────────────────

/// The three tiers of the AETHER development and test loop.
///
/// Each tier trades iteration speed for test fidelity.  New feature development
/// always starts at Tier 1 and only advances to higher tiers after the lower
/// tier passes completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestTier {
    /// Tier 1: QEMU + minimal bare-metal ARM64 test guest.
    ///
    /// No Android, no Windows.  A small ARM64 program exercises one hypervisor
    /// feature at a time.  Boot to test result in under 5 seconds.  Run on
    /// every commit in CI; required for `git bisect run` automation.
    QemuMinimal,
    /// Tier 2: QEMU + real Linux kernel guest (Android Common Kernel).
    ///
    /// Validates that real guest software operates correctly with the
    /// hypervisor.  10–30 minutes per cycle.  Run on every pull request.
    QemuLinuxGuest,
    /// Tier 3: Real Snapdragon X Elite hardware.
    ///
    /// Hardware-specific validation: SR-IOV, GPU passthrough, physical NVMe
    /// namespaces, and performance measurement.  Run nightly on a fleet of
    /// physical test machines.  Never used for initial feature development.
    RealHardware,
}

impl TestTier {
    /// Return `true` when this tier can be run in CI on every commit.
    ///
    /// Tier 1 completes in under 5 minutes and requires no physical hardware.
    pub const fn is_per_commit_gate(self) -> bool {
        matches!(self, TestTier::QemuMinimal)
    }

    /// Return `true` when this tier requires physical Snapdragon X Elite hardware.
    pub const fn requires_real_hardware(self) -> bool {
        matches!(self, TestTier::RealHardware)
    }

    /// Return `true` when this tier supports automated bisection via `git bisect run`.
    ///
    /// Only Tier 1 satisfies the bisection requirement: every test exits 0 or
    /// non-zero with no human interaction and in under 5 minutes.
    pub const fn supports_automated_bisection(self) -> bool {
        matches!(self, TestTier::QemuMinimal)
    }

    /// Return the typical wall-clock time for a complete Tier run, in seconds.
    ///
    /// These are order-of-magnitude estimates.  Tier 1 must stay under 300 s
    /// (5 minutes) to be viable as a per-commit CI gate.
    pub const fn typical_duration_seconds(self) -> u32 {
        match self {
            TestTier::QemuMinimal    => 5,     // < 5 s boot to result
            TestTier::QemuLinuxGuest => 1_800, // 10–30 min
            TestTier::RealHardware   => 3_600, // 60+ min including flash cycle
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QemuMachineConfig — QEMU ARM64 system emulation configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the QEMU ARM64 virtual machine used in Tier 1 and Tier 2
/// development.
///
/// The most critical flag is `virtualization_on`: without it QEMU does not
/// expose EL2 to the guest and all hypervisor code fails silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QemuMachineConfig {
    /// GIC version to emulate.
    ///
    /// Must be 3 to match the target Snapdragon X Elite hardware.  Using GICv2
    /// will cause the interrupt handling code to misbehave silently.
    pub gic_version: GicVersion,
    /// Whether EL2 is enabled in the QEMU virtual machine.
    ///
    /// **This must be `true`.**  Without it QEMU runs in EL1 only and the
    /// hypervisor entry point is unreachable.  The flag maps to the QEMU
    /// `-machine virt,...,virtualization=on` option.
    pub virtualization_on: bool,
    /// RAM size in gibibytes.
    ///
    /// 8 GiB matches the default partition budget.  Tier 1 tests can use 1 GiB
    /// to reduce startup time; Tier 2 tests should use 8 GiB to match real
    /// memory pressure.
    pub ram_gib: u8,
    /// Whether to freeze the CPU at startup and wait for a GDB connection.
    ///
    /// Maps to the QEMU `-S` flag.  Set `true` when debugging; `false` for
    /// automated CI runs where no debugger attaches.
    pub freeze_on_start: bool,
    /// TCP port for the GDB remote stub, or `None` to disable.
    ///
    /// Maps to the QEMU `-gdb tcp::<port>` flag.  Conventionally port 1234.
    /// Must be `Some` when `freeze_on_start` is `true`.
    pub gdb_port: Option<u16>,
    /// TCP port for the QEMU monitor, or `None` to disable.
    ///
    /// Maps to `-monitor telnet::<port>,server,nowait`.  Conventionally port
    /// 4444.  Needed to issue `savevm` / `loadvm` snapshot commands.
    pub monitor_port: Option<u16>,
}

/// GIC version emulated by QEMU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    /// GICv2 — NOT suitable for AETHER development.
    ///
    /// AETHER targets GICv3; using GICv2 will cause interrupt routing bugs.
    V2,
    /// GICv3 — the correct version for AETHER development.
    V3,
}

impl QemuMachineConfig {
    /// The standard Tier 1 configuration: GICv3, EL2 enabled, 8 GiB RAM,
    /// GDB stub on port 1234, monitor on port 4444, CPU not frozen (CI mode).
    pub const TIER1_CI: Self = Self {
        gic_version:    GicVersion::V3,
        virtualization_on: true,
        ram_gib:        8,
        freeze_on_start: false,
        gdb_port:       Some(1234),
        monitor_port:   Some(4444),
    };

    /// The standard Tier 1 configuration for interactive debugging.
    ///
    /// Same as `TIER1_CI` but with `freeze_on_start = true` so the CPU halts
    /// at EFI entry waiting for the debugger to attach.
    pub const TIER1_DEBUG: Self = Self {
        freeze_on_start: true,
        ..Self::TIER1_CI
    };

    /// Validate the QEMU machine configuration.
    ///
    /// Rejects configurations that would silently fail:
    /// - `virtualization_on` must be `true` (EL2 required for the hypervisor)
    /// - `gic_version` must be V3 (AETHER targets GICv3 exclusively)
    /// - `freeze_on_start` requires a GDB port to be configured
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if !self.virtualization_on {
            return Err(WorkflowError::QemuVirtualizationDisabled);
        }
        if self.gic_version != GicVersion::V3 {
            return Err(WorkflowError::QemuGicVersionNotV3);
        }
        if self.ram_gib == 0 {
            return Err(WorkflowError::QemuRamZero);
        }
        if self.freeze_on_start && self.gdb_port.is_none() {
            return Err(WorkflowError::FreezeOnStartRequiresGdbPort);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SerialDebugConfig — UART serial output for early-boot diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the UART serial debug output facility.
///
/// Serial output via the PL011 UART is the ONLY reliable debug channel
/// available before the MMU is configured and the GDB stub is active.  AETHER
/// maps the UART at the first instruction of `efi_main` and writes to it at
/// every major initialization step.
///
/// On the QEMU `virt` machine the PL011 UART is at physical address
/// `0x0900_0000`.  On real Snapdragon X Elite hardware the UART address must
/// be read from the ACPI SPCR table or the UEFI config table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialDebugConfig {
    /// Physical address of the PL011 UART MMIO base register.
    ///
    /// On QEMU virt: `0x0900_0000`.
    /// On real hardware: read from ACPI SPCR or UEFI config table.
    pub uart_base_pa: u64,
    /// Baud rate.  PL011 on QEMU ignores this; real hardware requires it.
    pub baud_rate: u32,
    /// Whether serial output is enabled.
    ///
    /// Must be `true` during development.  May be compiled out in a final
    /// production build to reduce code size, but must never be disabled during
    /// the development and integration testing phases.
    pub enabled: bool,
}

impl SerialDebugConfig {
    /// Standard QEMU `virt` machine PL011 UART at `0x0900_0000`, 115200 baud.
    pub const QEMU_VIRT: Self = Self {
        uart_base_pa: 0x0900_0000,
        baud_rate:    115_200,
        enabled:      true,
    };

    /// Validate the serial debug configuration.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.uart_base_pa == 0 {
            return Err(WorkflowError::SerialUartBaseZero);
        }
        if self.baud_rate == 0 {
            return Err(WorkflowError::SerialBaudRateZero);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakpointKind — hardware vs software breakpoints
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of debugger breakpoint to use at a given execution phase.
///
/// Software breakpoints overwrite the target instruction with a `BRK`
/// instruction.  Before the MMU is configured, the breakpoint write may not
/// reach executable memory correctly — the instruction cache may still hold
/// the original bytes, and the memory region might not be mapped writable.
/// Hardware breakpoints use dedicated BKPT registers and never modify code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// Hardware breakpoints — use before and during MMU configuration.
    ///
    /// ARM64 provides at least 2 and typically 6 hardware breakpoints
    /// (`BRPS` field of `ID_AA64DFR0_EL1`).  In GDB: `hbreak <symbol>`.
    /// In LLDB: `breakpoint set --hardware`.
    ///
    /// Required for all EL2 code paths before `SCTLR_EL2.M = 1`.
    Hardware,
    /// Software breakpoints — safe only after the MMU is on and the code
    /// segment is mapped as read-execute (not writable).
    ///
    /// After MMU configuration, software breakpoints are safe for EL1 guest
    /// code (the hypervisor does not use them on its own code paths).
    Software,
}

impl BreakpointKind {
    /// Return `true` when this breakpoint kind is safe for early EL2 boot code
    /// (before `SCTLR_EL2.M = 1` enables the MMU).
    pub const fn is_safe_before_mmu(self) -> bool {
        matches!(self, BreakpointKind::Hardware)
    }

    /// Return the GDB command prefix for this breakpoint kind.
    ///
    /// Use `hbreak <symbol>` for hardware breakpoints and `break <symbol>` for
    /// software breakpoints.
    pub const fn gdb_command_prefix(self) -> &'static str {
        match self {
            BreakpointKind::Hardware => "hbreak",
            BreakpointKind::Software => "break",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebuggerConfig — GDB/LLDB remote debugging configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for remote GDB/LLDB debugging of the AETHER hypervisor via
/// the QEMU GDB stub.
///
/// Connect with `rust-lldb` or `rust-gdb`, then:
///   `target remote :<gdb_port>`
///   `add-symbol-file aether.elf`
///
/// Always use hardware breakpoints (`hbreak` / `breakpoint set --hardware`)
/// for EL2 code paths before the MMU is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebuggerConfig {
    /// The GDB remote stub port (must match `QemuMachineConfig::gdb_port`).
    pub remote_port: u16,
    /// The breakpoint kind to use for early-boot EL2 code.
    ///
    /// Must be `Hardware` for any breakpoint set before `SCTLR_EL2.M = 1`.
    pub early_boot_breakpoint_kind: BreakpointKind,
}

impl DebuggerConfig {
    /// Standard debugger configuration: port 1234, hardware breakpoints.
    pub const DEFAULT: Self = Self {
        remote_port:                 1234,
        early_boot_breakpoint_kind:  BreakpointKind::Hardware,
    };

    /// Validate the debugger configuration.
    ///
    /// Rejects software breakpoints for early-boot code — they are unsafe
    /// before the MMU is on and produce misleading debug sessions.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.remote_port == 0 {
            return Err(WorkflowError::DebuggerPortZero);
        }
        if !self.early_boot_breakpoint_kind.is_safe_before_mmu() {
            return Err(WorkflowError::SoftwareBreakpointInEarlyBoot);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CiStage — CI pipeline stages and their scheduling constraints
// ─────────────────────────────────────────────────────────────────────────────

/// A stage in the AETHER continuous integration pipeline.
///
/// Stages are ordered by speed and resource cost.  Fast, cheap stages run on
/// every commit; slow, expensive stages run on a schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiStage {
    /// `cargo check` on the hypervisor crate — type-checks without codegen.
    ///
    /// Completes in ~10–30 s.  Run on every commit.  A failing check means the
    /// code does not type-check and must not be merged.
    CargoCheck,
    /// `cargo test --lib` on the hypervisor crate — runs unit tests on the host.
    ///
    /// Completes in ~30–60 s.  Run on every pull request.  Tests in `#[cfg(test)]`
    /// blocks exercise pure logic that does not require bare-metal hardware.
    CargoTestLib,
    /// QEMU Tier 1 integration test suite.
    ///
    /// Boots the hypervisor with a minimal bare-metal guest in QEMU and asserts
    /// boot milestones.  Completes in under 5 minutes.  Run on every pull request.
    /// Required to pass before merge.
    QemuTier1,
    /// AOSP `m checkbuild` — verifies that the Android image compiles.
    ///
    /// Takes 4+ hours and requires 200+ GB of disk.  Run nightly only.
    /// **Never run on every commit** — it is not a per-commit gate.
    AospCheckBuild,
    /// Full AOSP image build + hardware boot test on real Snapdragon X Elite.
    ///
    /// Run on release branches only.  Produces the flashable release artifacts.
    FullReleaseBuild,
}

impl CiStage {
    /// Return `true` when this stage is run on every commit (not just PRs/nightly).
    pub const fn is_per_commit(self) -> bool {
        matches!(self, CiStage::CargoCheck)
    }

    /// Return `true` when this stage is run on every pull request.
    pub const fn is_per_pr(self) -> bool {
        matches!(
            self,
            CiStage::CargoCheck | CiStage::CargoTestLib | CiStage::QemuTier1
        )
    }

    /// Return `true` when this stage runs on a nightly schedule only.
    ///
    /// Nightly stages are too slow or resource-intensive to gate every commit or PR.
    pub const fn is_nightly(self) -> bool {
        matches!(self, CiStage::AospCheckBuild)
    }

    /// Return `true` when this stage requires physical Snapdragon X Elite hardware.
    pub const fn requires_real_hardware(self) -> bool {
        matches!(self, CiStage::FullReleaseBuild)
    }

    /// Return the approximate wall-clock duration for this stage in seconds.
    ///
    /// Used to verify the CI ladder has no per-commit stages exceeding 5 minutes.
    pub const fn typical_duration_seconds(self) -> u32 {
        match self {
            CiStage::CargoCheck       => 30,
            CiStage::CargoTestLib     => 60,
            CiStage::QemuTier1        => 300,     // must stay < 5 min
            CiStage::AospCheckBuild   => 14_400,  // ~4 h
            CiStage::FullReleaseBuild => 28_800,  // ~8 h
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CiPipeline — complete CI configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The complete CI pipeline configuration for AETHER.
///
/// Three ladder levels: per-commit (fast), per-PR (medium), nightly (slow).
/// The tiered approach ensures developers get rapid feedback without blocking
/// on slow AOSP or hardware steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiPipeline {
    /// Whether `cargo check` is enabled as a per-commit gate.
    ///
    /// Must be `true`.  Catching type errors on every commit prevents broken
    /// code from accumulating in shared branches.
    pub cargo_check_on_commit: bool,
    /// Whether `cargo test --lib` is enabled as a per-PR gate.
    ///
    /// Must be `true`.  Unit tests run in seconds and catch logic regressions.
    pub cargo_test_on_pr: bool,
    /// Whether the QEMU Tier 1 test suite is enabled as a per-PR gate.
    ///
    /// Must be `true`.  The Tier 1 suite boots the hypervisor in QEMU and is
    /// the primary regression guard before merge.
    pub qemu_tier1_on_pr: bool,
    /// Whether AOSP `m checkbuild` is scheduled nightly.
    ///
    /// Should be `true` for an active development team.  Catches AOSP
    /// build-system regressions before they accumulate.  Cannot run per-commit.
    pub aosp_checkbuild_nightly: bool,
    /// Maximum allowed duration for per-commit CI stages, in seconds.
    ///
    /// All per-commit and per-PR stages must complete within this budget.
    /// Default: 300 s (5 minutes).  Exceeding this causes developers to skip CI.
    pub per_commit_budget_seconds: u32,
}

impl CiPipeline {
    /// The recommended CI pipeline configuration for active AETHER development.
    pub const RECOMMENDED: Self = Self {
        cargo_check_on_commit:      true,
        cargo_test_on_pr:           true,
        qemu_tier1_on_pr:           true,
        aosp_checkbuild_nightly:    true,
        per_commit_budget_seconds:  300,
    };

    /// Validate the CI pipeline configuration.
    ///
    /// Rejects pipelines that are missing required gates or have stages that
    /// exceed the per-commit time budget.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if !self.cargo_check_on_commit {
            return Err(WorkflowError::CargoCheckNotGated);
        }
        if !self.cargo_test_on_pr {
            return Err(WorkflowError::CargoTestNotGated);
        }
        if !self.qemu_tier1_on_pr {
            return Err(WorkflowError::QemuTier1NotGated);
        }
        if self.per_commit_budget_seconds == 0 {
            return Err(WorkflowError::PerCommitBudgetZero);
        }
        // Tier 1 must fit within the per-commit time budget
        if CiStage::QemuTier1.typical_duration_seconds() > self.per_commit_budget_seconds {
            return Err(WorkflowError::Tier1ExceedsPerCommitBudget {
                tier1_seconds: CiStage::QemuTier1.typical_duration_seconds(),
                budget_seconds: self.per_commit_budget_seconds,
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BisectionConfig — automated git bisect configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for automated regression bisection.
///
/// `git bisect run <command>` requires that each test invocation:
/// - Exits 0 on pass (the commit is good).
/// - Exits non-zero on fail (the commit is bad).
/// - Requires no human interaction.
/// - Completes in a reasonable time per commit.
///
/// The Tier 1 QEMU test suite is the bisection vehicle.  Every test must
/// satisfy the exit-code contract and the time budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BisectionConfig {
    /// Whether the Tier 1 test suite satisfies the automated bisection contract.
    ///
    /// Must be `true`: every test exits 0 or non-zero without human interaction.
    /// Any test that blocks on user input or produces an ambiguous exit code
    /// breaks `git bisect run` and must be fixed before enabling bisection.
    pub tier1_satisfies_bisection_contract: bool,
    /// Maximum seconds allowed per bisection step (one commit tested).
    ///
    /// At 300 s per step, a 10-commit range takes ~50 minutes.  Beyond 600 s
    /// per step, bisection becomes impractical on a typical workday.
    pub max_seconds_per_step: u32,
}

impl BisectionConfig {
    /// The standard bisection configuration.
    pub const DEFAULT: Self = Self {
        tier1_satisfies_bisection_contract: true,
        max_seconds_per_step: 300,
    };

    /// Validate the bisection configuration.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if !self.tier1_satisfies_bisection_contract {
            return Err(WorkflowError::BisectionContractNotSatisfied);
        }
        if self.max_seconds_per_step == 0 {
            return Err(WorkflowError::BisectionBudgetZero);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotConfig — QEMU savestate snapshot-based testing
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for QEMU savestate snapshots used to accelerate Tier 2
/// (Linux guest) test cycles.
///
/// After a slow initialization sequence (e.g., a 20-minute Android boot), a
/// QEMU snapshot captures the full machine state.  Future test runs restore
/// from the snapshot and reach post-boot state in seconds.
///
/// Snapshot workflow:
/// 1. Boot QEMU with `-monitor telnet::4444,server,nowait`
/// 2. Wait for Android to finish booting
/// 3. Connect to the monitor: `telnet localhost 4444`
/// 4. Issue: `savevm <name>` (e.g., `savevm android_post_boot`)
/// 5. Future runs: add `-loadvm android_post_boot` to the QEMU command line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Whether snapshot-based testing is enabled for Tier 2 tests.
    ///
    /// Requires the QEMU monitor to be enabled
    /// (`QemuMachineConfig::monitor_port` must be `Some`).
    pub enabled: bool,
    /// The name of the reference snapshot to restore from in Tier 2 test runs.
    ///
    /// Conventionally `"android_post_boot"` or `"linux_post_boot"`.
    pub snapshot_name: &'static str,
}

impl SnapshotConfig {
    /// Snapshot configuration targeting an Android post-boot checkpoint.
    pub const ANDROID_POST_BOOT: Self = Self {
        enabled:       true,
        snapshot_name: "android_post_boot",
    };

    /// Validate the snapshot configuration.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.enabled && self.snapshot_name.is_empty() {
            return Err(WorkflowError::SnapshotNameEmpty);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowConfig — complete development workflow configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The complete development workflow configuration for AETHER.
///
/// Aggregates the QEMU machine, serial debug, debugger, CI pipeline,
/// bisection, and snapshot configurations.  `validate()` checks every
/// subsystem before a development session begins.
#[derive(Debug)]
pub struct WorkflowConfig {
    /// QEMU machine configuration for Tier 1 and Tier 2 development.
    pub qemu: QemuMachineConfig,
    /// Serial UART debug output configuration.
    pub serial: SerialDebugConfig,
    /// Remote GDB/LLDB debugger configuration.
    pub debugger: DebuggerConfig,
    /// Continuous integration pipeline configuration.
    pub ci: CiPipeline,
    /// Automated regression bisection configuration.
    pub bisection: BisectionConfig,
    /// QEMU snapshot configuration for Tier 2 acceleration.
    pub snapshot: SnapshotConfig,
}

impl WorkflowConfig {
    /// The recommended workflow configuration for AETHER development.
    ///
    /// QEMU Tier 1 CI mode (no freeze), PL011 UART at QEMU `virt` address,
    /// hardware breakpoints, all CI gates enabled, Tier 1 bisection, Android
    /// post-boot snapshot.
    pub const RECOMMENDED: Self = Self {
        qemu:      QemuMachineConfig::TIER1_CI,
        serial:    SerialDebugConfig::QEMU_VIRT,
        debugger:  DebuggerConfig::DEFAULT,
        ci:        CiPipeline::RECOMMENDED,
        bisection: BisectionConfig::DEFAULT,
        snapshot:  SnapshotConfig::ANDROID_POST_BOOT,
    };

    /// Validate the complete workflow configuration.
    ///
    /// Checks (in order):
    ///   1. QEMU machine configuration (EL2 enabled, GICv3, non-zero RAM).
    ///   2. Serial debug configuration (non-zero UART base and baud rate).
    ///   3. Debugger configuration (hardware breakpoints for early boot).
    ///   4. CI pipeline (all required gates present, Tier 1 within time budget).
    ///   5. Bisection configuration (contract satisfied, non-zero budget).
    ///   6. Snapshot configuration (name non-empty when enabled).
    pub fn validate(&self) -> Result<(), WorkflowError> {
        self.qemu.validate()?;
        self.serial.validate()?;
        self.debugger.validate()?;
        self.ci.validate()?;
        self.bisection.validate()?;
        self.snapshot.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowSummary — workflow readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level development workflow readiness gate.
///
/// `workflow_ready()` returns `true` only when all four pillars of the
/// development workflow are in place: QEMU environment is valid, serial debug
/// is configured, CI is fully gated, and bisection is ready.
#[derive(Debug)]
pub struct WorkflowSummary {
    /// True when the QEMU configuration is valid (EL2 on, GICv3).
    pub qemu_valid: bool,
    /// True when the serial debug infrastructure is configured.
    pub serial_configured: bool,
    /// True when all required CI gates are in place.
    pub ci_gates_complete: bool,
    /// True when the Tier 1 test suite satisfies the bisection contract.
    pub bisection_ready: bool,
}

impl WorkflowSummary {
    /// Return `true` when all workflow preconditions are met.
    pub fn workflow_ready(&self) -> bool {
        self.qemu_valid
            && self.serial_configured
            && self.ci_gates_complete
            && self.bisection_ready
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowError — errors returned by workflow configuration validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by development workflow configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowError {
    /// QEMU `virtualization=on` is not set.
    ///
    /// Without this flag EL2 is inaccessible and the hypervisor entry point
    /// is unreachable.  This error produces silent failures — the QEMU VM
    /// boots but never reaches EL2.
    QemuVirtualizationDisabled,
    /// QEMU GIC version is not V3.
    ///
    /// AETHER targets GICv3 exclusively.  Using GICv2 causes interrupt routing
    /// bugs that may not be immediately obvious.
    QemuGicVersionNotV3,
    /// QEMU RAM is zero.
    QemuRamZero,
    /// `freeze_on_start = true` requires a GDB port to be configured.
    ///
    /// A frozen CPU with no GDB port produces a VM that cannot be debugged and
    /// cannot be escaped without a hard kill.
    FreezeOnStartRequiresGdbPort,
    /// Serial UART base address is zero.
    SerialUartBaseZero,
    /// Serial baud rate is zero.
    SerialBaudRateZero,
    /// Debugger remote port is zero.
    DebuggerPortZero,
    /// Software breakpoints are configured for early-boot EL2 code.
    ///
    /// Software breakpoints are unsafe before the MMU is on.  They overwrite
    /// instructions with `BRK` bytes; the instruction cache may not observe the
    /// write, and the memory region may not be mapped writable.  Use hardware
    /// breakpoints (`hbreak` / `breakpoint set --hardware`) instead.
    SoftwareBreakpointInEarlyBoot,
    /// `cargo check` is not configured as a per-commit CI gate.
    CargoCheckNotGated,
    /// `cargo test --lib` is not configured as a per-PR CI gate.
    CargoTestNotGated,
    /// QEMU Tier 1 is not configured as a per-PR CI gate.
    QemuTier1NotGated,
    /// Per-commit CI budget is zero seconds.
    PerCommitBudgetZero,
    /// The Tier 1 test suite exceeds the per-commit time budget.
    ///
    /// A CI stage that takes longer than the budget will be skipped by
    /// developers under time pressure, defeating its purpose.
    Tier1ExceedsPerCommitBudget {
        /// Actual Tier 1 duration in seconds.
        tier1_seconds: u32,
        /// Configured budget in seconds.
        budget_seconds: u32,
    },
    /// The Tier 1 test suite does not satisfy the automated bisection contract.
    ///
    /// Every test must exit 0 (good) or non-zero (bad) with no human
    /// interaction.  Any test that blocks, produces ambiguous output, or
    /// requires manual inspection breaks `git bisect run`.
    BisectionContractNotSatisfied,
    /// Bisection per-step time budget is zero.
    BisectionBudgetZero,
    /// Snapshot name is empty when snapshots are enabled.
    SnapshotNameEmpty,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TestTier ──────────────────────────────────────────────────────────────

    #[test]
    fn tier1_is_per_commit_gate() {
        assert!(TestTier::QemuMinimal.is_per_commit_gate());
        assert!(!TestTier::QemuLinuxGuest.is_per_commit_gate());
        assert!(!TestTier::RealHardware.is_per_commit_gate());
    }

    #[test]
    fn only_real_hardware_tier_requires_hardware() {
        assert!(!TestTier::QemuMinimal.requires_real_hardware());
        assert!(!TestTier::QemuLinuxGuest.requires_real_hardware());
        assert!(TestTier::RealHardware.requires_real_hardware());
    }

    #[test]
    fn only_tier1_supports_automated_bisection() {
        assert!(TestTier::QemuMinimal.supports_automated_bisection());
        assert!(!TestTier::QemuLinuxGuest.supports_automated_bisection());
        assert!(!TestTier::RealHardware.supports_automated_bisection());
    }

    #[test]
    fn tier1_duration_under_five_minutes() {
        assert!(TestTier::QemuMinimal.typical_duration_seconds() < 300);
    }

    // ── QemuMachineConfig ─────────────────────────────────────────────────────

    #[test]
    fn tier1_ci_config_validates_ok() {
        assert!(QemuMachineConfig::TIER1_CI.validate().is_ok());
    }

    #[test]
    fn tier1_debug_config_validates_ok() {
        assert!(QemuMachineConfig::TIER1_DEBUG.validate().is_ok());
    }

    #[test]
    fn qemu_without_virtualization_rejected() {
        let cfg = QemuMachineConfig {
            virtualization_on: false,
            ..QemuMachineConfig::TIER1_CI
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::QemuVirtualizationDisabled));
    }

    #[test]
    fn qemu_gicv2_rejected() {
        let cfg = QemuMachineConfig {
            gic_version: GicVersion::V2,
            ..QemuMachineConfig::TIER1_CI
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::QemuGicVersionNotV3));
    }

    #[test]
    fn qemu_zero_ram_rejected() {
        let cfg = QemuMachineConfig {
            ram_gib: 0,
            ..QemuMachineConfig::TIER1_CI
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::QemuRamZero));
    }

    #[test]
    fn freeze_without_gdb_port_rejected() {
        let cfg = QemuMachineConfig {
            freeze_on_start: true,
            gdb_port: None,
            ..QemuMachineConfig::TIER1_CI
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::FreezeOnStartRequiresGdbPort));
    }

    #[test]
    fn freeze_with_gdb_port_validates_ok() {
        let cfg = QemuMachineConfig {
            freeze_on_start: true,
            gdb_port: Some(1234),
            ..QemuMachineConfig::TIER1_CI
        };
        assert!(cfg.validate().is_ok());
    }

    // ── GicVersion ────────────────────────────────────────────────────────────

    #[test]
    fn gicv3_is_required_for_aether() {
        assert_eq!(QemuMachineConfig::TIER1_CI.gic_version, GicVersion::V3);
    }

    // ── SerialDebugConfig ─────────────────────────────────────────────────────

    #[test]
    fn qemu_virt_serial_validates_ok() {
        assert!(SerialDebugConfig::QEMU_VIRT.validate().is_ok());
    }

    #[test]
    fn serial_uart_base_zero_rejected() {
        let cfg = SerialDebugConfig {
            uart_base_pa: 0,
            ..SerialDebugConfig::QEMU_VIRT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::SerialUartBaseZero));
    }

    #[test]
    fn serial_baud_rate_zero_rejected() {
        let cfg = SerialDebugConfig {
            baud_rate: 0,
            ..SerialDebugConfig::QEMU_VIRT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::SerialBaudRateZero));
    }

    #[test]
    fn serial_uart_base_is_pl011_qemu_virt() {
        assert_eq!(SerialDebugConfig::QEMU_VIRT.uart_base_pa, 0x0900_0000);
    }

    // ── BreakpointKind ────────────────────────────────────────────────────────

    #[test]
    fn hardware_breakpoint_is_safe_before_mmu() {
        assert!(BreakpointKind::Hardware.is_safe_before_mmu());
    }

    #[test]
    fn software_breakpoint_not_safe_before_mmu() {
        assert!(!BreakpointKind::Software.is_safe_before_mmu());
    }

    #[test]
    fn hardware_breakpoint_gdb_command_prefix() {
        assert_eq!(BreakpointKind::Hardware.gdb_command_prefix(), "hbreak");
    }

    #[test]
    fn software_breakpoint_gdb_command_prefix() {
        assert_eq!(BreakpointKind::Software.gdb_command_prefix(), "break");
    }

    // ── DebuggerConfig ────────────────────────────────────────────────────────

    #[test]
    fn default_debugger_validates_ok() {
        assert!(DebuggerConfig::DEFAULT.validate().is_ok());
    }

    #[test]
    fn debugger_port_zero_rejected() {
        let cfg = DebuggerConfig {
            remote_port: 0,
            ..DebuggerConfig::DEFAULT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::DebuggerPortZero));
    }

    #[test]
    fn software_breakpoint_early_boot_rejected() {
        let cfg = DebuggerConfig {
            early_boot_breakpoint_kind: BreakpointKind::Software,
            ..DebuggerConfig::DEFAULT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::SoftwareBreakpointInEarlyBoot));
    }

    #[test]
    fn debugger_default_port_is_1234() {
        assert_eq!(DebuggerConfig::DEFAULT.remote_port, 1234);
    }

    // ── CiStage ───────────────────────────────────────────────────────────────

    #[test]
    fn cargo_check_is_per_commit() {
        assert!(CiStage::CargoCheck.is_per_commit());
        assert!(!CiStage::CargoTestLib.is_per_commit());
        assert!(!CiStage::QemuTier1.is_per_commit());
    }

    #[test]
    fn cargo_check_is_per_pr() {
        assert!(CiStage::CargoCheck.is_per_pr());
    }

    #[test]
    fn cargo_test_lib_is_per_pr() {
        assert!(CiStage::CargoTestLib.is_per_pr());
    }

    #[test]
    fn qemu_tier1_is_per_pr() {
        assert!(CiStage::QemuTier1.is_per_pr());
    }

    #[test]
    fn aosp_checkbuild_is_nightly() {
        assert!(CiStage::AospCheckBuild.is_nightly());
        assert!(!CiStage::CargoCheck.is_nightly());
    }

    #[test]
    fn only_full_release_requires_real_hardware() {
        assert!(CiStage::FullReleaseBuild.requires_real_hardware());
        assert!(!CiStage::QemuTier1.requires_real_hardware());
    }

    #[test]
    fn qemu_tier1_stage_under_five_minutes() {
        assert!(CiStage::QemuTier1.typical_duration_seconds() <= 300);
    }

    #[test]
    fn aosp_checkbuild_far_exceeds_five_minutes() {
        assert!(CiStage::AospCheckBuild.typical_duration_seconds() > 300);
    }

    // ── CiPipeline ────────────────────────────────────────────────────────────

    #[test]
    fn recommended_pipeline_validates_ok() {
        assert!(CiPipeline::RECOMMENDED.validate().is_ok());
    }

    #[test]
    fn pipeline_without_cargo_check_rejected() {
        let cfg = CiPipeline {
            cargo_check_on_commit: false,
            ..CiPipeline::RECOMMENDED
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::CargoCheckNotGated));
    }

    #[test]
    fn pipeline_without_cargo_test_rejected() {
        let cfg = CiPipeline {
            cargo_test_on_pr: false,
            ..CiPipeline::RECOMMENDED
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::CargoTestNotGated));
    }

    #[test]
    fn pipeline_without_qemu_tier1_rejected() {
        let cfg = CiPipeline {
            qemu_tier1_on_pr: false,
            ..CiPipeline::RECOMMENDED
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::QemuTier1NotGated));
    }

    #[test]
    fn pipeline_zero_budget_rejected() {
        let cfg = CiPipeline {
            per_commit_budget_seconds: 0,
            ..CiPipeline::RECOMMENDED
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::PerCommitBudgetZero));
    }

    #[test]
    fn pipeline_budget_smaller_than_tier1_rejected() {
        let cfg = CiPipeline {
            per_commit_budget_seconds: 10, // Tier 1 needs 300 s
            ..CiPipeline::RECOMMENDED
        };
        assert_eq!(
            cfg.validate(),
            Err(WorkflowError::Tier1ExceedsPerCommitBudget {
                tier1_seconds: 300,
                budget_seconds: 10,
            })
        );
    }

    // ── BisectionConfig ───────────────────────────────────────────────────────

    #[test]
    fn default_bisection_validates_ok() {
        assert!(BisectionConfig::DEFAULT.validate().is_ok());
    }

    #[test]
    fn bisection_contract_not_satisfied_rejected() {
        let cfg = BisectionConfig {
            tier1_satisfies_bisection_contract: false,
            ..BisectionConfig::DEFAULT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::BisectionContractNotSatisfied));
    }

    #[test]
    fn bisection_budget_zero_rejected() {
        let cfg = BisectionConfig {
            max_seconds_per_step: 0,
            ..BisectionConfig::DEFAULT
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::BisectionBudgetZero));
    }

    // ── SnapshotConfig ────────────────────────────────────────────────────────

    #[test]
    fn android_post_boot_snapshot_validates_ok() {
        assert!(SnapshotConfig::ANDROID_POST_BOOT.validate().is_ok());
    }

    #[test]
    fn snapshot_enabled_with_empty_name_rejected() {
        let cfg = SnapshotConfig {
            enabled: true,
            snapshot_name: "",
        };
        assert_eq!(cfg.validate(), Err(WorkflowError::SnapshotNameEmpty));
    }

    #[test]
    fn snapshot_disabled_with_empty_name_ok() {
        let cfg = SnapshotConfig {
            enabled: false,
            snapshot_name: "",
        };
        assert!(cfg.validate().is_ok());
    }

    // ── WorkflowConfig ────────────────────────────────────────────────────────

    #[test]
    fn recommended_workflow_validates_ok() {
        assert!(WorkflowConfig::RECOMMENDED.validate().is_ok());
    }

    // ── WorkflowSummary ───────────────────────────────────────────────────────

    #[test]
    fn workflow_summary_all_ready() {
        let s = WorkflowSummary {
            qemu_valid:          true,
            serial_configured:   true,
            ci_gates_complete:   true,
            bisection_ready:     true,
        };
        assert!(s.workflow_ready());
    }

    #[test]
    fn workflow_summary_partial_not_ready() {
        let cases = [
            WorkflowSummary { qemu_valid: false, serial_configured: true,  ci_gates_complete: true,  bisection_ready: true  },
            WorkflowSummary { qemu_valid: true,  serial_configured: false, ci_gates_complete: true,  bisection_ready: true  },
            WorkflowSummary { qemu_valid: true,  serial_configured: true,  ci_gates_complete: false, bisection_ready: true  },
            WorkflowSummary { qemu_valid: true,  serial_configured: true,  ci_gates_complete: true,  bisection_ready: false },
        ];
        for s in &cases {
            assert!(!s.workflow_ready(), "expected not-ready for {:?}", s);
        }
    }
}
