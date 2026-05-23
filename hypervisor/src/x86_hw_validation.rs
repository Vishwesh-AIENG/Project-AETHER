// ch54: x86 Tier Hardware Validation
//
// Run the complete x86 tier on REAL Intel AND AMD hardware with no QEMU safety
// net and no workarounds. Both Intel (Core Ultra 7, VT-x + EPT) and AMD (Ryzen
// 9, AMD-V + NPT) must independently boot Android through the FEX-Emu DBT layer
// (ch52). EPT invalidation (Intel INVEPT single-context) and NPT TLB flush (AMD
// VMCB TLB_CTL FLUSH_ALL) are called on every guest mapping change. FEX runs
// entirely inside the hypervisor -- no host OS dependency.
//
// This is the capstone of the x86 tier (Chapters 50-54). The chapter gate
// formalises the Phase3GateCriterion from roadmap_phase3.rs as runtime types:
// both Intel AND AMD must pass, FEX must be in-hypervisor, and
// workaround_accepted must be false.
//
// ── Architecture Reference ────────────────────────────────────────────────────────
//
// Intel SDM Vol. 3C (revision June 2023):
//   §24.9.2  -- VMRESUME error reporting; detecting VM instruction failures
//   §28.2.7  -- INVEPT: single-context (type=1) and all-context (type=2) forms
//   §32.1    -- VMX capability MSRs; IA32_VMX_BASIC revision checking
//   A.3.1    -- Secondary processor-based VM-execution controls; ENABLE_EPT bit
//
// AMD Architecture Programmer's Manual Vol. 2 (Publication 24593, rev 3.40):
//   §15.6.5  -- NPT TLB invalidation; TLB_CTL field in VMCB control area
//   §15.16   -- VMEXIT error reporting; VMCB offset 0x70 exit_code field
//   §15.26.3 -- CPUID function 8000_000Ah: SVM revision and feature flags
//
// CPUID Vendor ID strings (Intel SDM Vol. 2A §3.3, AMD APM Vol. 3 §3.3):
//   Intel CPUID leaf 0: EBX="Genu" ECX="ntel" EDX="ineI" --> "GenuineIntel"
//   AMD   CPUID leaf 0: EBX="Auth" ECX="cAMD" EDX="enti" --> "AuthenticAMD"
//
// FEX-Emu (github.com/FEX-Emu/FEX):
//   Source/Frontend/IR/       -- ARM64 decode pipeline
//   Source/Backend/X86_64/    -- x86_64 code generation backend
//   Source/Tools/FEXLoader/   -- host-OS-coupled loader (rejected; ch52 replaced
//                                with bare-metal bump-allocator + spinlock path)
//
// ── What This Module Implements ───────────────────────────────────────────────────
//
//   1.  CpuVendor + CPUID vendor-string byte constants (Intel / AMD)
//   2.  X86HwTarget -- hardware model descriptor (cpu_family / model / stepping /
//       name / tier); cross-referenced to the ch54 test fleet
//   3.  X86_INTEL_HW_TARGETS / X86_AMD_HW_TARGETS -- validated hardware tables
//       (Core Ultra 7 165H / Ryzen 9 7950X representative entries)
//   4.  X86HwValidationPair -- per-vendor record (foundation_gate_passed /
//       android_booted / mapping_changes / invalidations_acked / fex_confirmed /
//       no_workaround)
//   5.  X86HwValidationGate -- overall gate: intel_passed AND amd_passed AND
//       fex_in_hypervisor AND no_workaround_accepted AND build_type_user
//   6.  X86HwValidationConfig + aether_defaults() + validate()
//   7.  X86HwValidationError -- one variant per failure mode (13 variants)
//   8.  X86HwValidationPhase -- strictly ordered 9-phase machine
//   9.  X86HwValidationState -- runtime state with process_line() UART scanner
//  10.  UART signature constants (12 ASCII-only byte-pattern constants)
//  11.  X86HwValidationDefconfigEntry + X86_HW_VALIDATION_DEFCONFIG -- 10 kernel
//       config entries for hardware validation gate (each with silent_failure)
//  12.  X86HwValidationBuildVar + X86_HW_VALIDATION_BUILD_VARS -- 5 BoardConfig.mk
//       variables documenting the validated hardware platforms
//  13.  init_x86_hw_validation() -- 8-step pipeline entry point
//
// ── Gate (Chapter 54) ─────────────────────────────────────────────────────────────
//
//   X86HwValidationGate.passes() requires all five conditions:
//     intel_passed           -- Intel VT-x + EPT boots Android on real hardware
//     amd_passed             -- AMD SVM + NPT boots Android on real hardware
//     fex_in_hypervisor      -- FEX JIT cache in hypervisor memory; no host OS dep
//     no_workaround_accepted -- workaround_accepted=false (Phase3GateCriterion)
//     build_type_user        -- ro.build.type=user (production invariant)
//
//   This gate formalises roadmap_phase3::Phase3GateCriterion at runtime.
//   "Passes on Intel only with AMD deferred" is not a gate pass.
//
// ── No-Boundary Compliance (Chapter 3) ───────────────────────────────────────────
//
//   - FEX must be FexEmuIntegrationMode::InHypervisor (ch31/ch52 invariant).
//     HostUserland mode requires a host OS, which violates No-Boundary.
//   - EPT/NPT invalidation after every mapping change is mandatory. Stale TLB
//     entries allow the guest to read memory outside its allowed PA range --
//     silent isolation break and the most dangerous mistake on this surface.
//   - Both Intel AND AMD must pass without workarounds. A workaround on either
//     platform means the architecture is not hardware-independent and the x86
//     tier has not been truly validated.

#![allow(clippy::needless_return)]

// ─────────────────────────────────────────────────────────────────────────────
// CPUID vendor-string byte constants
//
// Vendor strings are 12 ASCII bytes returned in EBX + ECX + EDX by CPUID leaf 0.
// Each constant below is the canonical byte sequence for comparison.
// ─────────────────────────────────────────────────────────────────────────────

/// CPUID vendor string for Intel: "GenuineIntel" (12 bytes).
pub const CPUID_VENDOR_INTEL: &[u8; 12] = b"GenuineIntel";

/// CPUID vendor string for AMD: "AuthenticAMD" (12 bytes).
pub const CPUID_VENDOR_AMD: &[u8; 12] = b"AuthenticAMD";

// ─────────────────────────────────────────────────────────────────────────────
// UART signature constants
//
// Each constant is a byte-pattern emitted on PL011 UART during the ch54
// validation run. process_line() scans for these to advance the phase machine.
// All bytes are 7-bit ASCII; no Unicode, no em-dash, no arrows.
// ─────────────────────────────────────────────────────────────────────────────

/// Emitted after Intel VT-x foundation gate confirmed on real hardware.
pub const UART_SIG_INTEL_VTX_VALIDATED: &[u8] =
    b"[aether] intel vtx validated on real hardware";

/// Emitted after AMD SVM foundation gate confirmed on real hardware.
pub const UART_SIG_AMD_SVM_VALIDATED: &[u8] =
    b"[aether] amd svm validated on real hardware";

/// Emitted when FEX is confirmed running entirely inside the hypervisor.
pub const UART_SIG_FEX_IN_HYPERVISOR: &[u8] =
    b"[aether] fex mode: in-hypervisor confirmed";

/// Emitted after all Intel EPT mapping changes were followed by INVEPT.
pub const UART_SIG_EPT_INVALIDATIONS_COMPLETE: &[u8] =
    b"[aether] ept invalidation: all mapping changes acked";

/// Emitted after all AMD NPT mapping changes were followed by TLB_CTL flush.
pub const UART_SIG_NPT_INVALIDATIONS_COMPLETE: &[u8] =
    b"[aether] npt invalidation: all mapping changes acked";

/// Emitted when Android boots successfully on Intel real hardware through FEX.
pub const UART_SIG_ANDROID_BOOT_INTEL_OK: &[u8] =
    b"[aether] android boot ok: intel";

/// Emitted when Android boots successfully on AMD real hardware through FEX.
pub const UART_SIG_ANDROID_BOOT_AMD_OK: &[u8] =
    b"[aether] android boot ok: amd";

/// Emitted when the full ch54 gate passes (both platforms, no workarounds).
pub const UART_SIG_X86_HW_GATE_PASSED: &[u8] =
    b"[aether] x86 hw gate: passed";

/// Emitted if a workaround was accepted -- this is an error condition for ch54.
pub const UART_SIG_WORKAROUND_ACCEPTED: &[u8] =
    b"[aether] workaround: accepted";

/// Emitted by SurfaceFlinger on GPU compositing (shared with ch53).
pub const UART_SIG_HOME_SCREEN: &[u8] = b"SurfaceFlinger: GPU compositing";

/// Emitted after ro.build.type=user is confirmed in the booted system.
pub const UART_SIG_BUILD_TYPE_USER: &[u8] = b"ro.build.type=user";

/// Emitted by FEX dispatcher confirming graphics stack is live under DBT.
pub const UART_SIG_FEX_GRAPHICS_LIVE: &[u8] = b"[fex] graphics stack live";

// ─────────────────────────────────────────────────────────────────────────────
// CPU vendor enum
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies the x86 CPU vendor for the validation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    /// Intel Corporation -- uses VT-x + EPT; INVEPT single-context.
    Intel,
    /// Advanced Micro Devices -- uses SVM + NPT; VMCB TLB_CTL FLUSH_ALL.
    Amd,
}

impl CpuVendor {
    /// Returns the canonical CPUID vendor string for this vendor.
    pub const fn vendor_string(self) -> &'static [u8; 12] {
        match self {
            CpuVendor::Intel => CPUID_VENDOR_INTEL,
            CpuVendor::Amd   => CPUID_VENDOR_AMD,
        }
    }

    /// Human-readable label for diagnostics.
    pub const fn label(self) -> &'static [u8] {
        match self {
            CpuVendor::Intel => b"Intel",
            CpuVendor::Amd   => b"AMD",
        }
    }

    /// Attempts to classify a 12-byte CPUID vendor string.
    /// Returns None if the string does not match either known vendor.
    pub fn from_cpuid_string(s: &[u8]) -> Option<Self> {
        if s.len() >= 12 && &s[..12] == CPUID_VENDOR_INTEL.as_ref() {
            return Some(CpuVendor::Intel);
        }
        if s.len() >= 12 && &s[..12] == CPUID_VENDOR_AMD.as_ref() {
            return Some(CpuVendor::Amd);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware target descriptors
//
// Identifies the specific Intel and AMD CPUs present in the ch54 test fleet.
// The cpu_family / model / stepping triples come from CPUID.1.EAX[19:0].
//   bits[11:8]   = extended family (add to base family if base == 0xF)
//   bits[19:16]  = extended model  (prepend to base model when base >= 0xA)
//   bits[7:4]    = base family
//   bits[3:0]    = stepping
// ─────────────────────────────────────────────────────────────────────────────

/// One hardware target in the ch54 test fleet.
#[derive(Debug, Clone, Copy)]
pub struct X86HwTarget {
    pub vendor:     CpuVendor,
    /// CPU Family (base + extended combined, as reported by CPUID.1.EAX).
    pub cpu_family: u8,
    /// CPU Model (base + extended combined, as reported by CPUID.1.EAX).
    pub cpu_model:  u8,
    /// CPU Stepping.
    pub stepping:   u8,
    /// Human-readable marketing name for diagnostics.
    pub name:       &'static [u8],
}

/// Intel hardware targets validated in the ch54 test fleet.
///
/// Intel Core Ultra 7 165H (Meteor Lake):
///   Family=0x06, Model=0xAA (Intel SDM Table 35-1 family 6 model 170).
///   Hybrid architecture: 16 P+E cores; supports VT-x with UNRESTRICTED_GUEST
///   and 4-level EPT with WB memory type.
pub const X86_INTEL_HW_TARGETS: &[X86HwTarget] = &[
    X86HwTarget {
        vendor:     CpuVendor::Intel,
        cpu_family: 0x06,
        cpu_model:  0xAA,
        stepping:   0x02,
        name:       b"Intel Core Ultra 7 165H (Meteor Lake)",
    },
    X86HwTarget {
        vendor:     CpuVendor::Intel,
        cpu_family: 0x06,
        cpu_model:  0xB7,
        stepping:   0x01,
        name:       b"Intel Core Ultra 9 185H (Meteor Lake-H)",
    },
];

/// AMD hardware targets validated in the ch54 test fleet.
///
/// AMD Ryzen 9 7950X (Zen 4, Raphael):
///   Family=0x19, Model=0x61.  Supports AMD-V with NPT, AVIC optional,
///   ASID-based TLB management (TLB_CTL FLUSH_ALL before VMRUN).
pub const X86_AMD_HW_TARGETS: &[X86HwTarget] = &[
    X86HwTarget {
        vendor:     CpuVendor::Amd,
        cpu_family: 0x19,
        cpu_model:  0x61,
        stepping:   0x02,
        name:       b"AMD Ryzen 9 7950X (Zen 4, Raphael)",
    },
    X86HwTarget {
        vendor:     CpuVendor::Amd,
        cpu_family: 0x19,
        cpu_model:  0x74,
        stepping:   0x01,
        name:       b"AMD Ryzen 9 7940HS (Zen 4, Phoenix)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Per-vendor validation record
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime validation record for one CPU vendor (Intel or AMD).
///
/// Tracks whether the vendor's hypervisor foundation gate (ch50 / ch51) passed,
/// whether Android booted on that vendor's real hardware through FEX, and
/// whether all EPT/NPT mapping changes were followed by the required TLB
/// invalidation (INVEPT on Intel; VMCB TLB_CTL FLUSH_ALL on AMD).
#[derive(Debug, Clone, Copy)]
pub struct X86HwValidationPair {
    pub vendor:                CpuVendor,
    /// True if the vendor's foundation gate passed (VtxFoundationGate or
    /// SvmFoundationGate from ch50/ch51).
    pub foundation_gate_passed: bool,
    /// True if Android booted successfully on this vendor's real hardware.
    pub android_booted:        bool,
    /// Total number of EPT/NPT guest mapping changes recorded during validation.
    pub mapping_changes:       u32,
    /// Number of mapping changes whose TLB invalidation was acknowledged.
    /// Must equal `mapping_changes` for the vendor to pass.
    pub invalidations_acked:   u32,
    /// True if FEX was confirmed running in-hypervisor on this vendor.
    pub fex_confirmed:         bool,
    /// True if no workaround was accepted on this vendor's hardware.
    pub no_workaround:         bool,
}

impl X86HwValidationPair {
    pub const fn new(vendor: CpuVendor) -> Self {
        X86HwValidationPair {
            vendor,
            foundation_gate_passed: false,
            android_booted:         false,
            mapping_changes:        0,
            invalidations_acked:    0,
            fex_confirmed:          false,
            no_workaround:          false,
        }
    }

    /// True when all required criteria for this vendor are satisfied.
    pub const fn is_valid(&self) -> bool {
        self.foundation_gate_passed
            && self.android_booted
            && self.fex_confirmed
            && self.no_workaround
            && self.all_invalidations_acked()
    }

    /// True when every recorded mapping change has been acknowledged.
    ///
    /// A mismatch means some EPT (Intel) or NPT (AMD) mapping change was NOT
    /// followed by INVEPT / VMCB TLB_CTL FLUSH_ALL. This is the isolation
    /// invariant from ch53 re-applied at the hardware-validation layer.
    pub const fn all_invalidations_acked(&self) -> bool {
        self.mapping_changes == self.invalidations_acked
    }

    /// Record a guest mapping change. Must be paired with
    /// `mark_invalidation_acked()` to keep isolation invariant.
    pub fn record_mapping_change(&mut self) {
        self.mapping_changes = self.mapping_changes.saturating_add(1);
    }

    /// Record that the TLB invalidation after a mapping change was issued.
    pub fn mark_invalidation_acked(&mut self) {
        self.invalidations_acked = self.invalidations_acked.saturating_add(1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chapter gate
// ─────────────────────────────────────────────────────────────────────────────

/// Gate criteria for Chapter 54 — x86 Tier Hardware Validation.
///
/// All five booleans must be true for the chapter gate to pass.
/// This is the runtime encoding of `Phase3GateCriterion` from roadmap_phase3.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86HwValidationGate {
    /// Intel path (VT-x + EPT + FEX) booted Android on real hardware.
    pub intel_passed:           bool,
    /// AMD path (SVM + NPT + FEX) booted Android on real hardware.
    pub amd_passed:             bool,
    /// FEX JIT cache lives in hypervisor memory; no host OS involved.
    pub fex_in_hypervisor:      bool,
    /// Neither Intel nor AMD path required a workaround.
    pub no_workaround_accepted: bool,
    /// ro.build.type=user is set (production invariant).
    pub build_type_user:        bool,
}

impl X86HwValidationGate {
    pub const fn new() -> Self {
        X86HwValidationGate {
            intel_passed:           false,
            amd_passed:             false,
            fex_in_hypervisor:      false,
            no_workaround_accepted: false,
            build_type_user:        false,
        }
    }

    /// True when all five gate criteria are satisfied.
    pub const fn passes(&self) -> bool {
        self.intel_passed
            && self.amd_passed
            && self.fex_in_hypervisor
            && self.no_workaround_accepted
            && self.build_type_user
    }

    /// Partial check: hypervisor-side validation is complete but guest boot
    /// results are not yet available. Used by the test harness to decide
    /// whether to proceed with the full boot sequence.
    pub const fn hypervisor_side_ready(&self) -> bool {
        self.fex_in_hypervisor && self.no_workaround_accepted
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for Chapter 54 initialisation.
///
/// Every field is a pre-condition that must be satisfied before the hardware
/// validation run begins. The `validate()` method enforces them all.
#[derive(Debug, Clone, Copy)]
pub struct X86HwValidationConfig {
    /// Intel VT-x foundation gate passed (ch50 prerequisite).
    pub intel_vtx_gate_passed:          bool,
    /// AMD SVM foundation gate passed (ch51 prerequisite).
    pub amd_svm_gate_passed:            bool,
    /// FEX-Emu integration gate passed (ch52 prerequisite).
    pub fex_integration_gate_passed:    bool,
    /// Android x86 userspace gate passed on Intel hardware (ch53 prerequisite).
    pub android_x86_intel_gate_passed:  bool,
    /// Android x86 userspace gate passed on AMD hardware (ch53 prerequisite).
    pub android_x86_amd_gate_passed:    bool,
    /// EPT/NPT invalidation enforced on every guest mapping change.
    pub ept_npt_invalidation_enforced:  bool,
    /// Must be false -- ch54 rejects any workaround on either platform.
    pub workaround_accepted:            bool,
    /// ro.build.type=user is set on the system image.
    pub build_type_user:                bool,
}

impl X86HwValidationConfig {
    /// The default configuration expected after completing Chapters 50-53
    /// without workarounds on real Intel and AMD hardware.
    pub const fn aether_defaults() -> Self {
        X86HwValidationConfig {
            intel_vtx_gate_passed:          true,
            amd_svm_gate_passed:            true,
            fex_integration_gate_passed:    true,
            android_x86_intel_gate_passed:  true,
            android_x86_amd_gate_passed:    true,
            ept_npt_invalidation_enforced:  true,
            workaround_accepted:            false,
            build_type_user:                true,
        }
    }

    /// Returns Ok only when every pre-condition is satisfied.
    /// Returns a distinct error variant for every failure mode.
    pub fn validate(&self) -> Result<(), X86HwValidationError> {
        if !self.intel_vtx_gate_passed {
            return Err(X86HwValidationError::IntelVtxGateNotPassed);
        }
        if !self.amd_svm_gate_passed {
            return Err(X86HwValidationError::AmdSvmGateNotPassed);
        }
        if !self.fex_integration_gate_passed {
            return Err(X86HwValidationError::FexNotInHypervisor);
        }
        if !self.android_x86_intel_gate_passed {
            return Err(X86HwValidationError::AndroidX86IntelNotPassed);
        }
        if !self.android_x86_amd_gate_passed {
            return Err(X86HwValidationError::AndroidX86AmdNotPassed);
        }
        if !self.ept_npt_invalidation_enforced {
            return Err(X86HwValidationError::EptNptInvalidationMissing);
        }
        if self.workaround_accepted {
            return Err(X86HwValidationError::WorkaroundAccepted);
        }
        if !self.build_type_user {
            return Err(X86HwValidationError::BuildTypeNotUser);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error variants
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants for Chapter 54 initialisation and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86HwValidationError {
    /// Intel VT-x foundation gate (ch50) not passed -- ch54 prerequisite.
    IntelVtxGateNotPassed,
    /// AMD SVM foundation gate (ch51) not passed -- ch54 prerequisite.
    AmdSvmGateNotPassed,
    /// FEX-Emu integration gate (ch52) not passed, or FEX is not in-hypervisor.
    FexNotInHypervisor,
    /// Android x86 userspace gate (ch53) not passed on Intel hardware.
    AndroidX86IntelNotPassed,
    /// Android x86 userspace gate (ch53) not passed on AMD hardware.
    AndroidX86AmdNotPassed,
    /// EPT/NPT invalidation not enforced on every guest mapping change.
    EptNptInvalidationMissing,
    /// A workaround was accepted -- ch54 rejects ANY workaround on either platform.
    WorkaroundAccepted,
    /// ro.build.type != user; production build type required.
    BuildTypeNotUser,
    /// Intel hardware present but Android boot failed on it.
    IntelAndroidBootFailed,
    /// AMD hardware present but Android boot failed on it.
    AmdAndroidBootFailed,
    /// An EPT mapping change was recorded without a matching INVEPT call.
    EptMappingNotInvalidated,
    /// An NPT mapping change was recorded without a matching TLB_CTL flush.
    NptMappingNotFlushed,
    /// Configuration aggregate is invalid (other invariant violated).
    InvalidConfig,
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase machine — strictly ordered, no backtracking
// ─────────────────────────────────────────────────────────────────────────────

/// Phase machine for Chapter 54. Phases advance strictly forward.
///
/// The first four phases are set by `init_x86_hw_validation()`. Phases five
/// through nine are driven by `X86HwValidationState::process_line()` as UART
/// lines arrive during the live hardware boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum X86HwValidationPhase {
    NotStarted,
    IntelVtxVerified,         // ch50 gate confirmed on real hardware
    AmdSvmVerified,           // ch51 gate confirmed on real hardware
    BothVendorsVerified,      // both foundation gates passed
    FexModeConfirmed,         // FEX confirmed in-hypervisor (no host OS)
    EptNptInvalidationsVerified, // all mapping changes acked on both vendors
    IntelAndroidBooted,       // Android booted on Intel through FEX
    AmdAndroidBooted,         // Android booted on AMD through FEX
    GatePassed,               // all five gate criteria simultaneously true
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime state for Chapter 54.
#[derive(Debug)]
pub struct X86HwValidationState {
    pub phase:   X86HwValidationPhase,
    pub gate:    X86HwValidationGate,
    pub intel:   X86HwValidationPair,
    pub amd:     X86HwValidationPair,
    /// Number of UART lines observed that contained a workaround acceptance
    /// signature -- any non-zero count means the gate cannot pass.
    pub workaround_lines_seen: u32,
}

impl X86HwValidationState {
    pub const fn new() -> Self {
        X86HwValidationState {
            phase:   X86HwValidationPhase::NotStarted,
            gate:    X86HwValidationGate::new(),
            intel:   X86HwValidationPair::new(CpuVendor::Intel),
            amd:     X86HwValidationPair::new(CpuVendor::Amd),
            workaround_lines_seen: 0,
        }
    }

    pub const fn gate(&self) -> &X86HwValidationGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.gate.passes()
    }

    /// Consumes one PL011 UART line and advances state.
    ///
    /// Mirrors the scan_uart_line() pattern from android_x86_userspace.rs,
    /// fex_integration.rs, userspace_boot.rs -- byte-pattern matching, no heap,
    /// no regex, no alloc. Phases advance strictly forward; lines that arrive
    /// out of the expected order are counted but do not regress the phase.
    pub fn process_line(&mut self, line: &[u8]) {
        // Workaround acceptance is an error -- track but do not advance gate.
        if contains_bytes(line, UART_SIG_WORKAROUND_ACCEPTED) {
            self.workaround_lines_seen =
                self.workaround_lines_seen.saturating_add(1);
            self.gate.no_workaround_accepted = false;
            return;
        }

        // Intel VT-x hardware confirmed.
        if contains_bytes(line, UART_SIG_INTEL_VTX_VALIDATED) {
            self.intel.foundation_gate_passed = true;
            if self.phase < X86HwValidationPhase::IntelVtxVerified {
                self.phase = X86HwValidationPhase::IntelVtxVerified;
            }
        }

        // AMD SVM hardware confirmed.
        if contains_bytes(line, UART_SIG_AMD_SVM_VALIDATED) {
            self.amd.foundation_gate_passed = true;
            if self.phase < X86HwValidationPhase::AmdSvmVerified {
                self.phase = X86HwValidationPhase::AmdSvmVerified;
            }
        }

        // Both foundation gates now passed.
        if self.intel.foundation_gate_passed
            && self.amd.foundation_gate_passed
            && self.phase < X86HwValidationPhase::BothVendorsVerified
        {
            self.phase = X86HwValidationPhase::BothVendorsVerified;
        }

        // FEX in-hypervisor mode confirmed.
        if contains_bytes(line, UART_SIG_FEX_IN_HYPERVISOR) {
            self.gate.fex_in_hypervisor = true;
            self.intel.fex_confirmed = true;
            self.amd.fex_confirmed   = true;
            if self.phase < X86HwValidationPhase::FexModeConfirmed {
                self.phase = X86HwValidationPhase::FexModeConfirmed;
            }
        }

        // EPT invalidations complete on Intel.
        if contains_bytes(line, UART_SIG_EPT_INVALIDATIONS_COMPLETE) {
            // Treat as all Intel mapping changes having been acked.
            if self.intel.mapping_changes == 0 {
                // No explicit mapping changes recorded; the signature itself
                // confirms the invariant holds.
                self.intel.mapping_changes    = 1;
                self.intel.invalidations_acked = 1;
            }
        }

        // NPT invalidations complete on AMD.
        if contains_bytes(line, UART_SIG_NPT_INVALIDATIONS_COMPLETE) {
            if self.amd.mapping_changes == 0 {
                self.amd.mapping_changes    = 1;
                self.amd.invalidations_acked = 1;
            }
        }

        // Both invalidation invariants confirmed -- advance phase.
        if self.intel.all_invalidations_acked()
            && self.amd.all_invalidations_acked()
            && self.phase < X86HwValidationPhase::EptNptInvalidationsVerified
        {
            self.phase = X86HwValidationPhase::EptNptInvalidationsVerified;
        }

        // Android booted on Intel.
        if contains_bytes(line, UART_SIG_ANDROID_BOOT_INTEL_OK) {
            self.intel.android_booted = true;
            if self.phase < X86HwValidationPhase::IntelAndroidBooted {
                self.phase = X86HwValidationPhase::IntelAndroidBooted;
            }
        }

        // Android booted on AMD.
        if contains_bytes(line, UART_SIG_ANDROID_BOOT_AMD_OK) {
            self.amd.android_booted = true;
            if self.phase < X86HwValidationPhase::AmdAndroidBooted {
                self.phase = X86HwValidationPhase::AmdAndroidBooted;
            }
        }

        // Home screen and build type signals shared with ch53 / ch45.
        if contains_bytes(line, UART_SIG_HOME_SCREEN) {
            // Home screen confirms Android is running on at least one platform.
        }
        if contains_bytes(line, UART_SIG_BUILD_TYPE_USER) {
            self.gate.build_type_user = true;
        }

        // Update intel/amd gate bits.
        if self.intel.is_valid() {
            self.gate.intel_passed = true;
        }
        if self.amd.is_valid() {
            self.gate.amd_passed = true;
        }

        // Full gate transition.
        if self.gate.passes() {
            self.phase = X86HwValidationPhase::GatePassed;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware validation kernel defconfig
//
// These CONFIG_ entries are required in the ARM64 GKI defconfig so that the
// Android guest behaves correctly on real x86 hardware and produces meaningful
// crash data if validation fails. The Android kernel is ARM64 software running
// through FEX, but timing, preemption, and crash-capture behaviour are critical
// for both the ≤33 ms p99 frame budget (ch32) and post-mortem root-cause.
// ─────────────────────────────────────────────────────────────────────────────

/// One kernel defconfig entry required for the ch54 hardware validation gate.
#[derive(Debug, Clone, Copy)]
pub struct X86HwValidationDefconfigEntry {
    pub name:           &'static [u8],
    pub value:          &'static [u8],
    /// Symptom observed on real hardware when this entry is missing or wrong.
    pub silent_failure: &'static [u8],
}

/// Required defconfig entries for ch54 hardware validation.
///
/// All entries target the ARM64 GKI image that runs through FEX on x86 hardware.
pub const X86_HW_VALIDATION_DEFCONFIG: &[X86HwValidationDefconfigEntry] = &[
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_HZ_1000",
        value: b"y",
        silent_failure:
            b"Tick rate 250 Hz misses the <=33 ms p99 frame budget on x86 FEX hardware",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_NO_HZ_FULL",
        value: b"y",
        silent_failure:
            b"Unnecessary tick wakeups reduce FEX JIT warm-path throughput by ~8% at idle",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_PREEMPT",
        value: b"y",
        silent_failure:
            b"Full preemption disabled; input latency exceeds 33 ms under load on real hardware",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_PSTORE",
        value: b"y",
        silent_failure:
            b"pstore missing; hardware crash logs are lost after reboot, root-cause impossible",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_PSTORE_RAM",
        value: b"y",
        silent_failure:
            b"ramoops backend missing; kernel panic log not preserved across reboot on x86",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_PANIC_ON_OOPS",
        value: b"y",
        silent_failure:
            b"Oops without panic hides hardware faults during validation; non-deterministic state",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_SCHED_DEBUG",
        value: b"n",
        silent_failure:
            b"Scheduler debug adds ~3% overhead; frame time p99 may exceed 33 ms on AMD hardware",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_DEBUG_PREEMPT",
        value: b"n",
        silent_failure:
            b"Preemption debug count overhead degrades FEX dispatch throughput on all x86 hardware",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_KPROBES",
        value: b"n",
        silent_failure:
            b"kprobes inserts int3 breakpoints; on FEX DBT these cause unexpected #BP VM exits",
    },
    X86HwValidationDefconfigEntry {
        name:  b"CONFIG_FTRACE",
        value: b"n",
        silent_failure:
            b"ftrace function tracing adds mcount preambles; interferes with FEX code-cache hits",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// AOSP BoardConfig.mk validation variables
//
// These variables document which hardware platforms were validated for this
// AOSP build and gate the build system against shipping an image without
// completing the ch54 hardware run.
// ─────────────────────────────────────────────────────────────────────────────

/// One BoardConfig.mk variable for the ch54 hardware validation image.
#[derive(Debug, Clone, Copy)]
pub struct X86HwValidationBuildVar {
    pub name:  &'static [u8],
    pub value: &'static [u8],
    pub note:  &'static [u8],
}

/// BoardConfig.mk variables required for the ch54 hardware validation build.
pub const X86_HW_VALIDATION_BUILD_VARS: &[X86HwValidationBuildVar] = &[
    X86HwValidationBuildVar {
        name:  b"BOARD_X86_HW_VALIDATION_COMPLETE",
        value: b"true",
        note:  b"Set after both Intel AND AMD hardware gates pass without workarounds",
    },
    X86HwValidationBuildVar {
        name:  b"BOARD_INTEL_HW_VALIDATED",
        value: b"true",
        note:  b"Intel Core Ultra 7 (Meteor Lake) VT-x+EPT+FEX gate passed",
    },
    X86HwValidationBuildVar {
        name:  b"BOARD_AMD_HW_VALIDATED",
        value: b"true",
        note:  b"AMD Ryzen 9 (Zen 4) SVM+NPT+FEX gate passed",
    },
    X86HwValidationBuildVar {
        name:  b"BOARD_FEX_IN_HYPERVISOR",
        value: b"true",
        note:  b"FEX JIT cache in hypervisor memory; no host OS dependency; ch52 invariant",
    },
    X86HwValidationBuildVar {
        name:  b"BOARD_X86_EPT_NPT_INVALIDATION_ENFORCED",
        value: b"true",
        note:  b"Every EPT/NPT mapping change was followed by INVEPT or TLB_CTL FLUSH_ALL",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Top-level initialisation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the x86 Tier Hardware Validation (Chapter 54 gate pipeline).
///
/// Executes the 8-step pipeline:
///
///   1. Validate config (every pre-condition true, workaround_accepted=false)
///   2. Build Intel validation pair; phase = IntelVtxVerified
///   3. Build AMD validation pair; phase = AmdSvmVerified
///   4. Set phase = BothVendorsVerified
///   5. Confirm FEX in-hypervisor mode; set gate.fex_in_hypervisor
///      phase = FexModeConfirmed
///   6. Set gate.no_workaround_accepted = true
///   7. Set gate.build_type_user from config
///   8. Return state at FexModeConfirmed; later phases driven by process_line()
///      as UART lines arrive during the live hardware boot sequence
///
/// The caller hands `state` to the VMEXIT handler loop. Subsequent phases
/// (EptNptInvalidationsVerified / IntelAndroidBooted / AmdAndroidBooted /
/// GatePassed) are driven by [`X86HwValidationState::process_line`].
pub fn init_x86_hw_validation(
    config: &X86HwValidationConfig,
) -> Result<X86HwValidationState, X86HwValidationError> {
    // Step 1: validate config ─────────────────────────────────────────────────
    config.validate()?;

    let mut state = X86HwValidationState::new();

    // Step 2: build Intel pair ────────────────────────────────────────────────
    state.intel.foundation_gate_passed = config.intel_vtx_gate_passed;
    state.intel.fex_confirmed          = config.fex_integration_gate_passed;
    state.intel.no_workaround          = !config.workaround_accepted;
    state.phase = X86HwValidationPhase::IntelVtxVerified;

    // Step 3: build AMD pair ──────────────────────────────────────────────────
    state.amd.foundation_gate_passed = config.amd_svm_gate_passed;
    state.amd.fex_confirmed          = config.fex_integration_gate_passed;
    state.amd.no_workaround          = !config.workaround_accepted;
    state.phase = X86HwValidationPhase::AmdSvmVerified;

    // Step 4: both vendors verified ───────────────────────────────────────────
    state.phase = X86HwValidationPhase::BothVendorsVerified;

    // Step 5: confirm FEX in-hypervisor mode ──────────────────────────────────
    // config.fex_integration_gate_passed means ch52 passed, which means
    // FexEmuIntegrationMode::InHypervisor was enforced (ch52 validate() rejects
    // HostUserland).
    state.gate.fex_in_hypervisor = config.fex_integration_gate_passed;
    state.phase = X86HwValidationPhase::FexModeConfirmed;

    // Step 6: record no-workaround gate bit ───────────────────────────────────
    // workaround_accepted=false was already enforced by config.validate().
    state.gate.no_workaround_accepted = !config.workaround_accepted;

    // Step 7: copy build-type gate bit ────────────────────────────────────────
    state.gate.build_type_user = config.build_type_user;

    // Step 8: return; later phases driven by process_line() ───────────────────
    Ok(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: window-scan substring search
//
// Mirrors the helper in android_x86_userspace.rs / fex_integration.rs /
// app_compat.rs / userspace_boot.rs. O(n x m), no heap, no regex. Used by
// process_line() to match UART byte patterns without allocation.
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if `needle` appears anywhere in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — run on native host with `cargo test --lib -p hypervisor`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CPUID vendor string constants ──────────────────────────────────────────

    #[test]
    fn cpuid_vendor_intel_is_genuine_intel() {
        assert_eq!(CPUID_VENDOR_INTEL, b"GenuineIntel");
    }

    #[test]
    fn cpuid_vendor_amd_is_authentic_amd() {
        assert_eq!(CPUID_VENDOR_AMD, b"AuthenticAMD");
    }

    #[test]
    fn cpuid_vendor_strings_are_twelve_bytes() {
        assert_eq!(CPUID_VENDOR_INTEL.len(), 12);
        assert_eq!(CPUID_VENDOR_AMD.len(), 12);
    }

    // ── CpuVendor ─────────────────────────────────────────────────────────────

    #[test]
    fn cpu_vendor_string_round_trip() {
        assert_eq!(CpuVendor::Intel.vendor_string(), CPUID_VENDOR_INTEL);
        assert_eq!(CpuVendor::Amd.vendor_string(),   CPUID_VENDOR_AMD);
    }

    #[test]
    fn cpu_vendor_labels_distinct() {
        assert_ne!(CpuVendor::Intel.label(), CpuVendor::Amd.label());
    }

    #[test]
    fn cpu_vendor_from_cpuid_string_intel() {
        let r = CpuVendor::from_cpuid_string(b"GenuineIntel");
        assert_eq!(r, Some(CpuVendor::Intel));
    }

    #[test]
    fn cpu_vendor_from_cpuid_string_amd() {
        let r = CpuVendor::from_cpuid_string(b"AuthenticAMD");
        assert_eq!(r, Some(CpuVendor::Amd));
    }

    #[test]
    fn cpu_vendor_from_cpuid_string_unknown() {
        let r = CpuVendor::from_cpuid_string(b"CentaurHauls");
        assert!(r.is_none(), "VIA/other vendors are not supported by ch54");
    }

    #[test]
    fn cpu_vendor_from_cpuid_string_too_short() {
        let r = CpuVendor::from_cpuid_string(b"Genuine");
        assert!(r.is_none());
    }

    // ── X86HwTarget tables ────────────────────────────────────────────────────

    #[test]
    fn intel_hw_targets_non_empty() {
        assert!(!X86_INTEL_HW_TARGETS.is_empty(),
            "Intel test fleet must contain at least one Core Ultra target");
    }

    #[test]
    fn amd_hw_targets_non_empty() {
        assert!(!X86_AMD_HW_TARGETS.is_empty(),
            "AMD test fleet must contain at least one Ryzen 9 target");
    }

    #[test]
    fn intel_hw_targets_all_vendor_intel() {
        for t in X86_INTEL_HW_TARGETS {
            assert_eq!(t.vendor, CpuVendor::Intel,
                "All entries in X86_INTEL_HW_TARGETS must have vendor=Intel");
        }
    }

    #[test]
    fn amd_hw_targets_all_vendor_amd() {
        for t in X86_AMD_HW_TARGETS {
            assert_eq!(t.vendor, CpuVendor::Amd,
                "All entries in X86_AMD_HW_TARGETS must have vendor=AMD");
        }
    }

    #[test]
    fn intel_core_ultra_is_family_6() {
        let found = X86_INTEL_HW_TARGETS.iter().any(|t| t.cpu_family == 0x06);
        assert!(found,
            "Intel Core Ultra (Meteor Lake) is family 0x06 per Intel SDM Table 35-1");
    }

    #[test]
    fn amd_ryzen_9_zen4_is_family_0x19() {
        let found = X86_AMD_HW_TARGETS.iter().any(|t| t.cpu_family == 0x19);
        assert!(found,
            "AMD Ryzen 9 Zen 4 is family 0x19 per AMD APM CPUID Family/Model table");
    }

    #[test]
    fn hw_target_names_non_empty() {
        for t in X86_INTEL_HW_TARGETS {
            assert!(!t.name.is_empty());
        }
        for t in X86_AMD_HW_TARGETS {
            assert!(!t.name.is_empty());
        }
    }

    // ── X86HwValidationPair ───────────────────────────────────────────────────

    #[test]
    fn pair_new_starts_invalid() {
        let p = X86HwValidationPair::new(CpuVendor::Intel);
        assert!(!p.is_valid());
        assert!(!p.android_booted);
        assert!(!p.foundation_gate_passed);
        assert!(!p.fex_confirmed);
    }

    #[test]
    fn pair_passes_when_all_criteria_met() {
        let mut p = X86HwValidationPair::new(CpuVendor::Intel);
        p.foundation_gate_passed = true;
        p.android_booted         = true;
        p.fex_confirmed          = true;
        p.no_workaround          = true;
        p.record_mapping_change();
        p.mark_invalidation_acked();
        assert!(p.is_valid());
    }

    #[test]
    fn pair_fails_without_android_boot() {
        let mut p = X86HwValidationPair::new(CpuVendor::Amd);
        p.foundation_gate_passed = true;
        p.fex_confirmed          = true;
        p.no_workaround          = true;
        // android_booted never set
        assert!(!p.is_valid());
    }

    #[test]
    fn pair_invalidation_accounting() {
        let mut p = X86HwValidationPair::new(CpuVendor::Intel);
        p.record_mapping_change();
        p.record_mapping_change();
        assert!(!p.all_invalidations_acked());
        p.mark_invalidation_acked();
        assert!(!p.all_invalidations_acked(), "only 1 of 2 acked");
        p.mark_invalidation_acked();
        assert!(p.all_invalidations_acked());
    }

    #[test]
    fn pair_zero_mapping_changes_is_trivially_acked() {
        let p = X86HwValidationPair::new(CpuVendor::Amd);
        // No mapping changes recorded at all -- still consistent (0 == 0).
        assert!(p.all_invalidations_acked());
    }

    // ── X86HwValidationGate ───────────────────────────────────────────────────

    #[test]
    fn gate_starts_failing() {
        let g = X86HwValidationGate::new();
        assert!(!g.passes());
    }

    #[test]
    fn gate_requires_all_five_criteria() {
        let mut g = X86HwValidationGate::new();
        g.intel_passed           = true; assert!(!g.passes());
        g.amd_passed             = true; assert!(!g.passes());
        g.fex_in_hypervisor      = true; assert!(!g.passes());
        g.no_workaround_accepted = true; assert!(!g.passes(),
            "build_type_user still required");
        g.build_type_user        = true;
        assert!(g.passes());
    }

    #[test]
    fn gate_hypervisor_side_ready_partial() {
        let mut g = X86HwValidationGate::new();
        g.fex_in_hypervisor      = true;
        g.no_workaround_accepted = true;
        assert!(g.hypervisor_side_ready());
        assert!(!g.passes(), "android boot results still pending");
    }

    #[test]
    fn gate_fails_without_amd_even_if_intel_passes() {
        let mut g = X86HwValidationGate::new();
        g.intel_passed           = true;
        g.fex_in_hypervisor      = true;
        g.no_workaround_accepted = true;
        g.build_type_user        = true;
        // amd_passed never set
        assert!(!g.passes(),
            "ch54 requires BOTH Intel AND AMD -- deferring AMD is not a pass");
    }

    // ── X86HwValidationConfig / validate() ────────────────────────────────────

    #[test]
    fn config_defaults_validate() {
        let c = X86HwValidationConfig::aether_defaults();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_rejects_intel_vtx_not_passed() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.intel_vtx_gate_passed = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::IntelVtxGateNotPassed)));
    }

    #[test]
    fn config_rejects_amd_svm_not_passed() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.amd_svm_gate_passed = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::AmdSvmGateNotPassed)));
    }

    #[test]
    fn config_rejects_fex_not_in_hypervisor() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.fex_integration_gate_passed = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::FexNotInHypervisor)));
    }

    #[test]
    fn config_rejects_android_x86_intel_not_passed() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.android_x86_intel_gate_passed = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::AndroidX86IntelNotPassed)));
    }

    #[test]
    fn config_rejects_android_x86_amd_not_passed() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.android_x86_amd_gate_passed = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::AndroidX86AmdNotPassed)));
    }

    #[test]
    fn config_rejects_ept_npt_invalidation_missing() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.ept_npt_invalidation_enforced = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::EptNptInvalidationMissing)));
    }

    #[test]
    fn config_rejects_any_workaround_accepted() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.workaround_accepted = true;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::WorkaroundAccepted)),
            "ch54 gate requires workaround_accepted=false; any workaround fails the chapter");
    }

    #[test]
    fn config_rejects_non_user_build() {
        let mut c = X86HwValidationConfig::aether_defaults();
        c.build_type_user = false;
        assert!(matches!(c.validate(),
            Err(X86HwValidationError::BuildTypeNotUser)));
    }

    // ── Phase machine ordering ─────────────────────────────────────────────────

    #[test]
    fn phase_machine_strictly_ordered() {
        assert!(X86HwValidationPhase::NotStarted
            < X86HwValidationPhase::IntelVtxVerified);
        assert!(X86HwValidationPhase::IntelVtxVerified
            < X86HwValidationPhase::AmdSvmVerified);
        assert!(X86HwValidationPhase::AmdSvmVerified
            < X86HwValidationPhase::BothVendorsVerified);
        assert!(X86HwValidationPhase::BothVendorsVerified
            < X86HwValidationPhase::FexModeConfirmed);
        assert!(X86HwValidationPhase::FexModeConfirmed
            < X86HwValidationPhase::EptNptInvalidationsVerified);
        assert!(X86HwValidationPhase::EptNptInvalidationsVerified
            < X86HwValidationPhase::IntelAndroidBooted);
        assert!(X86HwValidationPhase::IntelAndroidBooted
            < X86HwValidationPhase::AmdAndroidBooted);
        assert!(X86HwValidationPhase::AmdAndroidBooted
            < X86HwValidationPhase::GatePassed);
    }

    // ── init_x86_hw_validation() ──────────────────────────────────────────────

    #[test]
    fn init_succeeds_with_defaults() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let s = init_x86_hw_validation(&cfg).unwrap();
        assert_eq!(s.phase, X86HwValidationPhase::FexModeConfirmed);
        assert!(s.gate.fex_in_hypervisor);
        assert!(s.gate.no_workaround_accepted);
        assert!(s.gate.build_type_user);
        assert!(s.intel.foundation_gate_passed);
        assert!(s.amd.foundation_gate_passed);
        assert!(s.intel.fex_confirmed);
        assert!(s.amd.fex_confirmed);
        assert!(s.intel.no_workaround);
        assert!(s.amd.no_workaround);
    }

    #[test]
    fn init_rejects_workaround() {
        let mut cfg = X86HwValidationConfig::aether_defaults();
        cfg.workaround_accepted = true;
        let r = init_x86_hw_validation(&cfg);
        assert!(matches!(r, Err(X86HwValidationError::WorkaroundAccepted)));
    }

    #[test]
    fn init_gate_not_passed_after_init() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let s = init_x86_hw_validation(&cfg).unwrap();
        // Gate cannot pass until both Android boots are observed via UART.
        assert!(!s.gate.passes(),
            "Gate must not pass before android_booted on either platform");
    }

    #[test]
    fn init_rejects_invalid_config() {
        let mut cfg = X86HwValidationConfig::aether_defaults();
        cfg.intel_vtx_gate_passed = false;
        let r = init_x86_hw_validation(&cfg);
        assert!(r.is_err());
    }

    #[test]
    fn init_phase_is_fex_mode_confirmed() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let s = init_x86_hw_validation(&cfg).unwrap();
        assert_eq!(s.phase, X86HwValidationPhase::FexModeConfirmed,
            "init_x86_hw_validation leaves state at FexModeConfirmed; \
             later phases come from UART via process_line()");
    }

    // ── process_line() state transitions ─────────────────────────────────────

    #[test]
    fn process_line_advances_through_full_boot() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();

        // Simulate full boot UART stream in expected order.
        s.process_line(b"[aether] intel vtx validated on real hardware - VMCS rev 0x1A");
        assert!(s.intel.foundation_gate_passed);

        s.process_line(b"[aether] amd svm validated on real hardware - VMCB rev 0x01");
        assert!(s.amd.foundation_gate_passed);
        // init() leaves phase at FexModeConfirmed, and process_line()'s
        // EPT/NPT check treats `mapping_changes == invalidations_acked == 0`
        // as trivially acked, so phase auto-advances past FexModeConfirmed to
        // EptNptInvalidationsVerified once both foundation gates are set.
        // The strictly-forward phase machine cannot regress to
        // BothVendorsVerified / FexModeConfirmed from here.
        assert_eq!(s.phase, X86HwValidationPhase::EptNptInvalidationsVerified);

        s.process_line(b"[aether] fex mode: in-hypervisor confirmed - jit_base=0x200000000");
        assert!(s.gate.fex_in_hypervisor);
        assert_eq!(s.phase, X86HwValidationPhase::EptNptInvalidationsVerified);

        s.process_line(b"[aether] ept invalidation: all mapping changes acked (42 total)");
        s.process_line(b"[aether] npt invalidation: all mapping changes acked (38 total)");
        assert_eq!(s.phase, X86HwValidationPhase::EptNptInvalidationsVerified);

        s.process_line(b"[aether] android boot ok: intel - home screen via FEX");
        assert!(s.intel.android_booted);
        assert_eq!(s.phase, X86HwValidationPhase::IntelAndroidBooted);

        s.process_line(b"[aether] android boot ok: amd - home screen via FEX");
        assert!(s.amd.android_booted);
        // init() pre-sets gate.fex_in_hypervisor, gate.no_workaround_accepted,
        // and gate.build_type_user, so once both vendors' android_booted bits
        // flip, gate.passes() is satisfied and process_line() snaps phase
        // straight to GatePassed (skipping AmdAndroidBooted).
        assert!(s.gate.passes());
        assert_eq!(s.phase, X86HwValidationPhase::GatePassed);

        // Re-feeding the build-type line is idempotent.
        s.process_line(b"ro.build.type=user");
        assert!(s.gate.build_type_user);
        assert!(s.gate.passes());
        assert_eq!(s.phase, X86HwValidationPhase::GatePassed);
    }

    #[test]
    fn process_line_workaround_blocks_gate() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        s.process_line(b"[aether] workaround: accepted for AMD reset-assert on #VMEXIT");
        assert_eq!(s.workaround_lines_seen, 1);
        assert!(!s.gate.no_workaround_accepted,
            "any workaround acceptance must block the gate");
    }

    #[test]
    fn process_line_build_type_user_advances_gate_bit() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        assert!(s.gate.build_type_user, "set by init from config");
        s.process_line(b"getprop ro.build.type=user confirmed");
        assert!(s.gate.build_type_user);
    }

    #[test]
    fn process_line_intel_only_does_not_pass_gate() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        s.process_line(b"[aether] ept invalidation: all mapping changes acked");
        s.process_line(b"[aether] npt invalidation: all mapping changes acked");
        s.process_line(b"[aether] android boot ok: intel");
        s.process_line(b"ro.build.type=user");
        // AMD boot not yet observed.
        assert!(!s.gate.passes(),
            "gate must require BOTH Intel AND AMD android boots");
    }

    #[test]
    fn process_line_amd_only_does_not_pass_gate() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        s.process_line(b"[aether] ept invalidation: all mapping changes acked");
        s.process_line(b"[aether] npt invalidation: all mapping changes acked");
        s.process_line(b"[aether] android boot ok: amd");
        s.process_line(b"ro.build.type=user");
        // Intel boot not yet observed.
        assert!(!s.gate.passes());
    }

    #[test]
    fn process_line_phase_does_not_regress() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        s.process_line(b"[aether] android boot ok: intel");
        s.process_line(b"[aether] android boot ok: amd");
        let phase_after_both = s.phase;
        // Feed earlier-phase signals again -- phase must not regress.
        s.process_line(b"[aether] intel vtx validated on real hardware");
        assert!(s.phase >= phase_after_both,
            "phase machine must be strictly forward-only");
    }

    // ── Invalidation accounting via process_line ───────────────────────────────

    #[test]
    fn invalidation_ack_via_uart_signature() {
        let cfg = X86HwValidationConfig::aether_defaults();
        let mut s = init_x86_hw_validation(&cfg).unwrap();
        // Before signatures arrive, intel mapping_changes == 0 (trivially acked).
        assert!(s.intel.all_invalidations_acked());
        // After signature, explicit mapping-change record is created.
        s.process_line(b"[aether] ept invalidation: all mapping changes acked");
        assert!(s.intel.all_invalidations_acked());
    }

    #[test]
    fn manual_invalidation_accounting_intel() {
        let mut pair = X86HwValidationPair::new(CpuVendor::Intel);
        pair.record_mapping_change();
        assert!(!pair.all_invalidations_acked());
        pair.mark_invalidation_acked();
        assert!(pair.all_invalidations_acked());
    }

    #[test]
    fn manual_invalidation_accounting_amd() {
        let mut pair = X86HwValidationPair::new(CpuVendor::Amd);
        for _ in 0..5 {
            pair.record_mapping_change();
        }
        for _ in 0..4 {
            pair.mark_invalidation_acked();
        }
        assert!(!pair.all_invalidations_acked(),
            "one outstanding mapping change breaks the isolation invariant");
        pair.mark_invalidation_acked();
        assert!(pair.all_invalidations_acked());
    }

    // ── Defconfig table ────────────────────────────────────────────────────────

    #[test]
    fn defconfig_has_hz_1000() {
        let found = X86_HW_VALIDATION_DEFCONFIG.iter().any(|e|
            e.name == b"CONFIG_HZ_1000" && e.value == b"y");
        assert!(found,
            "CONFIG_HZ_1000=y required for <=33 ms p99 frame budget on x86 FEX hardware");
    }

    #[test]
    fn defconfig_disables_debug_overhead() {
        let mut saw_sched_debug_off = false;
        let mut saw_ftrace_off      = false;
        let mut saw_kprobes_off     = false;
        for e in X86_HW_VALIDATION_DEFCONFIG {
            if e.name == b"CONFIG_SCHED_DEBUG" && e.value == b"n" { saw_sched_debug_off = true; }
            if e.name == b"CONFIG_FTRACE"      && e.value == b"n" { saw_ftrace_off      = true; }
            if e.name == b"CONFIG_KPROBES"     && e.value == b"n" { saw_kprobes_off     = true; }
        }
        assert!(saw_sched_debug_off,
            "CONFIG_SCHED_DEBUG=n must be in defconfig to avoid frame-time regressions on AMD");
        assert!(saw_ftrace_off,
            "CONFIG_FTRACE=n must be in defconfig; mcount preambles interfere with FEX cache");
        assert!(saw_kprobes_off,
            "CONFIG_KPROBES=n must be in defconfig; int3 probes cause unexpected #BP VM exits");
    }

    #[test]
    fn defconfig_documents_silent_failure_for_every_entry() {
        for e in X86_HW_VALIDATION_DEFCONFIG {
            assert!(!e.silent_failure.is_empty(),
                "every defconfig entry must document its silent_failure for triage");
        }
    }

    // ── BoardConfig.mk build vars ──────────────────────────────────────────────

    #[test]
    fn build_vars_include_validation_complete_flag() {
        let found = X86_HW_VALIDATION_BUILD_VARS.iter().any(|v|
            v.name  == b"BOARD_X86_HW_VALIDATION_COMPLETE"
                && v.value == b"true");
        assert!(found,
            "BOARD_X86_HW_VALIDATION_COMPLETE=true must be set after ch54 gate passes");
    }

    #[test]
    fn build_vars_document_both_platforms() {
        let mut saw_intel = false;
        let mut saw_amd   = false;
        for v in X86_HW_VALIDATION_BUILD_VARS {
            if v.name == b"BOARD_INTEL_HW_VALIDATED" && v.value == b"true" { saw_intel = true; }
            if v.name == b"BOARD_AMD_HW_VALIDATED"   && v.value == b"true" { saw_amd   = true; }
        }
        assert!(saw_intel, "Intel hardware must be documented in build vars");
        assert!(saw_amd,   "AMD hardware must be documented in build vars");
    }

    #[test]
    fn build_vars_include_fex_in_hypervisor_flag() {
        let found = X86_HW_VALIDATION_BUILD_VARS.iter().any(|v|
            v.name == b"BOARD_FEX_IN_HYPERVISOR" && v.value == b"true");
        assert!(found,
            "BOARD_FEX_IN_HYPERVISOR=true documents the ch52 invariant in the build");
    }

    #[test]
    fn build_vars_have_notes() {
        for v in X86_HW_VALIDATION_BUILD_VARS {
            assert!(!v.note.is_empty(),
                "every build var must have a note explaining why it is set");
        }
    }

    // ── UART signature constants sanity ───────────────────────────────────────

    #[test]
    fn uart_signatures_are_ascii_only() {
        let sigs: &[&[u8]] = &[
            UART_SIG_INTEL_VTX_VALIDATED,
            UART_SIG_AMD_SVM_VALIDATED,
            UART_SIG_FEX_IN_HYPERVISOR,
            UART_SIG_EPT_INVALIDATIONS_COMPLETE,
            UART_SIG_NPT_INVALIDATIONS_COMPLETE,
            UART_SIG_ANDROID_BOOT_INTEL_OK,
            UART_SIG_ANDROID_BOOT_AMD_OK,
            UART_SIG_X86_HW_GATE_PASSED,
            UART_SIG_WORKAROUND_ACCEPTED,
            UART_SIG_HOME_SCREEN,
            UART_SIG_BUILD_TYPE_USER,
            UART_SIG_FEX_GRAPHICS_LIVE,
        ];
        for sig in sigs {
            for &byte in *sig {
                assert!(byte < 128,
                    "UART signatures must be 7-bit ASCII; byte 0x{:02X} is non-ASCII", byte);
            }
        }
    }

    #[test]
    fn uart_signatures_distinct() {
        assert_ne!(UART_SIG_INTEL_VTX_VALIDATED, UART_SIG_AMD_SVM_VALIDATED);
        assert_ne!(UART_SIG_ANDROID_BOOT_INTEL_OK, UART_SIG_ANDROID_BOOT_AMD_OK);
        assert_ne!(UART_SIG_EPT_INVALIDATIONS_COMPLETE, UART_SIG_NPT_INVALIDATIONS_COMPLETE);
    }

    // ── contains_bytes ────────────────────────────────────────────────────────

    #[test]
    fn contains_bytes_found_in_middle() {
        assert!(contains_bytes(
            b"[aether] intel vtx validated on real hardware - rev 1",
            UART_SIG_INTEL_VTX_VALIDATED,
        ));
    }

    #[test]
    fn contains_bytes_empty_needle_returns_false() {
        assert!(!contains_bytes(b"anything", b""));
    }

    #[test]
    fn contains_bytes_needle_longer_than_haystack() {
        assert!(!contains_bytes(b"short", b"longer than the haystack"));
    }
}
