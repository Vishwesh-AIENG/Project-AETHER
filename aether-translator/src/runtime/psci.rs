//! M4b-4: PSCI (Power State Coordination Interface) emulation.
//!
//! The Android guest's `psci` Linux driver calls into firmware via `HVC` (or
//! `SMC`) with a PSCI function ID in `w0` and arguments in `x1..x3`, expecting a
//! 32-bit status / value back in `w0`. On AETHER there is no firmware below the
//! hypervisor, so the DBT intercepts the `HVC`/`SMC` VM-exit and services PSCI
//! here. This module is the PURE decode + policy: given `(func_id, x1, x2, x3)`
//! it returns the value to place in `x0` plus an [`PsciAction`] the hypervisor
//! carries out (power off, reset, bring up a secondary core, …).
//!
//! Spec: Arm Power State Coordination Interface (DEN 0022, v1.1). Conduit is
//! `HVC` for a hypervisor-provided implementation (the guest DT declares
//! `method = "hvc"`).
//!
//! `no_std`, no-alloc, no I/O — a single match. Host-tested.

// ── Function IDs ─────────────────────────────────────────────────────────────
// SMC32 ("Fast Call", 32-bit) IDs are 0x8400_00xx; their 64-bit (SMC64)
// counterparts are 0xC400_00xx. The guest uses the 64-bit forms for calls that
// pass addresses/MPIDRs (CPU_ON, AFFINITY_INFO, …) and the 32-bit forms for the
// rest. We accept both where both exist.
pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const PSCI_CPU_SUSPEND_32: u32 = 0x8400_0001;
pub const PSCI_CPU_SUSPEND_64: u32 = 0xC400_0001;
pub const PSCI_CPU_OFF: u32 = 0x8400_0002;
pub const PSCI_CPU_ON_32: u32 = 0x8400_0003;
pub const PSCI_CPU_ON_64: u32 = 0xC400_0003;
pub const PSCI_AFFINITY_INFO_32: u32 = 0x8400_0004;
pub const PSCI_AFFINITY_INFO_64: u32 = 0xC400_0004;
pub const PSCI_MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
pub const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
pub const PSCI_FEATURES: u32 = 0x8400_000A;
pub const PSCI_SYSTEM_SUSPEND_32: u32 = 0x8400_000E;
pub const PSCI_SYSTEM_SUSPEND_64: u32 = 0xC400_000E;

// ── Return codes (DEN 0022 §5.2.2) — 32-bit signed, sign-extended into x0 ─────
pub const PSCI_SUCCESS: i64 = 0;
pub const PSCI_NOT_SUPPORTED: i64 = -1;
pub const PSCI_INVALID_PARAMETERS: i64 = -2;
pub const PSCI_DENIED: i64 = -3;
pub const PSCI_ALREADY_ON: i64 = -4;
pub const PSCI_ON_PENDING: i64 = -5;
pub const PSCI_INTERNAL_FAILURE: i64 = -6;
pub const PSCI_NOT_PRESENT: i64 = -7;
pub const PSCI_DISABLED: i64 = -8;
pub const PSCI_INVALID_ADDRESS: i64 = -9;

/// Reported PSCI version: 1.1 ((major << 16) | minor).
pub const PSCI_VERSION_1_1: u64 = (1 << 16) | 1;

/// AFFINITY_INFO state values.
pub const AFFINITY_ON: u64 = 0;
pub const AFFINITY_OFF: u64 = 1;
pub const AFFINITY_ON_PENDING: u64 = 2;

/// MIGRATE_INFO_TYPE: Trusted OS not present / not required (MP system).
pub const TOS_NOT_PRESENT_MP: u64 = 2;

/// What the hypervisor must do after PSCI returns `x0` to the guest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PsciAction {
    /// Place `x0` in the guest, advance past the `HVC`/`SMC`, continue.
    Return,
    /// SYSTEM_OFF — power the guest down (the call does not return).
    SystemOff,
    /// SYSTEM_RESET — reset the guest.
    SystemReset,
    /// CPU_OFF — the calling vCPU goes offline (does not return).
    CpuOff,
    /// CPU_ON — bring up a secondary core at `entry_point` with `context_id` in
    /// its x0. The hypervisor performs the bring-up (or, single-core, replaces
    /// `x0` with a failure code). `target_mpidr` is the MPIDR_EL1 affinity.
    CpuOn {
        target_mpidr: u64,
        entry_point: u64,
        context_id: u64,
    },
}

/// PSCI call result: the value for the caller's `x0` plus the hypervisor action.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PsciOutcome {
    pub x0: u64,
    pub action: PsciAction,
}

impl PsciOutcome {
    #[inline]
    fn ret(code: i64) -> Self {
        PsciOutcome { x0: code as u64, action: PsciAction::Return }
    }
    #[inline]
    fn val(x0: u64) -> Self {
        PsciOutcome { x0, action: PsciAction::Return }
    }
}

/// True if `func_id` is a PSCI function this implementation services — the set
/// `PSCI_FEATURES` reports as supported.
fn is_supported(func_id: u32) -> bool {
    matches!(
        func_id,
        PSCI_VERSION
            | PSCI_CPU_SUSPEND_32 | PSCI_CPU_SUSPEND_64
            | PSCI_CPU_OFF
            | PSCI_CPU_ON_32 | PSCI_CPU_ON_64
            | PSCI_AFFINITY_INFO_32 | PSCI_AFFINITY_INFO_64
            | PSCI_MIGRATE_INFO_TYPE
            | PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET
            | PSCI_FEATURES
            | PSCI_SYSTEM_SUSPEND_32 | PSCI_SYSTEM_SUSPEND_64
    )
}

/// Service one PSCI call. `func_id` is `w0` (the low 32 bits of x0); `x1..x3`
/// are the argument registers.
///
/// `boot_mpidr` is the affinity of the (single, for bring-up) running core —
/// AFFINITY_INFO reports it ON and every other affinity OFF.
pub fn psci_dispatch(func_id: u32, x1: u64, x2: u64, x3: u64, boot_mpidr: u64) -> PsciOutcome {
    /// MPIDR affinity bits [39:0] (Aff3 [39:32] | Aff2 [23:16] | Aff1 [15:8] |
    /// Aff0 [7:0]); the U/MT/RES bits above are ignored for comparison.
    const MPIDR_AFFINITY_MASK: u64 = 0x0000_00FF_00FF_FFFF;

    match func_id {
        PSCI_VERSION => PsciOutcome::val(PSCI_VERSION_1_1),

        PSCI_FEATURES => {
            // x1 = the queried function ID. SUCCESS(0) = supported with default
            // features; NOT_SUPPORTED otherwise. (PSCI_VERSION/FEATURES query as
            // supported too.)
            if is_supported(x1 as u32) {
                PsciOutcome::ret(PSCI_SUCCESS)
            } else {
                PsciOutcome::ret(PSCI_NOT_SUPPORTED)
            }
        }

        PSCI_AFFINITY_INFO_32 | PSCI_AFFINITY_INFO_64 => {
            // x1 = target affinity (MPIDR-format), x2 = lowest affinity level.
            // Only the boot core is ON in the bring-up (single-core) model.
            if x1 & MPIDR_AFFINITY_MASK == boot_mpidr & MPIDR_AFFINITY_MASK {
                PsciOutcome::val(AFFINITY_ON)
            } else {
                PsciOutcome::val(AFFINITY_OFF)
            }
        }

        PSCI_MIGRATE_INFO_TYPE => PsciOutcome::val(TOS_NOT_PRESENT_MP),

        PSCI_CPU_ON_32 | PSCI_CPU_ON_64 => {
            // x1 = target MPIDR, x2 = entry point, x3 = context id. The boot
            // core is already on; turning it on again is ALREADY_ON.
            if x1 & MPIDR_AFFINITY_MASK == boot_mpidr & MPIDR_AFFINITY_MASK {
                return PsciOutcome::ret(PSCI_ALREADY_ON);
            }
            PsciOutcome {
                x0: PSCI_SUCCESS as u64,
                action: PsciAction::CpuOn {
                    target_mpidr: x1,
                    entry_point: x2,
                    context_id: x3,
                },
            }
        }

        PSCI_CPU_OFF => PsciOutcome {
            x0: PSCI_SUCCESS as u64,
            action: PsciAction::CpuOff,
        },

        // CPU_SUSPEND / SYSTEM_SUSPEND: a successful suspend returns to the
        // caller (wakeup) with SUCCESS in the DBT's non-suspending model.
        PSCI_CPU_SUSPEND_32 | PSCI_CPU_SUSPEND_64
        | PSCI_SYSTEM_SUSPEND_32 | PSCI_SYSTEM_SUSPEND_64 => {
            PsciOutcome::ret(PSCI_SUCCESS)
        }

        PSCI_SYSTEM_OFF => PsciOutcome {
            x0: PSCI_SUCCESS as u64,
            action: PsciAction::SystemOff,
        },
        PSCI_SYSTEM_RESET => PsciOutcome {
            x0: PSCI_SUCCESS as u64,
            action: PsciAction::SystemReset,
        },

        _ => PsciOutcome::ret(PSCI_NOT_SUPPORTED),
    }
}

// ── HVC/SMC conduit — guest entry point ──────────────────────────────────────

use crate::runtime::context::{CTX_U64S, SYSREG_SLOT0};

/// MPIDR_EL1 sysreg sub-slot index (must match `backend/lower_int.rs`
/// `sysreg_read_idx`).
const SR_MPIDR: usize = 41;

/// A platform action an HVC requested that the hypervisor must carry out after
/// the current block (the value is returned to the guest in x0 regardless).
/// `#[repr(u32)]` so the `extern "C"` [`aether_hvc_take_action`] is FFI-safe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum HvcPlatformAction {
    /// Nothing for the hypervisor to do; just resume the guest.
    None,
    /// PSCI SYSTEM_OFF — power the guest down.
    SystemOff,
    /// PSCI SYSTEM_RESET — reset the guest.
    SystemReset,
    /// PSCI CPU_OFF — the calling vCPU goes offline.
    CpuOff,
}

/// Pending platform action recorded by the most recent HVC (single-vCPU global,
/// the established EL2 pattern). The hypervisor polls [`aether_hvc_take_action`].
static mut HVC_PENDING: HvcPlatformAction = HvcPlatformAction::None;

/// Service a guest `HVC`/`SMC` (the PSCI conduit). Reads the function ID + args
/// from the guest GPRs in `ctx` (x0 = func id, x1..x3 = args), dispatches PSCI,
/// writes the result to the guest x0, and records any platform action (power
/// off / reset / cpu off) for the hypervisor to carry out.
///
/// The guest register file lives in the R15 context memory between instructions
/// (the template-JIT model re-reads each GPR from `ctx` per instruction), so
/// reading/writing `ctx[0..4]` here is consistent with the surrounding block.
///
/// # Safety
/// `ctx` must point at a valid context buffer of ≥ `CTX_U64S` u64s.
#[allow(unsafe_code)]
pub unsafe extern "C" fn aether_hvc_dispatch(ctx: *mut u64) {
    // SAFETY: caller's contract — ctx is the register-file base.
    let regs = unsafe { core::slice::from_raw_parts_mut(ctx, CTX_U64S) };
    let func_id = regs[0] as u32;
    let (x1, x2, x3) = (regs[1], regs[2], regs[3]);
    let boot_mpidr = regs[SYSREG_SLOT0 + SR_MPIDR];
    let outcome = psci_dispatch(func_id, x1, x2, x3, boot_mpidr);
    regs[0] = outcome.x0;
    let action = match outcome.action {
        PsciAction::SystemOff => HvcPlatformAction::SystemOff,
        PsciAction::SystemReset => HvcPlatformAction::SystemReset,
        PsciAction::CpuOff => HvcPlatformAction::CpuOff,
        // CPU_ON for a secondary returns SUCCESS in x0, but single-core bring-up
        // does not actually start it (the guest DT can declare one CPU). SMP
        // secondary bring-up is future work.
        PsciAction::CpuOn { .. } | PsciAction::Return => HvcPlatformAction::None,
    };
    if action != HvcPlatformAction::None {
        // SAFETY: EL2-private, single-vCPU.
        unsafe {
            *core::ptr::addr_of_mut!(HVC_PENDING) = action;
        }
    }
}

/// Read and clear the pending HVC platform action. The hypervisor polls this
/// after a block to power off / reset / take a vCPU offline.
#[allow(unsafe_code)]
pub extern "C" fn aether_hvc_take_action() -> HvcPlatformAction {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        let p = core::ptr::addr_of_mut!(HVC_PENDING);
        let a = *p;
        *p = HvcPlatformAction::None;
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: u64 = 0x8000_0000; // MPIDR_EL1 boot core (bit31 RES1, Aff0=0)

    #[test]
    fn version_is_1_1() {
        let o = psci_dispatch(PSCI_VERSION, 0, 0, 0, BOOT);
        assert_eq!(o.x0, PSCI_VERSION_1_1);
        assert_eq!(o.x0, 0x0001_0001);
        assert_eq!(o.action, PsciAction::Return);
    }

    #[test]
    fn features_reports_supported_and_unsupported() {
        assert_eq!(
            psci_dispatch(PSCI_FEATURES, PSCI_CPU_ON_64 as u64, 0, 0, BOOT).x0,
            PSCI_SUCCESS as u64
        );
        assert_eq!(
            psci_dispatch(PSCI_FEATURES, 0xDEAD_BEEF, 0, 0, BOOT).x0,
            PSCI_NOT_SUPPORTED as u64
        );
    }

    #[test]
    fn affinity_info_boot_on_others_off() {
        // Boot core (affinity 0) -> ON.
        assert_eq!(
            psci_dispatch(PSCI_AFFINITY_INFO_64, 0, 0, 0, BOOT).x0,
            AFFINITY_ON
        );
        // A different affinity -> OFF.
        assert_eq!(
            psci_dispatch(PSCI_AFFINITY_INFO_64, 1, 0, 0, BOOT).x0,
            AFFINITY_OFF
        );
    }

    #[test]
    fn cpu_on_secondary_yields_action_and_already_on_for_boot() {
        let o = psci_dispatch(PSCI_CPU_ON_64, 1, 0x4080_0000, 0xABCD, BOOT);
        assert_eq!(o.x0, PSCI_SUCCESS as u64);
        assert_eq!(
            o.action,
            PsciAction::CpuOn { target_mpidr: 1, entry_point: 0x4080_0000, context_id: 0xABCD }
        );
        // Turning the boot core on again -> ALREADY_ON, no action.
        let boot_again = psci_dispatch(PSCI_CPU_ON_64, BOOT, 0x4080_0000, 0, BOOT);
        assert_eq!(boot_again.x0, PSCI_ALREADY_ON as u64);
        assert_eq!(boot_again.action, PsciAction::Return);
    }

    #[test]
    fn system_off_and_reset_actions() {
        assert_eq!(
            psci_dispatch(PSCI_SYSTEM_OFF, 0, 0, 0, BOOT).action,
            PsciAction::SystemOff
        );
        assert_eq!(
            psci_dispatch(PSCI_SYSTEM_RESET, 0, 0, 0, BOOT).action,
            PsciAction::SystemReset
        );
    }

    #[test]
    fn migrate_info_type_is_mp() {
        assert_eq!(
            psci_dispatch(PSCI_MIGRATE_INFO_TYPE, 0, 0, 0, BOOT).x0,
            TOS_NOT_PRESENT_MP
        );
    }

    #[test]
    fn unknown_func_is_not_supported() {
        assert_eq!(
            psci_dispatch(0x8400_00FF, 0, 0, 0, BOOT).x0,
            PSCI_NOT_SUPPORTED as u64
        );
    }

    #[test]
    fn negative_codes_sign_extend_into_x0() {
        // The kernel reads w0 as a signed int; -1 must be 0xFFFF_FFFF_FFFF_FFFF.
        assert_eq!(
            psci_dispatch(PSCI_FEATURES, 0xDEAD_BEEF, 0, 0, BOOT).x0,
            0xFFFF_FFFF_FFFF_FFFF
        );
    }
}
