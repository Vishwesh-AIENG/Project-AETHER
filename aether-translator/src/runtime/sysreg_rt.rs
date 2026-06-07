//! M4b-4: runtime dispatch for system registers with LIVE behaviour.
//!
//! Most guest sysregs are plain storage — `MRS`/`MSR` lower to a load/store of a
//! ctx slot (`backend/lower_int.rs`). A handful are NOT plain storage:
//!   * `CNTVCT_EL0` must return a monotonically advancing count (the kernel's
//!     delay loops spin on it — a static value hangs the boot).
//!   * `CNTV_TVAL_EL0` is `CVAL − CNTVCT`, i.e. relative to the live count.
//!   * `ICC_IAR1_EL1` (read) ACKNOWLEDGES the top interrupt — a side effect.
//!   * `ICC_EOIR1_EL1` (write) ENDS an interrupt — a side effect.
//!
//! For these, `MRS`/`MSR` instead lower to a Win64 CALL to [`aether_sysreg_read`]
//! / [`aether_sysreg_write`] (the same mid-block-call discipline as the MMU
//! walker), which dispatch on a baked `reg_id` to the live [`VirtualTimer`] /
//! [`VirtualGic`] singletons held here.
//!
//! Single-vCPU global state (the established EL2/VMX-root pattern, like the MMU
//! TLB). The hypervisor advances the live count each dispatch tick via
//! [`aether_timer_set_now`] and polls [`aether_pending_irq`] to decide IRQ
//! injection. The GIC DISTRIBUTOR config (enable / priority / group of each
//! INTID) arrives from the guest via GICD/GICR MMIO — the hypervisor's
//! `mmio_emu` routes those stores to [`aether_gic_set_enable`] etc. (the
//! documented integration boundary).
//!
//! `#![deny(unsafe_code)]` crate: localized `#[allow(unsafe_code)]` for the
//! `static mut` singletons, mirroring `mmu.rs`.

use crate::runtime::gic::{VirtualGic, SPURIOUS_INTID};
use crate::runtime::timer::{VirtualTimer, TIMER_VIRT_INTID};

/// Stable register IDs baked into the emitted `MRS`/`MSR` runtime call. Grouped
/// 0x1xx = timer, 0x2xx = GIC CPU interface. These are an internal ABI between
/// `backend/lower_int.rs` and this dispatcher; keep them in sync.
pub mod regid {
    // ── Generic timer ────────────────────────────────────────────────────────
    pub const CNTVCT_EL0: u32 = 0x100;
    pub const CNTFRQ_EL0: u32 = 0x101;
    pub const CNTV_CTL_EL0: u32 = 0x102;
    pub const CNTV_CVAL_EL0: u32 = 0x103;
    pub const CNTV_TVAL_EL0: u32 = 0x104;
    /// Physical count — aliased to the virtual count in the DBT (no CNTVOFF).
    pub const CNTPCT_EL0: u32 = 0x105;
    // ── GICv3 CPU interface ──────────────────────────────────────────────────
    pub const ICC_PMR_EL1: u32 = 0x200;
    pub const ICC_IAR1_EL1: u32 = 0x201;
    pub const ICC_EOIR1_EL1: u32 = 0x202;
    pub const ICC_HPPIR1_EL1: u32 = 0x203;
    pub const ICC_IGRPEN1_EL1: u32 = 0x204;
    pub const ICC_CTLR_EL1: u32 = 0x205;
    pub const ICC_SRE_EL1: u32 = 0x206;
    pub const ICC_BPR1_EL1: u32 = 0x207;
    pub const ICC_DIR_EL1: u32 = 0x208;
}

/// Default counter frequency (24 MHz — matches `seed_sysregs` CNTFRQ_EL0 and the
/// QEMU virt platform).
pub const DEFAULT_CNTFRQ: u64 = 24_000_000;

// ── Single-vCPU global platform state ────────────────────────────────────────
static mut TIMER: VirtualTimer = VirtualTimer::new(DEFAULT_CNTFRQ);
static mut GIC: VirtualGic = VirtualGic::new();
/// The live virtual count (CNTVCT_EL0). Advanced by `aether_timer_set_now`.
static mut NOW: u64 = 0;
/// `ICC_BPR1_EL1` storage (binary point — no preemption grouping modelled).
static mut BPR1: u64 = 0;

/// Diagnostic trackers for sysreg observability. The hypervisor heartbeat
/// reads these to answer "did the kernel poll an unmodeled sysreg between
/// the last two heartbeats?" A kernel feature-probe loop that reads
/// e.g. `ID_AA64ISAR1_EL1` and waits for a bit that we always return 0
/// for is invisible in MMIO/fault counters but pops here.
pub static mut SYSREG_LAST_READ_ID: u32 = 0;
pub static mut SYSREG_LAST_READ_VAL: u64 = 0;
pub static mut SYSREG_LAST_WRITE_ID: u32 = 0;
pub static mut SYSREG_LAST_WRITE_VAL: u64 = 0;
pub static mut SYSREG_UNKNOWN_READS: u32 = 0;
pub static mut SYSREG_UNKNOWN_WRITES: u32 = 0;
pub static mut SYSREG_LAST_UNKNOWN_READ_ID: u32 = 0;
pub static mut SYSREG_LAST_UNKNOWN_WRITE_ID: u32 = 0;

#[allow(unsafe_code)]
fn now() -> u64 {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { *core::ptr::addr_of!(NOW) }
}

/// Advance the live virtual count. The hypervisor calls this each dispatch tick
/// with a host-TSC-derived, CNTFRQ-scaled monotonic value.
#[allow(unsafe_code)]
pub extern "C" fn aether_timer_set_now(count: u64) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        *core::ptr::addr_of_mut!(NOW) = count;
    }
}

/// Reset all platform state (timer disabled, GIC empty, count 0). For the host
/// test harness between cases; also safe at boot bring-up.
#[allow(unsafe_code)]
pub extern "C" fn aether_platform_reset() {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        *core::ptr::addr_of_mut!(TIMER) = VirtualTimer::new(DEFAULT_CNTFRQ);
        *core::ptr::addr_of_mut!(GIC) = VirtualGic::new();
        *core::ptr::addr_of_mut!(NOW) = 0;
        *core::ptr::addr_of_mut!(BPR1) = 0;
    }
}

/// Service an `MRS` of a live sysreg. `reg_id` is a [`regid`] constant.
#[allow(unsafe_code)]
pub extern "C" fn aether_sysreg_read(reg_id: u32) -> u64 {
    use regid::*;
    let now = now();
    // SAFETY: EL2-private, single-vCPU; in-place access to the singletons.
    unsafe {
        let timer = &*core::ptr::addr_of!(TIMER);
        let gic = &mut *core::ptr::addr_of_mut!(GIC);
        let val = match reg_id {
            CNTVCT_EL0 | CNTPCT_EL0 => now,
            CNTFRQ_EL0 => timer.cntfrq,
            CNTV_CTL_EL0 => timer.read_ctl(now),
            CNTV_CVAL_EL0 => timer.read_cval(),
            CNTV_TVAL_EL0 => timer.read_tval(now),
            ICC_PMR_EL1 => gic.pmr as u64,
            ICC_IAR1_EL1 => gic.ack_iar1() as u64, // SIDE EFFECT: acknowledges
            ICC_HPPIR1_EL1 => gic.hppir1() as u64,
            ICC_IGRPEN1_EL1 => u64::from(gic.igrpen1),
            ICC_CTLR_EL1 => gic.ctlr,
            ICC_SRE_EL1 => gic.read_sre(),
            ICC_BPR1_EL1 => *core::ptr::addr_of!(BPR1),
            other => {
                *core::ptr::addr_of_mut!(SYSREG_UNKNOWN_READS) =
                    (*core::ptr::addr_of!(SYSREG_UNKNOWN_READS)).saturating_add(1);
                *core::ptr::addr_of_mut!(SYSREG_LAST_UNKNOWN_READ_ID) = other;
                0
            }
        };
        *core::ptr::addr_of_mut!(SYSREG_LAST_READ_ID) = reg_id;
        *core::ptr::addr_of_mut!(SYSREG_LAST_READ_VAL) = val;
        val
    }
}

/// Service an `MSR` of a live sysreg. `reg_id` is a [`regid`] constant.
#[allow(unsafe_code)]
pub extern "C" fn aether_sysreg_write(reg_id: u32, val: u64) {
    use regid::*;
    let now = now();
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        let timer = &mut *core::ptr::addr_of_mut!(TIMER);
        let gic = &mut *core::ptr::addr_of_mut!(GIC);
        *core::ptr::addr_of_mut!(SYSREG_LAST_WRITE_ID) = reg_id;
        *core::ptr::addr_of_mut!(SYSREG_LAST_WRITE_VAL) = val;
        match reg_id {
            CNTV_CTL_EL0 => timer.write_ctl(val),
            CNTV_CVAL_EL0 => timer.write_cval(val),
            CNTV_TVAL_EL0 => timer.write_tval(val, now),
            CNTFRQ_EL0 => timer.cntfrq = val,
            ICC_PMR_EL1 => gic.pmr = val as u8,
            ICC_EOIR1_EL1 => gic.eoir1(val as u32), // SIDE EFFECT: ends interrupt
            ICC_DIR_EL1 => gic.dir(val as u32),
            ICC_IGRPEN1_EL1 => gic.igrpen1 = val & 1 != 0,
            ICC_CTLR_EL1 => gic.ctlr = val,
            ICC_SRE_EL1 => { /* SRE is RAO/effectively fixed; ignore writes */ }
            ICC_BPR1_EL1 => *core::ptr::addr_of_mut!(BPR1) = val,
            other => {
                *core::ptr::addr_of_mut!(SYSREG_UNKNOWN_WRITES) =
                    (*core::ptr::addr_of!(SYSREG_UNKNOWN_WRITES)).saturating_add(1);
                *core::ptr::addr_of_mut!(SYSREG_LAST_UNKNOWN_WRITE_ID) = other;
            }
        }
    }
}

/// Poll the platform for a deliverable IRQ. Re-evaluates the virtual-timer PPI
/// (raising / lowering INTID 27 from the timer condition at the live count),
/// then returns the highest signalled GIC INTID — or [`SPURIOUS_INTID`] if none.
/// The dispatcher injects an IRQ exception when this is not spurious AND the
/// guest has `PSTATE.I` clear (`exceptions::irqs_unmasked`).
#[allow(unsafe_code)]
pub extern "C" fn aether_pending_irq() -> u32 {
    let now = now();
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        let timer = &*core::ptr::addr_of!(TIMER);
        let gic = &mut *core::ptr::addr_of_mut!(GIC);
        if timer.irq_pending(now) {
            gic.raise(TIMER_VIRT_INTID);
        } else {
            gic.lower(TIMER_VIRT_INTID);
        }
        gic.signalled_irq().unwrap_or(SPURIOUS_INTID)
    }
}

// ── GIC distributor configuration (driven by GICD/GICR MMIO emulation) ───────
// The hypervisor's mmio_emu routes guest stores to the GICD_ISENABLER /
// GICD_IPRIORITYR / GICD_IGROUPR (and GICR equivalents for PPIs/SGIs) windows
// to these entry points so the modelled distributor state tracks the guest's
// configuration. Until that MMIO routing lands these can also be called by the
// boot path to pre-arm the timer PPI.

#[allow(unsafe_code)]
pub extern "C" fn aether_gic_set_enable(intid: u32, enable: u32) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { (*core::ptr::addr_of_mut!(GIC)).set_enable(intid, enable != 0) }
}
#[allow(unsafe_code)]
pub extern "C" fn aether_gic_set_priority(intid: u32, prio: u32) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { (*core::ptr::addr_of_mut!(GIC)).set_priority(intid, prio as u8) }
}
#[allow(unsafe_code)]
pub extern "C" fn aether_gic_set_group1(intid: u32, group1: u32) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { (*core::ptr::addr_of_mut!(GIC)).set_group1(intid, group1 != 0) }
}
/// Assert an SPI/PPI/SGI line (e.g. the UART raising its SPI). Idempotent.
#[allow(unsafe_code)]
pub extern "C" fn aether_gic_raise(intid: u32) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { (*core::ptr::addr_of_mut!(GIC)).raise(intid) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::gic::ICC_IGRPEN1_ENABLE;
    use crate::runtime::timer::{CNTV_CTL_ENABLE, TIMER_VIRT_INTID};
    use regid::*;
    use std::sync::Mutex;

    // The dispatcher is process-global; serialize the tests that drive it.
    static RT_LOCK: Mutex<()> = Mutex::new(());

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = RT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        aether_platform_reset();
        g
    }

    #[test]
    fn cntvct_advances_with_set_now() {
        let _g = setup();
        aether_timer_set_now(1000);
        assert_eq!(aether_sysreg_read(CNTVCT_EL0), 1000);
        aether_timer_set_now(2500);
        assert_eq!(aether_sysreg_read(CNTVCT_EL0), 2500, "CNTVCT tracks the live count");
        // CNTPCT aliases the virtual count.
        assert_eq!(aether_sysreg_read(CNTPCT_EL0), 2500);
        assert_eq!(aether_sysreg_read(CNTFRQ_EL0), DEFAULT_CNTFRQ);
    }

    #[test]
    fn timer_ctl_cval_tval_roundtrip() {
        let _g = setup();
        aether_timer_set_now(5000);
        aether_sysreg_write(CNTV_CTL_EL0, CNTV_CTL_ENABLE);
        aether_sysreg_write(CNTV_TVAL_EL0, 1000); // CVAL = 6000
        assert_eq!(aether_sysreg_read(CNTV_CVAL_EL0), 6000);
        aether_timer_set_now(5500);
        assert_eq!(aether_sysreg_read(CNTV_TVAL_EL0), 500, "TVAL = CVAL - now");
        assert_eq!(aether_sysreg_read(CNTV_CTL_EL0) & CNTV_CTL_ENABLE, CNTV_CTL_ENABLE);
    }

    #[test]
    fn pending_irq_fires_when_timer_expires_and_gic_armed() {
        let _g = setup();
        // Arm the timer PPI in the GIC the way GICR MMIO config would.
        aether_gic_set_priority(TIMER_VIRT_INTID, 0xA0);
        aether_gic_set_group1(TIMER_VIRT_INTID, 1);
        aether_gic_set_enable(TIMER_VIRT_INTID, 1);
        aether_sysreg_write(ICC_PMR_EL1, 0xF0);
        aether_sysreg_write(ICC_IGRPEN1_EL1, ICC_IGRPEN1_ENABLE);
        // Program a timer for count 1000.
        aether_sysreg_write(CNTV_CVAL_EL0, 1000);
        aether_sysreg_write(CNTV_CTL_EL0, CNTV_CTL_ENABLE);
        // Before expiry: spurious.
        aether_timer_set_now(500);
        assert_eq!(aether_pending_irq(), SPURIOUS_INTID, "not yet expired");
        // After expiry: the timer PPI signals.
        aether_timer_set_now(1500);
        assert_eq!(aether_pending_irq(), TIMER_VIRT_INTID, "timer fires -> PPI signalled");
        // Acknowledge via IAR1, EOI via EOIR1 — lifecycle through the sysreg path.
        assert_eq!(aether_sysreg_read(ICC_IAR1_EL1), TIMER_VIRT_INTID as u64);
        assert_eq!(aether_pending_irq(), SPURIOUS_INTID, "acked -> no longer signalled");
        aether_sysreg_write(ICC_EOIR1_EL1, TIMER_VIRT_INTID as u64);
        // Still expired -> re-raised + signalled again after EOI.
        assert_eq!(aether_pending_irq(), TIMER_VIRT_INTID, "still expired -> re-signals");
    }

    #[test]
    fn icc_sre_reads_as_set() {
        let _g = setup();
        assert_ne!(aether_sysreg_read(ICC_SRE_EL1) & 1, 0, "SRE reads as 1");
    }
}
