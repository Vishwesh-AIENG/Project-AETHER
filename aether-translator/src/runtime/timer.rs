//! M4b-4: virtual AArch64 generic timer (the EL1 virtual timer, CNTV).
//!
//! The guest kernel programs the virtual timer through system registers —
//! `CNTVCT_EL0` (the live count), `CNTV_CTL_EL0` (enable / mask / status),
//! `CNTV_CVAL_EL0` (compare value), `CNTV_TVAL_EL0` (a count-relative
//! down-value), `CNTFRQ_EL0` (frequency) — and expects a virtual-timer
//! interrupt (PPI 27) when the count reaches the compare value and the timer is
//! enabled and unmasked. Under the DBT these registers are not real silicon, so
//! this module models them.
//!
//! `VirtualTimer` is a PURE state machine: the live count `now` is supplied by
//! the caller (the hypervisor's monotonic tick, derived from a scaled host TSC),
//! so the struct has no global/host dependency and is fully host-tested. The
//! global instance + the live-count plumbing live in the sysreg-dispatch layer
//! (`runtime::sysreg_rt`).
//!
//! Architectural condition (Arm ARM D11.2.4): the timer asserts its interrupt
//! when `CNTV_CTL.ENABLE == 1`, `(CNTVCT - CNTV_CVAL) >= 0` interpreted as a
//! **signed 64-bit** difference (so it is wrap-correct), and `CNTV_CTL.IMASK ==
//! 0`. `CNTV_CTL.ISTATUS` reflects the (enable + compare) condition regardless
//! of IMASK and is read-only.
//!
//! `no_std`, no-alloc.

/// `CNTV_CTL_EL0.ENABLE` (bit 0).
pub const CNTV_CTL_ENABLE: u64 = 1 << 0;
/// `CNTV_CTL_EL0.IMASK` (bit 1) — when set, the timer condition does not raise
/// an interrupt (but ISTATUS still reflects it).
pub const CNTV_CTL_IMASK: u64 = 1 << 1;
/// `CNTV_CTL_EL0.ISTATUS` (bit 2) — read-only; the compare condition is met.
pub const CNTV_CTL_ISTATUS: u64 = 1 << 2;

/// Default virtual-timer interrupt INTID — PPI 11 maps to absolute INTID 27,
/// the standard arm64 virtual timer PPI (matches `irq_forward::TIMER_VIRT_INTID`
/// on the ARM tier).
pub const TIMER_VIRT_INTID: u32 = 27;

/// Virtual EL1 timer state. `now` (CNTVCT) is passed to every method that needs
/// it, keeping the struct pure and host-testable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualTimer {
    /// `CNTFRQ_EL0` — counter frequency in Hz (seeded by the platform).
    pub cntfrq: u64,
    /// `CNTV_CTL_EL0` ENABLE|IMASK (ISTATUS is computed live, never stored).
    pub ctl: u64,
    /// `CNTV_CVAL_EL0` — the 64-bit compare value.
    pub cval: u64,
}

impl VirtualTimer {
    /// A disabled timer at frequency `cntfrq`.
    pub const fn new(cntfrq: u64) -> Self {
        VirtualTimer { cntfrq, ctl: 0, cval: 0 }
    }

    /// `CNTV_CTL_EL0` read: stored ENABLE|IMASK plus the live ISTATUS bit.
    pub fn read_ctl(&self, now: u64) -> u64 {
        let mut v = self.ctl & (CNTV_CTL_ENABLE | CNTV_CTL_IMASK);
        if self.condition_met(now) {
            v |= CNTV_CTL_ISTATUS;
        }
        v
    }

    /// `CNTV_CTL_EL0` write: ISTATUS is read-only, so only ENABLE|IMASK persist.
    pub fn write_ctl(&mut self, v: u64) {
        self.ctl = v & (CNTV_CTL_ENABLE | CNTV_CTL_IMASK);
    }

    /// `CNTV_CVAL_EL0` read / write (the 64-bit compare value).
    pub fn read_cval(&self) -> u64 {
        self.cval
    }
    pub fn write_cval(&mut self, v: u64) {
        self.cval = v;
    }

    /// `CNTV_TVAL_EL0` read = `(CNTV_CVAL - CNTVCT)` truncated to a signed 32-bit
    /// value and sign-extended (the kernel reads it as a `w` register / `s32`).
    pub fn read_tval(&self, now: u64) -> u64 {
        let diff = self.cval.wrapping_sub(now) as i32; // truncate to 32 bits
        diff as i64 as u64 // sign-extend to 64
    }

    /// `CNTV_TVAL_EL0` write: `CNTV_CVAL = CNTVCT + sign_extend32(v)`.
    pub fn write_tval(&mut self, v: u64, now: u64) {
        let tval = v as u32 as i32 as i64; // low 32 bits, signed
        self.cval = now.wrapping_add(tval as u64);
    }

    /// The compare condition: ENABLE set and the signed 64-bit difference
    /// `CNTVCT - CNTV_CVAL >= 0` (wrap-correct).
    pub fn condition_met(&self, now: u64) -> bool {
        self.ctl & CNTV_CTL_ENABLE != 0 && (now.wrapping_sub(self.cval) as i64) >= 0
    }

    /// The virtual-timer interrupt is asserted: condition met AND not masked.
    pub fn irq_pending(&self, now: u64) -> bool {
        self.condition_met(now) && self.ctl & CNTV_CTL_IMASK == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRQ: u64 = 24_000_000; // 24 MHz, matches seed_sysregs CNTFRQ_EL0

    #[test]
    fn disabled_timer_never_fires() {
        let t = VirtualTimer::new(FRQ);
        assert!(!t.condition_met(u64::MAX), "disabled -> condition never met");
        assert!(!t.irq_pending(u64::MAX));
    }

    #[test]
    fn fires_when_count_reaches_cval() {
        let mut t = VirtualTimer::new(FRQ);
        t.write_cval(1000);
        t.write_ctl(CNTV_CTL_ENABLE);
        assert!(!t.condition_met(999), "before cval -> not met");
        assert!(t.condition_met(1000), "at cval -> met");
        assert!(t.condition_met(5000), "after cval -> met");
        assert!(t.irq_pending(1000), "met + unmasked -> pending");
    }

    #[test]
    fn imask_suppresses_irq_but_not_istatus() {
        let mut t = VirtualTimer::new(FRQ);
        t.write_cval(100);
        t.write_ctl(CNTV_CTL_ENABLE | CNTV_CTL_IMASK);
        assert!(t.condition_met(200), "condition still met under mask");
        assert!(!t.irq_pending(200), "masked -> no IRQ");
        // ISTATUS visible in CTL read even when masked.
        assert_ne!(t.read_ctl(200) & CNTV_CTL_ISTATUS, 0, "ISTATUS reflects condition");
        // ISTATUS is read-only: writing it does not persist.
        t.write_ctl(CNTV_CTL_ISTATUS);
        assert_eq!(t.ctl & CNTV_CTL_ISTATUS, 0, "ISTATUS not stored");
    }

    #[test]
    fn istatus_clears_when_cval_reprogrammed_ahead() {
        let mut t = VirtualTimer::new(FRQ);
        t.write_ctl(CNTV_CTL_ENABLE);
        t.write_cval(100);
        assert_ne!(t.read_ctl(150) & CNTV_CTL_ISTATUS, 0, "fired at 150");
        // Reprogram the compare ahead of now -> ISTATUS clears (kernel's tick).
        t.write_cval(500);
        assert_eq!(t.read_ctl(150) & CNTV_CTL_ISTATUS, 0, "rearmed -> ISTATUS clear");
        assert!(!t.irq_pending(150));
    }

    #[test]
    fn tval_is_cval_minus_now_signed() {
        let mut t = VirtualTimer::new(FRQ);
        t.write_ctl(CNTV_CTL_ENABLE);
        // Program a 1000-tick timeout from now=5000 via TVAL.
        t.write_tval(1000, 5000);
        assert_eq!(t.cval, 6000, "TVAL write sets CVAL = now + tval");
        // Read TVAL back at now=5500 -> 500 remaining.
        assert_eq!(t.read_tval(5500), 500, "TVAL = CVAL - now");
        // Past the deadline -> negative TVAL (sign-extended).
        assert_eq!(t.read_tval(6500) as i64 as i32, -500, "TVAL goes negative past CVAL");
        assert!(t.condition_met(6500), "and the condition is met");
    }

    #[test]
    fn condition_is_wrap_correct() {
        // CVAL just below the 64-bit wrap; now just after wrap. Signed diff >= 0.
        let mut t = VirtualTimer::new(FRQ);
        t.write_ctl(CNTV_CTL_ENABLE);
        t.write_cval(u64::MAX - 10);
        assert!(!t.condition_met(u64::MAX - 11), "before -> not met");
        assert!(t.condition_met(5), "wrapped past CVAL -> met (signed diff >= 0)");
    }
}
