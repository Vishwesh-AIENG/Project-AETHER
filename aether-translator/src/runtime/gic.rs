//! M4b-4: minimal virtual GICv3 for the x86 host-mode DBT.
//!
//! GICv3 has two halves: the **distributor / redistributor** (MMIO: GICD_* /
//! GICR_*) that holds per-interrupt configuration (enable / pending / priority /
//! group / routing), and the **CPU interface** (system registers: `ICC_*`) that
//! the core uses to mask, acknowledge, and end interrupts. The Android kernel's
//! GICv3 driver drives both. Under the DBT there is no silicon GIC, so this
//! module models the architectural state and the CPU-interface operations.
//!
//! This is the CPU-interface + per-INTID state machine, host-tested. The
//! MMIO GICD/GICR decode (which sets enable/priority/group from guest stores to
//! the distributor window) is the INTEGRATION BOUNDARY: the hypervisor's
//! `mmio_emu` routes GICD_* / GICR_* accesses to the `set_enable` / `set_priority`
//! / `set_group1` / `raise` methods here. The CPU-interface `ICC_*` system
//! registers route here through the sysreg-dispatch layer (`runtime::sysreg_rt`).
//!
//! INTID space modeled: 0..[`GIC_MAX_INTID`) — SGIs (0–15), PPIs (16–31, incl.
//! the virtual timer PPI 27), and the low SPIs (32+, e.g. the UART) the bring-up
//! path uses. Higher SPIs and LPIs are out of scope for bring-up.
//!
//! Priority convention (Arm IHI 0069): LOWER numeric value = HIGHER priority. An
//! interrupt is signalled to the CPU only when its priority is numerically less
//! than both `ICC_PMR_EL1` (the mask) and the current running priority. Group 1
//! (non-secure) is the only group Android uses; `ICC_IGRPEN1_EL1.Enable` gates
//! signalling.
//!
//! `no_std`, no-alloc, fixed-size arrays.

/// Number of INTIDs modeled (SGI + PPI + low SPI). 256 covers the timer PPI and
/// the handful of SPIs early boot touches.
pub const GIC_MAX_INTID: usize = 256;

/// The "no interrupt" / spurious INTID returned by `ICC_IAR1_EL1` when nothing
/// can be acknowledged (Arm IHI 0069: 1020–1023 are special; 1023 = spurious).
pub const SPURIOUS_INTID: u32 = 1023;

/// Idle running priority — numerically the lowest, so any real interrupt
/// (priority < 0xFF) preempts it.
const IDLE_PRIORITY: u8 = 0xFF;

/// `ICC_CTLR_EL1.EOImode` (bit 1): 0 = `EOIR1` drops priority AND deactivates;
/// 1 = `EOIR1` only drops priority, `ICC_DIR_EL1` deactivates (split EOI, the
/// mode modern Linux uses for its IRQ flow).
const ICC_CTLR_EOIMODE: u64 = 1 << 1;

/// `ICC_SRE_EL1.SRE` (bit 0) — System Register Enable. The kernel sets it; we
/// report it permanently set (the DBT CPU interface is sysreg-only).
pub const ICC_SRE_SRE: u64 = 1 << 0;

/// `ICC_IGRPEN1_EL1.Enable` (bit 0).
pub const ICC_IGRPEN1_ENABLE: u64 = 1 << 0;

/// Minimal virtual GICv3 (distributor state + one CPU interface).
#[derive(Clone, Copy)]
pub struct VirtualGic {
    // ── Distributor per-INTID state ──────────────────────────────────────────
    enabled: [bool; GIC_MAX_INTID],
    pending: [bool; GIC_MAX_INTID],
    active: [bool; GIC_MAX_INTID],
    priority: [u8; GIC_MAX_INTID],
    group1: [bool; GIC_MAX_INTID],

    // ── CPU interface (ICC_*) ────────────────────────────────────────────────
    /// `ICC_CTLR_EL1` (only EOImode is consulted).
    pub ctlr: u64,
    /// `ICC_PMR_EL1` priority mask — interrupts with `prio < pmr` pass.
    pub pmr: u8,
    /// `ICC_IGRPEN1_EL1.Enable`.
    pub igrpen1: bool,
    /// Current running priority (the priority of the active interrupt, or
    /// `IDLE_PRIORITY`). Single-level: nested preemption is simplified — correct
    /// for the non-nested bring-up IRQ flow.
    running_priority: u8,
}

impl VirtualGic {
    /// A fresh GIC: nothing enabled/pending, PMR=0 (all masked, the architectural
    /// reset), group 1 disabled, idle.
    pub const fn new() -> Self {
        VirtualGic {
            enabled: [false; GIC_MAX_INTID],
            pending: [false; GIC_MAX_INTID],
            active: [false; GIC_MAX_INTID],
            priority: [0xA0; GIC_MAX_INTID], // mid default; kernel programs real values
            group1: [false; GIC_MAX_INTID],
            ctlr: 0,
            pmr: 0,
            igrpen1: false,
            running_priority: IDLE_PRIORITY,
        }
    }

    // ── Distributor configuration (driven by GICD/GICR MMIO emulation) ───────

    pub fn set_enable(&mut self, intid: u32, en: bool) {
        if let Some(i) = Self::idx(intid) {
            self.enabled[i] = en;
        }
    }
    pub fn set_priority(&mut self, intid: u32, prio: u8) {
        if let Some(i) = Self::idx(intid) {
            self.priority[i] = prio;
        }
    }
    pub fn set_group1(&mut self, intid: u32, g1: bool) {
        if let Some(i) = Self::idx(intid) {
            self.group1[i] = g1;
        }
    }

    /// Assert interrupt `intid` (a peripheral or the virtual timer raising its
    /// line, or an SGI). Idempotent for level-pending.
    pub fn raise(&mut self, intid: u32) {
        if let Some(i) = Self::idx(intid) {
            self.pending[i] = true;
        }
    }
    /// Deassert a (level-triggered) interrupt's pending state — e.g. the timer
    /// after the kernel reprograms CVAL so its condition is no longer met.
    pub fn lower(&mut self, intid: u32) {
        if let Some(i) = Self::idx(intid) {
            self.pending[i] = false;
        }
    }

    // ── CPU interface operations (ICC_*) ─────────────────────────────────────

    /// The highest-priority group-1 interrupt that is enabled, pending, and not
    /// already active — independent of PMR / running priority / IGRPEN1. This is
    /// what `ICC_HPPIR1_EL1` reports.
    fn highest_pending_g1(&self) -> Option<(u32, u8)> {
        let mut best: Option<(u32, u8)> = None;
        for i in 0..GIC_MAX_INTID {
            if self.enabled[i] && self.pending[i] && !self.active[i] && self.group1[i] {
                let p = self.priority[i];
                match best {
                    Some((_, bp)) if bp <= p => {}
                    _ => best = Some((i as u32, p)),
                }
            }
        }
        best
    }

    /// The interrupt that would actually be SIGNALLED to the CPU now: the
    /// highest group-1 pending, gated by IGRPEN1 and by `prio < PMR` and
    /// `prio < running_priority`.
    fn to_signal(&self) -> Option<(u32, u8)> {
        if !self.igrpen1 {
            return None;
        }
        let (intid, prio) = self.highest_pending_g1()?;
        if (prio as u16) < (self.pmr as u16) && prio < self.running_priority {
            Some((intid, prio))
        } else {
            None
        }
    }

    /// INTID of the interrupt currently signalled to the CPU, if any. The
    /// dispatcher injects an IRQ exception when this is `Some` and `DAIF.I` is
    /// clear.
    pub fn signalled_irq(&self) -> Option<u32> {
        self.to_signal().map(|(i, _)| i)
    }

    /// `ICC_HPPIR1_EL1` read — highest pending group-1 INTID (no side effect),
    /// or `SPURIOUS_INTID` if none.
    pub fn hppir1(&self) -> u32 {
        self.highest_pending_g1().map(|(i, _)| i).unwrap_or(SPURIOUS_INTID)
    }

    /// `ICC_IAR1_EL1` read — acknowledge the signalled interrupt: move it to
    /// ACTIVE, clear its pending, raise the running priority, and return its
    /// INTID. Returns `SPURIOUS_INTID` if nothing is signalable.
    pub fn ack_iar1(&mut self) -> u32 {
        match self.to_signal() {
            Some((intid, prio)) => {
                let i = intid as usize;
                self.active[i] = true;
                self.pending[i] = false;
                self.running_priority = prio;
                intid
            }
            None => SPURIOUS_INTID,
        }
    }

    /// `ICC_EOIR1_EL1` write — end of interrupt. Always drops the running
    /// priority; with `EOImode == 0` it also deactivates `intid` (so a separate
    /// `ICC_DIR_EL1` is not needed).
    pub fn eoir1(&mut self, intid: u32) {
        self.running_priority = IDLE_PRIORITY;
        if self.ctlr & ICC_CTLR_EOIMODE == 0 {
            if let Some(i) = Self::idx(intid) {
                self.active[i] = false;
            }
        }
    }

    /// `ICC_DIR_EL1` write — deactivate `intid` (used when `EOImode == 1`).
    pub fn dir(&mut self, intid: u32) {
        if let Some(i) = Self::idx(intid) {
            self.active[i] = false;
        }
    }

    /// `ICC_SRE_EL1` read — SRE is permanently set (sysreg-only CPU interface).
    pub fn read_sre(&self) -> u64 {
        ICC_SRE_SRE
    }

    #[inline]
    fn idx(intid: u32) -> Option<usize> {
        let i = intid as usize;
        if i < GIC_MAX_INTID {
            Some(i)
        } else {
            None
        }
    }
}

impl Default for VirtualGic {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::timer::TIMER_VIRT_INTID;

    /// Program the GIC the way the kernel would for the virtual timer PPI:
    /// priority 0xA0, group 1, enabled; PMR 0xF0, group-1 signalling on.
    fn armed_for_timer() -> VirtualGic {
        let mut g = VirtualGic::new();
        g.set_priority(TIMER_VIRT_INTID, 0xA0);
        g.set_group1(TIMER_VIRT_INTID, true);
        g.set_enable(TIMER_VIRT_INTID, true);
        g.pmr = 0xF0;
        g.igrpen1 = true;
        g
    }

    #[test]
    fn nothing_signalled_when_idle() {
        let g = armed_for_timer();
        assert_eq!(g.signalled_irq(), None, "no pending -> nothing signalled");
        assert_eq!(g.hppir1(), SPURIOUS_INTID);
    }

    #[test]
    fn raise_then_signal_ack_eoi_lifecycle() {
        let mut g = armed_for_timer();
        g.raise(TIMER_VIRT_INTID);
        assert_eq!(g.signalled_irq(), Some(TIMER_VIRT_INTID), "raised -> signalled");
        assert_eq!(g.hppir1(), TIMER_VIRT_INTID);
        // Acknowledge: returns the INTID, moves to active, clears pending.
        assert_eq!(g.ack_iar1(), TIMER_VIRT_INTID, "IAR1 returns the INTID");
        assert_eq!(g.signalled_irq(), None, "active -> no longer signalled");
        // A second ack with nothing pending -> spurious.
        assert_eq!(g.ack_iar1(), SPURIOUS_INTID, "no pending -> spurious");
        // EOI deactivates (EOImode=0) and drops running priority.
        g.eoir1(TIMER_VIRT_INTID);
        // Re-raise works again now it's deactivated.
        g.raise(TIMER_VIRT_INTID);
        assert_eq!(g.signalled_irq(), Some(TIMER_VIRT_INTID), "re-raise after EOI signals again");
    }

    #[test]
    fn pmr_masks_lower_priority() {
        let mut g = armed_for_timer();
        g.set_priority(TIMER_VIRT_INTID, 0xF0); // priority == PMR -> NOT < PMR
        g.raise(TIMER_VIRT_INTID);
        assert_eq!(g.signalled_irq(), None, "prio == PMR is masked (needs prio < PMR)");
        g.pmr = 0xF1; // now PMR > prio -> passes
        assert_eq!(g.signalled_irq(), Some(TIMER_VIRT_INTID));
    }

    #[test]
    fn group1_enable_gates_signalling() {
        let mut g = armed_for_timer();
        g.raise(TIMER_VIRT_INTID);
        g.igrpen1 = false; // group 1 signalling off
        assert_eq!(g.signalled_irq(), None, "IGRPEN1 clear -> not signalled");
        // ...but it is still pending (visible once re-enabled).
        g.igrpen1 = true;
        assert_eq!(g.signalled_irq(), Some(TIMER_VIRT_INTID));
    }

    #[test]
    fn disabled_or_wrong_group_not_signalled() {
        let mut g = armed_for_timer();
        g.set_group1(TIMER_VIRT_INTID, false); // group 0 (secure) — Android uses g1
        g.raise(TIMER_VIRT_INTID);
        assert_eq!(g.signalled_irq(), None, "group 0 interrupt not signalled on g1 path");
        g.set_group1(TIMER_VIRT_INTID, true);
        g.set_enable(TIMER_VIRT_INTID, false); // disabled at the distributor
        assert_eq!(g.signalled_irq(), None, "disabled INTID not signalled");
    }

    #[test]
    fn highest_priority_wins_among_pending() {
        let mut g = VirtualGic::new();
        g.pmr = 0xFF;
        g.igrpen1 = true;
        // Two SPIs pending: 33 @ prio 0x80, 34 @ prio 0x40 (more urgent).
        for (intid, prio) in [(33u32, 0x80u8), (34u32, 0x40u8)] {
            g.set_priority(intid, prio);
            g.set_group1(intid, true);
            g.set_enable(intid, true);
            g.raise(intid);
        }
        assert_eq!(g.signalled_irq(), Some(34), "lower numeric priority wins");
        assert_eq!(g.ack_iar1(), 34);
        // After acking 34 (running prio 0x40), 33 @ 0x80 cannot preempt.
        assert_eq!(g.signalled_irq(), None, "0x80 cannot preempt running 0x40");
        // EOI 34 -> running priority drops -> 33 now signals.
        g.eoir1(34);
        assert_eq!(g.signalled_irq(), Some(33), "after EOI, lower-priority IRQ signals");
    }

    #[test]
    fn eoimode_split_requires_dir_to_deactivate() {
        let mut g = armed_for_timer();
        g.ctlr = ICC_CTLR_EOIMODE; // EOImode = 1
        g.raise(TIMER_VIRT_INTID);
        assert_eq!(g.ack_iar1(), TIMER_VIRT_INTID);
        g.eoir1(TIMER_VIRT_INTID); // drops priority only
        g.raise(TIMER_VIRT_INTID);
        // Still ACTIVE (EOImode=1, no DIR yet) -> not signalled.
        assert_eq!(g.signalled_irq(), None, "EOImode=1: active until DIR");
        g.dir(TIMER_VIRT_INTID); // deactivate
        assert_eq!(g.signalled_irq(), Some(TIMER_VIRT_INTID), "DIR deactivates -> signals");
    }
}
