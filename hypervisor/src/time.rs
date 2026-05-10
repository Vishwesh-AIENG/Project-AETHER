// ch26: Time
//
// Time is one of the subtlest aspects of virtualization and one where most
// hypervisors leak fingerprints.  This module documents and enforces AETHER's
// timer architecture decisions.
//
// ── ARM Generic Timer Architecture ───────────────────────────────────────────
//
// Every ARM64 core has two counters and four timers:
//
//   Physical counter  (CNTPCT_EL0)  — monotonic, synchronized to the platform
//                                     clock.  The ground truth for elapsed time.
//   Virtual counter   (CNTVCT_EL0)  — physical counter minus CNTVOFF_EL2 (the
//                                     virtual offset).  Used by most guest code.
//   CNTFRQ_EL0                      — counter frequency, typically 19.2 MHz or
//                                     24 MHz depending on platform.
//
//   CNTP_CTL/CVAL_EL0  — non-secure physical timer control and compare value.
//   CNTV_CTL/CVAL_EL0  — virtual timer control and compare value.
//   CNTHP_CTL/CVAL_EL2 — hypervisor physical timer (AETHER's own timer).
//   CNTHV_CTL/CVAL_EL2 — hypervisor virtual timer (EL2 virtual, rarely used).
//
// ── AETHER's Core Decision: No Timer Trapping ────────────────────────────────
//
// CNTHCTL_EL2 controls whether EL0/EL1 accesses to physical counter and timer
// registers trap to EL2.  AETHER sets both EL1PCTEN (bit 0) and EL1PCEN (bit 1)
// so guests read the physical counter and access physical timer registers
// directly — no trap to EL2, no hypervisor overhead on every timer access.
//
// This is safe because AETHER never time-multiplexes CPU cores between guests.
// Each core belongs exclusively to one guest from boot until the system is
// rebooted.  The physical counter advances at the same rate for that guest's
// cores regardless of what any other guest is doing.  There is no gap in the
// physical time stream that the guest would otherwise misinterpret.
//
// Leaving EL1PCTEN or EL1PCEN at zero — the reset default — forces every
// physical counter read from the guest into a trap.  A Cortex-X4 running at
// 3.8 GHz executing 1 000 timer reads per second would waste up to 5 million
// cycles per second purely on trap overhead.  Worse, the trap-induced latency
// makes timer reads visibly slower than real hardware, which anti-cheat and
// DRM systems detect.
//
// ── Virtual Counter Offset (CNTPOFF_EL2) ─────────────────────────────────────
//
// CNTPOFF_EL2 shifts the virtual counter relative to the physical counter:
//   CNTVCT_EL0 = CNTPCT_EL0 − CNTPOFF_EL2
//
// In a time-multiplexed hypervisor, CNTPOFF_EL2 hides the cycles consumed by
// other VMs.  AETHER does not time-multiplex cores, so CNTPOFF_EL2 is always
// zero — the virtual counter tracks the physical counter identically.  This
// means guest code that reads CNTVCT_EL0 sees the same natural progression of
// time as real hardware.  Any non-zero offset would be detectable as an
// anomalous discontinuity in the time stream.
//
// ── Timer Interrupts ─────────────────────────────────────────────────────────
//
// The ARM Generic Timer generates interrupts via the GIC as Private Peripheral
// Interrupts (PPIs).  PPI numbers map to absolute INTIDs by adding 16:
//
//   PPI 10  → INTID 26: EL2 hypervisor physical timer  (AETHER's own)
//   PPI 11  → INTID 27: EL1 virtual timer              (Android guest)
//   PPI 13  → INTID 29: EL1 secure physical timer      (unused by Android)
//   PPI 14  → INTID 30: EL1 non-secure physical timer  (Android guest, alt)
//
// The virtual timer (PPI 11, INTID 27) is the canonical timer interrupt for
// Linux-based Android guests.  The Linux clockevent driver programs
// CNTV_CVAL_EL0 and enables the timer via CNTV_CTL_EL0.ENABLE.  When the
// virtual counter reaches the compare value, the GIC delivers INTID 27 to
// the core.  AETHER does not intercept this path — it runs entirely in hardware.
//
// ── Wall-Clock Time and RTC ───────────────────────────────────────────────────
//
// The architectural timer is a monotonic counter, not a real-time clock.  Each
// guest initializes its wall-clock understanding from the platform RTC at boot,
// then maintains it via NTP through its assigned network interface.  AETHER does
// not provide time services to either guest and does not intercept RTC accesses.
//
// Primary references:
//   ARM ARM DDI0487 §D11    — Generic Timer architecture
//   ARM ARM DDI0487 §G5     — CNTHCTL_EL2, CNTPOFF_EL2 register descriptions
//   KVM arch/arm64/kvm/arch_timer.c — reference virtualization implementation

// ─────────────────────────────────────────────────────────────────────────────
// CounterFrequency — the platform's timer counter frequency
// ─────────────────────────────────────────────────────────────────────────────

/// The frequency at which the ARM architectural timer counter increments.
///
/// CNTFRQ_EL0 is set by the platform firmware (EL3) before handing off to
/// AETHER.  AETHER reads this register and propagates it to guests through the
/// device tree (`/timer` node, `clock-frequency` property) and ACPI GTDT.
///
/// AETHER never fabricates this frequency — it reads the real hardware value.
/// A guest cross-checking the timer frequency against its observed count rate
/// would detect a fabricated value within seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterFrequency(pub u32);

impl CounterFrequency {
    /// 19.2 MHz — the standard Qualcomm Snapdragon X Elite frequency.
    pub const MHZ_19_2: Self = Self(19_200_000);
    /// 24 MHz — used by some ARM development boards and QEMU.
    pub const MHZ_24: Self = Self(24_000_000);
    /// 25 MHz — used by some Ampere Altra platforms.
    pub const MHZ_25: Self = Self(25_000_000);

    /// Return `true` when the frequency is in a plausible range for real hardware.
    ///
    /// Qualcomm and ARM reference platforms use 19.2 MHz, 24 MHz, or 25 MHz.
    /// Values outside 1 MHz–100 MHz are likely misconfigured or fabricated.
    pub const fn is_plausible(self) -> bool {
        self.0 >= 1_000_000 && self.0 <= 100_000_000
    }

    /// Return the frequency in Hz.
    pub const fn hz(self) -> u32 {
        self.0
    }

    /// Compute the counter ticks corresponding to the given number of microseconds.
    ///
    /// Returns `None` on overflow (interval too large for u64 at this frequency).
    pub const fn ticks_per_us(self, us: u64) -> Option<u64> {
        let freq = self.0 as u64;
        match us.checked_mul(freq) {
            Some(product) => product.checked_div(1_000_000),
            None => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CnthctlConfig — CNTHCTL_EL2 timer access control
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for CNTHCTL_EL2, the hypervisor timer control register.
///
/// This register determines whether EL0 and EL1 accesses to the physical
/// counter and physical timer registers trap to EL2.  AETHER configures both
/// `el1pcten` and `el1pcen` to `true` so timer reads and timer programming
/// flow directly to the hardware without involving the hypervisor.
///
/// Setting either bit to `false` causes every corresponding timer access from
/// the guest to trap to EL2.  This produces two problems:
///   1. Performance: up to 5 million wasted cycles per second for a guest
///      issuing 1 000 timer reads per second.
///   2. Fingerprint: trap-induced latency is measurable and distinguishable
///      from real hardware by anti-cheat and DRM systems.
///
/// ARM ARM DDI0487 §G5 — CNTHCTL_EL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CnthctlConfig {
    /// EL1PCTEN (bit 0): allow EL0 and EL1 to read CNTPCT_EL0 (physical
    /// counter) without trapping to EL2.  Must be `true` for performance.
    pub el1pcten: bool,
    /// EL1PCEN (bit 1): allow EL0 and EL1 to access physical timer registers
    /// (CNTP_CTL_EL0, CNTP_CVAL_EL0, CNTP_TVAL_EL0) without trapping to EL2.
    /// Must be `true` for performance.
    pub el1pcen: bool,
    /// EVNTEN (bit 2): enable the event stream generator.  AETHER disables this
    /// (false) — the event stream is only needed for spin-wait optimization and
    /// is not required for Android workloads.
    pub evnten: bool,
}

impl CnthctlConfig {
    /// The correct CNTHCTL_EL2 configuration for AETHER's nVHE mode.
    ///
    /// Both EL1PCTEN and EL1PCEN are set: guests access the physical counter
    /// and physical timer registers directly.  The event stream is disabled.
    pub const AETHER_DEFAULT: Self = Self {
        el1pcten: true,
        el1pcen: true,
        evnten: false,
    };

    /// Compute the raw u64 value to write into CNTHCTL_EL2.
    pub const fn raw(self) -> u64 {
        let mut v: u64 = 0;
        if self.el1pcten { v |= 1 << 0; }
        if self.el1pcen  { v |= 1 << 1; }
        if self.evnten   { v |= 1 << 2; }
        v
    }

    /// Return `Ok(())` when the configuration is correct for AETHER.
    ///
    /// Rejects configurations that would cause timer traps.
    pub fn validate(&self) -> Result<(), TimerError> {
        if !self.el1pcten {
            return Err(TimerError::PhysicalCounterTrapEnabled);
        }
        if !self.el1pcen {
            return Err(TimerError::PhysicalTimerTrapEnabled);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CntpoffConfig — CNTPOFF_EL2 virtual counter offset
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for CNTPOFF_EL2, the physical-to-virtual counter offset.
///
/// `CNTVCT_EL0 = CNTPCT_EL0 − CNTPOFF_EL2`
///
/// In a time-multiplexing hypervisor, CNTPOFF_EL2 hides the time spent
/// running other VMs from each guest's virtual counter.  AETHER does not
/// time-multiplex cores, so this register is always zero.
///
/// A non-zero offset when cores are not multiplexed creates a synthetic gap in
/// the time stream that is detectable: the virtual counter will not match the
/// physical counter, and code that reads both (which anti-cheat systems do)
/// will detect the discrepancy.
///
/// ARM ARM DDI0487 §G5 — CNTPOFF_EL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CntpoffConfig {
    /// The offset value written to CNTPOFF_EL2.  Must be zero for AETHER.
    pub offset_ticks: u64,
}

impl CntpoffConfig {
    /// The correct CNTPOFF_EL2 configuration for AETHER (no offset).
    pub const ZERO: Self = Self { offset_ticks: 0 };

    /// Return `Ok(())` when the offset is zero.
    ///
    /// Any non-zero offset is rejected because AETHER does not time-multiplex
    /// cores — the virtual counter must track the physical counter exactly.
    pub fn validate(&self) -> Result<(), TimerError> {
        if self.offset_ticks != 0 {
            Err(TimerError::NonZeroVirtualCounterOffset {
                offset_ticks: self.offset_ticks,
            })
        } else {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerPpi — ARM Generic Timer PPI-to-INTID mapping
// ─────────────────────────────────────────────────────────────────────────────

/// The four ARM Generic Timer Private Peripheral Interrupts and their INTIDs.
///
/// ARM PPIs are in INTID range 16–31.  The four architectural timer PPIs are:
///
///   PPI 10 → INTID 26: EL2 hypervisor physical timer  (`CNTHP_CTL_EL2`)
///   PPI 11 → INTID 27: EL1 virtual timer              (`CNTV_CTL_EL0`)
///   PPI 13 → INTID 29: EL1 secure physical timer      (unused by Android)
///   PPI 14 → INTID 30: EL1 non-secure physical timer  (`CNTP_CTL_EL0`)
///
/// KVM source: `arch/arm64/kvm/arch_timer.c`, `default_ppi[]` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerPpi {
    /// EL2 hypervisor physical timer.  AETHER uses this for its own internal
    /// timing (inter-processor coordination, watchdog).  PPI 10 → INTID 26.
    HypervisorPhysical,
    /// EL1 virtual timer.  This is the canonical timer interrupt for Android's
    /// Linux kernel clockevent driver.  PPI 11 → INTID 27.
    VirtualEl1,
    /// EL1 secure physical timer.  Managed by EL3 firmware.  AETHER does not
    /// route this to Android.  PPI 13 → INTID 29.
    SecurePhysicalEl1,
    /// EL1 non-secure physical timer.  Available for guest use when
    /// CNTHCTL_EL2.EL1PCEN=1.  PPI 14 → INTID 30.
    NonSecurePhysicalEl1,
}

impl TimerPpi {
    /// The PPI number (relative interrupt ID within the PPI range 16–31).
    pub const fn ppi_number(self) -> u8 {
        match self {
            TimerPpi::HypervisorPhysical    => 10,
            TimerPpi::VirtualEl1            => 11,
            TimerPpi::SecurePhysicalEl1     => 13,
            TimerPpi::NonSecurePhysicalEl1  => 14,
        }
    }

    /// The absolute GIC INTID (PPI number + 16).
    pub const fn intid(self) -> u32 {
        self.ppi_number() as u32 + 16
    }

    /// Return `true` when this PPI is routed to an Android guest core.
    ///
    /// The virtual timer (INTID 27) and non-secure physical timer (INTID 30)
    /// are delivered to Android cores.  The hypervisor timer (INTID 26) is
    /// handled at EL2.  The secure timer (INTID 29) is managed by EL3.
    pub const fn is_guest_timer(self) -> bool {
        matches!(self, TimerPpi::VirtualEl1 | TimerPpi::NonSecurePhysicalEl1)
    }

    /// Return `true` when this PPI is used by AETHER itself (not a guest).
    pub const fn is_hypervisor_timer(self) -> bool {
        matches!(self, TimerPpi::HypervisorPhysical)
    }
}

/// The full set of ARM Generic Timer PPIs.
pub const TIMER_PPIS: &[TimerPpi] = &[
    TimerPpi::HypervisorPhysical,
    TimerPpi::VirtualEl1,
    TimerPpi::SecurePhysicalEl1,
    TimerPpi::NonSecurePhysicalEl1,
];

// ─────────────────────────────────────────────────────────────────────────────
// CounterPassthroughPolicy — justification for direct counter access
// ─────────────────────────────────────────────────────────────────────────────

/// The policy governing whether guests read the physical counter directly.
///
/// AETHER always chooses `DirectPassthrough` — see the module-level comment
/// for the full rationale.  This type exists to make the policy explicit and
/// auditable rather than implicit in a register write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterPassthroughPolicy {
    /// EL0/EL1 reads CNTPCT_EL0 directly without trapping to EL2.
    ///
    /// Safe when:
    ///   1. CPU cores are statically partitioned (no time-multiplexing).
    ///   2. CNTPOFF_EL2 = 0 (virtual and physical counters are identical).
    ///
    /// Both conditions hold in AETHER's design.
    DirectPassthrough,
    /// Every CNTPCT_EL0 read from EL0/EL1 traps to EL2.  EL2 then either
    /// returns the real value or an adjusted value.
    ///
    /// Only correct when cores are time-multiplexed across multiple guests
    /// and AETHER must hide the time slices from each guest.  AETHER does not
    /// time-multiplex cores, so this mode is never used.
    TrapAndEmulate,
}

impl CounterPassthroughPolicy {
    /// Return `true` when this policy is safe for AETHER's static-partition model.
    pub const fn is_safe_for_static_partitioning(self) -> bool {
        matches!(self, CounterPassthroughPolicy::DirectPassthrough)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WallClockSource — how each guest obtains real-time (wall-clock) knowledge
// ─────────────────────────────────────────────────────────────────────────────

/// The source from which a guest initializes and maintains its wall-clock time.
///
/// The architectural timer is monotonic but not absolute — it does not know the
/// calendar date.  Guests derive wall-clock time through separate mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockSource {
    /// Guest reads the platform RTC at boot and then maintains time via NTP.
    ///
    /// This is the correct model.  AETHER does not intercept RTC accesses or
    /// provide time services — each guest owns its own RTC access and NTP sync
    /// through its assigned network interface.
    PlatformRtcAndNtp,
    /// Hypervisor provides a synthetic time service (e.g., a para-virtual RTC
    /// or a hypercall-based time API).
    ///
    /// Not used by AETHER.  A synthetic time service would require AETHER to
    /// maintain accurate time itself, adding complexity and a potential source
    /// of divergence from real hardware behavior.
    HypervisorProvided,
}

impl WallClockSource {
    /// Return `true` when the hypervisor is uninvolved in wall-clock maintenance.
    pub const fn is_hypervisor_transparent(self) -> bool {
        matches!(self, WallClockSource::PlatformRtcAndNtp)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerConfiguration — aggregate timer configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The complete timer configuration for an AETHER deployment.
///
/// `validate()` checks that every timer configuration decision is consistent
/// with AETHER's no-fingerprint, no-trap-overhead timer architecture.
#[derive(Debug)]
pub struct TimerConfiguration {
    /// Counter frequency read from CNTFRQ_EL0.
    pub counter_frequency: CounterFrequency,
    /// CNTHCTL_EL2 bit configuration.
    pub cnthctl: CnthctlConfig,
    /// CNTPOFF_EL2 offset (must be zero).
    pub cntpoff: CntpoffConfig,
    /// Policy for guest physical-counter reads.
    pub passthrough_policy: CounterPassthroughPolicy,
    /// How guests obtain wall-clock time.
    pub wall_clock_source: WallClockSource,
}

impl TimerConfiguration {
    /// The correct timer configuration for AETHER.
    pub const AETHER_DEFAULT: Self = Self {
        counter_frequency: CounterFrequency::MHZ_19_2,
        cnthctl: CnthctlConfig::AETHER_DEFAULT,
        cntpoff: CntpoffConfig::ZERO,
        passthrough_policy: CounterPassthroughPolicy::DirectPassthrough,
        wall_clock_source: WallClockSource::PlatformRtcAndNtp,
    };

    /// Validate the complete timer configuration.
    ///
    /// Checks (in order):
    ///   1. Counter frequency is in a plausible range for real hardware.
    ///   2. CNTHCTL_EL2 does not cause physical counter or timer traps.
    ///   3. CNTPOFF_EL2 is zero (no synthetic time offset).
    ///   4. Passthrough policy is safe for static partitioning.
    ///   5. Wall-clock source does not require hypervisor time services.
    pub fn validate(&self) -> Result<(), TimerError> {
        if !self.counter_frequency.is_plausible() {
            return Err(TimerError::ImplausibleCounterFrequency {
                hz: self.counter_frequency.hz(),
            });
        }
        self.cnthctl.validate()?;
        self.cntpoff.validate()?;
        if !self.passthrough_policy.is_safe_for_static_partitioning() {
            return Err(TimerError::TrapAndEmulateOnStaticPartition);
        }
        if !self.wall_clock_source.is_hypervisor_transparent() {
            return Err(TimerError::HypervisorProvidedTimeService);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerSummary — timer readiness gate
// ─────────────────────────────────────────────────────────────────────────────

/// High-level timer readiness gate.
///
/// `timer_ready()` returns `true` only when the timer is configured correctly
/// for transparent, no-fingerprint, no-trap-overhead operation.  Use this gate
/// before transitioning to guest execution.
#[derive(Debug)]
pub struct TimerSummary {
    /// True when EL1PCTEN is set: guest physical counter reads do not trap.
    pub physical_counter_passthrough: bool,
    /// True when EL1PCEN is set: guest physical timer access does not trap.
    pub physical_timer_passthrough: bool,
    /// True when CNTPOFF_EL2 = 0: virtual and physical counters are identical.
    pub virtual_offset_zero: bool,
    /// True when the virtual timer PPI (INTID 27) is correctly wired in the GIC.
    pub virtual_timer_ppi_configured: bool,
}

impl TimerSummary {
    /// Return `true` when the timer is fully ready for transparent guest use.
    pub fn timer_ready(&self) -> bool {
        self.physical_counter_passthrough
            && self.physical_timer_passthrough
            && self.virtual_offset_zero
            && self.virtual_timer_ppi_configured
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerError — errors returned by timer validation functions
// ─────────────────────────────────────────────────────────────────────────────

/// Error variants returned by timer configuration and validation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// CNTHCTL_EL2.EL1PCTEN = 0: every physical counter read from EL0/EL1
    /// traps to EL2.  This creates measurable latency and a detectable
    /// fingerprint.
    PhysicalCounterTrapEnabled,
    /// CNTHCTL_EL2.EL1PCEN = 0: every physical timer register access from
    /// EL0/EL1 traps to EL2.  Same performance and fingerprint problem.
    PhysicalTimerTrapEnabled,
    /// CNTPOFF_EL2 ≠ 0 on a non-time-multiplexed system.  The virtual counter
    /// will diverge from the physical counter without cause, which is detectable
    /// by code that reads both.
    NonZeroVirtualCounterOffset {
        /// The non-zero offset value that was rejected.
        offset_ticks: u64,
    },
    /// `CounterPassthroughPolicy::TrapAndEmulate` was selected even though
    /// AETHER does not time-multiplex cores.  Trap-and-emulate is never needed.
    TrapAndEmulateOnStaticPartition,
    /// A hypervisor-provided time service was configured.  AETHER provides no
    /// time services — each guest maintains its own time independently.
    HypervisorProvidedTimeService,
    /// The counter frequency is outside the plausible range for real hardware
    /// (1 MHz – 100 MHz).  The value may have been fabricated or misconfigured.
    ImplausibleCounterFrequency {
        /// The frequency value that was rejected.
        hz: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CounterFrequency ──────────────────────────────────────────────────────

    #[test]
    fn counter_frequency_plausible_values() {
        assert!(CounterFrequency::MHZ_19_2.is_plausible());
        assert!(CounterFrequency::MHZ_24.is_plausible());
        assert!(CounterFrequency::MHZ_25.is_plausible());
    }

    #[test]
    fn counter_frequency_implausible_values() {
        assert!(!CounterFrequency(0).is_plausible());
        assert!(!CounterFrequency(100).is_plausible());
        assert!(!CounterFrequency(200_000_000).is_plausible());
    }

    #[test]
    fn counter_frequency_hz() {
        assert_eq!(CounterFrequency::MHZ_19_2.hz(), 19_200_000);
    }

    #[test]
    fn counter_frequency_ticks_per_us() {
        // 1 µs at 19.2 MHz = 19.2 ticks → 19 (integer division)
        assert_eq!(CounterFrequency::MHZ_19_2.ticks_per_us(1), Some(19));
        // 1 000 000 µs (1 s) at 19.2 MHz = 19 200 000 ticks
        assert_eq!(CounterFrequency::MHZ_19_2.ticks_per_us(1_000_000), Some(19_200_000));
    }

    #[test]
    fn counter_frequency_ticks_overflow_returns_none() {
        // u64::MAX µs × 19.2 MHz overflows u64
        assert_eq!(CounterFrequency::MHZ_19_2.ticks_per_us(u64::MAX), None);
    }

    // ── CnthctlConfig ─────────────────────────────────────────────────────────

    #[test]
    fn cnthctl_default_raw_value() {
        // EL1PCTEN(bit 0) | EL1PCEN(bit 1) = 0b11 = 3
        assert_eq!(CnthctlConfig::AETHER_DEFAULT.raw(), 0b11);
    }

    #[test]
    fn cnthctl_default_validates_ok() {
        assert!(CnthctlConfig::AETHER_DEFAULT.validate().is_ok());
    }

    #[test]
    fn cnthctl_el1pcten_zero_fails() {
        let cfg = CnthctlConfig { el1pcten: false, el1pcen: true, evnten: false };
        assert_eq!(cfg.validate(), Err(TimerError::PhysicalCounterTrapEnabled));
    }

    #[test]
    fn cnthctl_el1pcen_zero_fails() {
        let cfg = CnthctlConfig { el1pcten: true, el1pcen: false, evnten: false };
        assert_eq!(cfg.validate(), Err(TimerError::PhysicalTimerTrapEnabled));
    }

    #[test]
    fn cnthctl_evnten_does_not_affect_validation() {
        // evnten is a preference, not a security requirement
        let cfg = CnthctlConfig { el1pcten: true, el1pcen: true, evnten: true };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn cnthctl_raw_with_evnten() {
        let cfg = CnthctlConfig { el1pcten: true, el1pcen: true, evnten: true };
        // bits 0,1,2 all set = 0b111 = 7
        assert_eq!(cfg.raw(), 0b111);
    }

    // ── CntpoffConfig ─────────────────────────────────────────────────────────

    #[test]
    fn cntpoff_zero_validates_ok() {
        assert!(CntpoffConfig::ZERO.validate().is_ok());
    }

    #[test]
    fn cntpoff_nonzero_fails() {
        let cfg = CntpoffConfig { offset_ticks: 1 };
        assert_eq!(
            cfg.validate(),
            Err(TimerError::NonZeroVirtualCounterOffset { offset_ticks: 1 })
        );
    }

    #[test]
    fn cntpoff_large_nonzero_fails() {
        let cfg = CntpoffConfig { offset_ticks: 0xDEAD_BEEF_0000_0000 };
        assert_eq!(
            cfg.validate(),
            Err(TimerError::NonZeroVirtualCounterOffset {
                offset_ticks: 0xDEAD_BEEF_0000_0000
            })
        );
    }

    // ── TimerPpi ──────────────────────────────────────────────────────────────

    #[test]
    fn timer_ppi_intid_mapping() {
        // PPI N → INTID = N + 16
        assert_eq!(TimerPpi::HypervisorPhysical.intid(),   26);
        assert_eq!(TimerPpi::VirtualEl1.intid(),           27);
        assert_eq!(TimerPpi::SecurePhysicalEl1.intid(),    29);
        assert_eq!(TimerPpi::NonSecurePhysicalEl1.intid(), 30);
    }

    #[test]
    fn timer_ppi_ppi_numbers() {
        assert_eq!(TimerPpi::HypervisorPhysical.ppi_number(),   10);
        assert_eq!(TimerPpi::VirtualEl1.ppi_number(),           11);
        assert_eq!(TimerPpi::SecurePhysicalEl1.ppi_number(),    13);
        assert_eq!(TimerPpi::NonSecurePhysicalEl1.ppi_number(), 14);
    }

    #[test]
    fn timer_ppi_guest_classification() {
        assert!(!TimerPpi::HypervisorPhysical.is_guest_timer());
        assert!(TimerPpi::VirtualEl1.is_guest_timer());
        assert!(!TimerPpi::SecurePhysicalEl1.is_guest_timer());
        assert!(TimerPpi::NonSecurePhysicalEl1.is_guest_timer());
    }

    #[test]
    fn timer_ppi_hypervisor_classification() {
        assert!(TimerPpi::HypervisorPhysical.is_hypervisor_timer());
        assert!(!TimerPpi::VirtualEl1.is_hypervisor_timer());
        assert!(!TimerPpi::SecurePhysicalEl1.is_hypervisor_timer());
        assert!(!TimerPpi::NonSecurePhysicalEl1.is_hypervisor_timer());
    }

    #[test]
    fn timer_ppis_table_has_four_entries() {
        assert_eq!(TIMER_PPIS.len(), 4);
    }

    #[test]
    fn timer_ppis_intids_in_ppi_range() {
        for ppi in TIMER_PPIS {
            let intid = ppi.intid();
            assert!(intid >= 16 && intid < 32,
                "INTID {} is outside PPI range 16–31", intid);
        }
    }

    // ── CounterPassthroughPolicy ──────────────────────────────────────────────

    #[test]
    fn direct_passthrough_safe_for_static_partitioning() {
        assert!(CounterPassthroughPolicy::DirectPassthrough
            .is_safe_for_static_partitioning());
    }

    #[test]
    fn trap_and_emulate_not_safe_for_static_partitioning() {
        assert!(!CounterPassthroughPolicy::TrapAndEmulate
            .is_safe_for_static_partitioning());
    }

    // ── WallClockSource ───────────────────────────────────────────────────────

    #[test]
    fn platform_rtc_and_ntp_is_hypervisor_transparent() {
        assert!(WallClockSource::PlatformRtcAndNtp.is_hypervisor_transparent());
    }

    #[test]
    fn hypervisor_provided_is_not_transparent() {
        assert!(!WallClockSource::HypervisorProvided.is_hypervisor_transparent());
    }

    // ── TimerConfiguration ────────────────────────────────────────────────────

    #[test]
    fn aether_default_configuration_validates_ok() {
        assert!(TimerConfiguration::AETHER_DEFAULT.validate().is_ok());
    }

    #[test]
    fn configuration_implausible_frequency_fails() {
        let cfg = TimerConfiguration {
            counter_frequency: CounterFrequency(0),
            ..TimerConfiguration::AETHER_DEFAULT
        };
        assert_eq!(
            cfg.validate(),
            Err(TimerError::ImplausibleCounterFrequency { hz: 0 })
        );
    }

    #[test]
    fn configuration_bad_cnthctl_fails() {
        let cfg = TimerConfiguration {
            cnthctl: CnthctlConfig { el1pcten: false, el1pcen: true, evnten: false },
            ..TimerConfiguration::AETHER_DEFAULT
        };
        assert_eq!(cfg.validate(), Err(TimerError::PhysicalCounterTrapEnabled));
    }

    #[test]
    fn configuration_nonzero_cntpoff_fails() {
        let cfg = TimerConfiguration {
            cntpoff: CntpoffConfig { offset_ticks: 12345 },
            ..TimerConfiguration::AETHER_DEFAULT
        };
        assert_eq!(
            cfg.validate(),
            Err(TimerError::NonZeroVirtualCounterOffset { offset_ticks: 12345 })
        );
    }

    #[test]
    fn configuration_trap_and_emulate_fails() {
        let cfg = TimerConfiguration {
            passthrough_policy: CounterPassthroughPolicy::TrapAndEmulate,
            ..TimerConfiguration::AETHER_DEFAULT
        };
        assert_eq!(cfg.validate(), Err(TimerError::TrapAndEmulateOnStaticPartition));
    }

    #[test]
    fn configuration_hypervisor_time_service_fails() {
        let cfg = TimerConfiguration {
            wall_clock_source: WallClockSource::HypervisorProvided,
            ..TimerConfiguration::AETHER_DEFAULT
        };
        assert_eq!(cfg.validate(), Err(TimerError::HypervisorProvidedTimeService));
    }

    // ── TimerSummary ──────────────────────────────────────────────────────────

    #[test]
    fn timer_summary_all_ready() {
        let s = TimerSummary {
            physical_counter_passthrough: true,
            physical_timer_passthrough: true,
            virtual_offset_zero: true,
            virtual_timer_ppi_configured: true,
        };
        assert!(s.timer_ready());
    }

    #[test]
    fn timer_summary_partial_fails() {
        let cases = [
            TimerSummary {
                physical_counter_passthrough: false,
                physical_timer_passthrough:  true,
                virtual_offset_zero:         true,
                virtual_timer_ppi_configured: true,
            },
            TimerSummary {
                physical_counter_passthrough: true,
                physical_timer_passthrough:  false,
                virtual_offset_zero:         true,
                virtual_timer_ppi_configured: true,
            },
            TimerSummary {
                physical_counter_passthrough: true,
                physical_timer_passthrough:  true,
                virtual_offset_zero:         false,
                virtual_timer_ppi_configured: true,
            },
            TimerSummary {
                physical_counter_passthrough: true,
                physical_timer_passthrough:  true,
                virtual_offset_zero:         true,
                virtual_timer_ppi_configured: false,
            },
        ];
        for s in &cases {
            assert!(!s.timer_ready(), "expected not-ready for {:?}", s);
        }
    }
}
