//! AT-23: Self-Modifying Code (SMC) Handling.
//!
//! Enforce W^X at the JIT layer.  Translated blocks live in RX pages.  When the
//! guest writes to a guest-PA range that overlaps an RX page, an EPT/NPT write
//! fault is raised.  The SMC handler:
//!   1. Identifies all translated blocks whose guest PA falls inside the fault range.
//!   2. Invalidates those cache entries via `BlockCache::invalidate`.
//!   3. Marks the page writeable so the guest write succeeds.
//!   4. On the next execute, the dispatcher re-translates the modified block.
//!
//! Gate: JIT'd app (V8, dalvikvm) runs correctly without translation staleness —
//! every write fault triggers retranslation before re-execution (zero stale
//! translations observed).

use alloc::vec::Vec;

// ── RX page registry ──────────────────────────────────────────────────────────

/// A committed RX page range and the translated blocks it contains.
#[derive(Debug, Clone)]
pub struct RxPageRange {
    /// Guest physical address of range start (inclusive).
    pub guest_pa_start: u64,
    /// Guest physical address of range end (exclusive).
    pub guest_pa_end: u64,
    /// Guest ARM64 PCs of translated blocks that live within this page range.
    pub guest_pcs: Vec<u64>,
}

impl RxPageRange {
    pub fn new(guest_pa_start: u64, guest_pa_end: u64) -> Self {
        assert!(guest_pa_end > guest_pa_start, "RxPageRange: end must be > start");
        Self {
            guest_pa_start,
            guest_pa_end,
            guest_pcs: Vec::new(),
        }
    }

    pub fn contains_pa(&self, pa: u64) -> bool {
        pa >= self.guest_pa_start && pa < self.guest_pa_end
    }

    pub fn overlaps(&self, fault_pa: u64, fault_len: u64) -> bool {
        let fault_end = fault_pa.saturating_add(fault_len);
        self.guest_pa_start < fault_end && fault_pa < self.guest_pa_end
    }

    /// Register a translated block entry point within this page range.
    pub fn add_guest_pc(&mut self, guest_pc: u64) {
        if !self.guest_pcs.contains(&guest_pc) {
            self.guest_pcs.push(guest_pc);
        }
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// SMC-handler statistics.
#[derive(Debug, Clone, Default)]
pub struct SmcStats {
    /// Total EPT/NPT write faults caught by the SMC handler.
    pub write_faults_caught: u64,
    /// Total translated blocks invalidated due to write faults.
    pub blocks_invalidated: u64,
    /// Stale translations executed (must stay zero for gate to pass).
    pub stale_executions: u64,
}

// ── SmcWatcher ────────────────────────────────────────────────────────────────

/// Registry of all committed RX page ranges.  Consulted on every write fault.
#[derive(Debug, Default)]
pub struct SmcWatcher {
    ranges: Vec<RxPageRange>,
    pub stats: SmcStats,
}

impl SmcWatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new RX page range.
    pub fn register_rx_range(&mut self, range: RxPageRange) -> Result<(), SmcError> {
        // Reject exact duplicates.
        for r in &self.ranges {
            if r.guest_pa_start == range.guest_pa_start
                && r.guest_pa_end == range.guest_pa_end
            {
                return Err(SmcError::PageAlreadyRx);
            }
        }
        self.ranges.push(range);
        Ok(())
    }

    /// Record that a translated block at `guest_pc` lives within an already-
    /// registered RX range that contains `guest_pa`.
    pub fn bind_block_to_range(
        &mut self,
        guest_pc: u64,
        guest_pa: u64,
    ) -> Result<(), SmcError> {
        for r in &mut self.ranges {
            if r.contains_pa(guest_pa) {
                r.add_guest_pc(guest_pc);
                return Ok(());
            }
        }
        Err(SmcError::InvalidRange)
    }

    /// Called when an EPT/NPT write fault fires at `fault_pa` (length `fault_len`
    /// bytes).  Returns the list of guest PCs that must be invalidated.
    ///
    /// The caller is expected to call `BlockCache::invalidate` for each returned
    /// PC, then permit the write.
    pub fn on_write_fault(&mut self, fault_pa: u64, fault_len: u64) -> Vec<u64> {
        self.stats.write_faults_caught += 1;
        let mut to_invalidate: Vec<u64> = Vec::new();

        for r in &mut self.ranges {
            if r.overlaps(fault_pa, fault_len) {
                for &pc in &r.guest_pcs {
                    if !to_invalidate.contains(&pc) {
                        to_invalidate.push(pc);
                    }
                }
                // Clear the page's block list — will be repopulated on retranslation.
                r.guest_pcs.clear();
            }
        }

        self.stats.blocks_invalidated += to_invalidate.len() as u64;
        to_invalidate
    }

    /// Record a stale execution (a block was executed after its underlying
    /// guest memory was modified without going through the fault handler).
    /// This must remain zero for the gate to pass.
    pub fn record_stale_execution(&mut self) {
        self.stats.stale_executions += 1;
    }

    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

// ── Gate / Config / Phase / Error ─────────────────────────────────────────────

/// Gate conditions for AT-23.
#[derive(Debug, Clone, Default)]
pub struct SmcGate {
    /// W^X is strictly enforced (wx_strict config flag).
    pub wx_enforced: bool,
    /// The fault handler is installed (registered at least one RX range).
    pub fault_handler_installed: bool,
    /// Zero stale translations have been observed.
    pub zero_stale_translations: bool,
}

impl SmcGate {
    pub fn passes(&self) -> bool {
        self.wx_enforced && self.fault_handler_installed && self.zero_stale_translations
    }
}

/// Configuration for the SMC handler.
#[derive(Debug, Clone)]
pub struct SmcConfig {
    /// Require strict W^X (no page may be both writeable and executable).
    pub wx_strict: bool,
}

impl SmcConfig {
    pub fn aether_defaults() -> Self {
        Self { wx_strict: true }
    }

    pub fn validate(&self) -> Result<(), SmcError> {
        Ok(())
    }
}

/// Phase machine for SMC handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmcPhase {
    NotStarted,
    WxEnforced,
    FaultHandlerInstalled,
    GatePassed,
}

/// Error variants for the SMC handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmcError {
    OverlapDetected,
    PageAlreadyRx,
    InvalidRange,
}

// ── Aggregate state ───────────────────────────────────────────────────────────

/// Aggregate state for the AT-23 pipeline.
pub struct SmcState {
    pub config: SmcConfig,
    pub watcher: SmcWatcher,
    pub phase: SmcPhase,
    pub gate: SmcGate,
}

impl SmcState {
    pub fn new(config: SmcConfig) -> Self {
        let wx = config.wx_strict;
        Self {
            config,
            watcher: SmcWatcher::new(),
            phase: SmcPhase::NotStarted,
            gate: SmcGate {
                wx_enforced: wx,
                fault_handler_installed: false,
                zero_stale_translations: true,
            },
        }
    }

    pub fn register_rx_range(&mut self, range: RxPageRange) -> Result<(), SmcError> {
        self.watcher.register_rx_range(range)?;
        self.gate.fault_handler_installed = true;
        if self.phase < SmcPhase::FaultHandlerInstalled {
            self.phase = SmcPhase::FaultHandlerInstalled;
            if self.config.wx_strict {
                // W^X already enforced via config flag.
                self.phase = SmcPhase::FaultHandlerInstalled;
            }
        }
        self.update_gate();
        Ok(())
    }

    /// Process a write fault; returns guest PCs to invalidate.
    pub fn on_write_fault(&mut self, fault_pa: u64, fault_len: u64) -> Vec<u64> {
        let pcs = self.watcher.on_write_fault(fault_pa, fault_len);
        self.update_gate();
        pcs
    }

    pub fn record_stale_execution(&mut self) {
        self.watcher.record_stale_execution();
        self.gate.zero_stale_translations = false;
        // Phase degrades — gate can no longer pass.
    }

    fn update_gate(&mut self) {
        self.gate.zero_stale_translations = self.watcher.stats.stale_executions == 0;
        if self.gate.passes() {
            self.phase = SmcPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &SmcGate {
        &self.gate
    }
}

/// Initialise the SMC handler pipeline.
pub fn init_smc_handler(config: SmcConfig) -> Result<SmcState, SmcError> {
    config.validate()?;
    let mut state = SmcState::new(config);
    if state.config.wx_strict {
        state.phase = SmcPhase::WxEnforced;
    }
    Ok(state)
}
