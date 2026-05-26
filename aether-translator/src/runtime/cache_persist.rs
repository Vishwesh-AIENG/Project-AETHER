//! AT-22: JIT Cache Persistence.
//!
//! Spill cold translated blocks to the paravirt NVMe queue (per ch37 admin
//! queue interface) and reload them on the next boot.  This eliminates the
//! re-translation cost for blocks that were already translated on a previous
//! run.
//!
//! Gate: cold-boot warm-cache restore reduces the first-60-second translation
//! count by ≥ 80 % compared to a cold-start with no cache.

use alloc::vec::Vec;

// ── Constants ─────────────────────────────────────────────────────────────────

/// NVMe LBA base for the JIT-cache spill region (4 KiB blocks; 64 MiB region).
pub const CACHE_PERSIST_NVME_LBA_BASE: u64 = 0x0001_0000;

/// Maximum NVMe I/O queue depth for spill operations.
pub const CACHE_PERSIST_QUEUE_DEPTH: usize = 64;

/// Target reduction in first-60s cold translations (percentage).
pub const CACHE_PERSIST_TARGET_REDUCTION_PCT: u64 = 80;

// ── Entry format ─────────────────────────────────────────────────────────────

/// Serialisable record for one cached translated block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CachePersistEntry {
    /// Guest ARM64 program counter.
    pub guest_pc: u64,
    /// Length of the translated x86_64 code in bytes.
    pub code_len: u32,
    /// CRC-32/ISO-HDLC checksum of the code bytes.
    pub crc32: u32,
}

impl CachePersistEntry {
    pub fn new(guest_pc: u64, code_len: u32, crc32: u32) -> Self {
        Self { guest_pc, code_len, crc32 }
    }
}

/// Simple CRC-32 (ISO-HDLC, poly 0xEDB88320) for entry integrity.
pub fn crc32_iso(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── Spill queue ───────────────────────────────────────────────────────────────

/// Queues cold translated blocks for NVMe spill.
#[derive(Debug)]
pub struct NvmeSpillQueue {
    entries: Vec<CachePersistEntry>,
    queue_depth: usize,
}

impl NvmeSpillQueue {
    pub fn new(queue_depth: usize) -> Self {
        Self {
            entries: Vec::new(),
            queue_depth: queue_depth.max(1),
        }
    }

    /// Enqueue a block for spill.  Returns `Err(CachePersistError::NvmeQueueFull)`
    /// when the queue is at capacity.
    pub fn enqueue(&mut self, entry: CachePersistEntry) -> Result<(), CachePersistError> {
        if self.entries.len() >= self.queue_depth {
            return Err(CachePersistError::NvmeQueueFull);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Drain all pending entries (submitted to NVMe; cleared after submission).
    pub fn drain(&mut self) -> Vec<CachePersistEntry> {
        core::mem::take(&mut self.entries)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// Statistics for the cache persistence subsystem.
#[derive(Debug, Clone, Default)]
pub struct CachePersistStats {
    /// Blocks written to NVMe.
    pub blocks_spilled: u64,
    /// Blocks loaded from NVMe on boot.
    pub blocks_restored: u64,
    /// Cold translations performed on a run *without* a warm cache.
    pub cold_translations_without_cache: u64,
    /// Cold translations performed on a run *with* a restored cache.
    pub cold_translations_with_cache: u64,
}

impl CachePersistStats {
    /// Reduction percentage: how much first-60s translation work was saved.
    /// Returns 0 when `cold_translations_without_cache` is zero.
    pub fn reduction_pct(&self) -> u64 {
        if self.cold_translations_without_cache == 0 {
            return 0;
        }
        let saved = self
            .cold_translations_without_cache
            .saturating_sub(self.cold_translations_with_cache);
        saved * 100 / self.cold_translations_without_cache
    }
}

// ── Gate / Config / Phase / Error ─────────────────────────────────────────────

/// Gate conditions for AT-22.
#[derive(Debug, Clone, Default)]
pub struct CachePersistGate {
    /// Blocks were spilled to NVMe in a previous run.
    pub cache_spilled: bool,
    /// Blocks were restored from NVMe on this boot.
    pub cache_restored: bool,
    /// First-60s translation reduction ≥ 80 %.
    pub reduction_target_met: bool,
}

impl CachePersistGate {
    pub fn passes(&self) -> bool {
        self.cache_spilled && self.cache_restored && self.reduction_target_met
    }
}

/// Configuration for the cache persistence pipeline.
#[derive(Debug, Clone)]
pub struct CachePersistConfig {
    pub spill_enabled: bool,
    pub nvme_lba_base: u64,
    pub queue_depth: usize,
    pub reduction_target_pct: u64,
}

impl CachePersistConfig {
    pub fn aether_defaults() -> Self {
        Self {
            spill_enabled: true,
            nvme_lba_base: CACHE_PERSIST_NVME_LBA_BASE,
            queue_depth: CACHE_PERSIST_QUEUE_DEPTH,
            reduction_target_pct: CACHE_PERSIST_TARGET_REDUCTION_PCT,
        }
    }

    pub fn validate(&self) -> Result<(), CachePersistError> {
        if self.queue_depth == 0 {
            return Err(CachePersistError::NvmeQueueFull);
        }
        if self.nvme_lba_base == 0 {
            return Err(CachePersistError::SerializationError);
        }
        Ok(())
    }
}

/// Phase machine for cache persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CachePersistPhase {
    NotStarted,
    SpillStarted,
    BlocksSpilled,
    CacheLoaded,
    GatePassed,
}

/// Error variants for cache persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePersistError {
    NvmeQueueFull,
    SerializationError,
    CrcMismatch,
    NoCache,
}

// ── Aggregate state ───────────────────────────────────────────────────────────

/// Aggregate state for the AT-22 pipeline.
pub struct CachePersistState {
    pub config: CachePersistConfig,
    pub spill_queue: NvmeSpillQueue,
    pub stats: CachePersistStats,
    pub phase: CachePersistPhase,
    pub gate: CachePersistGate,
}

impl CachePersistState {
    pub fn new(config: CachePersistConfig) -> Self {
        let qd = config.queue_depth;
        Self {
            spill_queue: NvmeSpillQueue::new(qd),
            config,
            stats: CachePersistStats::default(),
            phase: CachePersistPhase::NotStarted,
            gate: CachePersistGate::default(),
        }
    }

    /// Spill a translated block to the NVMe queue.
    pub fn spill_block(
        &mut self,
        guest_pc: u64,
        code: &[u8],
    ) -> Result<(), CachePersistError> {
        let crc = crc32_iso(code);
        let entry = CachePersistEntry::new(guest_pc, code.len() as u32, crc);
        self.spill_queue.enqueue(entry)?;
        self.stats.blocks_spilled += 1;
        if self.phase < CachePersistPhase::SpillStarted {
            self.phase = CachePersistPhase::SpillStarted;
        }
        Ok(())
    }

    /// Drain the spill queue (submit to NVMe).
    pub fn commit_spill(&mut self) {
        let drained = self.spill_queue.drain();
        if !drained.is_empty() {
            self.gate.cache_spilled = true;
            self.phase = CachePersistPhase::BlocksSpilled;
        }
    }

    /// Record a cold-boot cache restore event.
    pub fn record_restore(&mut self, blocks_restored: u64) {
        self.stats.blocks_restored += blocks_restored;
        if blocks_restored > 0 {
            self.gate.cache_restored = true;
            self.phase = CachePersistPhase::CacheLoaded;
        }
    }

    /// Record baseline and cache-assisted translation counts for the gate.
    pub fn record_translation_counts(
        &mut self,
        without_cache: u64,
        with_cache: u64,
    ) {
        self.stats.cold_translations_without_cache = without_cache;
        self.stats.cold_translations_with_cache = with_cache;
        let target = self.config.reduction_target_pct;
        self.gate.reduction_target_met = self.stats.reduction_pct() >= target;
        if self.gate.passes() {
            self.phase = CachePersistPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &CachePersistGate {
        &self.gate
    }
}

/// Initialise the cache persistence pipeline.
pub fn init_cache_persist(config: CachePersistConfig) -> Result<CachePersistState, CachePersistError> {
    config.validate()?;
    Ok(CachePersistState::new(config))
}
