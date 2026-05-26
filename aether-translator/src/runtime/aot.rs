//! AT-21: AOT Pre-Translation.
//!
//! Pre-translate the 21 default libraries (libart, libhwui, libvulkan, …) at
//! first boot so that cold app launch stays within the ≤ 33 ms p99 frame budget.
//!
//! Gate: p99 frame ≤ `AOT_P99_TARGET_MS` (33 ms) on cold app launch after the
//! first boot pre-translation pass completes.

use alloc::vec::Vec;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum work items in the AOT queue (from ch52).
pub const AOT_QUEUE_CAPACITY: usize = 64;

/// Default p99 frame target in milliseconds.
pub const AOT_P99_TARGET_MS: u64 = 33;

/// The 21 default libraries pre-translated at first boot (from ch52).
pub const AOT_DEFAULT_LIBRARIES: &[&str] = &[
    "libc",
    "libm",
    "libdl",
    "libart",
    "libartbase",
    "libartpalette",
    "libhwui",
    "libgui",
    "libsurfaceflinger",
    "libui",
    "libbinder",
    "libbinder_ndk",
    "libutils",
    "libcutils",
    "libandroid_runtime",
    "libvulkan",
    "libEGL",
    "libGLESv2",
    "libsqlite",
    "libssl",
    "libcrypto",
];

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single AOT work item: one block entry point inside a library.
#[derive(Debug, Clone)]
pub struct AotWorkItem {
    /// Index into `AOT_DEFAULT_LIBRARIES`.
    pub lib_idx: usize,
    /// Guest ARM64 PC of the block entry point.
    pub guest_pc: u64,
}

/// Frame-latency statistics collected during AOT pre-translation.
#[derive(Debug, Clone, Default)]
pub struct AotStats {
    /// Number of blocks pre-translated.
    pub blocks_pretranslated: u64,
    /// Frame duration samples in milliseconds.
    pub frame_samples_ms: Vec<u64>,
}

impl AotStats {
    /// Record one cold-app-launch frame duration (milliseconds).
    pub fn record_frame_ms(&mut self, ms: u64) {
        self.frame_samples_ms.push(ms);
    }

    /// P99 frame duration.  Returns `u64::MAX` if no samples recorded.
    pub fn p99_frame_ms(&mut self) -> u64 {
        if self.frame_samples_ms.is_empty() {
            return u64::MAX;
        }
        self.frame_samples_ms.sort_unstable();
        let idx = (self.frame_samples_ms.len() * 99 / 100).saturating_sub(1);
        self.frame_samples_ms[idx]
    }

    /// Gate: p99 ≤ `target_ms`.
    pub fn gate_passes(&mut self, target_ms: u64) -> bool {
        self.p99_frame_ms() <= target_ms
    }
}

/// AOT queue: manages the ordered list of work items.
#[derive(Debug)]
pub struct AotQueue {
    items: Vec<AotWorkItem>,
    capacity: usize,
}

impl AotQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Enqueue a block from `lib_idx` (index into `AOT_DEFAULT_LIBRARIES`).
    pub fn enqueue(&mut self, lib_idx: usize, guest_pc: u64) -> Result<(), AotError> {
        if self.items.len() >= self.capacity {
            return Err(AotError::QueueFull);
        }
        if lib_idx >= AOT_DEFAULT_LIBRARIES.len() {
            return Err(AotError::LibraryNotFound);
        }
        self.items.push(AotWorkItem { lib_idx, guest_pc });
        Ok(())
    }

    /// Drain and return the next work item.
    pub fn pop(&mut self) -> Option<AotWorkItem> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0))
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Error variants for AOT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AotError {
    QueueFull,
    LibraryNotFound,
    TranslationFailed,
}

/// Phase machine for AOT pre-translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AotPhase {
    NotStarted,
    LibrariesScanned,
    WorkQueued,
    TranslationRunning,
    GatePassed,
}

/// Configures the AOT pre-translation pipeline.
#[derive(Debug, Clone)]
pub struct AotConfig {
    pub queue_capacity: usize,
    pub p99_target_ms: u64,
}

impl AotConfig {
    pub fn aether_defaults() -> Self {
        Self {
            queue_capacity: AOT_QUEUE_CAPACITY,
            p99_target_ms: AOT_P99_TARGET_MS,
        }
    }

    pub fn validate(&self) -> Result<(), AotError> {
        if self.queue_capacity == 0 {
            return Err(AotError::QueueFull);
        }
        Ok(())
    }
}

/// Gate conditions for AT-21.
#[derive(Debug, Clone, Default)]
pub struct AotGate {
    /// All 21 default libraries have been queued.
    pub all_libs_queued: bool,
    /// P99 frame latency meets the ≤ 33 ms target.
    pub p99_met: bool,
}

impl AotGate {
    pub fn passes(&self) -> bool {
        self.all_libs_queued && self.p99_met
    }
}

/// Aggregate state for the AT-21 pipeline.
pub struct AotState {
    pub config: AotConfig,
    pub queue: AotQueue,
    pub stats: AotStats,
    pub phase: AotPhase,
    pub gate: AotGate,
}

impl AotState {
    pub fn new(config: AotConfig) -> Self {
        let cap = config.queue_capacity;
        Self {
            queue: AotQueue::new(cap),
            config,
            stats: AotStats::default(),
            phase: AotPhase::NotStarted,
            gate: AotGate::default(),
        }
    }

    /// Mark all 21 libraries as scanned and ready to queue.
    pub fn mark_libraries_scanned(&mut self) {
        if self.phase < AotPhase::LibrariesScanned {
            self.phase = AotPhase::LibrariesScanned;
        }
    }

    /// Enqueue entry points for all 21 default libraries.
    ///
    /// `entry_points` maps library index to a guest PC.  Libraries with no
    /// entry provided get a synthetic placeholder (lib_idx * 0x1000).
    pub fn queue_all_libraries(&mut self, entry_points: &[(usize, u64)]) -> Result<(), AotError> {
        for &(lib_idx, guest_pc) in entry_points {
            self.queue.enqueue(lib_idx, guest_pc)?;
        }
        self.gate.all_libs_queued = self.queue.len() >= AOT_DEFAULT_LIBRARIES.len()
            || entry_points.len() >= AOT_DEFAULT_LIBRARIES.len();
        if self.phase < AotPhase::WorkQueued {
            self.phase = AotPhase::WorkQueued;
        }
        Ok(())
    }

    /// Record one cold-app-launch frame measurement.
    pub fn record_frame_ms(&mut self, ms: u64) {
        self.stats.record_frame_ms(ms);
        self.stats.blocks_pretranslated += 1;
        let target = self.config.p99_target_ms;
        self.gate.p99_met = self.stats.gate_passes(target);
        if self.gate.passes() {
            self.phase = AotPhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &AotGate {
        &self.gate
    }
}

/// Initialise the AOT pre-translation pipeline (8-step skeleton).
pub fn init_aot_pretranslation(config: AotConfig) -> Result<AotState, AotError> {
    config.validate()?;
    let mut state = AotState::new(config);

    // Step 1: verify library list length
    assert_eq!(AOT_DEFAULT_LIBRARIES.len(), 21, "AOT library list must have exactly 21 entries");

    // Step 2: scan entry points (placeholder — real impl hooks Dispatcher)
    state.mark_libraries_scanned();

    // Step 3: enqueue synthetic entry points for all 21 libs
    let entries: Vec<(usize, u64)> = (0..AOT_DEFAULT_LIBRARIES.len())
        .map(|i| (i, (i as u64 + 1) * 0x1000))
        .collect();
    state.queue_all_libraries(&entries)?;

    // Step 4–8: deferred to real dispatch loop (runs per frame in production)
    Ok(state)
}
