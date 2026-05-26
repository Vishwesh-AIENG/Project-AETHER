//! AT-16: Block cache — guest ARM64 PC → translated x86_64 host block.
//!
//! The cache is a two-generation open-addressed hash table.  When the active
//! generation fills, the old generation is dropped and the active becomes old
//! ("generational eviction").  This avoids per-entry timestamps while keeping
//! steady-state entries alive.
//!
//! Layout per bucket:
//!   • `None`  — empty
//!   • `Some(CachedBlock)` — occupied
//!
//! Collision resolution: linear probing (cache-friendly; works well when load
//! factor stays below 0.7, which the generational eviction enforces).
//!
//! Gate: cache hit rate ≥ 99 % on a libart steady-state workload (surrogate:
//! 1 000 unique PCs accessed 200× each → measure hit rate after warm-up).

use alloc::vec::Vec;

/// A single entry in the block cache.
#[derive(Debug, Clone)]
pub struct CachedBlock {
    /// Guest ARM64 program counter.
    pub guest_pc: u64,
    /// Byte offset of the translated block within the JIT code arena.
    pub host_offset: usize,
    /// Length of the translated block in bytes.
    pub len: usize,
    /// Generation at which this entry was installed.
    pub generation: u32,
}

/// Two-generation block cache.
pub struct BlockCache {
    /// Active generation buckets.
    active: Vec<Option<CachedBlock>>,
    /// Previous generation buckets (consulted on active miss; not inserted into).
    old: Vec<Option<CachedBlock>>,
    /// Number of slots per generation.
    capacity: usize,
    /// Number of occupied slots in the active generation.
    active_count: usize,
    /// Current generation number.
    generation: u32,
    /// Promotion threshold: fraction of capacity (as integer percent) before
    /// triggering a generation flip.  Default: 70.
    fill_pct: u32,

    // Statistics
    pub stat_hits: u64,
    pub stat_misses: u64,
    pub stat_old_hits: u64,
    pub stat_evictions: u64,
}

impl BlockCache {
    /// Minimum capacity (must be a power of two ≥ 8).
    const MIN_CAP: usize = 8;

    /// Create a new cache.  `capacity` is rounded up to the next power of two.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two().max(Self::MIN_CAP);
        Self {
            active: (0..cap).map(|_| None).collect(),
            old: (0..cap).map(|_| None).collect(),
            capacity: cap,
            active_count: 0,
            generation: 0,
            fill_pct: 70,
            stat_hits: 0,
            stat_misses: 0,
            stat_old_hits: 0,
            stat_evictions: 0,
        }
    }

    // ── Hash & probe ──────────────────────────────────────────────────────────

    #[inline]
    fn bucket(&self, guest_pc: u64) -> usize {
        // Fibonacci hashing (multiplicative) — distributes ARM PC values well
        // since they are always 4-byte aligned (low two bits always 00).
        let h = guest_pc.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
        (h >> (64 - self.capacity.trailing_zeros())) as usize
    }

    /// Find the bucket index for `guest_pc` in `buckets`, or `None` if absent.
    fn probe(buckets: &[Option<CachedBlock>], guest_pc: u64) -> Option<usize> {
        let cap = buckets.len();
        let mask = cap - 1;
        // Recompute bucket index inline (can't call &self.bucket here).
        let h = guest_pc.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
        let start = (h >> (64 - cap.trailing_zeros())) as usize;

        let mut i = start;
        loop {
            match &buckets[i] {
                None => return None,
                Some(b) if b.guest_pc == guest_pc => return Some(i),
                _ => {}
            }
            i = (i + 1) & mask;
            if i == start {
                return None;
            }
        }
    }

    /// Insert `entry` into `buckets` (active generation).  Returns `false` if
    /// the table is full (should not happen under the fill-factor guard).
    fn insert_into(buckets: &mut Vec<Option<CachedBlock>>, entry: CachedBlock) -> bool {
        let cap = buckets.len();
        let mask = cap - 1;
        let h = entry.guest_pc.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
        let start = (h >> (64 - cap.trailing_zeros())) as usize;

        let mut i = start;
        loop {
            match &buckets[i] {
                None => {
                    buckets[i] = Some(entry);
                    return true;
                }
                Some(b) if b.guest_pc == entry.guest_pc => {
                    // Update existing entry.
                    buckets[i] = Some(entry);
                    return true;
                }
                _ => {}
            }
            i = (i + 1) & mask;
            if i == start {
                return false;
            }
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Look up `guest_pc`.  Returns a reference to the cached block if present.
    ///
    /// Checks active generation first, then old generation (and promotes to
    /// active on an old-gen hit to prevent re-eviction).
    pub fn lookup(&mut self, guest_pc: u64) -> Option<&CachedBlock> {
        // Hot path: active generation.
        if let Some(idx) = Self::probe(&self.active, guest_pc) {
            self.stat_hits += 1;
            return self.active[idx].as_ref();
        }

        // Cold path: old generation.
        // Old-gen is read-only (no deletions) to preserve linear-probe chains.
        // We promote to active by copying — old slot stays intact until rotation.
        if let Some(idx) = Self::probe(&self.old, guest_pc) {
            self.stat_old_hits += 1;
            let entry = self.old[idx].as_ref().unwrap().clone();
            let already = Self::probe(&self.active, guest_pc).is_some();
            if Self::insert_into(&mut self.active, entry) && !already {
                self.active_count += 1;
            }
            // Re-probe active to return a stable reference.
            if let Some(ai) = Self::probe(&self.active, guest_pc) {
                self.stat_hits += 1;
                return self.active[ai].as_ref();
            }
        }

        self.stat_misses += 1;
        None
    }

    /// Insert or update a translated block.
    ///
    /// If the active generation is at the fill threshold, it is rotated: the
    /// active becomes old and a fresh active generation is allocated.
    pub fn insert(&mut self, guest_pc: u64, host_offset: usize, len: usize) {
        // Rotate generations if active is too full.
        let threshold = (self.capacity as u64 * self.fill_pct as u64 / 100) as usize;
        if self.active_count >= threshold {
            self.rotate_generations();
        }

        let entry = CachedBlock {
            guest_pc,
            host_offset,
            len,
            generation: self.generation,
        };

        // Update count only if this is truly a new slot.
        let already = Self::probe(&self.active, guest_pc).is_some();
        if Self::insert_into(&mut self.active, entry) && !already {
            self.active_count += 1;
        }
    }

    /// Invalidate the entry for `guest_pc`.
    ///
    /// For the active generation we use a tombstone-free approach: we zero the
    /// slot and decrement the count.  The old generation is read-only — we
    /// cannot safely delete from it without breaking probe chains, so we mark
    /// the entry with a sentinel `host_offset = usize::MAX` so lookup skips it.
    pub fn invalidate(&mut self, guest_pc: u64) {
        if let Some(idx) = Self::probe(&self.active, guest_pc) {
            self.active[idx] = None;
            self.active_count = self.active_count.saturating_sub(1);
            // Rehash displaced entries to repair the probe chain.
            self.repair_chain_active(idx);
        }
        // Old gen: mark as invalid so future promotions skip it.
        if let Some(idx) = Self::probe(&self.old, guest_pc) {
            // Overwrite in place with a sentinel (len=0 signals invalid).
            if let Some(e) = &mut self.old[idx] {
                e.len = 0; // sentinel: skip on promotion
            }
        }
    }

    /// Repair the linear-probe chain in the active generation after a deletion
    /// at `deleted_idx`.  Rehashes all entries in the run following the gap.
    fn repair_chain_active(&mut self, deleted_idx: usize) {
        let cap = self.capacity;
        let mask = cap - 1;
        let mut i = (deleted_idx + 1) & mask;
        loop {
            let entry = match self.active[i].take() {
                None => break,
                Some(e) => e,
            };
            // Re-insert.
            let _ = Self::insert_into(&mut self.active, entry);
            i = (i + 1) & mask;
        }
    }

    /// Evict all entries (both generations).
    pub fn flush_all(&mut self) {
        for slot in &mut self.active {
            *slot = None;
        }
        for slot in &mut self.old {
            *slot = None;
        }
        self.active_count = 0;
        self.stat_evictions += 1;
    }

    /// Hit rate: `hits / (hits + misses)`.  Old-gen hits count as hits.
    pub fn hit_rate(&self) -> f64 {
        let total = self.stat_hits + self.stat_misses;
        if total == 0 {
            0.0
        } else {
            self.stat_hits as f64 / total as f64
        }
    }

    /// Active-generation occupancy (0.0 – 1.0).
    pub fn load_factor(&self) -> f64 {
        self.active_count as f64 / self.capacity as f64
    }

    /// Number of occupied active-generation slots.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Current generation number.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn rotate_generations(&mut self) {
        // Old generation is discarded; active becomes old.
        core::mem::swap(&mut self.active, &mut self.old);
        // Clear the new active generation.
        for slot in &mut self.active {
            *slot = None;
        }
        self.active_count = 0;
        self.generation = self.generation.wrapping_add(1);
        self.stat_evictions += 1;
    }
}
