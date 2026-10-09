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
    /// Structural-safety verdict computed ONCE at translation time
    /// (`block_bytes_are_safe`): ends in RET, no UD2 sentinel. Cached here so
    /// the dispatch hot path does not re-scan the block's bytes on every entry
    /// — the translated bytes are immutable until eviction/re-translation, so a
    /// per-entry rescan was pure waste (O(len) softmmu reads × every dispatch).
    pub safe: bool,
    /// Generation at which this entry was installed.
    pub generation: u32,
    /// ch66: address-space epoch at install time (see `BlockCache::epoch`). The
    /// entry is live only while it equals the current epoch of its VA half.
    pub epoch: u64,
    /// ch66: address space the block was translated in — the live `TTBR0_EL1`
    /// value (table base + ASID) for a low-half PC, 0 for a high-half (global
    /// kernel) PC. Part of the key: the same user VA in two processes is two
    /// entries, so a TTBR0 switch needs no invalidation at all.
    pub space: u64,
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
    /// ch66: O(1) invalidation. `epoch[0]` covers low (TTBR0, VA[55]=0) PCs,
    /// `epoch[1]` high (TTBR1) PCs. Bumping an epoch makes every entry of that
    /// half stale at once (a stale entry reads as a miss and is overwritten in
    /// place on re-insert; rotation reclaims the rest). Replaces the O(capacity)
    /// clear of both generations that every TLBI / TTBR write used to pay.
    epoch: [u64; 2],

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
            epoch: [1, 1],
            stat_hits: 0,
            stat_misses: 0,
            stat_old_hits: 0,
            stat_evictions: 0,
        }
    }

    // ── Hash & probe ──────────────────────────────────────────────────────────

    /// Address-space half of a guest PC: 1 for TTBR1 (VA[55] set), else 0.
    #[inline]
    pub fn half(guest_pc: u64) -> usize {
        ((guest_pc >> 55) & 1) as usize
    }

    /// Current epoch of `guest_pc`'s half.
    #[inline]
    pub fn epoch_of(&self, guest_pc: u64) -> u64 {
        self.epoch[Self::half(guest_pc)]
    }

    #[inline]
    fn bucket(&self, guest_pc: u64) -> usize {
        // Fibonacci hashing (multiplicative) — distributes ARM PC values well
        // since they are always 4-byte aligned (low two bits always 00).
        let h = guest_pc.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
        (h >> (64 - self.capacity.trailing_zeros())) as usize
    }

    /// Find the bucket index for `(guest_pc, space)` in `buckets`, or `None`.
    fn probe(buckets: &[Option<CachedBlock>], guest_pc: u64, space: u64) -> Option<usize> {
        let cap = buckets.len();
        let mask = cap - 1;
        // Recompute bucket index inline (can't call &self.bucket here).
        let h = guest_pc.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
        let start = (h >> (64 - cap.trailing_zeros())) as usize;

        let mut i = start;
        loop {
            match &buckets[i] {
                None => return None,
                Some(b) if b.guest_pc == guest_pc && b.space == space => return Some(i),
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
                Some(b) if b.guest_pc == entry.guest_pc && b.space == entry.space => {
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
        self.lookup_in(guest_pc, 0)
    }

    /// ch66: look up `guest_pc` translated in address space `space` (see
    /// [`CachedBlock::space`]).
    pub fn lookup_in(&mut self, guest_pc: u64, space: u64) -> Option<&CachedBlock> {
        let ep = self.epoch_of(guest_pc);
        // Hot path: active generation.
        if let Some(idx) = Self::probe(&self.active, guest_pc, space) {
            if self.active[idx].as_ref().map_or(false, |e| e.epoch == ep) {
                self.stat_hits += 1;
                return self.active[idx].as_ref();
            }
            // Stale (invalidated) entry: a miss. Do not consult `old` — any
            // old-generation copy is at least as stale.
            self.stat_misses += 1;
            return None;
        }

        // Cold path: old generation.
        // Old-gen is read-only (no deletions) to preserve linear-probe chains.
        // We promote to active by copying — old slot stays intact until rotation.
        if let Some(idx) = Self::probe(&self.old, guest_pc, space)
            .filter(|&i| self.old[i].as_ref().map_or(false, |e| e.epoch == ep && e.len != 0))
        {
            self.stat_old_hits += 1;
            let entry = self.old[idx].as_ref().unwrap().clone();
            let already = Self::probe(&self.active, guest_pc, space).is_some();
            if Self::insert_into(&mut self.active, entry) && !already {
                self.active_count += 1;
            }
            // Re-probe active to return a stable reference.
            if let Some(ai) = Self::probe(&self.active, guest_pc, space) {
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
    pub fn insert(&mut self, guest_pc: u64, host_offset: usize, len: usize, safe: bool) {
        self.insert_in(guest_pc, 0, host_offset, len, safe)
    }

    /// ch66: insert a block translated in address space `space`.
    pub fn insert_in(&mut self, guest_pc: u64, space: u64, host_offset: usize, len: usize, safe: bool) {
        // Rotate generations if active is too full.
        let threshold = (self.capacity as u64 * self.fill_pct as u64 / 100) as usize;
        if self.active_count >= threshold {
            self.rotate_generations();
        }

        let entry = CachedBlock {
            guest_pc,
            host_offset,
            len,
            safe,
            generation: self.generation,
            epoch: self.epoch_of(guest_pc),
            space,
        };

        // Update count only if this is truly a new slot.
        let already = Self::probe(&self.active, guest_pc, space).is_some();
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
        if let Some(idx) = Self::probe(&self.active, guest_pc, 0) {
            self.active[idx] = None;
            self.active_count = self.active_count.saturating_sub(1);
            // Rehash displaced entries to repair the probe chain.
            self.repair_chain_active(idx);
        }
        // Old gen: mark as invalid so future promotions skip it.
        if let Some(idx) = Self::probe(&self.old, guest_pc, 0) {
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

    /// Evict all entries (both generations) — O(1): bump both epochs.
    pub fn flush_all(&mut self) {
        self.epoch[0] = self.epoch[0].wrapping_add(1);
        self.epoch[1] = self.epoch[1].wrapping_add(1);
        self.stat_evictions += 1;
    }

    /// Evict every low-half (TTBR0 / user) entry — O(1). Kernel (TTBR1) blocks
    /// stay live: a TTBR0 switch cannot change what a high VA maps to.
    pub fn flush_low(&mut self) {
        self.epoch[0] = self.epoch[0].wrapping_add(1);
        self.stat_evictions += 1;
    }

    /// Physically clear both generations (arena reset: every offset is dead).
    pub fn clear(&mut self) {
        for slot in &mut self.active {
            *slot = None;
        }
        for slot in &mut self.old {
            *slot = None;
        }
        self.active_count = 0;
        self.flush_all();
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
