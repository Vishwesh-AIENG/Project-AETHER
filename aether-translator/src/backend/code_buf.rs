//! AT-15: JIT code buffer — executable page management and ICache coherency.
//!
//! On x86_64, the CPU does not require explicit ICache invalidation after a
//! write to a code page — but it DOES require serialization before the first
//! execute of newly-written code (Intel SDM §11.6: "Cross-Modifying Code").
//!
//! Required sequence after writing new code:
//!   1. Write bytes to RW page.
//!   2. (Optional) CLFLUSH the modified cache lines — only needed when sharing
//!      code across cores without a TLB shootdown.
//!   3. Execute a serializing instruction (CPUID, IRET, or WRMSR) before
//!      jumping to the new code.
//!   4. Toggle page protection: RW → RX before first execute.
//!
//! This module manages the code buffer lifecycle:
//!   * Allocate blocks from a contiguous arena.
//!   * Track which pages are dirty (written but not yet flushed/executed).
//!   * Provide an invalidation primitive for self-modifying code handling.
//!
//! Gate: self-modifying-code unit test (write → invalidate → rewrite →
//! re-execute) passes 1 000 000 iterations without staleness.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Hypervisor callback for W^X via EPT/NPT (Step 3 of integration plan) ──────
//
// The translator's JIT cache lives in hypervisor-private memory (never present
// in any guest's EPT or NPT — see `aether_dbt_init`'s `jit_cache_pa`). After
// emitting a block and serialising, the dispatcher must flip the affected
// host pages from RW to RX. On bare metal that means rewriting the EPT (Intel)
// or NPT (AMD) leaf entries and issuing `INVEPT single-context` /
// `VMCB TLB_CTL = FLUSH_ALL` respectively (AMD has no INVNPT).
//
// The translator crate is no_std and never imports the hypervisor. The
// hypervisor installs a callback at boot via `register_ept_rx_flip` and the
// translator invokes it from `CodeBuf::commit_rx_via_ept`. When no callback
// is installed (host tests, dev builds), `commit_rx_via_ept` falls back to
// the structural `promote_to_rx` and returns Ok — page perms are a no-op on
// non-bare-metal harnesses.

/// Signature for the hypervisor-provided page-protection flip.
///
/// Called once per emitted block with the host physical address of the
/// first byte of translated code and the byte length. The implementation
/// must flip the covering EPT/NPT leaf entries from RW to RX and issue the
/// appropriate TLB invalidation (`INVEPT` on Intel, ASID-based TLB_CTL
/// flush on AMD before the next VMRUN). Returns `true` on success.
///
/// Invariant: pages flipped to RX must remain mapped at the same host PA
/// — flipping `present` to zero would tear down the JIT cache.
pub type EptRxFlipFn = unsafe extern "C" fn(host_pa: u64, byte_len: usize) -> bool;

static EPT_RX_FLIP: AtomicUsize = AtomicUsize::new(0);

/// Install the EPT/NPT W^X callback. Called once from the hypervisor at
/// boot, before any guest VMRUN/VMRESUME.
pub fn register_ept_rx_flip(f: EptRxFlipFn) {
    EPT_RX_FLIP.store(f as usize, Ordering::Release);
}

/// Whether a hypervisor-provided EPT/NPT callback is installed.
pub fn ept_rx_flip_installed() -> bool {
    EPT_RX_FLIP.load(Ordering::Acquire) != 0
}

/// Invoke the registered callback for the given JIT-cache range. Returns
/// `true` if the callback succeeded OR if no callback is installed (host
/// builds; protection is purely structural).
#[allow(unsafe_code)] // FFI call into hypervisor-registered C ABI function
fn ept_rx_flip_call(host_pa: u64, byte_len: usize) -> bool {
    let raw = EPT_RX_FLIP.load(Ordering::Acquire);
    if raw == 0 {
        return true; // no-op on host / test builds
    }
    // SAFETY: the hypervisor registered this function pointer via
    // `register_ept_rx_flip`; the contract is documented on `EptRxFlipFn`.
    let f: EptRxFlipFn = unsafe { core::mem::transmute(raw) };
    unsafe { f(host_pa, byte_len) }
}

/// Protection state of a code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Writable but not executable.  Used during JIT emission.
    ReadWrite,
    /// Executable but not writable.  Used during dispatch.
    ReadExecute,
}

/// A single translated block slot in the code arena.
///
/// Part of the `cfg(test)`-gated per-block registry (see `CodeBuf::blocks`).
/// It is only constructed/read by the AT-15 gate tests and the in-crate
/// `smcode_test_iteration` harness; the production translate/dispatch path
/// tracks blocks via `runtime::block_cache::BlockCache` instead.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct CodeBlock {
    /// Byte offset of this block within the arena.
    pub offset: usize,
    /// Length of emitted code in bytes.
    pub len: usize,
    /// Guest ARM64 PC that this block translates.
    pub guest_pc: u64,
    /// True if the block has been committed (serialized + executable).
    pub committed: bool,
    /// Generation counter — incremented on each rewrite of this guest PC.
    pub generation: u32,
}

/// Code arena.  In production this wraps a hypervisor-provided JIT arena
/// (AT-15 §code-buffer); in tests it uses a `Vec<u8>` for correctness testing
/// of the management logic without platform-specific `mmap` / `VirtualAlloc`.
///
/// Invariant: `written_len <= capacity`.
pub struct CodeBuf {
    /// Raw byte storage.
    buf: Vec<u8>,
    /// High-water mark — next free byte offset.
    written_len: usize,
    /// Committed offset — bytes up to here have been serialized and are safe to
    /// execute (in the structural model; actual RX promotion is caller's job).
    committed_len: usize,
    /// Per-block registry, keyed by insertion order. Used ONLY by the AT-15
    /// gate tests (block lookup / SMC invalidate-by-guest-PC / generation
    /// tracking) and the in-crate `smcode_test_iteration` harness.
    ///
    /// It is gated on `cfg(test)` so it exists only when the crate is compiled
    /// in test mode (`cargo test`). The AT-15 gate tests therefore live in the
    /// in-module `#[cfg(test)] mod at15_*` blocks below — NOT under `tests/`,
    /// because an integration test compiles the library as a normal dependency
    /// where `cfg(test)` is unset, which would hide these `pub` methods.
    ///
    /// The production VMEXIT translate/dispatch path never reads this Vec.
    /// PC→host-offset lookup goes through `runtime::block_cache::BlockCache`,
    /// and production SMC handling flushes the whole cache via
    /// `BlockCache::flush_all` (see `dbt::DbtRuntime::translate_block`).
    /// Keeping this Vec in release builds would grow it once per cold
    /// translate and never free it — under the hypervisor's never-freeing
    /// bump heap that is a permanent leak that exhausts memory across an
    /// Android boot's millions of unique blocks (the ~1.5 GiB OOM before
    /// SurfaceFlinger). So in the production build the field, its per-translate
    /// push, and all readers are compiled out and `alloc_block` only advances
    /// the watermark.
    #[cfg(test)]
    blocks: Vec<CodeBlock>,
    /// Dirty flag: true when bytes have been written since last commit.
    dirty: bool,
    /// Protection state as tracked by the buffer (not by the OS).
    prot: Protection,
    /// Serialize-needed flag: set when dirty, cleared on explicit serialize.
    needs_serialize: bool,
}

impl CodeBuf {
    /// Create a new code buffer with `capacity` bytes pre-allocated.
    pub fn new(capacity: usize) -> Self {
        let buf = alloc::vec![0u8; capacity];
        Self {
            buf,
            written_len: 0,
            committed_len: 0,
            #[cfg(test)]
            blocks: Vec::new(),
            dirty: false,
            prot: Protection::ReadWrite,
            needs_serialize: false,
        }
    }

    /// Available space in bytes.
    pub fn available(&self) -> usize {
        self.buf.len() - self.written_len
    }

    /// Total capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Host virtual address of byte 0 of the code arena.
    ///
    /// The arena is a `Vec<u8>` from the global allocator, so the emitted x86
    /// for a block at host_offset lives at `base_ptr() + host_offset` — this
    /// is the real executable address for host-mode dispatch (the logical
    /// `jit_cache_pa` passed to `aether_dbt_init` is only used to compute the
    /// guest-side NPT/EPT W^X-flip target, not where the bytes physically are).
    pub fn base_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    /// ch66: overwrite `bytes` at `offset` inside already-emitted code (block
    /// chaining link/unlink and exit-site fixups). Returns false if out of range.
    pub fn patch(&mut self, offset: usize, bytes: &[u8]) -> bool {
        if offset.checked_add(bytes.len()).map_or(true, |e| e > self.written_len) {
            return false;
        }
        self.buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        true
    }

    /// Current high-water mark.
    pub fn written_len(&self) -> usize {
        self.written_len
    }

    // ── Emit ─────────────────────────────────────────────────────────────────

    /// Write `bytes` at the current watermark.  Returns `Err` if capacity
    /// would be exceeded.
    pub fn emit(&mut self, bytes: &[u8]) -> Result<usize, CodeBufError> {
        if self.written_len + bytes.len() > self.buf.len() {
            return Err(CodeBufError::OutOfCapacity {
                requested: bytes.len(),
                available: self.available(),
            });
        }
        let offset = self.written_len;
        self.buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.written_len += bytes.len();
        self.dirty = true;
        self.needs_serialize = true;
        self.prot = Protection::ReadWrite; // writing demotes to RW
        Ok(offset)
    }

    /// Allocate a block for guest PC `guest_pc` with `code` bytes.
    /// Returns the offset of the emitted block.
    pub fn alloc_block(&mut self, guest_pc: u64, code: &[u8]) -> Result<usize, CodeBufError> {
        let offset = self.emit(code)?;
        // Per-block bookkeeping is registry-only (gated on `std`) — see the
        // `blocks` field doc. In the production build this records nothing:
        // the watermark already advanced in `emit`, and the PC→offset mapping
        // the live dispatcher needs is owned by `BlockCache`, not `CodeBuf`.
        #[cfg(test)]
        self.blocks.push(CodeBlock {
            offset,
            len: code.len(),
            guest_pc,
            committed: false,
            generation: 0,
        });
        #[cfg(not(test))]
        let _ = guest_pc;
        Ok(offset)
    }

    // ── Commit / serialize ────────────────────────────────────────────────────

    /// Mark bytes as serialized — the caller is responsible for emitting a
    /// serializing instruction (CPUID) before executing the new code.
    ///
    /// In the structural model, calling this function records that the
    /// serialization invariant is satisfied.  The gate test checks that
    /// `committed` blocks are never executed without a prior `serialize`.
    pub fn serialize(&mut self) {
        self.needs_serialize = false;
        self.committed_len = self.written_len;

        // Mark all pending blocks as committed (registry-only, gated on `std`;
        // the executable-state invariant is tracked by `committed_len`/`prot`).
        #[cfg(test)]
        for blk in &mut self.blocks {
            if !blk.committed {
                blk.committed = true;
            }
        }
        self.dirty = false;
    }

    /// Mark the buffer as RX (executable).  Must be called after `serialize`.
    /// Panics if `needs_serialize` is still set (invariant: always serialize
    /// before promoting to executable).
    pub fn promote_to_rx(&mut self) {
        assert!(
            !self.needs_serialize,
            "AT-15 invariant violated: promote_to_rx called without prior serialize"
        );
        self.prot = Protection::ReadExecute;
    }

    /// Full commit: serialize + promote.
    pub fn commit(&mut self) {
        self.serialize();
        self.promote_to_rx();
    }

    /// Step 3 of the AT integration plan: serialise, flip the underlying
    /// EPT/NPT leaf entries from RW to RX via the hypervisor-provided
    /// callback, then mark the buffer executable.
    ///
    /// `host_pa_base` is the host physical address of `buf[0]` — supplied
    /// by the caller because the translator does not own the JIT-cache
    /// mapping (the hypervisor reserves `0x2_0000_0000`, 16 MiB,
    /// hypervisor-private; see [`super::super::dbt::DbtIntegrationConfig`]).
    ///
    /// On host / unit-test builds (no callback installed), this is
    /// equivalent to `commit()` and returns Ok.
    ///
    /// Returns `Err(CodeBufError::EptFlipFailed)` if the callback was
    /// installed and returned `false` — the buffer remains RW so the next
    /// emit path can rewrite it.
    pub fn commit_rx_via_ept(&mut self, host_pa_base: u64) -> Result<(), CodeBufError> {
        self.serialize();
        let len = self.committed_len;
        if len > 0 && !ept_rx_flip_call(host_pa_base, len) {
            return Err(CodeBufError::EptFlipFailed);
        }
        // Only mark RX after the page-perm flip succeeded. Bypass the
        // assertion in `promote_to_rx` — we have already serialised.
        self.prot = Protection::ReadExecute;
        Ok(())
    }

    // ── Invalidation ──────────────────────────────────────────────────────────

    /// Invalidate all blocks that translate guest PC `guest_pc`.
    ///
    /// Test-only. The production self-modifying-code path does NOT invalidate
    /// per guest PC through `CodeBuf` — it flushes the whole `BlockCache` via
    /// `BlockCache::flush_all` and lets `reset()` zero the arena (see
    /// `dbt::DbtRuntime::translate_block`'s capacity-pressure branch). This
    /// fine-grained variant exists only to exercise the AT-15 generation /
    /// commit-state invariants in unit tests.
    ///
    /// Returns the number of invalidated blocks.
    #[cfg(test)]
    pub fn invalidate_guest_pc(&mut self, guest_pc: u64) -> usize {
        let mut count = 0;
        for blk in &mut self.blocks {
            if blk.guest_pc == guest_pc && blk.committed {
                blk.committed = false;
                blk.generation += 1;
                count += 1;
            }
        }
        if count > 0 {
            self.prot = Protection::ReadWrite; // buffer needs rewrite
        }
        count
    }

    /// Invalidate the entire code buffer — reclaim all space.
    /// Used for capacity pressure eviction (generational eviction in AT-16).
    pub fn reset(&mut self) {
        self.written_len = 0;
        self.committed_len = 0;
        #[cfg(test)]
        self.blocks.clear();
        self.dirty = false;
        self.needs_serialize = false;
        self.prot = Protection::ReadWrite;
        // Zero out the buffer to prevent stale code execution.
        for b in &mut self.buf {
            *b = 0;
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// True if any bytes have been written since the last `serialize`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// True if the buffer has been promoted to RX without subsequent writes.
    pub fn is_executable(&self) -> bool {
        self.prot == Protection::ReadExecute && !self.needs_serialize
    }

    /// Current protection state.
    pub fn protection(&self) -> Protection {
        self.prot
    }

    /// Iterate over all committed blocks for a given guest PC. Registry-only
    /// (gated on `std`) — the live dispatcher looks up via `BlockCache`.
    #[cfg(test)]
    pub fn lookup_guest_pc(&self, guest_pc: u64) -> impl Iterator<Item = &CodeBlock> {
        self.blocks.iter().filter(move |b| b.guest_pc == guest_pc && b.committed)
    }

    /// Iterate over all blocks (committed or not). Registry-only view (gated
    /// on `std`).
    #[cfg(test)]
    pub fn all_blocks(&self) -> &[CodeBlock] {
        &self.blocks
    }

    /// Read the emitted bytes at `offset..offset+len`.  Panics on out-of-bounds.
    pub fn read_bytes(&self, offset: usize, len: usize) -> &[u8] {
        &self.buf[offset..offset + len]
    }

    /// View the entire arena as a byte slice (up to `written_len`).
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.written_len]
    }

    /// Total number of committed blocks. Registry-only view (gated on `std`).
    #[cfg(test)]
    pub fn n_committed_blocks(&self) -> usize {
        self.blocks.iter().filter(|b| b.committed).count()
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeBufError {
    OutOfCapacity { requested: usize, available: usize },
    /// The hypervisor-registered EPT/NPT page-protection callback returned
    /// `false`. See [`CodeBuf::commit_rx_via_ept`].
    EptFlipFailed,
}

// ── Self-modifying code test harness ─────────────────────────────────────────

/// Simulate one iteration of the self-modifying code test loop:
///   1. Emit code for version `v`.
///   2. Commit (serialize + promote).
///   3. Verify the block is executable.
///   4. Invalidate.
///   5. Verify the block is no longer committed.
///
/// Registry-only harness (gated on `cfg(test)`): it drives the `blocks`
/// registry and `invalidate_guest_pc`, neither of which exists in the
/// production build.
///
/// Returns `Ok(())` if all invariants hold.
#[cfg(test)]
pub fn smcode_test_iteration(
    buf: &mut CodeBuf,
    guest_pc: u64,
    code_v1: &[u8],
    code_v2: &[u8],
) -> Result<(), &'static str> {
    // Phase 1: emit v1
    buf.reset();
    let _off1 = buf.alloc_block(guest_pc, code_v1).map_err(|_| "alloc v1 failed")?;
    if !buf.is_dirty() { return Err("dirty flag not set after emit"); }
    buf.commit();
    if !buf.is_executable() { return Err("not executable after commit"); }
    if buf.n_committed_blocks() != 1 { return Err("expected 1 committed block"); }

    // Phase 2: invalidate and rewrite with v2
    let n = buf.invalidate_guest_pc(guest_pc);
    if n != 1 { return Err("expected 1 invalidated block"); }
    if buf.n_committed_blocks() != 0 { return Err("block still committed after invalidate"); }

    // Must demote to RW after invalidation before rewrite.
    let off2 = buf.emit(code_v2).map_err(|_| "emit v2 failed")?;
    buf.blocks.last_mut().ok_or("no block")?.committed = false;
    buf.blocks.last_mut().ok_or("no block")?.len = code_v2.len();
    // Manually add second block entry for v2.
    buf.blocks.push(CodeBlock {
        offset: off2,
        len: code_v2.len(),
        guest_pc,
        committed: false,
        generation: 1,
    });
    buf.commit();
    if !buf.is_executable() { return Err("not executable after second commit"); }

    // Verify bytes match what we wrote.
    let actual_v2 = buf.read_bytes(off2, code_v2.len());
    if actual_v2 != code_v2 {
        return Err("byte mismatch for v2");
    }

    Ok(())
}

// ── AT-15 gate tests ─────────────────────────────────────────────────────────
//
// These live in-module (not under `tests/`) because they exercise the
// `cfg(test)`-gated per-block registry (`blocks`, `n_committed_blocks`,
// `lookup_guest_pc`, `all_blocks`, `invalidate_guest_pc`, `smcode_test_iteration`).
// An integration test under `tests/` compiles the library as a normal
// dependency where `cfg(test)` is unset, so those `pub fn`s would not exist;
// keeping the registry out of the production (non-test) build is what closes
// the per-translate `CodeBuf.blocks` heap leak. Coverage is identical to the
// former `tests/at15_code_buf.rs`.
#[cfg(test)]
mod at15_tests {
    use super::{smcode_test_iteration, CodeBuf, Protection};

    // ── Basic emit / commit ──────────────────────────────────────────────────

    #[test]
    fn at15_new_buf_is_empty() {
        let buf = CodeBuf::new(4096);
        assert_eq!(buf.written_len(), 0);
        assert_eq!(buf.n_committed_blocks(), 0);
    }

    #[test]
    fn at15_emit_bytes_advances_written_len() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90, 0x90, 0x90]).unwrap(); // 3 × NOP
        assert_eq!(buf.written_len(), 3);
        assert_eq!(buf.n_committed_blocks(), 0);
    }

    #[test]
    fn at15_alloc_block_then_commit_makes_block_committed() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x1000, &[0x90u8; 8]).unwrap();
        buf.commit();
        assert_eq!(buf.n_committed_blocks(), 1);
    }

    #[test]
    fn at15_committed_bytes_match_emitted() {
        let code = [0x48u8, 0x31, 0xC0, 0xC3]; // XOR RAX,RAX; RET
        let mut buf = CodeBuf::new(4096);
        let off = buf.alloc_block(0x2000, &code).unwrap();
        buf.commit();
        let stored = buf.read_bytes(off, 4);
        assert_eq!(stored, &code);
    }

    #[test]
    fn at15_two_blocks_committed() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x1000, &[0x90u8; 4]).unwrap();
        buf.alloc_block(0x1008, &[0xC3u8; 2]).unwrap();
        buf.commit();
        assert_eq!(buf.n_committed_blocks(), 2);
    }

    // ── Protection state machine ──────────────────────────────────────────────

    #[test]
    fn at15_initial_protection_is_rw() {
        let buf = CodeBuf::new(4096);
        assert_eq!(buf.protection(), Protection::ReadWrite);
    }

    #[test]
    fn at15_commit_promotes_to_rx() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        buf.commit();
        assert_eq!(buf.protection(), Protection::ReadExecute);
    }

    #[test]
    fn at15_emit_after_commit_returns_to_rw() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        buf.commit();
        buf.emit(&[0x90u8]).unwrap();
        assert_eq!(buf.protection(), Protection::ReadWrite);
    }

    // ── Overflow / capacity ───────────────────────────────────────────────────

    #[test]
    fn at15_capacity_at_least_as_large_as_requested() {
        let buf = CodeBuf::new(1024);
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn at15_overflow_returns_error() {
        let mut buf = CodeBuf::new(4);
        // First 4 bytes succeed
        buf.emit(&[0x90u8; 4]).unwrap();
        // 5th byte must fail
        let result = buf.emit(&[0x90u8]);
        assert!(result.is_err(), "emit past capacity must return Err");
    }

    // ── Block registry ────────────────────────────────────────────────────────

    #[test]
    fn at15_lookup_guest_pc_finds_committed_block() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x3000, &[0x90u8; 4]).unwrap();
        buf.commit();
        let blk = buf.lookup_guest_pc(0x3000).next().expect("block must be found");
        assert_eq!(blk.guest_pc, 0x3000);
        assert_eq!(blk.len, 4);
        assert!(blk.committed);
    }

    #[test]
    fn at15_uncommitted_block_not_returned_by_lookup() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x4000, &[0xC3u8]).unwrap();
        // not committed
        assert!(buf.lookup_guest_pc(0x4000).next().is_none());
    }

    #[test]
    fn at15_multiple_blocks_lookup() {
        let mut buf = CodeBuf::new(4096);
        for pc in [0x1000u64, 0x2000, 0x3000] {
            buf.alloc_block(pc, &[0x90u8; 2]).unwrap();
        }
        buf.commit();
        assert!(buf.lookup_guest_pc(0x1000).next().is_some());
        assert!(buf.lookup_guest_pc(0x2000).next().is_some());
        assert!(buf.lookup_guest_pc(0x3000).next().is_some());
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    #[test]
    fn at15_invalidate_marks_block_uncommitted() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x5000, &[0x90u8]).unwrap();
        buf.commit();
        assert_eq!(buf.n_committed_blocks(), 1);
        buf.invalidate_guest_pc(0x5000);
        assert_eq!(buf.n_committed_blocks(), 0);
    }

    #[test]
    fn at15_invalidate_increments_generation() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x6000, &[0x90u8]).unwrap();
        buf.commit();
        let gen_before = buf.all_blocks()[0].generation;
        buf.invalidate_guest_pc(0x6000);
        let gen_after = buf.all_blocks()[0].generation;
        assert!(gen_after > gen_before, "generation must increment on invalidation");
    }

    #[test]
    fn at15_invalidate_nonexistent_pc_is_noop() {
        let mut buf = CodeBuf::new(4096);
        let n = buf.invalidate_guest_pc(0xDEAD_BEEF);
        assert_eq!(n, 0);
    }

    #[test]
    fn at15_reinject_after_invalidate_succeeds() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x7000, &[0x90u8]).unwrap();
        buf.commit();
        buf.invalidate_guest_pc(0x7000);
        // Re-emit same PC
        buf.alloc_block(0x7000, &[0xC3u8]).unwrap();
        buf.commit();
        assert!(buf.lookup_guest_pc(0x7000).next().is_some());
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    #[test]
    fn at15_reset_clears_all_state() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x8000, &[0x90u8; 16]).unwrap();
        buf.commit();
        buf.reset();
        assert_eq!(buf.written_len(), 0);
        assert_eq!(buf.n_committed_blocks(), 0);
        assert!(buf.all_blocks().is_empty());
        assert_eq!(buf.protection(), Protection::ReadWrite);
    }

    #[test]
    fn at15_reset_allows_fresh_emit() {
        let mut buf = CodeBuf::new(4096);
        buf.alloc_block(0x1000, &[0x90u8; 4]).unwrap();
        buf.commit();
        buf.reset();
        buf.alloc_block(0x2000, &[0xC3u8]).unwrap();
        buf.commit();
        assert_eq!(buf.written_len(), 1);
        assert_eq!(buf.n_committed_blocks(), 1);
    }

    // ── needs_serialize / dirty invariant ────────────────────────────────────

    #[test]
    fn at15_dirty_after_emit() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        assert!(buf.is_dirty());
    }

    #[test]
    fn at15_not_dirty_after_commit() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        buf.commit();
        assert!(!buf.is_dirty());
    }

    #[test]
    fn at15_executable_after_commit() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        buf.commit();
        assert!(buf.is_executable());
    }

    #[test]
    fn at15_not_executable_when_dirty() {
        let mut buf = CodeBuf::new(4096);
        buf.emit(&[0x90u8]).unwrap();
        assert!(!buf.is_executable());
    }

    // ── Self-modifying code surrogate (AT-15 gate) ────────────────────────────

    /// One SMC cycle via the `smcode_test_iteration` harness.
    #[test]
    fn at15_smc_single_cycle_succeeds() {
        let mut buf = CodeBuf::new(65536);
        smcode_test_iteration(
            &mut buf,
            0xA000,
            &[0x90u8], // NOP v1
            &[0xC3u8], // RET v2
        )
        .expect("single SMC cycle must succeed");
    }

    /// Verify generation increments after SMC cycle.
    #[test]
    fn at15_smc_generation_advances_after_cycle() {
        let mut buf = CodeBuf::new(65536);
        smcode_test_iteration(&mut buf, 0xB000, &[0x90u8], &[0xC3u8])
            .expect("SMC cycle");
        // After cycle buf has been reset + rebuilt; all_blocks has generation=1 for v2 block.
        let max_gen = buf.all_blocks().iter().map(|b| b.generation).max().unwrap_or(0);
        assert!(max_gen >= 1, "generation must be ≥ 1 after one SMC cycle");
    }

    /// 1 000-iteration fast surrogate (runs in normal CI).
    #[test]
    fn at15_smc_1k_iterations_structural_fast() {
        const ITERS: u32 = 1_000;
        let mut buf = CodeBuf::new(4096);
        for _ in 0..ITERS {
            smcode_test_iteration(&mut buf, 0xC000, &[0x90u8], &[0xC3u8])
                .expect("SMC iteration must succeed");
        }
    }

    /// 1 000 000-iteration structural surrogate — marked #[ignore] for normal CI.
    /// Run with `cargo test -- --include-ignored at15_smc_1m` for the full gate.
    #[test]
    #[ignore]
    fn at15_smc_1m_iterations_structural() {
        const ITERS: u32 = 1_000_000;
        let mut buf = CodeBuf::new(4096);
        for i in 0..ITERS {
            smcode_test_iteration(&mut buf, 0xD000, &[0x90u8], &[0xC3u8])
                .unwrap_or_else(|e| panic!("SMC iteration {i} failed: {e}"));
        }
    }

    // ── Byte-exact stored content ─────────────────────────────────────────────

    /// Bytes written must survive through commit unchanged.
    #[test]
    fn at15_xor_rax_rax_ret_survives_commit() {
        let code = [0x48u8, 0x31, 0xC0, 0xC3]; // XOR RAX,RAX; RET
        let mut buf = CodeBuf::new(4096);
        let off = buf.alloc_block(0xE000, &code).unwrap();
        buf.commit();
        assert_eq!(buf.read_bytes(off, 4), &code);
    }

    #[test]
    fn at15_mfence_encoding_survives_commit() {
        let mfence = [0x0Fu8, 0xAE, 0xF0];
        let mut buf = CodeBuf::new(4096);
        let off = buf.alloc_block(0xF000, &mfence).unwrap();
        buf.commit();
        assert_eq!(buf.read_bytes(off, 3), &mfence);
    }
}
