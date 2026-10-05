//! M4b-2: software ARM64 stage-1 MMU page-table walker for the x86 DBT.
//!
//! The real GKI kernel turns on the MMU at `__enable_mmu` (writes
//! `SCTLR_EL1.M = 1`). From that instant every guest load/store/fetch carries a
//! VIRTUAL address that must be translated through the guest's own page tables
//! (`TTBR0_EL1` / `TTBR1_EL1` + `TCR_EL1`) before it can touch physical RAM.
//! On real ARM hardware the CPU's hardware table-walker does this; under the
//! x86 DBT there is no such hardware, so we walk the tables in software.
//!
//! Integration (later sub-milestones): the lowered Load/Store/fetch paths CALL
//! [`aether_mmu_xlate`] to convert a guest VA into a host PA. When the MMU is
//! off (`SCTLR_EL1.M == 0`, early boot) translation is flat (VA == PA). On a
//! fault the walker records a pending Data/Instruction Abort in the free
//! sysreg slots (the [pending-fault ABI](#pending-fault-abi)); the dispatcher
//! injects it via `VBAR_EL1` after the current block returns (M4b-3).
//!
//! GUEST-PA == HOST-PA INVARIANT: in the Android handoff window the guest's
//! physical address space is identity-mapped to host physical memory, so a
//! descriptor's output address (a guest PA) is read directly as a host pointer.
//!
//! This module is `no_std` + no-alloc. It carries localized `#[allow(unsafe_code)]`
//! for the raw PTE reads and the EL2-private TLB (the crate is
//! `#![deny(unsafe_code)]`), mirroring the pattern in `dbt.rs`.

use crate::runtime::context::{CTX_U64S, SYSREG_SLOT0};

// ── Sysreg slot indices ─────────────────────────────────────────────────────
// These MUST match the encoding->slot map in `backend/lower_int.rs`
// (`sysreg_read_disp` / `sysreg_write_disp`). A mismatch means the walker reads
// a different word than `MSR TTBR0_EL1, Xn` wrote.
/// SCTLR_EL1 — bit 0 is the MMU enable (`M`).
pub const SLOT_SCTLR: usize = 0;
/// TTBR0_EL1 — low-VA (bit 55 == 0) translation base.
pub const SLOT_TTBR0: usize = 1;
/// TTBR1_EL1 — high-VA (bit 55 == 1) translation base.
pub const SLOT_TTBR1: usize = 2;
/// TCR_EL1 — translation control (granule / VA size). Read for completeness;
/// 2a assumes the GKI default (4 KiB granule, 48-bit VA, 4-level).
pub const SLOT_TCR: usize = 3;
/// MAIR_EL1 — memory attributes. Not needed to compute the PA in 2a.
pub const SLOT_MAIR: usize = 4;
/// PAR_EL1 — Address Translate result. Phase-E. Written by
/// `aether_mmu_at_s1e1` (runtime AT helper), read by the kernel's
/// `is_spurious_el1_translation_fault`. MUST match the `ParEl1 => 26`
/// arm in `backend/lower_int.rs::sysreg_read_idx`.
pub const SLOT_PAR_EL1: usize = 26;

// ── Pending-fault ABI ───────────────────────────────────────────────────────
// Free sysreg slots 56..62 (40..55 are RO ID regs, 63 is the write sink). The
// dispatcher reads PEND_PENDING after every block; non-zero => inject. LOCKED
// (this is the seam with the M4b-3 exception-injection path).
/// 0 = no fault pending; 1 = Data/Instruction Abort pending.
pub const SLOT_PEND_PENDING: usize = 56;
/// Faulting virtual address -> FAR_EL1 on injection.
pub const SLOT_PEND_FAR: usize = 57;
/// Exception syndrome -> ESR_EL1 on injection.
pub const SLOT_PEND_ESR: usize = 58;

/// `SCTLR_EL1.M` — MMU enable bit.
const SCTLR_M: u64 = 1 << 0;

/// Master compile-time switch for the per-access diagnostic / capture machinery
/// (the store-VALUE watch, PTE-slot watches, vmemmap + eBPF store/load trackers,
/// the deferred-xlate-write read-back, and the post-store read-back verification).
///
/// These were debugging instruments for past blockers. Each runs on EVERY guest
/// load / store / fetch — even when disarmed they cost a static load + compare
/// (and the trackers a function call) per access, which on a multi-hour Android
/// boot (billions of memory accesses) is pure overhead. Gating them behind this
/// `const false` lets the optimizer drop the entire block (dead-code elimination)
/// so the production hot path pays nothing. Flip to `true` (or wire a feature)
/// to re-arm them for a diagnostic boot.
///
/// CORRECTNESS: every gated block is observation-only (writes to EL2-private
/// diagnostic statics, never to guest RAM or the fault ABI), so disabling them
/// is semantics-preserving for the guest. The one exception — the post-store
/// read-back, which the prior code used purely to record a MISMATCH trace entry
/// — likewise has no effect on guest-visible state, so it is gated too.
pub const MMU_DIAG: bool = false;

/// Descriptor / TTBR address field mask: output address bits [47:12].
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Sentinel returned by [`aether_mmu_xlate`] on a fault. Guest RAM in the
/// handoff window starts well above 0 (`GUEST_PA_BASE == 0x1_0000_0000`, the
/// relocated 4 GiB window), so host PA 0 is never a valid translation here and
/// is unambiguous as "faulted". (The PA-window clamp below makes this airtight:
/// an in-window PA is provably never 0.)
pub const XLATE_FAULT: u64 = 0;

// ── Guest physical window (No-Boundary confinement) ──────────────────────────
//
// CRITICAL (AETHER Ch.3 No-Boundary): every table base and output address comes
// from GUEST-CONTROLLED descriptor bits, and the x86 host-mode DBT has no
// stage-2 / NPT backstop on the translated load/store path — so a crafted guest
// page table could otherwise translate to ANY host PA (hypervisor .text, the
// VMCB/HSAVE, the JIT cache) = arbitrary host read/write = total compromise; an
// out-of-identity-map descriptor address would also fault the host (#PF) and
// wedge it. The walker therefore confines EVERY guest PA it touches (table
// bases AND leaf output) to the handoff window; anything outside is reflected
// to the guest as a translation fault, never dereferenced.
//
// RELOCATED guest DRAM. The window was moved off the old <4 GiB region (carved
// from a UEFI AllocatePages span that interleaved firmware holes, capping usable
// RAM at ~562 MiB) to [4 GiB, 8 GiB) — raw `-m 16G` high-RAM, contiguous and
// hole-free (the same class of memory the PMEM images + JIT cache occupy). The
// hypervisor installs four 1-GiB host-CR3 identity leaves for it and copies the
// boot.img up from the low ESP scratch (boot_x86.rs). Mirrors
// `android_handoff::HANDOFF_REGION_SIZE` (4 GiB). Settable so the hypervisor can
// pin the exact mapped span and tests can scope their host-allocated page tables.
/// Default guest-PA window base (4 GiB — relocated; matches `GUEST_PA_BASE`
/// installed in the host CR3 by `boot_x86::host_pt_map_identity_1g`).
pub const GUEST_PA_BASE: u64 = 0x1_0000_0000;
/// Default guest-PA window size (4 GiB == `HANDOFF_REGION_SIZE`, exactly filling
/// [4 GiB, 8 GiB) below the translator JIT cache at 8 GiB).
pub const GUEST_PA_SIZE: u64 = 0x1_0000_0000;

static mut WIN_BASE: u64 = GUEST_PA_BASE;
static mut WIN_SIZE: u64 = GUEST_PA_SIZE;

// Second (optional) guest-PA window. The x86 tier stages the AOSP `system.raw`
// image as a PMEM block device in a FIXED high-RAM region (8 GiB, well above the
// primary handoff window) — a single contiguous window cannot cover both, so a
// disjoint second range is registered here. 0/0 = disabled (the ARM tier and all
// tests leave it off). Same No-Boundary confinement: a fixed, hypervisor-set
// range, never guest-controlled.
static mut WIN2_BASE: u64 = 0;
static mut WIN2_SIZE: u64 = 0;

/// Pin the guest physical window the walker confines all PAs to. Called once by
/// the hypervisor at MMU bring-up with the exact mapped span.
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_set_window(base: u64, size: u64) {
    // SAFETY: EL2-private, single-vCPU; set once before any walk.
    unsafe {
        *core::ptr::addr_of_mut!(WIN_BASE) = base;
        *core::ptr::addr_of_mut!(WIN_SIZE) = size;
    }
}

/// Register a SECOND disjoint guest-PA window (e.g. the PMEM system image at
/// 8 GiB). Pass `(0, 0)` to disable. Mirrors [`aether_mmu_set_window`].
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_set_window2(base: u64, size: u64) {
    // SAFETY: EL2-private, single-vCPU; set once before any walk.
    unsafe {
        *core::ptr::addr_of_mut!(WIN2_BASE) = base;
        *core::ptr::addr_of_mut!(WIN2_SIZE) = size;
    }
}

/// True iff `pa` lies within either configured guest physical window.
#[allow(unsafe_code)]
fn in_window(pa: u64) -> bool {
    // SAFETY: EL2-private, single-vCPU.
    let (base, size, base2, size2) = unsafe {
        (
            *core::ptr::addr_of!(WIN_BASE),
            *core::ptr::addr_of!(WIN_SIZE),
            *core::ptr::addr_of!(WIN2_BASE),
            *core::ptr::addr_of!(WIN2_SIZE),
        )
    };
    if pa >= base && pa.wrapping_sub(base) < size {
        return true;
    }
    size2 != 0 && pa >= base2 && pa.wrapping_sub(base2) < size2
}

// ── MMIO device-window allow-list (M4b-5) ────────────────────────────────────
//
// The guest GKI kernel talks to a handful of memory-mapped devices that are NOT
// backing RAM: the PL011 UART, the GICv3 distributor/redistributor, and the
// virtio-mmio transport. Their physical addresses sit OUTSIDE the guest RAM
// window, so the stage-1 walk (or a flat early-boot access) would otherwise
// reflect them as translation faults and the kernel would die at its first
// `writel` to the console. Instead, an access whose final PA lands in one of
// these fixed ranges is routed to a host-registered MMIO handler
// ([`aether_set_mmio_handler`]) that emulates the device.
//
// No-Boundary (Ch.3) still holds: this is a FIXED allow-list, never a
// guest-controlled escape. The handler decides what each register does; the
// guest can no more reach host RAM through it than through a real MMIO bus.
// Bases/sizes mirror `hypervisor::mmio_emu` (PL011 / GICD / GICR / virtio).
struct MmioRange {
    base: u64,
    size: u64,
}
const MMIO_RANGES: [MmioRange; 4] = [
    MmioRange { base: 0x0900_0000, size: 0x0000_1000 }, // PL011 UART
    MmioRange { base: 0x0800_0000, size: 0x0001_0000 }, // GICv3 GICD
    MmioRange { base: 0x080A_0000, size: 0x00F6_0000 }, // GICv3 GICR
    MmioRange { base: 0x0A00_0000, size: 0x0000_1000 }, // virtio-mmio
];

/// True iff `pa` is in a known emulated-device MMIO window.
fn is_mmio(pa: u64) -> bool {
    let mut i = 0;
    while i < MMIO_RANGES.len() {
        let r = &MMIO_RANGES[i];
        if pa >= r.base && pa.wrapping_sub(r.base) < r.size {
            return true;
        }
        i += 1;
    }
    false
}

/// Free sysreg slot used to stage an MMIO READ value so the existing
/// `mov rd, [rax]` load deref can pick it up without changing the load-lowering
/// ABI: for an MMIO load, [`aether_mmu_xlate`] performs the emulated read, parks
/// the value here, and returns this slot's host address as the "PA". Single
/// loads are ≤ 8 bytes so one u64 suffices; slot 60 (the next free slot) is a
/// valid in-bounds ctx slot, so the never-real "LDP from MMIO" edge reads an
/// adjacent free ctx word rather than out-of-bounds memory.
pub const SLOT_MMIO_SCRATCH: usize = 59;

/// 16-byte (slots 60–61) gather/scatter bounce buffer for a CROSS-PAGE access
/// whose two guest pages map to PHYSICALLY NON-CONTIGUOUS host PAs. A single
/// host load/store at one PA cannot serve such a span, but the kernel HAS mapped
/// both pages (demand-paged anon pages are rarely PA-adjacent), so faulting just
/// loops forever — `do_page_fault` sees both pages present and does nothing, the
/// guest re-executes the same straddling LDP/STP/LDR-Q and re-faults. Instead:
/// a LOAD gathers both pages' bytes here and returns this slot's host address
/// (the caller's `mov rd,[rax]` / `movdqu` reads the contiguous copy); a STORE
/// returns this address for the caller to write into, then [`flush_scatter`]
/// (run at the top of every xlate/store/fetch entry) scatters the bytes back to
/// the two real pages before any subsequent guest access can observe them.
/// 16 bytes covers LDP/STP (X-pair) and LDR/STR-Q — the memcpy/string hot path.
pub const SLOT_SPAN_SCRATCH: usize = 60;
/// Largest cross-page span served by the bounce buffer (bytes). Wider spans
/// (LDP-Q = 32 B, LD4 = 64 B) crossing a NON-contiguous boundary stay loud
/// (pending Data Abort) until the scratch is widened — they are vanishingly rare
/// versus 16-byte bulk copies.
const SPAN_SCRATCH_MAX: u64 = 16;

// ── Deferred cross-page STORE scatter ────────────────────────────────────────
// A store routed through `aether_mmu_xlate` (STP, STR-Q/D/S) returns a host PA
// the caller writes through; when that PA is the bounce buffer (non-contiguous
// cross-page span) the written bytes must be scattered back to the two real
// pages. There is no post-write callback, so the scatter is DEFERRED and flushed
// lazily at the head of the next xlate/store/fetch — every guest RAM access (and
// the dispatcher's next-block fetch) funnels through one of those, and nothing
// else reads guest RAM, so the bytes always land before they can be observed.
// EL2-private, single-vCPU: plain statics (the software TLB uses the same model).
static mut SCATTER_PENDING: bool = false;
static mut SCATTER_SRC: *const u8 = core::ptr::null(); // bounce-buffer host addr
static mut SCATTER_PA1: u64 = 0; // page-1 host PA (first `n1` bytes)
static mut SCATTER_N1: u64 = 0;
static mut SCATTER_PA2: u64 = 0; // page-2 host PA base (next `n2` bytes)
static mut SCATTER_N2: u64 = 0;
// Diagnostic balance counters: a deferred store-scatter that is SET but never
// FLUSHED would leave the cross-page bytes unwritten (e.g. a prologue STP's
// saved x30 stays as the fresh-page zero → RET to NULL). SET and FLUSH should
// stay within 1 of each other (at most one pending at a time).
pub static mut SCATTER_SET_COUNT: u64 = 0;
pub static mut SCATTER_FLUSH_COUNT: u64 = 0;

/// Flush a pending cross-page STORE scatter (no-op when none pending). Copies the
/// bytes the caller wrote into the bounce buffer back out to the two real guest
/// pages. Called at the head of every guest-RAM entry point so the scatter is
/// always materialised before any later access (or block fetch) can read it.
#[allow(unsafe_code)]
fn flush_scatter() {
    // SAFETY: EL2-private single-vCPU statics; the recorded PAs were confined to
    // the guest window by `xlate_page` when the scatter was queued, and the src
    // is the in-ctx bounce buffer. Cleared FIRST so a re-entrant entry can't
    // double-apply.
    unsafe {
        if !*core::ptr::addr_of!(SCATTER_PENDING) {
            return;
        }
        *core::ptr::addr_of_mut!(SCATTER_PENDING) = false;
        *core::ptr::addr_of_mut!(SCATTER_FLUSH_COUNT) =
            (*core::ptr::addr_of!(SCATTER_FLUSH_COUNT)).wrapping_add(1);
        let src = *core::ptr::addr_of!(SCATTER_SRC);
        let pa1 = *core::ptr::addr_of!(SCATTER_PA1);
        let n1 = *core::ptr::addr_of!(SCATTER_N1);
        let pa2 = *core::ptr::addr_of!(SCATTER_PA2);
        let n2 = *core::ptr::addr_of!(SCATTER_N2);
        // [wstore] catch a scatter whose range overwrites the watched PTE slot
        // (this is a non-aether_mmu_store write path that the PTE watch misses).
        let wpa = *core::ptr::addr_of!(WATCH_PA);
        if wpa != 0
            && ((wpa >= pa1 && wpa < pa1 + n1) || (wpa >= pa2 && wpa < pa2 + n2))
        {
            *core::ptr::addr_of_mut!(WATCH_SCATTER_HITS) =
                (*core::ptr::addr_of!(WATCH_SCATTER_HITS)).saturating_add(1);
        }
        core::ptr::copy_nonoverlapping(src, pa1 as *mut u8, n1 as usize);
        core::ptr::copy_nonoverlapping(src.add(n1 as usize), pa2 as *mut u8, n2 as usize);
    }
}

/// Non-zero "ok" sentinel returned by [`aether_mmu_store`] on success (0 ==
/// [`XLATE_FAULT`] keeps the lowered fault-check `test rax,rax; jz fault` valid).
const MMIO_STORE_OK: u64 = 1;

// ── Phase-E vmemmap store/load tracer ─────────────────────────────────────────
// When the hypervisor arms a (lo, hi) VA range, every store AND load that
// resolves into that range gets a (va, pa, value, size, kind) entry in a
// circular buffer. The hypervisor reads this on first BRK to cross-reference
// the store PA with the load PA at the failing PTE slot. `kind` = 0 for load,
// 1 for store. `value` is the actual u64 written (stores) or zero (loads —
// the load primitive doesn't return value; the trace just records that the
// xlate happened so PA can be compared with the corresponding store).
pub const VMM_TRACE_CAP: usize = 1024;
pub static mut VMM_TRACE_LO: u64 = 0;
pub static mut VMM_TRACE_HI: u64 = 0;
pub static mut VMM_TRACE_VA: [u64; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
pub static mut VMM_TRACE_PA: [u64; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
pub static mut VMM_TRACE_VAL: [u64; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
pub static mut VMM_TRACE_SIZE: [u8; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
pub static mut VMM_TRACE_KIND: [u8; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
/// Phase-E: guest PC of the basic-block whose code most recently ran
/// (and therefore is currently executing the traced store/load). The
/// backend emits a `mov [LAST_GUEST_PC], imm64` at every block entry,
/// so each trace entry can be attributed to the ARM64 block containing
/// the offending instruction. A single block may emit multiple stores;
/// combined with the VA in the same entry, the source-level write site
/// is uniquely identified.
pub static mut LAST_GUEST_PC: u64 = 0;

/// Per-INSTRUCTION PC stamp (set by the `StampFaultPc` op the lifter emits before
/// every instruction). Unlike LAST_GUEST_PC (per-block, skipped for chained
/// blocks), this is the EXACT instruction executing — so a memory fault records
/// the precise faulting instruction's PC.
pub static mut FAULT_OP_PC: u64 = 0;

/// Store-VALUE watch: boot_x86 sets `SV_WATCH` to the corrupted code pointer
/// (init's bad resume PC, 0x7ce8274c08, masked low 56 bits). When any STORE
/// writes that value, record a ring of (FAULT_OP_PC, store-addr, value, x30) —
/// the instruction that wrote the bad pointer + how it was formed.
pub static mut SV_WATCH: u64 = 0;
pub static mut SV_WATCH_HITS: u64 = 0;
pub static mut SV_WATCH_IDX: u64 = 0;
pub static mut SV_WATCH_PC: [u64; 8] = [0; 8];
pub static mut SV_WATCH_ADDR: [u64; 8] = [0; 8];
pub static mut SV_WATCH_VAL: [u64; 8] = [0; 8];
pub static mut SV_WATCH_X30: [u64; 8] = [0; 8];

pub static mut VMM_TRACE_PC: [u64; VMM_TRACE_CAP] = [0; VMM_TRACE_CAP];
/// Monotonic counter — `(idx % CAP)` is the next slot. Lets the dumper
/// distinguish "ring wrapped" from "ring not full" and walk oldest-first.
pub static mut VMM_TRACE_IDX: u64 = 0;

// ── Phase-G eBPF buffer store tracker ──────────────────────────────────────
// When `EBPF_STORE_LO <= va < EBPF_STORE_HI`, every guest STR is logged into
// a parallel ring of (pc, va, size, value). Arm the range at runtime from
// the hypervisor (boot_x86.rs) once we know where convert_bpf_filter's
// output buffer lands; dump the ring when bpf_jit hits "unknown opcode" so
// we can pinpoint which exact guest PC stored zero (or nothing) at insn[20].
pub const EBPF_STORE_CAP: usize = 8192;
pub static mut EBPF_STORE_LO: u64 = 0;
pub static mut EBPF_STORE_HI: u64 = 0;
// Phase-G PASS-2 diagnostic: a SECOND VA range so the same ring can
// simultaneously capture stores to the kernel's bpf_convert_filter stack
// scratch buffer AND stores to the eBPF output buffer. Armed at runtime
// from the memcpy hook in boot_x86.rs once we know the stack src VA.
pub static mut EBPF_STORE_LO2: u64 = 0;
pub static mut EBPF_STORE_HI2: u64 = 0;
pub static mut EBPF_STORE_IDX: u64 = 0;
/// When non-zero, ebpf_store_record only logs stores whose value is
/// STRICTLY LESS than this threshold. Used to filter out legitimate
/// high-VA-valued writes (e.g. saved x30 = 0xffffffc0...) when hunting
/// for a lifter bug that writes a small/garbage value to a stack slot.
/// Default 0 disables the filter (matches all values).
pub static mut EBPF_STORE_VAL_MAX: u64 = 0;
pub static mut EBPF_STORE_PC:   [u64; EBPF_STORE_CAP] = [0; EBPF_STORE_CAP];
pub static mut EBPF_STORE_VA:   [u64; EBPF_STORE_CAP] = [0; EBPF_STORE_CAP];
pub static mut EBPF_STORE_VAL:  [u64; EBPF_STORE_CAP] = [0; EBPF_STORE_CAP];
pub static mut EBPF_STORE_SIZE: [u8;  EBPF_STORE_CAP] = [0; EBPF_STORE_CAP];
/// Monotonic event counter logged with each entry — lets the dumper
/// determine temporal order even across ring wraps.
pub static mut EBPF_STORE_SEQ: [u64; EBPF_STORE_CAP] = [0; EBPF_STORE_CAP];

/// Arm the eBPF store tracker over `[lo, hi)` by VA. Resets the ring AND
/// clears the second VA range.
#[allow(unsafe_code)]
pub extern "C" fn aether_arm_ebpf_store_trace(lo: u64, hi: u64) {
    unsafe {
        *core::ptr::addr_of_mut!(EBPF_STORE_LO) = lo;
        *core::ptr::addr_of_mut!(EBPF_STORE_HI) = hi;
        *core::ptr::addr_of_mut!(EBPF_STORE_LO2) = 0;
        *core::ptr::addr_of_mut!(EBPF_STORE_HI2) = 0;
        *core::ptr::addr_of_mut!(EBPF_STORE_IDX) = 0;
    }
}

/// Arm a SECOND VA range `[lo, hi)` for the eBPF store tracker WITHOUT
/// resetting the ring. Used to add a stack window mid-flight so the
/// existing entries (and ongoing capture of the primary range) are
/// preserved. Pass `(0, 0)` to disable the second range.
#[allow(unsafe_code)]
pub extern "C" fn aether_arm_ebpf_store_trace_range2(lo: u64, hi: u64) {
    unsafe {
        *core::ptr::addr_of_mut!(EBPF_STORE_LO2) = lo;
        *core::ptr::addr_of_mut!(EBPF_STORE_HI2) = hi;
    }
}

/// Freeze the tracker without resetting the ring — used when bpf_jit hits
/// "unknown opcode" so subsequent boot activity doesn't overwrite the
/// convert_bpf_filter traces. Clears both VA ranges.
#[allow(unsafe_code)]
pub extern "C" fn aether_freeze_ebpf_store_trace() {
    unsafe {
        *core::ptr::addr_of_mut!(EBPF_STORE_LO) = 0;
        *core::ptr::addr_of_mut!(EBPF_STORE_HI) = 0;
        *core::ptr::addr_of_mut!(EBPF_STORE_LO2) = 0;
        *core::ptr::addr_of_mut!(EBPF_STORE_HI2) = 0;
        // IDX preserved so dumper sees existing entries.
    }
}

#[inline]
#[allow(unsafe_code)]
fn ebpf_store_record(va: u64, value: u64, size: u8) {
    // SAFETY: EL2-private statics; single-vCPU; tracker arming is one-shot
    // and the ring is plain POD. Mirrors the vmm_trace_record pattern above.
    unsafe {
        let lo = *core::ptr::addr_of!(EBPF_STORE_LO);
        let hi = *core::ptr::addr_of!(EBPF_STORE_HI);
        let lo2 = *core::ptr::addr_of!(EBPF_STORE_LO2);
        let hi2 = *core::ptr::addr_of!(EBPF_STORE_HI2);
        let in_primary = lo != 0 && va >= lo && va < hi;
        let in_second  = lo2 != 0 && va >= lo2 && va < hi2;
        if !in_primary && !in_second { return; }
        // Value filter: when EBPF_STORE_VAL_MAX > 0, only record stores
        // strictly below that threshold. Lets us hunt for the buggy STR
        // that writes a tiny value (e.g. 0x42) to a stack slot without
        // overflowing the ring with legitimate high-VA writes.
        let vmax = *core::ptr::addr_of!(EBPF_STORE_VAL_MAX);
        if vmax != 0 && value >= vmax { return; }
        // Also filter out the xlate-only sentinel value 0xFFFF_FFFF_FFFF_FFFF
        // (with size flag 0x80) emitted from aether_mmu_xlate when value
        // is unknown -- those are duplicates of the real stores logged
        // here, and they pollute the ring under the value filter.
        if vmax != 0 && (size & 0x80) != 0 { return; }
        let idx = *core::ptr::addr_of!(EBPF_STORE_IDX);
        let i = (idx as usize) % EBPF_STORE_CAP;
        *core::ptr::addr_of_mut!(EBPF_STORE_IDX) = idx.wrapping_add(1);
        *core::ptr::addr_of_mut!(EBPF_STORE_PC[i])   = *core::ptr::addr_of!(LAST_GUEST_PC);
        *core::ptr::addr_of_mut!(EBPF_STORE_VA[i])   = va;
        *core::ptr::addr_of_mut!(EBPF_STORE_VAL[i])  = value;
        *core::ptr::addr_of_mut!(EBPF_STORE_SIZE[i]) = size;
        *core::ptr::addr_of_mut!(EBPF_STORE_SEQ[i])  = idx;
    }
}

/// Set the value-filter threshold for ebpf_store_record. When set to a
/// non-zero value, only stores whose written value is < threshold are
/// recorded. Pass 0 to disable the filter.
#[allow(unsafe_code)]
pub extern "C" fn aether_arm_ebpf_store_value_max(max: u64) {
    unsafe {
        *core::ptr::addr_of_mut!(EBPF_STORE_VAL_MAX) = max;
    }
}

/// True if `va` falls in either armed eBPF-tracker VA range. Cheap guard so
/// the LOAD path only peeks host memory for in-window accesses (and pays
/// nothing when the tracker is disarmed, i.e. `EBPF_STORE_LO == 0`).
#[inline]
#[allow(unsafe_code)]
fn ebpf_in_window(va: u64) -> bool {
    unsafe {
        let lo = *core::ptr::addr_of!(EBPF_STORE_LO);
        let hi = *core::ptr::addr_of!(EBPF_STORE_HI);
        let lo2 = *core::ptr::addr_of!(EBPF_STORE_LO2);
        let hi2 = *core::ptr::addr_of!(EBPF_STORE_HI2);
        (lo != 0 && va >= lo && va < hi) || (lo2 != 0 && va >= lo2 && va < hi2)
    }
}

/// Phase-G x30-hunt LOAD recorder. Single-`STR` stores are captured by
/// `aether_mmu_store` (real value) and PAIR/wide stores leave a sentinel
/// entry (value unknown, size flag 0x80) on the is_write xlate path — but the
/// LOAD side (the epilogue `ldp x29,x30,[sp,#N]` that reads a saved x30) was
/// never recorded. This peeks the *physical* value the access is about to
/// read and logs it with the LOAD flag (size | 0x40), one entry per ≤8-byte
/// chunk so a pair load surfaces BOTH the x29 slot (chunk 0) and the x30 slot
/// (chunk 1) by VA. Comparing the recorded slot value here against the
/// resulting GPR at the fault tells load-side (slot ok, reg wrong) from
/// store-side (slot itself holds the garbage) corruption.
///
/// `pa` is the resolved, in-window, RAM (non-MMIO) host PA of the first byte;
/// the caller has already proven the whole `size`-byte span is mapped and
/// physically contiguous, so `pa + off` is valid host RAM for `off < size`.
#[inline]
#[allow(unsafe_code)]
fn ebpf_load_record(va: u64, pa: u64, size: u64) {
    // Fast out when disarmed or the access misses both ranges entirely. The
    // span is contiguous, so if neither endpoint is in-window we still test
    // each chunk below (a window narrower than the access could sit inside).
    if !ebpf_in_window(va) && !ebpf_in_window(va.wrapping_add(size.saturating_sub(1))) {
        return;
    }
    let mut off: u64 = 0;
    while off < size {
        let cva = va.wrapping_add(off);
        let cpa = pa.wrapping_add(off);
        let rem = (size - off).min(8);
        if ebpf_in_window(cva) {
            // SAFETY: cpa is within the validated, contiguous host-RAM span.
            let val = unsafe {
                match rem {
                    1 => core::ptr::read_volatile(cpa as *const u8) as u64,
                    2 => core::ptr::read_volatile(cpa as *const u16) as u64,
                    4 => core::ptr::read_volatile(cpa as *const u32) as u64,
                    _ => core::ptr::read_volatile(cpa as *const u64),
                }
            };
            // Flag 0x40 = LOAD; low bits carry the chunk byte width.
            ebpf_store_record(cva, val, (rem as u8) | 0x40);
        }
        off += 8;
    }
}

/// Arm the vmemmap tracer over `[lo, hi)` BY VA. Pass `(0, 0)` to disable.
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_arm_vmm_trace(lo: u64, hi: u64) {
    // SAFETY: EL2-private, single-vCPU; set once at boot.
    unsafe {
        *core::ptr::addr_of_mut!(VMM_TRACE_LO) = lo;
        *core::ptr::addr_of_mut!(VMM_TRACE_HI) = hi;
        *core::ptr::addr_of_mut!(VMM_TRACE_IDX) = 0;
    }
}

/// PA-based trace range. When non-zero, ANY store/load whose RESOLVED PA
/// is in `[VMM_TRACE_PA_LO, VMM_TRACE_PA_HI)` is recorded, regardless of
/// the VA the kernel used to reach it. Catches "different VA aliases
/// hitting the same PA" patterns that VA-only tracing misses.
pub static mut VMM_TRACE_PA_LO: u64 = 0;
pub static mut VMM_TRACE_PA_HI: u64 = 0;

#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_arm_vmm_pa_trace(lo: u64, hi: u64) {
    // SAFETY: EL2-private, single-vCPU; set once at boot.
    unsafe {
        *core::ptr::addr_of_mut!(VMM_TRACE_PA_LO) = lo;
        *core::ptr::addr_of_mut!(VMM_TRACE_PA_HI) = hi;
    }
}

/// Phase-E: `AT S1E1R/W` and `AT S1E0R/W` runtime — Address Translate
/// Stage 1 at EL1 / EL0 for read or write. The kernel uses this in
/// `is_spurious_el1_translation_fault` (and various other places) to
/// "probe" whether a VA would translate cleanly. Without this, PAR_EL1
/// always reads 0 → kernel thinks every fault is spurious → ERETs back
/// → re-faults → infinite loop.
///
/// Behaviour (per ARM ARM D8.12 PAR_EL1):
///   - Success: PAR.F = 0, bits[51:12] = PA, attrs in upper bits.
///   - Fault: PAR.F = 1, FST = encoded fault status, PTW/S/NS as
///     appropriate. We pack a minimal Translation fault encoding
///     (FST = 0b000111 = translation at level 3) for any walk failure;
///     the kernel only reads F to make the spurious-vs-real decision.
///
/// `is_write` selects the access type for AP[2] permission checks.
/// `at_el0` selects the EL0 regime (uses PAN — but we ignore PAN for
/// simplicity; the kernel handles the few cases that matter).
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_at_s1e1(
    ctx: *mut u64,
    va: u64,
    is_write: u32,
    _at_el0: u32,
) {
    // SAFETY: caller contract — `ctx` is the register-file base.
    let sysregs = unsafe { core::slice::from_raw_parts(ctx, CTX_U64S) };
    let par: u64 = match xlate_page(sysregs, va, is_write != 0) {
        Ok(pa) => {
            // PAR.F = 0 (success). Bits [51:12] = PA bits, page-aligned.
            // Bits [10:9] = SH (inner shareable), [7] = NS, [11] = NSE,
            // bits[63:56] = MAIR attrs. We set NS=0 (secure) and SH=3
            // (inner shareable, matches our walker default) and MAIR=
            // 0xFF (Normal WB cacheable — the common case for kernel
            // RAM accesses). The kernel only checks F for spurious; the
            // attr bits are correct enough for read-back.
            let pa_field = pa & 0x000F_FFFF_FFFF_F000;
            let sh = 3u64 << 9;
            let mair = 0xFFu64 << 56;
            pa_field | sh | mair
        }
        Err(_) => {
            // PAR.F = 1. FST = 0b000111 (translation fault, level 3).
            // Bit 0 = F (=1), bits [6:1] = FST. We don't bother with
            // the PTW (page table walk) or S2 bits.
            let f = 1u64;
            let fst = 0b000111u64 << 1;
            f | fst
        }
    };
    // Write into PAR_EL1's storage slot. PAR_EL1 lives at sysreg slot
    // SLOT_PAR_EL1 in the context. Find that slot.
    unsafe {
        *ctx.add(SYSREG_SLOT0 + SLOT_PAR_EL1) = par;
        // Bookkeeping counter for diag.
        let c = core::ptr::addr_of_mut!(MMU_AT_HITS);
        *c = (*c).saturating_add(1);
    }
}

/// Count of AT S1E1 instructions our runtime serviced. The kernel
/// issues these aggressively in is_spurious_el1_translation_fault; a
/// non-zero value here confirms the lifter is routing AT correctly.
pub static mut MMU_AT_HITS: u64 = 0;

#[allow(unsafe_code)]
/// [dcache-hunt] Force a record into the VMM trace ring, bypassing the VA/PA
/// range gate. Used by the UTF-16-store-pattern trap to catch the mistranslated
/// store that corrupts a dentry pointer (the __d_lookup_rcu Oops, new GCC kernel).
#[allow(unsafe_code)]
fn force_vmm_record(va: u64, pa: u64, value: u64, size: u8, kind: u8) {
    unsafe {
        let i = (*core::ptr::addr_of!(VMM_TRACE_IDX) as usize) % VMM_TRACE_CAP;
        *core::ptr::addr_of_mut!(VMM_TRACE_VA[i]) = va;
        *core::ptr::addr_of_mut!(VMM_TRACE_PA[i]) = pa;
        *core::ptr::addr_of_mut!(VMM_TRACE_VAL[i]) = value;
        *core::ptr::addr_of_mut!(VMM_TRACE_SIZE[i]) = size;
        *core::ptr::addr_of_mut!(VMM_TRACE_KIND[i]) = kind;
        *core::ptr::addr_of_mut!(VMM_TRACE_PC[i]) = *core::ptr::addr_of!(LAST_GUEST_PC);
        let cur = *core::ptr::addr_of!(VMM_TRACE_IDX);
        *core::ptr::addr_of_mut!(VMM_TRACE_IDX) = cur.wrapping_add(1);
    }
}

/// [dcache-hunt] True for the UTF-16-interleaved-null corruption pattern: an
/// 8-byte value whose every 16-bit lane has a zero low byte and an ASCII high
/// byte (e.g. 0x6400650069006600 = "fied"). Rare enough that the 1024-slot ring
/// won't overflow before the Oops.
/// [dcache-hunt] FP/vector-store trap. The Vec128/F64/F32 store lowering writes
/// inline (movdqu/movsd) and BYPASSES aether_mmu_store, so the integer trap can't
/// see it. The lowering calls this with the store's host PA and the low 64 bits of
/// the value; if it matches the UTF-16 corruption pattern, record PC+PA+value.
pub extern "C" fn aether_fpstore_trace(pa: u64, low64: u64) {
    if is_utf16_store_pattern(low64, 8) {
        force_vmm_record(pa, pa, low64, 8, 9);
    }
}

#[inline]
fn is_utf16_store_pattern(value: u64, size: u64) -> bool {
    if size != 8 || value == 0 {
        return false;
    }
    // Leftover UTF-16 string data in a pointer slot, EITHER alignment:
    //   chars in HIGH bytes (0x6400650069006600 "fied"): low bytes all 0
    //   chars in LOW bytes  (0x007300660066004e "Nffs"): high bytes all 0
    // Require ≥3 of the 4 char bytes printable ASCII (rejects page-ish values).
    let count_ascii = |shift: u32| {
        (0..4)
            .filter(|i| {
                let b = (value >> (8 * (2 * i) + shift)) & 0xFF;
                (0x20..0x7f).contains(&b)
            })
            .count()
    };
    let high_chars = value & 0x00FF_00FF_00FF_00FF == 0 && count_ascii(8) >= 3;
    let low_chars = value & 0xFF00_FF00_FF00_FF00 == 0 && count_ascii(0) >= 3;
    high_chars || low_chars
}

#[allow(unsafe_code)]
fn vmm_trace_record(va: u64, pa: u64, value: u64, size: u8, kind: u8) {
    // SAFETY: EL2-private, single-vCPU; bounded indexing into a fixed array.
    unsafe {
        let va_lo = *core::ptr::addr_of!(VMM_TRACE_LO);
        let va_hi = *core::ptr::addr_of!(VMM_TRACE_HI);
        let pa_lo = *core::ptr::addr_of!(VMM_TRACE_PA_LO);
        let pa_hi = *core::ptr::addr_of!(VMM_TRACE_PA_HI);
        let va_hit = (va_lo != 0 || va_hi != 0) && va >= va_lo && va < va_hi;
        let pa_hit = (pa_lo != 0 || pa_hi != 0) && pa >= pa_lo && pa < pa_hi;
        if !va_hit && !pa_hit { return; }
        let i = (*core::ptr::addr_of!(VMM_TRACE_IDX) as usize) % VMM_TRACE_CAP;
        *core::ptr::addr_of_mut!(VMM_TRACE_VA[i]) = va;
        *core::ptr::addr_of_mut!(VMM_TRACE_PA[i]) = pa;
        *core::ptr::addr_of_mut!(VMM_TRACE_VAL[i]) = value;
        *core::ptr::addr_of_mut!(VMM_TRACE_SIZE[i]) = size;
        *core::ptr::addr_of_mut!(VMM_TRACE_KIND[i]) = kind;
        *core::ptr::addr_of_mut!(VMM_TRACE_PC[i]) =
            *core::ptr::addr_of!(LAST_GUEST_PC);
        let cur = *core::ptr::addr_of!(VMM_TRACE_IDX);
        *core::ptr::addr_of_mut!(VMM_TRACE_IDX) = cur.wrapping_add(1);
    }
}

/// Signature of the host MMIO emulation callback the hypervisor registers.
/// `is_write != 0` ⇒ write `value` (return ignored); otherwise read and return
/// the value (zero-extended into the u64).
pub type AetherMmioHandler =
    unsafe extern "C" fn(addr: u64, size: u32, is_write: u32, value: u64) -> u64;

static mut MMIO_HANDLER: Option<AetherMmioHandler> = None;

/// Register the host MMIO emulation callback. The hypervisor calls this once at
/// boot (before the dispatch loop) with a bridge to its `mmio_emu`. When unset
/// (host-test default) MMIO reads return 0 and writes are dropped.
#[allow(unsafe_code)]
pub extern "C" fn aether_set_mmio_handler(handler: AetherMmioHandler) {
    // SAFETY: EL2-private, single-vCPU; set once at boot before any walk runs.
    unsafe {
        *core::ptr::addr_of_mut!(MMIO_HANDLER) = Some(handler);
    }
}

/// Dispatch one MMIO access to the registered handler (no-op default if unset).
#[allow(unsafe_code)]
fn mmio_dispatch(addr: u64, size: u64, is_write: bool, value: u64) -> u64 {
    // SAFETY: EL2-private, single-vCPU; MMIO_HANDLER is a plain fn pointer.
    let h = unsafe { *core::ptr::addr_of!(MMIO_HANDLER) };
    match h {
        Some(f) => unsafe { f(addr, size as u32, u32::from(is_write), value) },
        None => 0,
    }
}

/// `TCR_EL1.TBI0` — top-byte-ignore for the TTBR0 (low-VA) regime (bit 37).
const TCR_TBI0: u64 = 1 << 37;
/// `TCR_EL1.TBI1` — top-byte-ignore for the TTBR1 (high-VA) regime (bit 38).
const TCR_TBI1: u64 = 1 << 38;

/// Normalise a guest VA to its architectural translation form under Top-Byte-
/// Ignore (TBI). ARM64 TBI (`TCR_EL1.TBI0`/`TBI1`) makes the CPU IGNORE bits
/// [63:56] of a VA for translation, so a tagged pointer (e.g. Scudo's `0xb4..`
/// heap tags) and its untagged form MUST resolve to the SAME page. Android runs
/// with TBI0=1 (userspace MTE/Scudo tagging); the kernel commonly sets TBI1 too.
///
/// On real hardware the hardware table-walker strips the tag transparently and
/// FAR_EL1 reports the *tagged* address back. Our software walker and software
/// TLB key off the raw VA, so without this a tagged access and its untagged twin
/// land in different TLB slots and may diverge on permission/translation — the
/// intermittent tagged-pointer `SEGV_ACCERR` signature. We therefore strip the
/// tag here for translation AND for the TLB key. (FAR for injection is masked at
/// the same point in `aether_mmu_xlate` so the kernel's own un-tag matches.)
///
/// Bit 55 — the TTBR0/TTBR1 selector — is PRESERVED (only [63:56] are cleared),
/// so regime selection downstream is unaffected. When the relevant TBI bit is 0
/// the VA is returned unchanged (architectural top-byte is significant then).
#[inline]
fn tbi_mask_va(sysregs: &[u64], va: u64) -> u64 {
    let tcr = sysregs[SYSREG_SLOT0 + SLOT_TCR];
    let va_high = (va >> 55) & 1 == 1;
    let tbi = if va_high { tcr & TCR_TBI1 != 0 } else { tcr & TCR_TBI0 != 0 };
    if tbi {
        // Clear bits [63:56]; keep bit 55 (regime selector) and [54:0] intact.
        va & 0x00FF_FFFF_FFFF_FFFF
    } else {
        va
    }
}

/// Derive the stage-1 start level from `TCR_EL1` for the selected regime.
///
/// Returns `None` for a non-4 KiB granule (unsupported in 2a — reject loudly).
/// For 4 KiB granule, the start level follows the input VA size
/// `64 - TxSZ` (ARM ARM D5, 4 KiB granule start-level table): TxSZ ≤ 24 →
/// 48..40-bit VA → start L0 (4-level); 25..33 → 39..31-bit → start L1 (3-level,
/// the Android GKI `CONFIG_ARM64_VA_BITS_39` default); 34..42 → L2; else L3.
/// `TG1`'s encoding differs from `TG0` (TG1: 0b10 = 4 KiB; TG0: 0b00 = 4 KiB).
fn regime_start_level(tcr: u64, va_high: bool) -> Option<u8> {
    let (txsz, granule_4k) = if va_high {
        ((tcr >> 16) & 0x3F, ((tcr >> 30) & 0b11) == 0b10) // T1SZ, TG1
    } else {
        (tcr & 0x3F, ((tcr >> 14) & 0b11) == 0b00) // T0SZ, TG0
    };
    if !granule_4k {
        return None;
    }
    Some(if txsz <= 24 {
        0
    } else if txsz <= 33 {
        1
    } else if txsz <= 42 {
        2
    } else {
        3
    })
}

// ── Fault classification ────────────────────────────────────────────────────

/// Stage-1 translation fault kind (maps to an ESR DFSC code).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// Descriptor invalid (bit 0 clear, or a reserved level-3 block).
    Translation,
    /// Access flag (bit 10) clear on the leaf.
    AccessFlag,
    /// Write to a read-only (`AP[2]` set) leaf.
    Permission,
}

/// Build a Data Abort `ESR_EL1` for a same-EL (EL1->EL1) fault.
///
/// EC = 0b100101 (Data Abort, current EL), IL = 1 (32-bit instruction),
/// WnR = bit 6 (1 = write), DFSC[5:0] = fault class + level.
pub fn data_abort_esr(kind: FaultKind, level: u8, is_write: bool) -> u64 {
    let dfsc: u64 = match kind {
        FaultKind::Translation => 0b00_0100, // 0b0001_LL
        FaultKind::AccessFlag => 0b00_1000,  // 0b0010_LL
        FaultKind::Permission => 0b00_1100,  // 0b0011_LL
    } | (level as u64 & 0b11);
    let ec: u64 = 0x25; // Data Abort taken from the same EL
    let il: u64 = 1;
    let wnr: u64 = if is_write { 1 } else { 0 };
    (ec << 26) | (il << 25) | (wnr << 6) | dfsc
}

/// Build an Instruction Abort `ESR_EL1` for a same-EL (EL1->EL1) fetch fault.
///
/// EC = 0b100001 (0x21, Instruction Abort taken from the same EL), IL = 1
/// (32-bit instruction), IFSC[5:0] = fault class + level. An instruction abort
/// has NO WnR bit (it is never a write) and reuses the same fault-class/level
/// status codes as a data abort. This is the fetch-path counterpart to
/// [`data_abort_esr`]: the data path records EC=0x25, the fetch path EC=0x21,
/// so M4b-3 routes each to the correct exception vector with the right syndrome.
pub fn inst_abort_esr(kind: FaultKind, level: u8) -> u64 {
    let ifsc: u64 = match kind {
        FaultKind::Translation => 0b00_0100, // 0b0001_LL
        FaultKind::AccessFlag => 0b00_1000,  // 0b0010_LL
        FaultKind::Permission => 0b00_1100,  // 0b0011_LL
    } | (level as u64 & 0b11);
    let ec: u64 = 0x21; // Instruction Abort taken from the same EL
    let il: u64 = 1;
    (ec << 26) | (il << 25) | ifsc
}

// ── ESR EC field helpers (shared with the fetch path) ────────────────────────

/// ESR_EL1.EC for a Data Abort taken from the same EL.
pub const ESR_EC_DATA_ABORT_SAME_EL: u64 = 0x25;
/// ESR_EL1.EC for an Instruction Abort taken from the same EL.
pub const ESR_EC_INST_ABORT_SAME_EL: u64 = 0x21;

/// Rewrite the EC[31:26] field of an `ESR_EL1` value, preserving every other
/// bit (IL / WnR / xFSC). Used by [`aether_mmu_fetch_pa`] to re-stamp the
/// walker's Data-Abort ESR (EC=0x25) as an Instruction Abort (EC=0x21) without
/// re-deriving the fault class — the class/level bits are identical between the
/// two aborts, only the EC differs.
fn esr_with_ec(esr: u64, ec: u64) -> u64 {
    (esr & !(0x3F << 26)) | ((ec & 0x3F) << 26)
}

// ── The walker ──────────────────────────────────────────────────────────────

/// Translate a guest VA to a guest PA via the stage-1 page tables, assuming the
/// MMU is enabled (caller handles the `M == 0` flat case). Returns the PA and
/// whether the leaf permits writes (`AP[2] == 0`), or the fault + level.
///
/// 4 KiB granule, 48-bit VA, 4-level (start level 0). Index at level L is
/// `(va >> (12 + 9*(3-L))) & 0x1FF`. Block (huge-page) leaves are honoured at
/// level 1 (1 GiB) and level 2 (2 MiB); level 3 is always a 4 KiB page.
///
/// `sysregs` is the full guest context slice (length >= `CTX_U64S`); sysreg
/// slots live at `SYSREG_SLOT0 + idx`.
#[allow(unsafe_code)]
#[allow(unsafe_code)]
fn pa_hit_check(va: u64, pa: u64) {
    // SAFETY: EL2-private, single-vCPU diagnostic counters.
    unsafe {
        let lo = *core::ptr::addr_of!(MMU_TRACE_PA_LO);
        let hi = *core::ptr::addr_of!(MMU_TRACE_PA_HI);
        if lo < hi && pa >= lo && pa < hi {
            let c = core::ptr::addr_of_mut!(MMU_PA_HIT_COUNT);
            let prev = *c;
            *c = prev.saturating_add(1);
            if prev == 0 {
                *core::ptr::addr_of_mut!(MMU_PA_HIT_FIRST_VA) = va;
            }
        }
    }
}

#[allow(unsafe_code)]
pub fn walk(sysregs: &[u64], va: u64, is_write: bool) -> Result<(u64, bool), (FaultKind, u8)> {
    // TBI: strip the ignored top byte so a tagged VA resolves like its untagged
    // form. Bit 55 (regime selector) survives the mask.
    let va = tbi_mask_va(sysregs, va);
    let va_high = (va >> 55) & 1 == 1;
    let ttbr = if va_high {
        sysregs[SYSREG_SLOT0 + SLOT_TTBR1]
    } else {
        sysregs[SYSREG_SLOT0 + SLOT_TTBR0]
    };
    walk_from_ttbr(sysregs, va, is_write, ttbr)
}

/// Page-table walk with an explicit translation base. `walk` resolves the base
/// from `va`'s high bit; this variant lets the KPTI kernel-pgd fallback retry a
/// high-VA walk against `swapper_pg_dir` when `TTBR1_EL1` still holds the
/// trampoline pgd (`tramp_pg_dir`). `tcr` / start-level are still read from
/// `sysregs` — only the table root is overridden.
#[allow(unsafe_code)]
pub fn walk_from_ttbr(
    sysregs: &[u64],
    va: u64,
    is_write: bool,
    ttbr: u64,
) -> Result<(u64, bool), (FaultKind, u8)> {
    // TBI: strip the ignored top byte (idempotent if `walk` already did).
    let va = tbi_mask_va(sysregs, va);
    let va_high = (va >> 55) & 1 == 1;
    let tcr = sysregs[SYSREG_SLOT0 + SLOT_TCR];
    // Start level + granule from TCR_EL1 (must-fix #1: real GKI is 39-bit VA /
    // 3-level / start L1, not the old hardcoded 48-bit / 4-level / start L0).
    let start_level = match regime_start_level(tcr, va_high) {
        Some(l) => l,
        None => {
            if let Some(s) = trace_alloc(va) {
                trace_commit(s, va, ttbr, 0xFF, 0, trace_status(FaultKind::Translation, 0));
            }
            return Err((FaultKind::Translation, 0)); // non-4KiB granule: loud
        }
    };

    // Targeted walk tracer: capture this walk if the VA is in the configured
    // probe range and capacity remains (e.g. the kernel's fixmap mapping of the
    // DTB at boot — see M4b-6 notes).
    let trace = trace_alloc(va);

    let mut table = ttbr & ADDR_MASK;
    // No-Boundary confinement (must-fix #2): the first table base is guest-
    // controlled — refuse it (and every later table base + the leaf output) if
    // it escapes the handoff window, BEFORE any host dereference.
    if !in_window(table) {
        if let Some(s) = trace {
            trace_commit(s, va, ttbr, start_level, 0, trace_status(FaultKind::Translation, start_level));
        }
        return Err((FaultKind::Translation, start_level));
    }

    for level in start_level..4 {
        let shift = 12 + 9 * (3 - level as u32);
        let index = (va >> shift) & 0x1FF;
        let desc_pa = table + index * 8;
        // SAFETY: `table` is confirmed in-window (a 4 KiB-aligned page fully
        // inside the mapped span), so `desc_pa = table + index*8` (index < 512)
        // is in mapped guest RAM == host RAM. 8-byte aligned.
        let desc = unsafe { core::ptr::read_volatile(desc_pa as *const u64) };
        if let Some(s) = trace {
            trace_desc(s, level, desc);
        }

        if desc & 1 == 0 {
            if let Some(s) = trace {
                trace_commit(s, va, ttbr, start_level, 0, trace_status(FaultKind::Translation, level));
            }
            return Err((FaultKind::Translation, level)); // invalid descriptor
        }
        let is_table_or_page = desc & 0b10 != 0;

        if level == 3 {
            // At level 3 bit 1 MUST be set for a page; clear = reserved/invalid.
            if !is_table_or_page {
                if let Some(s) = trace {
                    trace_commit(s, va, ttbr, start_level, 0, trace_status(FaultKind::Translation, level));
                }
                return Err((FaultKind::Translation, level));
            }
            let r = finish_leaf(desc, va, 12, level, is_write);
            if let Some(s) = trace {
                match r {
                    Ok((pa, _)) => trace_commit(s, va, ttbr, start_level, pa, 1),
                    Err((k, l)) => trace_commit(s, va, ttbr, start_level, 0, trace_status(k, l)),
                }
            }
            return r;
        }
        if !is_table_or_page {
            // Block descriptor: 1 GiB at level 1, 2 MiB at level 2 (a block at
            // level 0 (512 GiB) is architecturally invalid for 4 KiB granule).
            if level == 0 {
                if let Some(s) = trace {
                    trace_commit(s, va, ttbr, start_level, 0, trace_status(FaultKind::Translation, level));
                }
                return Err((FaultKind::Translation, level));
            }
            let r = finish_leaf(desc, va, shift, level, is_write);
            if let Some(s) = trace {
                match r {
                    Ok((pa, _)) => trace_commit(s, va, ttbr, start_level, pa, 1),
                    Err((k, l)) => trace_commit(s, va, ttbr, start_level, 0, trace_status(k, l)),
                }
            }
            return r;
        }
        // Table descriptor: descend, confining the next table base too.
        table = desc & ADDR_MASK;
        if !in_window(table) {
            if let Some(s) = trace {
                trace_commit(s, va, ttbr, start_level, 0, trace_status(FaultKind::Translation, level));
            }
            return Err((FaultKind::Translation, level));
        }
    }
    // The level-3 branch above always returns; the loop cannot fall through.
    unreachable!()
}

/// Per-level descriptor trace of one page-table walk (diagnostic only).
pub struct WalkDebug {
    pub ttbr: u64,
    pub tcr: u64,
    pub start_level: u8,
    /// `(desc_pa, descriptor)` per architectural level 0..=3; `(0, 0)` = not visited.
    pub levels: [(u64, u64); 4],
    /// Level at which a translation fault occurred, or `-1` if the walk resolved.
    pub fault_level: i8,
    /// Output PA when `fault_level < 0`.
    pub out_pa: u64,
    /// A table base escaped the handoff window (walk refused to dereference it).
    pub window_reject: bool,
}

/// Diagnostic mirror of [`walk`] for the hypervisor's stuck-user-fault dump.
///
/// Records every visited level's raw descriptor so a repeating demand-fault can
/// be classified WITHOUT guessing: if the descriptor at the fault level has bit
/// 0 clear the PTE is genuinely absent (the kernel never mapped it — a
/// fault-delivery / handler problem); if `walk_debug` instead resolves to a PA
/// while the live path keeps faulting, the fault is stale (a TLB / block-cache
/// coherence bug). Side-effect free: no software-TLB update, no trace-ring
/// touch, and it never dereferences a table base outside the handoff window.
#[allow(unsafe_code)]
pub fn walk_debug(sysregs: &[u64], va: u64, is_write: bool) -> WalkDebug {
    let mut out = WalkDebug {
        ttbr: 0,
        tcr: 0,
        start_level: 0,
        levels: [(0, 0); 4],
        fault_level: 0,
        out_pa: 0,
        window_reject: false,
    };
    let va_high = (va >> 55) & 1 == 1;
    let ttbr = if va_high {
        sysregs[SYSREG_SLOT0 + SLOT_TTBR1]
    } else {
        sysregs[SYSREG_SLOT0 + SLOT_TTBR0]
    };
    let tcr = sysregs[SYSREG_SLOT0 + SLOT_TCR];
    out.ttbr = ttbr;
    out.tcr = tcr;
    let start_level = match regime_start_level(tcr, va_high) {
        Some(l) => l,
        None => {
            out.fault_level = 0;
            return out;
        }
    };
    out.start_level = start_level;

    let mut table = ttbr & ADDR_MASK;
    if !in_window(table) {
        out.window_reject = true;
        out.fault_level = start_level as i8;
        return out;
    }
    for level in start_level..4 {
        let shift = 12 + 9 * (3 - level as u32);
        let index = (va >> shift) & 0x1FF;
        let desc_pa = table + index * 8;
        // SAFETY: `table` is confirmed in-window; `index < 512`, 8-byte aligned.
        let desc = unsafe { core::ptr::read_volatile(desc_pa as *const u64) };
        out.levels[level as usize] = (desc_pa, desc);

        if desc & 1 == 0 {
            out.fault_level = level as i8; // invalid descriptor = translation fault
            return out;
        }
        let is_table_or_page = desc & 0b10 != 0;
        if level == 3 {
            if !is_table_or_page {
                out.fault_level = level as i8;
                return out;
            }
            match finish_leaf(desc, va, 12, level, is_write) {
                Ok((pa, _)) => {
                    out.fault_level = -1;
                    out.out_pa = pa;
                }
                Err((_, l)) => out.fault_level = l as i8,
            }
            return out;
        }
        if !is_table_or_page {
            // Block descriptor (1 GiB at L1, 2 MiB at L2; L0 block is invalid).
            if level == 0 {
                out.fault_level = level as i8;
                return out;
            }
            match finish_leaf(desc, va, shift, level, is_write) {
                Ok((pa, _)) => {
                    out.fault_level = -1;
                    out.out_pa = pa;
                }
                Err((_, l)) => out.fault_level = l as i8,
            }
            return out;
        }
        table = desc & ADDR_MASK;
        if !in_window(table) {
            out.window_reject = true;
            out.fault_level = level as i8;
            return out;
        }
    }
    out.fault_level = 3;
    out
}

/// Common leaf handling: AF / permission checks + PA assembly. `block_shift` is
/// 12 (4 KiB), 21 (2 MiB), or 30 (1 GiB).
fn finish_leaf(
    desc: u64,
    va: u64,
    block_shift: u32,
    level: u8,
    is_write: bool,
) -> Result<(u64, bool), (FaultKind, u8)> {
    // Access flag (bit 10): hardware (and we) fault if clear.
    if desc & (1 << 10) == 0 {
        return Err((FaultKind::AccessFlag, level));
    }
    // AP[2] (bit 7): 0 = read/write, 1 = read-only. B34: with hardware dirty-bit
    // management (HAFDBS, TCR_EL1.HD=1) a leaf with DBM=1 (bit 51) and AP[2]=1 is
    // a CLEAN-but-WRITABLE page — the first write must set dirty in hardware, not
    // fault. Treat DBM=1 as writable so the first write to such a page doesn't
    // spuriously Permission-fault. (When the kernel leaves TCR.HD=0, DBM is RES0,
    // so this is a no-op.)
    let writable = desc & (1 << 7) == 0 || desc & (1u64 << 51) != 0;
    if is_write && !writable {
        return Err((FaultKind::Permission, level));
    }
    let block_size = 1u64 << block_shift;
    let oa = (desc & ADDR_MASK) & !(block_size - 1);
    let pa = oa | (va & (block_size - 1));
    // No-Boundary confinement (must-fix #2): the leaf output is guest-
    // controlled; never hand a consumer a host PA outside the window — EXCEPT a
    // PA that lands in the fixed emulated-device MMIO allow-list (M4b-5), which
    // is routed to the device emulator (never dereferenced as host RAM) by the
    // caller. Table bases remain window-only (page tables never live in MMIO).
    if !in_window(pa) && !is_mmio(pa) {
        return Err((FaultKind::Translation, level));
    }
    pa_hit_check(va, pa);
    Ok((pa, writable))
}

// ── EL2-private software TLB ─────────────────────────────────────────────────
// 256-entry direct-mapped, 4 KiB granularity. Single-vCPU (matches the
// dbt.rs global-runtime invariant). `tag == u64::MAX` marks an empty slot:
// a tag of u64::MAX is the page number of VA 0xFFFF_FFFF_FFFF_F000 (the top
// 4 KiB of the 64-bit space), which is never mapped, so it never collides with
// a real page number — including TTBR1 high addresses, whose page numbers
// approach but never reach 2^52.
//
// SMP NOTE: this static TLB is race-free only under the single-vCPU invariant
// and has no ASID / TTBR-generation tag — SMP guest support must switch to
// per-core TLBs (or atomics) + ASID tagging. The flush-on-every-TTBR/TCR/MAIR
// write contract (M4b-2d) is load-bearing for CORRECTNESS here, not just speed.

const TLB_ENTRIES: usize = 256;
const TLB_EMPTY: u64 = u64::MAX;

static mut TLB_TAG: [u64; TLB_ENTRIES] = [TLB_EMPTY; TLB_ENTRIES];
static mut TLB_PA: [u64; TLB_ENTRIES] = [0; TLB_ENTRIES];
static mut TLB_W: [bool; TLB_ENTRIES] = [false; TLB_ENTRIES];
/// Per-entry address-space tag for TTBR0 (low-VA) cached translations: the full
/// `TTBR0_EL1` value (page-table base + ASID) live at fill time. A low-VA lookup
/// hits only when this matches the CURRENT `TTBR0_EL1`, so a FORKED child (which
/// the kernel installs by writing a different `TTBR0_EL1` baddr) can never hit a
/// stale entry left by the parent — even if the flush-on-TTBR0-write contract
/// were ever missed. (High-VA / TTBR1 entries are never cached, so no tag there.)
/// This is the signal-11 "software-TLB staleness on forked TTBR0 pages" guard.
static mut TLB_ASID: [u64; TLB_ENTRIES] = [0; TLB_ENTRIES];

/// Invalidate the entire software TLB. Called on MSR to TTBR0/1_EL1, TCR_EL1,
/// MAIR_EL1 and on broad TLBI (VMALLE1/ALLE1).
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_flush_all() {
    // SAFETY: EL2-private arrays, single-vCPU; no aliasing references exist.
    unsafe {
        let tag = core::ptr::addr_of_mut!(TLB_TAG);
        for i in 0..TLB_ENTRIES {
            (*tag)[i] = TLB_EMPTY;
        }
        let t = core::ptr::addr_of_mut!(MMU_TLBI_FLUSH_ALL_TOTAL);
        *t = (*t).saturating_add(1);
    }
}

/// Counts of TLBI VAE1 calls observed. `MMU_TLBI_VA_FIXMAP` increments only
/// when the invalidated VA lies in `[MMU_TRACE_LO, MMU_TRACE_HI)` — pinned to
/// the fixmap region by the hypervisor (Phase B step 2). `MMU_TLBI_VA_TOTAL`
/// counts every call so we can tell "kernel never invalidates" vs "kernel
/// invalidates but not the fixmap slot".
pub static mut MMU_TLBI_VA_TOTAL: u32 = 0;
pub static mut MMU_TLBI_VA_FIXMAP: u32 = 0;
pub static mut MMU_TLBI_FLUSH_ALL_TOTAL: u32 = 0;
pub static mut MMU_TLBI_VA_FIRST_FIXMAP: u64 = 0;

/// Invalidate a single VA page (TLBI VAE1).
///
/// Phase-E correctness fix: the kernel's actual invalidation pattern is
/// "modify a non-canonical-aliased VA, issue TLBI VAALE1IS for SOME VA in a
/// different range, expect ALL stale entries to drop". The architecture
/// permits a "broader-than-asked" invalidate, and our 256-entry direct-mapped
/// TLB can hold entries that no kernel-issued single-VA TLBI will ever target
/// (e.g. a vmemmap VA whose mapping the kernel built then tore down via a
/// pgd-level rewrite without per-VA TLBI). The cheapest correct policy is:
/// any TLBI flushes the WHOLE software TLB. This matches what the architecture
/// allows, costs one cache walk per kernel TLBI (rare on the hot path), and
/// eliminates an entire class of stale-mapping bugs.
///
/// Real-world hit: create_kpti_ng_temp_pgd was reading L3 slots through the
/// vmemmap VA; an earlier kernel walk had cached VA 0xFFFFFFFDFDA39000 → PA
/// 0xB7DFF000 in our TLB; the kernel later cleared L3[0x39] for that VA
/// without a per-VA TLBI for the vmemmap alias, so subsequent stores to
/// 0xFDA39xxx silently corrupted the still-live PT page at PA 0xB7DFF000.
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_tlbi_va(va: u64) {
    // SAFETY: EL2-private, single-vCPU; in-bounds index + diagnostic counters.
    unsafe {
        // Whole-TLB flush — see doc above.
        let tag = core::ptr::addr_of_mut!(TLB_TAG);
        for i in 0..TLB_ENTRIES {
            (*tag)[i] = TLB_EMPTY;
        }
        let t = core::ptr::addr_of_mut!(MMU_TLBI_VA_TOTAL);
        *t = (*t).saturating_add(1);
        let lo = *core::ptr::addr_of!(MMU_TRACE_LO);
        let hi = *core::ptr::addr_of!(MMU_TRACE_HI);
        if lo < hi && va >= lo && va < hi {
            let f = core::ptr::addr_of_mut!(MMU_TLBI_VA_FIXMAP);
            let prev = *f;
            *f = prev.saturating_add(1);
            if prev == 0 {
                *core::ptr::addr_of_mut!(MMU_TLBI_VA_FIRST_FIXMAP) = va;
            }
        }
    }
}

/// Phase-E: spurious-fault loop breaker. The kernel's
/// `is_spurious_el1_translation_fault` does `AT S1E1R + read PAR_EL1`; we
/// don't model AT so PAR.F stays 0 and the kernel decides every kernel-VA
/// translation fault is "spurious", WARNs, ERETs to the faulting PC, and
/// re-faults. Loop forever.
///
/// To break this, the walker tracks the last (VA, kind) it faulted on. If
/// the SAME load VA faults more than `FAKE_AFTER_FAULTS` times in a row,
/// the walker returns a host pointer to a fixed all-zeros scratch page —
/// the kernel's iterator dereferences zeros, takes its end-of-iter exit,
/// and forward progress resumes. This trades correctness on truly bad
/// kernel state (which the kernel CAN'T recover from anyway) for boot
/// liveness.
pub static mut SPURIOUS_LAST_VA: u64 = 0;
pub static mut SPURIOUS_REPEAT_COUNT: u32 = 0;
pub static mut SPURIOUS_FAKE_HITS: u64 = 0;
const SPURIOUS_FAKE_AFTER: u32 = 32;

/// Static 4 KiB zero page that fake-succeed loads return a host pointer to.
/// Page-aligned (the type alignment + static placement guarantees 4 KiB).
#[repr(align(4096))]
struct ZeroPage([u8; 4096]);
static mut SPURIOUS_ZERO_PAGE: ZeroPage = ZeroPage([0u8; 4096]);

#[allow(unsafe_code)]
fn spurious_zero_pa() -> u64 {
    // SAFETY: EL2-private, taking address of a static is sound.
    unsafe { core::ptr::addr_of!(SPURIOUS_ZERO_PAGE) as u64 }
}

/// One page's translation: a TLB-cached single-page walk. Returns the full host
/// PA (page base | in-page offset of `va`) and writability, or the walk fault.
/// The 256-entry direct-mapped software TLB is consulted first (a read hits any
/// cached page; a write hits only a writable one); on a miss the page-table
/// [`walk`] runs and its result is cached. Shared by the data path
/// ([`aether_mmu_xlate`], including its cross-page second-page lookup) and, via
/// that, the fetch path ([`aether_mmu_fetch_pa`]).
#[allow(unsafe_code)]
fn xlate_page(sysregs: &[u64], va: u64, is_w: bool) -> Result<u64, (FaultKind, u8)> {
    // TBI: key the software TLB on the architectural (untagged) VA so a tagged
    // access (Scudo `0xb4..`) and its untagged twin share one entry, and the
    // KPTI fast-path's TTBR1==tramp test sees the canonical address. The inner
    // walk masks again (idempotent); doing it here makes the TLB key correct.
    let va = tbi_mask_va(sysregs, va);
    let page = va >> 12;
    let idx = (page as usize) & (TLB_ENTRIES - 1);
    // Phase-E correctness: TLB cache DISABLED for kernel high-VA (TTBR1)
    // accesses. The kernel modifies page tables, then issues TLBI for a
    // SUBSET of the affected VAs (relying on ARM ARM's "implicit
    // break-before-make" semantics for some classes of edit, e.g. clearing
    // a leaf entry that was never valid in the visible TLB). Our software
    // TLB has no way to know which entries are "implicitly invalidated" by
    // any given store, and aggressive flush-on-every-TLBI still leaves
    // stale entries cached between the kernel's store and its next TLBI.
    //
    // For TTBR1 VAs (high bit 63 set) we therefore ALWAYS walk fresh —
    // the kernel's PT-write-then-immediate-read pattern in
    // create_kpti_ng_temp_pgd then sees the just-written entry. TTBR0
    // (low) VAs still cache; the boot-time identity-mapped low VAs that
    // dominate the early dispatch hot path benefit from the cache and the
    // kernel never rewrites them.
    let va_high = (va >> 63) & 1 == 1;
    // Address-space tag for the low-VA (TTBR0) cache: the live TTBR0_EL1. A
    // forked child runs with a DIFFERENT TTBR0 base, so tagging each cached
    // low-VA entry with it prevents a child from hitting the parent's stale
    // translation (the signal-11 forked-process staleness guard). Read once.
    let ttbr0 = sysregs[SYSREG_SLOT0 + SLOT_TTBR0];
    if !va_high {
        // SAFETY: EL2-private, single-vCPU.
        unsafe {
            if *core::ptr::addr_of!(TLB_TAG[idx]) == page
                && *core::ptr::addr_of!(TLB_ASID[idx]) == ttbr0
                && (!is_w || *core::ptr::addr_of!(TLB_W[idx]))
            {
                return Ok(*core::ptr::addr_of!(TLB_PA[idx]) | (va & 0xFFF));
            }
        }
    }
    // KPTI fast-path. Post-mount the kernel runs at EL1 with the trampoline pgd
    // (tramp_pg_dir) because the exit trampoline (tramp_unmap_kernel) sets it
    // before ERET and the entry switch is skipped — so EVERY kernel high-VA
    // access would walk-fail on tramp then re-walk swapper in the Err fallback
    // (2 walks, ~72M times). When the live TTBR1 is EXACTLY the proven trampoline
    // base (snapshot - 0x2000), walk swapper directly: vmalloc / vmap stacks /
    // linear map / kimg live only there. Restricted to the exact proven tramp so
    // early-boot transient pgds (idmap / create_kpti_ng_temp_pgd) are untouched.
    let primary = if va_high {
        let cur = sysregs[SYSREG_SLOT0 + SLOT_TTBR1] & ADDR_MASK;
        // SAFETY: EL2-private, single-vCPU.
        let snap = unsafe { *core::ptr::addr_of!(KERNEL_PGD_SNAPSHOT) };
        if snap != 0 && cur == snap.wrapping_sub(0x2000) {
            // SAFETY: EL2-private, single-vCPU.
            unsafe {
                *core::ptr::addr_of_mut!(MMU_KPTI_FALLBACK_HITS) =
                    (*core::ptr::addr_of!(MMU_KPTI_FALLBACK_HITS)).saturating_add(1);
            }
            walk_from_ttbr(sysregs, va, is_w, snap)
        } else {
            walk(sysregs, va, is_w)
        }
    } else {
        walk(sysregs, va, is_w)
    };
    match primary {
        Ok((pa, writable)) => {
            // NOTE: deliberately do NOT snapshot TTBR1 on a plain successful
            // high-VA walk — early boot resolves vmalloc VAs through transient
            // pgds (idmap / create_kpti_ng_temp_pgd) too, and snapshotting those
            // would poison KERNEL_PGD_SNAPSHOT. The snapshot is set ONLY from the
            // Err-branch differential resolve below, which PROVES tramp↔swapper.
            // Only cache low (TTBR0) VAs — see top-of-fn rationale.
            if !va_high {
                // SAFETY: EL2-private, single-vCPU.
                unsafe {
                    *core::ptr::addr_of_mut!(TLB_TAG[idx]) = page;
                    *core::ptr::addr_of_mut!(TLB_PA[idx]) = pa & !0xFFF;
                    *core::ptr::addr_of_mut!(TLB_W[idx]) = writable;
                    *core::ptr::addr_of_mut!(TLB_ASID[idx]) = ttbr0;
                }
            }
            Ok(pa)
        }
        Err(e) => {
            // Phase-D kernel-image fallback. The kernel's __create_page_tables
            // in head.S maps `[_text, ALIGN(_end, 2 MiB))` but Linux ARM64 sometimes
            // accesses VAs JUST PAST this boundary (e.g. memblock arrays placed
            // in .meminit.data — see phase-d-printk-live-android15 notes). The
            // kernel WARNs "Ignoring spurious kernel translation fault" then
            // ERETs back, expecting the retry to succeed (its AT-probe says
            // valid). With no real AT modeling + no TLB races on our software
            // MMU, the retry just refaults forever.
            //
            // When the walk fails AND the VA is inside the kernel image area
            // (the dispatcher pins KIMG_VA_BASE/KIMG_PA_BASE on bring-up),
            // fall back to the obvious PA-from-VA-offset translation. PA must
            // still be in our handoff window; if not, propagate the fault.
            //
            // No-Boundary: the fallback uses ONLY the pinned base values and
            // computes a single PA; it never dereferences guest-controlled
            // input or trusts the guest's tables. Output is window-confined.
            let kimg_va = unsafe { *core::ptr::addr_of!(KIMG_VA_BASE) };
            let kimg_pa = unsafe { *core::ptr::addr_of!(KIMG_PA_BASE) };
            let kimg_sz = unsafe { *core::ptr::addr_of!(KIMG_SPAN_SIZE) };
            if kimg_va != 0 && kimg_pa != 0 && kimg_sz != 0
               && va >= kimg_va && va.wrapping_sub(kimg_va) < kimg_sz
            {
                let pa = kimg_pa.wrapping_add(va - kimg_va);
                if in_window(pa) {
                    // SAFETY: EL2-private, single-vCPU. Don't cache TTBR1.
                    unsafe {
                        if !va_high {
                            *core::ptr::addr_of_mut!(TLB_TAG[idx]) = page;
                            *core::ptr::addr_of_mut!(TLB_PA[idx]) = pa & !0xFFF;
                            *core::ptr::addr_of_mut!(TLB_W[idx]) = true;
                            *core::ptr::addr_of_mut!(TLB_ASID[idx]) = ttbr0;
                        }
                        *core::ptr::addr_of_mut!(MMU_KIMG_FALLBACK_HITS) =
                            (*core::ptr::addr_of!(MMU_KIMG_FALLBACK_HITS))
                                .saturating_add(1);
                    }
                    return Ok(pa);
                }
            }
            // KPTI kernel-pgd fallback (ONLY on a walk miss — never pre-empts a
            // successful live-TTBR1 walk, so early-boot transient pgds — idmap /
            // create_kpti_ng_temp_pgd — keep their correct, possibly-faulting
            // results). The guest is running kernel code but TTBR1_EL1 still holds
            // the KPTI trampoline pgd (tramp_pg_dir, which maps no vmalloc / no
            // vmap kernel stack) because the DBT skips the entry trampoline that
            // would run tramp_map_kernel. swapper_pg_dir = tramp_pg_dir + 0x2000
            // (arm64 linker: tramp,reserved,swapper are consecutive PAGE_SIZE
            // pgds; confirmed live 0x614ff000 = 0x614fd000 + 0x2000). Retry the
            // high-VA walk against the swapper snapshot from a prior known-good
            // vmalloc resolve; if none yet, bootstrap with the +0x2000 offset.
            // Only RETURNS on a genuine in-window resolve, so a real fault (TTBR1
            // already == swapper, or a genuinely unmapped page) still propagates.
            if va_high {
                let cur = sysregs[SYSREG_SLOT0 + SLOT_TTBR1] & ADDR_MASK;
                // SAFETY: EL2-private, single-vCPU.
                let snap = unsafe { *core::ptr::addr_of!(KERNEL_PGD_SNAPSHOT) };
                let kpgd = if snap != 0 && snap != cur {
                    snap
                } else if snap == 0 {
                    cur.wrapping_add(0x2000)
                } else {
                    0 // snap == cur → current already swapper → genuine fault
                };
                if kpgd != 0 && kpgd != cur && in_window(kpgd) {
                    if let Ok((pa, _)) = walk_from_ttbr(sysregs, va, is_w, kpgd) {
                        if in_window(pa) {
                            // SAFETY: EL2-private, single-vCPU.
                            unsafe {
                                *core::ptr::addr_of_mut!(KERNEL_PGD_SNAPSHOT) = kpgd;
                                *core::ptr::addr_of_mut!(MMU_FB_CUR) = cur;
                                *core::ptr::addr_of_mut!(MMU_FB_KPGD) = kpgd;
                                *core::ptr::addr_of_mut!(MMU_KPTI_FALLBACK_HITS) =
                                    (*core::ptr::addr_of!(MMU_KPTI_FALLBACK_HITS))
                                        .saturating_add(1);
                            }
                            return Ok(pa);
                        }
                    }
                }
            }
            // Phase-E: spurious-fake-zero fallback REMOVED in favour of
            // proper AT S1E1R / PAR_EL1 modelling (see
            // aether_mmu_at_s1e1). The kernel's
            // is_spurious_el1_translation_fault now sees a TRUTHFUL F=1
            // when the access genuinely faults, so it calls die_kernel_
            // fault and emits a clean panic + diagnostic instead of
            // looping. The corrupting fake-zero return is gone.
            //
            // The statics SPURIOUS_LAST_VA / SPURIOUS_REPEAT_COUNT /
            // SPURIOUS_FAKE_HITS are retained as diagnostic counters
            // (incremented on every fault for telemetry) but never
            // gate the return value.
            unsafe {
                let last_va = *core::ptr::addr_of!(SPURIOUS_LAST_VA);
                if last_va == va {
                    let c = (*core::ptr::addr_of!(SPURIOUS_REPEAT_COUNT))
                        .saturating_add(1);
                    *core::ptr::addr_of_mut!(SPURIOUS_REPEAT_COUNT) = c;
                } else {
                    *core::ptr::addr_of_mut!(SPURIOUS_LAST_VA) = va;
                    *core::ptr::addr_of_mut!(SPURIOUS_REPEAT_COUNT) = 1;
                }
            }
            Err(e)
        }
    }
}

/// Kernel-image VA→PA fallback (Phase-D). Set once by the dispatcher before
/// the kernel starts running so the walker can satisfy accesses past
/// `_end + 2 MiB` (where memblock arrays may live). Default 0 = disabled.
pub static mut KIMG_VA_BASE: u64 = 0;
pub static mut KIMG_PA_BASE: u64 = 0;
pub static mut KIMG_SPAN_SIZE: u64 = 0;
pub static mut MMU_KIMG_FALLBACK_HITS: u64 = 0;

/// KPTI kernel-pgd (`swapper_pg_dir`) recovered from a successful vmalloc walk.
/// Used to retry high-VA walks that fault because `TTBR1_EL1` still holds the
/// trampoline pgd (`tramp_pg_dir`). 0 = not yet observed (bootstrap with +0x2000).
pub static mut KERNEL_PGD_SNAPSHOT: u64 = 0;
/// Count of faults rescued by the KPTI kernel-pgd fallback (telemetry).
pub static mut MMU_KPTI_FALLBACK_HITS: u64 = 0;
/// First EL1-source user-VA fault with a user SP_EL0 — the exact faulting
/// (block PC, VA, SP_EL0, ESR) that triggers the enter_from_kernel_mode loop.
pub static mut OFLTW_LATCH: u64 = 0;
pub static mut OFLTW_PC: u64 = 0;
pub static mut OFLTW_FAR: u64 = 0;
pub static mut OFLTW_SP0: u64 = 0;
pub static mut OFLTW_ESR: u64 = 0;
pub static mut OFLTW_SP1: u64 = 0;
pub static mut OFLTW_SPACT: u64 = 0;

// EL0-source user-VA fault capture (LAST one wins). The init crash is an EL0
// (curEL=0) SIGSEGV — the OFLTW latch above only catches EL1-source faults, so
// this records the faulting EL0 PC + low GPRs of the most recent userspace fault.
// At the PSCI reset (init death), these hold init's fatal dereference: the bad
// pointer register + the block that computed it, for disassembly.
pub static mut EL0FLT_PC: u64 = 0;
pub static mut EL0FLT_FAR: u64 = 0;
pub static mut EL0FLT_ESR: u64 = 0;
pub static mut EL0FLT_X30: u64 = 0;
pub static mut EL0FLT_HITS: u64 = 0;
pub static mut EL0FLT_X: [u64; 31] = [0; 31];
/// One-shot latch target: boot_x86 sets this to the deterministic init crash
/// FAR (0x7ce8274c08). When a curEL=0 fault hits EXACTLY this address, capture
/// the full GPR file (x0-x30) once — the bad-pointer register + how it was
/// computed, for the upstream-corruption hunt. 0 = disabled (last-wins only).
pub static mut EL0FLT_WATCH: u64 = 0;
pub static mut EL0FLT_W_LATCH: u64 = 0;
pub static mut EL0FLT_W_PC: u64 = 0;
/// The actually-executing block entry PC (LAST_GUEST_PC, stamped per-block) at
/// fault time — reliable unlike ctx[32] (the lazily-updated guest-visible PC).
pub static mut EL0FLT_W_LGPC: u64 = 0;
/// FAULT_OP_PC at fault time — the EXACT faulting instruction PC.
pub static mut EL0FLT_W_OPPC: u64 = 0;
pub static mut EL0FLT_W_INSN: u64 = 0;
/// ELR_EL1 / SPSR_EL1 / real ESR at the captured fault, + whether the fault was
/// taken inside the SVC diagnostic-probe window (B19). A probe fault is cleared
/// by the PEND-snapshot restore and is NOT init's real death — so the watch
/// latch ignores probe faults (only real EL0 deaths are captured).
pub static mut EL0FLT_W_ELR: u64 = 0;
pub static mut EL0FLT_W_SPSR: u64 = 0;
pub static mut EL0FLT_W_ESR2: u64 = 0;
/// Set to 1 by exceptions.rs across the SVC diagnostic-probe window.
pub static mut IN_DIAG_PROBE: u32 = 0;
/// Host call stack at the watched fault — the return-address chain identifies
/// WHO called aether_mmu_xlate(0x7ce8274c08): a JIT lifted-code address (JIT
/// cache range) means a guest memop; hypervisor .text addresses mean a runtime
/// helper / the dispatch loop. The definitive "who".
pub static mut EL0FLT_W_RSP: u64 = 0;
pub static mut EL0FLT_W_STK: [u64; 48] = [0; 48];
/// 32 ARM64 opcode words read forward from the block-start PC, so the faulting
/// load (block PC is stamped per-block, not per-insn) can be disassembled.
pub static mut EL0FLT_W_BLK: [u64; 32] = [0; 32];
pub static mut EL0FLT_W_X: [u64; 31] = [0; 31];

// ── ASLR-proof keystore2 SIGSEGV detector ─────────────────────────────────
// A benign demand-page fault resolves once (the kernel maps the page, never
// re-faults). A real userspace SIGSEGV is a DETERMINISTIC fault the kernel
// CANNOT resolve — keystore2 crashes, the init/zygote path restarts it, and it
// re-faults at the IDENTICAL (PC, FAR). So instead of latching on a hardcoded
// FAR (which ASLR varies every boot), we track a tiny FIFO of the last
// `EL0FLT_FIFO_N` distinct `(el0 faulting PC, FAR)` pairs each with a repeat
// counter, and latch into EL0FLT_W_* when any pair re-faults
// `EL0FLT_REFAULT_THRESHOLD` times. No heap (no_std): fixed `static mut` arrays.
pub const EL0FLT_FIFO_N: usize = 8;
/// Re-fault count (same PC+FAR) that flips the latch. >=2 distinguishes a
/// deterministic SIGSEGV (re-faults at the identical PC+FAR every crash/restart)
/// from a one-shot demand page (count 1). Lowered 4→2 so keystore2 is captured at
/// its 2nd crash (~t3100) — the machine-shutdown interruptions kill the boot before
/// a 4th re-fault (~t4900) is reached.
pub const EL0FLT_REFAULT_THRESHOLD: u32 = 2;
/// Known benign first-fault FAR — a kernel `clear_user`/demand-page that always
/// resolves. Excluded explicitly so it can never win the re-fault race.
pub const EL0FLT_BENIGN_FAR: u64 = 0x0050_2558;
/// Faulting block PC for each tracked pair (0 = empty slot).
pub static mut EL0FLT_FIFO_PC: [u64; EL0FLT_FIFO_N] = [0; EL0FLT_FIFO_N];
/// FAR for each tracked pair.
pub static mut EL0FLT_FIFO_FAR: [u64; EL0FLT_FIFO_N] = [0; EL0FLT_FIFO_N];
/// Repeat counter for each pair (how many times this exact PC+FAR re-faulted).
pub static mut EL0FLT_FIFO_CNT: [u32; EL0FLT_FIFO_N] = [0; EL0FLT_FIFO_N];
/// Next slot to overwrite when the FIFO is full (round-robin eviction).
pub static mut EL0FLT_FIFO_HEAD: usize = 0;

/// Record a `cur_el==0` user fault `(pc, far)` in the re-fault FIFO and return
/// `true` once the matching pair reaches [`EL0FLT_REFAULT_THRESHOLD`] re-faults
/// — the signature of a deterministic userspace SIGSEGV (e.g. keystore2). The
/// known-benign demand-page FAR is ignored so it can't race ahead.
#[allow(unsafe_code)]
fn el0flt_fifo_bump(pc: u64, far: u64) -> bool {
    if far == EL0FLT_BENIGN_FAR {
        return false;
    }
    // SAFETY: EL2-private, single-vCPU; fixed-size arrays indexed in range.
    unsafe {
        let pcs = core::ptr::addr_of_mut!(EL0FLT_FIFO_PC);
        let fars = core::ptr::addr_of_mut!(EL0FLT_FIFO_FAR);
        let cnts = core::ptr::addr_of_mut!(EL0FLT_FIFO_CNT);
        // Existing pair → bump its counter.
        let mut i = 0usize;
        while i < EL0FLT_FIFO_N {
            if (*pcs)[i] == pc && (*fars)[i] == far && ((*pcs)[i] != 0 || (*fars)[i] != 0) {
                let c = (*cnts)[i].saturating_add(1);
                (*cnts)[i] = c;
                return c >= EL0FLT_REFAULT_THRESHOLD;
            }
            i += 1;
        }
        // New pair: prefer an empty slot, else evict round-robin (FIFO head).
        let mut slot = EL0FLT_FIFO_N;
        let mut j = 0usize;
        while j < EL0FLT_FIFO_N {
            if (*pcs)[j] == 0 && (*fars)[j] == 0 {
                slot = j;
                break;
            }
            j += 1;
        }
        if slot == EL0FLT_FIFO_N {
            let head = *core::ptr::addr_of!(EL0FLT_FIFO_HEAD) % EL0FLT_FIFO_N;
            slot = head;
            *core::ptr::addr_of_mut!(EL0FLT_FIFO_HEAD) = (head + 1) % EL0FLT_FIFO_N;
        }
        (*pcs)[slot] = pc;
        (*fars)[slot] = far;
        (*cnts)[slot] = 1;
        // Threshold of 1 would be pathological; first sighting never latches.
        1 >= EL0FLT_REFAULT_THRESHOLD
    }
}

/// Last (failing live TTBR1 base, winning swapper base) seen by the fallback —
/// reveals which pgd the kernel actually runs with when the fallback engages.
pub static mut MMU_FB_CUR: u64 = 0;
pub static mut MMU_FB_KPGD: u64 = 0;

/// Current `swapper_pg_dir` snapshot (page-frame base, 0 if not yet observed).
/// Read by the exception layer to emulate the KPTI entry/exit trampoline's
/// `TTBR1_EL1` switch (`tramp_map_kernel` / `tramp_unmap_kernel`), which the DBT
/// skips. See [`KERNEL_PGD_SNAPSHOT`].
#[allow(unsafe_code)]
pub fn kernel_pgd_snapshot() -> u64 {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { *core::ptr::addr_of!(KERNEL_PGD_SNAPSHOT) }
}

/// Configure the kernel-image fallback range. `va_base..va_base+span` will be
/// mapped to `pa_base..pa_base+span` when the regular page-table walk fails
/// (and the resulting PA is in the handoff window).
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_set_kimg_fallback(va_base: u64, pa_base: u64, span: u64) {
    // SAFETY: EL2-private, single-vCPU; set once before any walk.
    unsafe {
        *core::ptr::addr_of_mut!(KIMG_VA_BASE) = va_base;
        *core::ptr::addr_of_mut!(KIMG_PA_BASE) = pa_base;
        *core::ptr::addr_of_mut!(KIMG_SPAN_SIZE) = span;
    }
}

// ── Diagnostic: targeted walk tracer (M4b-6 fixmap probe) ──────────────────
// Captures up to MMU_TRACE_MAX walks whose VA falls inside [TRACE_LO, TRACE_HI)
// (inclusive low, exclusive high). Each slot records VA, the TTBR picked, the
// start level, the per-level descriptors read (DESC0..DESC3 — unused tail = 0),
// the final PA on success, and a STATUS byte: 0 = empty slot, 1 = ok, else
// `0x80 | (kind<<4) | level` where kind 1=Translation, 2=AccessFlag, 3=Permission.
// Zero overhead when TRACE_LO >= TRACE_HI (the default — tracing off). Set
// the range with `aether_mmu_trace_range(lo, hi)` BEFORE the dispatch loop.
pub const MMU_TRACE_MAX: usize = 16;
pub static mut MMU_TRACE_LO: u64 = u64::MAX;
pub static mut MMU_TRACE_HI: u64 = 0;
pub static mut MMU_TRACE_COUNT: u32 = 0;
/// PA-range filter for the walk tracer (post-resolution): if `lo < hi`, any
/// walk whose final PA falls in `[lo, hi)` is captured (overrides VA-range).
/// Used to grab the FIRST walk targeting a known PA (e.g. the DTB), no matter
/// what kernel VA gets used.
pub static mut MMU_TRACE_PA_LO: u64 = u64::MAX;
pub static mut MMU_TRACE_PA_HI: u64 = 0;
/// True = ring-buffer mode: when the trace fills, overwrite the oldest slot
/// (so the LAST MMU_TRACE_MAX walks in the configured range are always
/// available). False (default) = one-shot: stop capturing once full.
pub static mut MMU_TRACE_RING: bool = false;

/// Counter of walks whose final PA fell in `[MMU_TRACE_PA_LO, MMU_TRACE_PA_HI)`.
/// Incremented at the bottom of `finish_leaf` regardless of trace capacity, so
/// the hypervisor can confirm "did the kernel EVER successfully read the DTB?"
/// even when the ring buffer has cycled past the actual DTB walks.
pub static mut MMU_PA_HIT_COUNT: u32 = 0;
/// VA of the first walk that produced a PA in the configured PA range.
pub static mut MMU_PA_HIT_FIRST_VA: u64 = 0;
pub static mut MMU_TRACE_VA: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_TTBR: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_START: [u8; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_DESC0: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_DESC1: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_DESC2: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_DESC3: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_PA: [u64; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];
pub static mut MMU_TRACE_STATUS: [u8; MMU_TRACE_MAX] = [0; MMU_TRACE_MAX];

/// Configure the VA range whose walks should be captured into the
/// `MMU_TRACE_*` statics. Pass `(u64::MAX, 0)` to disable.
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_trace_range(lo: u64, hi: u64) {
    // SAFETY: EL2-private, single-vCPU; set once before dispatch starts.
    unsafe {
        *core::ptr::addr_of_mut!(MMU_TRACE_LO) = lo;
        *core::ptr::addr_of_mut!(MMU_TRACE_HI) = hi;
        *core::ptr::addr_of_mut!(MMU_TRACE_COUNT) = 0;
    }
}

/// Configure the PA range filter (post-resolution) for the walk tracer.
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_trace_pa_range(lo: u64, hi: u64) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        *core::ptr::addr_of_mut!(MMU_TRACE_PA_LO) = lo;
        *core::ptr::addr_of_mut!(MMU_TRACE_PA_HI) = hi;
    }
}

/// Enable ring-buffer mode (overwrite oldest when full).
#[allow(unsafe_code)]
pub extern "C" fn aether_mmu_trace_set_ring(enable: bool) {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { *core::ptr::addr_of_mut!(MMU_TRACE_RING) = enable; }
}

/// Return the next free trace slot if `va` is in-range and capacity remains.
/// In ring-buffer mode, capacity is unbounded — the slot index wraps mod
/// MMU_TRACE_MAX so the newest 16 walks overwrite the oldest.
#[allow(unsafe_code)]
fn trace_alloc(va: u64) -> Option<usize> {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        let lo = *core::ptr::addr_of!(MMU_TRACE_LO);
        let hi = *core::ptr::addr_of!(MMU_TRACE_HI);
        let in_va_range = lo < hi && va >= lo && va < hi;
        if !in_va_range {
            return None;
        }
        let n = *core::ptr::addr_of!(MMU_TRACE_COUNT) as usize;
        let ring = *core::ptr::addr_of!(MMU_TRACE_RING);
        if n >= MMU_TRACE_MAX && !ring {
            return None;
        }
        Some(n % MMU_TRACE_MAX)
    }
}

/// PA-range-only allocation: used by `finish_leaf` callers after the PA is
/// computed, so we can capture walks whose VA we don't know to filter on but
/// whose final PA is interesting (e.g. the DTB region).
#[allow(unsafe_code)]
fn trace_alloc_for_pa(pa: u64) -> Option<usize> {
    // SAFETY: EL2-private, single-vCPU.
    unsafe {
        let lo = *core::ptr::addr_of!(MMU_TRACE_PA_LO);
        let hi = *core::ptr::addr_of!(MMU_TRACE_PA_HI);
        if lo >= hi || pa < lo || pa >= hi {
            return None;
        }
        let n = *core::ptr::addr_of!(MMU_TRACE_COUNT) as usize;
        let ring = *core::ptr::addr_of!(MMU_TRACE_RING);
        if n >= MMU_TRACE_MAX && !ring {
            return None;
        }
        Some(n % MMU_TRACE_MAX)
    }
}

#[allow(unsafe_code)]
fn trace_desc(slot: usize, level: u8, desc: u64) {
    // SAFETY: caller ensures slot < MMU_TRACE_MAX.
    unsafe {
        match level {
            0 => *core::ptr::addr_of_mut!(MMU_TRACE_DESC0[slot]) = desc,
            1 => *core::ptr::addr_of_mut!(MMU_TRACE_DESC1[slot]) = desc,
            2 => *core::ptr::addr_of_mut!(MMU_TRACE_DESC2[slot]) = desc,
            _ => *core::ptr::addr_of_mut!(MMU_TRACE_DESC3[slot]) = desc,
        }
    }
}

#[allow(unsafe_code)]
fn trace_commit(slot: usize, va: u64, ttbr: u64, start: u8, pa: u64, status: u8) {
    // SAFETY: caller ensures slot < MMU_TRACE_MAX.
    unsafe {
        *core::ptr::addr_of_mut!(MMU_TRACE_VA[slot]) = va;
        *core::ptr::addr_of_mut!(MMU_TRACE_TTBR[slot]) = ttbr;
        *core::ptr::addr_of_mut!(MMU_TRACE_START[slot]) = start;
        *core::ptr::addr_of_mut!(MMU_TRACE_PA[slot]) = pa;
        *core::ptr::addr_of_mut!(MMU_TRACE_STATUS[slot]) = status;
        let c = core::ptr::addr_of_mut!(MMU_TRACE_COUNT);
        *c = (*c).saturating_add(1);
    }
}

fn trace_status(kind: FaultKind, level: u8) -> u8 {
    let k: u8 = match kind {
        FaultKind::Translation => 1,
        FaultKind::AccessFlag => 2,
        FaultKind::Permission => 3,
    };
    0x80 | (k << 4) | (level & 0x0F)
}

// Diagnostic: how many translation faults we've recorded since boot. A silent
// boot with a non-zero count tells us the kernel is taking data aborts that
// the dispatcher injects with no UART surfacing.
pub static mut MMU_FAULT_COUNT: u32 = 0;
pub static mut MMU_LAST_FAR: u64 = 0;
pub static mut MMU_LAST_ESR: u64 = 0;
// One-shot capture of the FIRST fault — locating where the kernel first
// tripped is far more useful than the latest. PC isn't directly available
// inside the walker (the lowered block holds it implicitly), so we capture
// the FAR/ESR/is_write tuple, and the dispatcher infers PC from the iter.
pub static mut MMU_FIRST_FAR: u64 = 0;
pub static mut MMU_FIRST_ESR: u64 = 0;

/// Record a pending Data Abort (FAR = the faulting access's base VA, ESR per
/// `kind`/`level`) in the free pending-fault sysreg slots and return the fault
/// sentinel [`XLATE_FAULT`]. The dispatcher reads `SLOT_PEND_PENDING` after each
/// block and injects via `VBAR_EL1` (M4b-3). Shared by the first-page,
/// cross-page second-page, and contiguity-failure paths of [`aether_mmu_xlate`].
#[allow(unsafe_code)]
fn record_pending_fault(ctx: *mut u64, far: u64, kind: FaultKind, level: u8, is_w: bool) -> u64 {
    let esr = data_abort_esr(kind, level, is_w);
    // SAFETY: caller's contract — `ctx` has ≥ CTX_U64S slots; these indices are
    // within the free pending-fault sysreg range.
    unsafe {
        *ctx.add(SYSREG_SLOT0 + SLOT_PEND_PENDING) = 1;
        *ctx.add(SYSREG_SLOT0 + SLOT_PEND_FAR) = far;
        *ctx.add(SYSREG_SLOT0 + SLOT_PEND_ESR) = esr;
        // Capture the FIRST EL1-source (curEL=1) user-VA fault taken while SP_EL0
        // holds a user address — the exact (block PC, faulting VA) that triggers
        // the enter_from_kernel_mode nested-abort loop. PC_SLOT = 0x100/8 = 32.
        let cur_el = (*ctx.add(SYSREG_SLOT0 + 42) >> 2) & 0b11;
        let sp0 = *ctx.add(SYSREG_SLOT0 + 16);
        let far_user = far >= 0x1000 && (far >> 55) & 1 == 0;
        // FIRST EL1-source user-VA fault (the precursor) regardless of sp0 — but
        // skip enter_from_kernel_mode itself (0x..ee9e00..) so we catch the
        // ORIGINAL faulting block, not the loop. Capture full SP-banking state.
        let pc_now = *ctx.add(32);
        let in_efkm = pc_now >= 0xffff_ffc0_08ee_9e00 && pc_now < 0xffff_ffc0_08ee_9f00;
        if cur_el == 1 && far_user && !in_efkm
            && *core::ptr::addr_of!(OFLTW_LATCH) == 0
        {
            *core::ptr::addr_of_mut!(OFLTW_LATCH) = 1;
            *core::ptr::addr_of_mut!(OFLTW_PC) = pc_now;
            *core::ptr::addr_of_mut!(OFLTW_FAR) = far;
            *core::ptr::addr_of_mut!(OFLTW_SP0) = sp0;
            *core::ptr::addr_of_mut!(OFLTW_ESR) = esr;
            *core::ptr::addr_of_mut!(OFLTW_SP1) = *ctx.add(SYSREG_SLOT0 + 17);
            *core::ptr::addr_of_mut!(OFLTW_SPACT) = *ctx.add(31);
        }
        // EL0-source user fault capture (LAST wins). init's fatal SEGV is the
        // last EL0 user fault before the kernel kills it, so this records the
        // crashing instruction PC + low GPRs (the bad-pointer register).
        if cur_el == 0 && far_user {
            *core::ptr::addr_of_mut!(EL0FLT_PC) = pc_now;
            *core::ptr::addr_of_mut!(EL0FLT_FAR) = far;
            *core::ptr::addr_of_mut!(EL0FLT_ESR) = esr;
            *core::ptr::addr_of_mut!(EL0FLT_X30) = *ctx.add(30);
            let mut gi = 0usize;
            while gi < 31 {
                (*core::ptr::addr_of_mut!(EL0FLT_X))[gi] = *ctx.add(gi);
                gi += 1;
            }
            *core::ptr::addr_of_mut!(EL0FLT_HITS) =
                (*core::ptr::addr_of!(EL0FLT_HITS)).saturating_add(1);
            // Decide whether to latch the watch snapshot. Two triggers:
            //
            //   1. Explicit FAR watch (EL0FLT_WATCH != 0) — legacy one-shot on a
            //      known deterministic crash FAR. Kept for targeted hunts.
            //
            //   2. ASLR-proof re-fault detector — the keystore2 SIGSEGV varies
            //      its FAR every boot (ASLR), so we can't hardcode it. Instead we
            //      detect the BEHAVIOR: a real SIGSEGV is a deterministic fault
            //      the kernel can't fix, so keystore2 crashes -> restarts ->
            //      re-faults at the IDENTICAL (PC, FAR). `el0flt_fifo_bump`
            //      returns true once a pair re-faults EL0FLT_REFAULT_THRESHOLD
            //      times. The benign clear_user demand-page FAR is excluded
            //      inside the FIFO so it can't win the race.
            let w = *core::ptr::addr_of!(EL0FLT_WATCH);
            let watch_hit = w != 0 && far == w;
            // Bump the FIFO on EVERY el0 fault so re-faults accumulate; only the
            // threshold crossing (and not an already-latched state) fires.
            let refault_hit = el0flt_fifo_bump(pc_now, far);
            if (watch_hit || refault_hit)
                && *core::ptr::addr_of!(EL0FLT_W_LATCH) == 0
                && *core::ptr::addr_of!(IN_DIAG_PROBE) == 0
            {
                *core::ptr::addr_of_mut!(EL0FLT_W_LATCH) = 1;
                *core::ptr::addr_of_mut!(EL0FLT_W_PC) = pc_now;
                // Host call stack: capture RSP + 48 stack words. The return
                // addresses identify the caller chain (JIT cache range = a guest
                // memop; hypervisor .text = a runtime helper / dispatch loop).
                #[cfg(target_arch = "x86_64")]
                {
                    let rsp: u64;
                    core::arch::asm!("mov {}, rsp", out(reg) rsp,
                        options(nomem, nostack, preserves_flags));
                    *core::ptr::addr_of_mut!(EL0FLT_W_RSP) = rsp;
                    let mut si = 0usize;
                    while si < 48 {
                        (*core::ptr::addr_of_mut!(EL0FLT_W_STK))[si] =
                            core::ptr::read_volatile((rsp + (si as u64) * 8) as *const u64);
                        si += 1;
                    }
                }
                // ELR_EL1 = sr(13), SPSR_EL1 = sr(14) (sr(i)=SYSREG_SLOT0+i).
                *core::ptr::addr_of_mut!(EL0FLT_W_ELR) = *ctx.add(SYSREG_SLOT0 + 13);
                *core::ptr::addr_of_mut!(EL0FLT_W_SPSR) = *ctx.add(SYSREG_SLOT0 + 14);
                *core::ptr::addr_of_mut!(EL0FLT_W_ESR2) = esr;
                let mut gj = 0usize;
                while gj < 31 {
                    (*core::ptr::addr_of_mut!(EL0FLT_W_X))[gj] = *ctx.add(gj);
                    gj += 1;
                }
                // Read 32 ARM64 opcode words centred on the EXACT faulting
                // instruction (FAULT_OP_PC, stamped per-instruction). Start 4
                // words before so the faulting insn (at +0x10) has context.
                let lgpc = *core::ptr::addr_of!(LAST_GUEST_PC);
                *core::ptr::addr_of_mut!(EL0FLT_W_LGPC) = lgpc;
                // FAULT_OP_PC = exact last guest instruction (per-insn stamp).
                let oppc = *core::ptr::addr_of!(FAULT_OP_PC);
                *core::ptr::addr_of_mut!(EL0FLT_W_OPPC) = oppc;
                // Disasm window centred on the last guest instruction (4 before).
                let blk_base = if oppc >= 16 { oppc - 16 } else { lgpc };
                let sr = core::slice::from_raw_parts(ctx as *const u64, CTX_U64S);
                let mut bi = 0usize;
                while bi < 32 {
                    let va = blk_base.wrapping_add((bi as u64) * 4);
                    if let Ok((ipa, _)) = walk(sr, va, false) {
                        if in_window(ipa) {
                            (*core::ptr::addr_of_mut!(EL0FLT_W_BLK))[bi] =
                                core::ptr::read_volatile(ipa as *const u32) as u64;
                        }
                    }
                    bi += 1;
                }
                *core::ptr::addr_of_mut!(EL0FLT_W_INSN) =
                    (*core::ptr::addr_of!(EL0FLT_W_BLK))[0];
            }
        }
    }
    // SAFETY: EL2-private single-vCPU; diagnostic counters via addr_of.
    unsafe {
        let p = core::ptr::addr_of_mut!(MMU_FAULT_COUNT);
        let prev = *p;
        *p = prev.saturating_add(1);
        if prev == 0 {
            *core::ptr::addr_of_mut!(MMU_FIRST_FAR) = far;
            *core::ptr::addr_of_mut!(MMU_FIRST_ESR) = esr;
        }
        *core::ptr::addr_of_mut!(MMU_LAST_FAR) = far;
        *core::ptr::addr_of_mut!(MMU_LAST_ESR) = esr;
    }
    XLATE_FAULT
}

/// Translate a guest VA to a host PA for a load/store of `size` bytes.
///
/// `ctx` is the live guest register-file base (x86 R15), at least `CTX_U64S`
/// u64s long. Returns the host PA, or [`XLATE_FAULT`] (0) after recording a
/// pending Data Abort in the pending-fault sysreg slots. When the MMU is off
/// (`SCTLR_EL1.M == 0`) translation is flat (VA == PA).
///
/// # Safety
/// `ctx` must point at a valid context buffer of >= `CTX_U64S` u64s; the guest
/// page tables it references must lie in mapped (host-readable) RAM.
#[allow(unsafe_code)]
pub unsafe extern "C" fn aether_mmu_xlate(ctx: *mut u64, va: u64, is_write: u64, size: u64) -> u64 {
    // SAFETY: caller's contract — ctx is the register-file base.
    let sysregs = unsafe { core::slice::from_raw_parts(ctx, CTX_U64S) };
    let is_w = is_write != 0;
    let mmu_on = sysregs[SYSREG_SLOT0 + SLOT_SCTLR] & SCTLR_M != 0;
    // TBI normalization (highest-priority signal-11 fix): strip the ignored top
    // byte BEFORE anything keys off `va` — the TLB (via xlate_page), the walk,
    // the MMIO/window checks, the cross-page span math, and crucially the FAR
    // recorded for injection (record_pending_fault). The kernel's do_page_fault
    // untags FAR_EL1 itself, so injecting the masked VA makes our FAR match what
    // the kernel computes; injecting the raw tagged VA (e.g. Scudo `0xb4..`)
    // would have the kernel demand-page a DIFFERENT address than the one that
    // faulted — the intermittent tagged-pointer SEGV_ACCERR. Only masks when the
    // regime's TBI bit is set; bit 55 (TTBR0/TTBR1 selector) is preserved.
    let va = tbi_mask_va(sysregs, va);
    // Materialise any deferred cross-page STORE scatter before this access reads
    // or writes guest RAM (it may target the very bytes just stored).
    flush_scatter();
    if MMU_DIAG {
        watch_capture_pending();
        // Phase-G: log xlate-for-write calls that fall in the eBPF buffer range.
        // STP / wide-Q stores go through here and write to host RAM directly,
        // bypassing aether_mmu_store — so the simple store-tracker would miss
        // them. Value is unknown at xlate time (the caller emits raw mov-to-pa
        // after we return), but the (pc, va, size) tuple is enough to identify
        // which guest PC wrote which slot.
        if is_w {
            ebpf_store_record(va, 0xFFFF_FFFF_FFFF_FFFFu64, (size.max(1) as u8) | 0x80);
        }
    }

    // Resolve the guest PA of the first byte: flat when the MMU is off, else a
    // TLB-cached single-page walk.
    let pa = if !mmu_on {
        va
    } else {
        match xlate_page(sysregs, va, is_w) {
            Ok(pa) => pa,
            Err((kind, level)) => return record_pending_fault(ctx, va, kind, level, is_w),
        }
    };
    // [wstore] the xlate-for-write path (vector/pair stores; the caller writes
    // the bytes after we return) — catch hits to the watched PTE slot.
    if MMU_DIAG && is_w {
        // SAFETY: EL2-private single-vCPU diagnostic counters.
        unsafe {
            // [vwatch] VA-watch on the xlate-for-write store path (value is written
            // by the caller; capture the corruptor's PC + x30 + hit count).
            let wva = *core::ptr::addr_of!(WATCH_VA);
            if wva != 0 && (va & !7) == wva {
                *core::ptr::addr_of_mut!(WATCH_VA_PC) = *core::ptr::addr_of!(LAST_GUEST_PC);
                *core::ptr::addr_of_mut!(WATCH_VA_X30) = sysregs[30];
                *core::ptr::addr_of_mut!(WATCH_VA_HITS) =
                    (*core::ptr::addr_of!(WATCH_VA_HITS)).saturating_add(1);
                let ri = (*core::ptr::addr_of!(WATCH_VA_RING_IDX) % 8) as usize;
                (*core::ptr::addr_of_mut!(WATCH_VA_RING_PC))[ri] =
                    *core::ptr::addr_of!(LAST_GUEST_PC);
                // value is written by the caller after we return — mark 0xX so we
                // know it was the xlate-write path.
                (*core::ptr::addr_of_mut!(WATCH_VA_RING_VAL))[ri] = 0xFFFF_FFFF_FFFF_FFFF;
                *core::ptr::addr_of_mut!(WATCH_VA_RING_IDX) =
                    (*core::ptr::addr_of!(WATCH_VA_RING_IDX)).wrapping_add(1);
            }
            let wpa = *core::ptr::addr_of!(WATCH_PA);
            if wpa != 0 && (pa & !7) == wpa {
                *core::ptr::addr_of_mut!(WATCH_XLATE_W_HITS) =
                    (*core::ptr::addr_of!(WATCH_XLATE_W_HITS)).saturating_add(1);
                // Stash for deferred read-back (caller writes the value next).
                *core::ptr::addr_of_mut!(WATCH_XLW_PENDING) = pa & !7;
                *core::ptr::addr_of_mut!(WATCH_XLW_PC) =
                    *core::ptr::addr_of!(LAST_GUEST_PC);
                // x30 = ctx GPR slot 30 (GPR_OFFSET=0): the caller's return addr.
                *core::ptr::addr_of_mut!(WATCH_XLW_X30) = sysregs[30];
                // x1 = the PTE pointer move_page_tables is clearing. Constant
                // across dumps => the move loop isn't advancing (DBT loop bug);
                // varying => move_page_tables re-entered. x29 = frame ptr (its
                // saved LR at [x29+8] is the real caller).
                *core::ptr::addr_of_mut!(WATCH_XLW_X1) = sysregs[1];
                *core::ptr::addr_of_mut!(WATCH_XLW_X29) = sysregs[29];
                // Resolve [x29+8] = move_page_tables' saved LR = its caller.
                if let Ok(capa) = xlate_page(sysregs, sysregs[29].wrapping_add(8), false) {
                    *core::ptr::addr_of_mut!(WATCH_XLW_CALLER) =
                        core::ptr::read_volatile(capa as *const u64);
                }
                *core::ptr::addr_of_mut!(WATCH_R4) = sysregs[4];
                *core::ptr::addr_of_mut!(WATCH_R27) = sysregs[27];
                *core::ptr::addr_of_mut!(WATCH_R28) = sysregs[28];
                *core::ptr::addr_of_mut!(WATCH_R24) = sysregs[24];
                *core::ptr::addr_of_mut!(WATCH_NZCV) = sysregs[33];
            }
        }
    }

    // ── MMIO device window (M4b-5) ───────────────────────────────────────────
    // An access whose PA lands in the emulated-device allow-list is routed to
    // the device emulator, never dereferenced as host RAM.
    if is_mmio(pa) {
        if is_w {
            // A WRITE reaching the xlate path is a PAIR/EXCLUSIVE store to a
            // device register (single `STR` uses `aether_mmu_store`, which
            // forwards the value). Pair/exclusive MMIO is not a real guest
            // pattern — fail loud (pending Data Abort) rather than corrupt RAM
            // or silently drop the write.
            return record_pending_fault(ctx, va, FaultKind::Translation, 3, true);
        }
        // READ: emulate now and park the value in the MMIO scratch slot; return
        // its host address so the caller's `mov rd, [rax]` picks it up (the
        // load-deref ABI is unchanged). Single loads are ≤ 8 bytes.
        let val = mmio_dispatch(pa, size.max(1), false, 0);
        // SAFETY: SLOT_MMIO_SCRATCH is an in-bounds free sysreg slot of ctx.
        unsafe {
            *ctx.add(SYSREG_SLOT0 + SLOT_MMIO_SCRATCH) = val;
            return ctx.add(SYSREG_SLOT0 + SLOT_MMIO_SCRATCH) as u64;
        }
    }

    // ── RAM ──
    if !mmu_on {
        // FLAT (MMU off): pa == va. The walked path confines every leaf PA via
        // `finish_leaf`'s `in_window` clamp, but the flat path performs no walk.
        // Without this clamp a guest LDR whose base register holds any host
        // address (hypervisor .text, the JIT cache, VMCB/HSAVE, the page tables)
        // is an arbitrary host READ in VMX-root / SVM-host mode — a No-Boundary
        // breach (Ch.3 invariants 1 & 2). The GKI kernel runs all of early boot
        // (head.S, page-table setup) flat before `__enable_mmu`, so this is the
        // common first path, not an edge. MMIO was already handled+returned
        // above. Confine the WHOLE span to the pinned guest window; the window
        // is a single contiguous range, so checking both endpoints suffices
        // (a flat access is PA-contiguous by construction).
        let last = va.wrapping_add(size.max(1) - 1);
        if !in_window(va) || !in_window(last) {
            return record_pending_fault(ctx, va, FaultKind::Translation, 0, is_w);
        }
        return pa; // flat (== va): contiguous by construction, no span check.
    }

    // CROSS-PAGE SPAN (M4b-2b): a multi-byte access whose last byte lands on a
    // different page must have THAT page mapped too AND physically contiguous
    // with the first. The guest's two consecutive VA pages can map to
    // non-adjacent PAs, so a single host access of `size` bytes based at `pa`
    // would otherwise read/write the wrong second page — silent corruption, and
    // a No-Boundary escape if that stray page is one the access never intended.
    // Confirm contiguity; reflect a Translation fault if the span is mapped but
    // discontiguous, or if the second page is MMIO while the first is RAM (a
    // single host access cannot serve a split RAM/MMIO span). `size` is clamped
    // to ≥ 1 so a zero-size probe never underflows. Page-granular fetches
    // (4-byte, 4-aligned) never span, so this path is data-only.
    let sz = size.max(1);
    let span = sz - 1;
    let last = va.wrapping_add(span);
    if (va >> 12) != (last >> 12) {
        let pa_last = match xlate_page(sysregs, last, is_w) {
            Ok(pa) => pa,
            // CRITICAL: report the faulting address in the SECOND page (`last`),
            // NOT the access start (`va`). When a cross-page LDP/LDR-Q straddles a
            // page boundary and the second page is unmapped, reporting `va` makes
            // the kernel demand-page the FIRST page (already present) and never the
            // second → do_page_fault is a no-op and the guest re-faults forever on
            // the same straddling access (seen as an 11.5k× loop on far=…fff8 with
            // the second page perpetually absent). `last` is inside the unmapped
            // page so the kernel faults in the right one and the access completes.
            Err((kind, level)) => return record_pending_fault(ctx, last, kind, level, is_w),
        };
        if is_mmio(pa_last) {
            // A split RAM/MMIO span can't be served by one host access, and a
            // device half can't be bounced — fail loud.
            return record_pending_fault(ctx, va, FaultKind::Translation, 3, is_w);
        }
        if pa_last != pa.wrapping_add(span) {
            // Mapped but PA-DISCONTIGUOUS. Both guest pages ARE present (the
            // kernel can't help — injecting a fault just spins the guest on the
            // straddling LDP/STP/LDR-Q forever), so serve the span via the
            // 16-byte bounce buffer when it fits. Wider non-contiguous spans
            // (LDP-Q/LD4) stay loud until the scratch is widened.
            if sz > SPAN_SCRATCH_MAX {
                return record_pending_fault(ctx, va, FaultKind::Translation, 3, is_w);
            }
            let n1 = 0x1000 - (va & 0xFFF); // bytes resident in page 1
            let n2 = sz - n1; // bytes resident in page 2
            let pa2_base = pa_last & !0xFFFu64; // page-2 host PA base
            // SAFETY: `pa`/`pa2_base` were confined to the guest window by
            // `xlate_page`; the scratch is two in-bounds free ctx slots.
            let scratch = unsafe { ctx.add(SYSREG_SLOT0 + SLOT_SPAN_SCRATCH) as *mut u8 };
            if is_w {
                // STORE: hand the caller the bounce buffer and DEFER the scatter
                // (no post-write hook). flush_scatter() at the next entry copies
                // the written bytes back to the two pages.
                unsafe {
                    *core::ptr::addr_of_mut!(SCATTER_SRC) = scratch as *const u8;
                    *core::ptr::addr_of_mut!(SCATTER_PA1) = pa;
                    *core::ptr::addr_of_mut!(SCATTER_N1) = n1;
                    *core::ptr::addr_of_mut!(SCATTER_PA2) = pa2_base;
                    *core::ptr::addr_of_mut!(SCATTER_N2) = n2;
                    *core::ptr::addr_of_mut!(SCATTER_PENDING) = true;
                    *core::ptr::addr_of_mut!(SCATTER_SET_COUNT) =
                        (*core::ptr::addr_of!(SCATTER_SET_COUNT)).wrapping_add(1);
                }
                return scratch as u64;
            }
            // LOAD: gather both pages' bytes into the bounce buffer NOW and
            // return its host address; the caller's `mov rd,[rax]` / `movdqu`
            // reads the contiguous copy.
            // SAFETY: in-window source PAs; `n1 + n2 == sz <= 16` fits the slot.
            unsafe {
                core::ptr::copy_nonoverlapping(pa as *const u8, scratch, n1 as usize);
                core::ptr::copy_nonoverlapping(
                    pa2_base as *const u8,
                    scratch.add(n1 as usize),
                    n2 as usize,
                );
            }
            return scratch as u64;
        }
    }
    // Phase-E: vmemmap LOAD tracer — record (va, pa, 0, size) so we can
    // compare the LOAD PA against the matching STORE PA for the same VA.
    // Stores carry the value field; loads carry 0 (the value isn't known
    // here, the caller does the actual read via the returned pa pointer).
    if MMU_DIAG && !is_w {
        vmm_trace_record(va, pa, 0, size.max(1) as u8, 0);
        // Phase-G x30-hunt: capture the physical value this load is about to
        // read (incl. LDP pair loads, which route through here) for the armed
        // stack-slot window. Lets the dispatcher tell a load-side miscompile
        // (slot value correct, dest reg wrong) from a store-side one.
        ebpf_load_record(va, pa, size.max(1));
    }
    pa
}

/// Store `value` (`size` bytes) to guest VA `va`, routing the emulated-device
/// MMIO allow-list to the registered handler and RAM to host memory. Returns a
/// non-zero "ok" sentinel ([`MMIO_STORE_OK`]) on success, or [`XLATE_FAULT`] (0)
/// after recording a pending Data Abort.
///
/// This is the single-`STR` counterpart to [`aether_mmu_xlate`]: it BOTH
/// translates AND performs the store, because an MMIO target's value is only
/// known at store time — a translate-then-`mov [pa],rs` split (as loads use)
/// would write the value to a scratch cell that never reaches the device. RAM
/// semantics are bit-identical to the old `mov [pa], rs` (a sized
/// `write_volatile`).
///
/// # Safety
/// Same contract as [`aether_mmu_xlate`].
/// [wstore] PTE-write watch. boot_x86.rs sets `WATCH_PA` to the L3 descriptor PA
/// of the looping anon-write fault; `aether_mmu_store` records the last value +
/// hit count written to that 8-byte slot. Answers "does the kernel ever install
/// a valid leaf PTE there?" — 0 hits => do_anonymous_page bailed before set_pte;
/// hits with a valid PTE while the walker still reads 0 => host coherence.
pub static mut WATCH_PA: u64 = 0;
pub static mut WATCH_VAL: u64 = 0;
pub static mut WATCH_HITS: u64 = 0;
/// [vwatch] VA-based store watchpoint for the fork-path SLUB-freelist corruptor.
/// boot_x86 sets `WATCH_VA` to the corrupted vm_area_struct freepointer VA
/// (object_VA + 0x60, from the slub_debug=F report); `aether_mmu_store` records
/// the guest PC + value + x30 of EVERY store that hits it, so the FIRST hit whose
/// value is a garbage (obfuscated) freelist pointer names the corrupting block.
pub static mut WATCH_VA: u64 = 0;
/// [vma] last vm_area_struct returned by kmem_cache_alloc in vm_area_dup (set by
/// the boot_x86 PC hook at vm_area_dup+0x2c). At the fork-corruption fault this
/// holds the CORRUPTED object — its freepointer (+0x60) was overwritten — so
/// Boot 2 sets WATCH_VA = LAST_VMA_ALLOC + 0x60.
pub static mut LAST_VMA_ALLOC: u64 = 0;
/// [garb] one-shot latch: when the walker is asked to translate a middle-range
/// garbage VA (the SLUB-freelist corruption deref), capture LAST_VMA_ALLOC (= the
/// corrupted object A, since the faulting alloc never updated it) + the garbage
/// VA. Boot 2 then sets WATCH_VA = GARB_LASTVMA + 0x60.
pub static mut GARB_LATCH: u64 = 0;
pub static mut GARB_LASTVMA: u64 = 0;
pub static mut GARB_VA: u64 = 0;
/// [inpage] last kmem_cache_alloc candidate object (x0 at kmem_cache_alloc+0xd4)
/// in the vma slab page 0xffffff801e002000. The faulting alloc's candidate is the
/// garbage pointer (NOT in-page → not recorded), so at the fault this holds the
/// PREVIOUS in-page allocation = the corrupted object whose +0x60 freepointer
/// deobfuscated to garbage. Boot N+1 sets WATCH_VA = LAST_INPAGE_ALLOC + 0x60.
pub static mut LAST_INPAGE_ALLOC: u64 = 0;
/// [casp] one-shot: the LIVE (post-alternative-patch) instruction words at
/// kmem_cache_alloc's cmpxchg_double site (0x831a724/728/72c). Tells us whether
/// the casp survived (LSE) or was patched to LL/SC. Bit32 set = captured.
pub static mut CASP_INSN0: u64 = 0; // [0x831a724]
pub static mut CASP_INSN1: u64 = 0; // [0x831a728] (the casp slot)
pub static mut CASP_INSN2: u64 = 0; // [0x831a72c]
/// [casp-diag] translate-time + runtime flags for the AtomicCasPair lowering.
/// CASP_LOWER_OK: incremented each time the non-spill lowering ran (translate).
/// CASP_LOWER_SPILL: incremented when the spill→UD2 branch ran (translate).
/// CASP_HIT: set to 1 by the JIT'd casp code when it actually EXECUTES (runtime).
pub static CASP_LOWER_OK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static CASP_LOWER_SPILL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static CASP_HIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static mut WATCH_VA_PC: u64 = 0;
pub static mut WATCH_VA_VAL: u64 = 0;
pub static mut WATCH_VA_HITS: u64 = 0;
pub static mut WATCH_VA_X30: u64 = 0;
/// [vwatch] ring of the last 8 stores to WATCH_VA: (guest PC, stored value).
/// The corruptor is the store with a garbage value whose PC is NOT
/// set_freepointer / vm_area_dup — visible in the recent-store sequence.
pub static mut WATCH_VA_RING_PC: [u64; 8] = [0; 8];
pub static mut WATCH_VA_RING_VAL: [u64; 8] = [0; 8];
pub static mut WATCH_VA_RING_IDX: u64 = 0;
/// [wstore] non-aether_mmu_store writes that hit the watched PTE slot: the
/// cross-page scatter, and the xlate-for-write path (vector/pair/caller-direct
/// stores). A hit on either while the PTE keeps reading 0 identifies which path
/// clobbers the kernel's just-written leaf PTE.
pub static mut WATCH_SCATTER_HITS: u64 = 0;
pub static mut WATCH_XLATE_W_HITS: u64 = 0;
/// [wstore] deferred capture of the xlate-for-write store's value: that path
/// returns `pa` and the CALLER writes the bytes after, so we can't see the value
/// in `aether_mmu_xlate`. Instead stash the pa here and read it back on the next
/// MMU entry (before any new write) — `WATCH_XLW_VAL` then holds what the xlate
/// store actually left at the watched PTE slot.
pub static mut WATCH_XLW_PENDING: u64 = 0;
pub static mut WATCH_XLW_VAL: u64 = 0;
/// [wstore] guest block PC of the PTE-writing store (aether_mmu_store) and of
/// the clobbering xlate-for-write store. Same PC => one instruction lowered down
/// BOTH paths (double-store bug); different PCs => two distinct kernel stores.
pub static mut WATCH_STORE_PC: u64 = 0;
pub static mut WATCH_XLW_PC: u64 = 0;
/// [wstore] x30 (link reg) at the clobbering xlate-write store = the return
/// address of whoever CALLED the function containing it. If it points into
/// move_vma (real mremap) init genuinely mremaps; if into do_page_fault /
/// handle_mm_fault, a DBT branch mistranslation jumps into the PTE-clear loop.
pub static mut WATCH_XLW_X30: u64 = 0;
pub static mut WATCH_XLW_X1: u64 = 0;
pub static mut WATCH_XLW_X29: u64 = 0;
/// [wstore] move_page_tables' caller: the saved LR at [x29+8] (its prologue
/// stored {x29,x30}). Symbolize to learn who drives the repeated PTE-clear —
/// move_vma (real mremap) vs an unexpected path.
pub static mut WATCH_XLW_CALLER: u64 = 0;
/// [wstore] move_page_tables loop bounds at the stuck store: inner (x4=cur,
/// x27=end), outer (x28=cur, x24=end), + NZCV (ctx byte 0x108 = u64 idx 33).
/// Sane values that should make the branch exit => NZCV/branch bug; a non-
/// advancing bound => an upstream register-value bug.
pub static mut WATCH_R4: u64 = 0;
pub static mut WATCH_R27: u64 = 0;
pub static mut WATCH_R28: u64 = 0;
pub static mut WATCH_R24: u64 = 0;
pub static mut WATCH_NZCV: u64 = 0;

/// Read back a stashed xlate-for-write target before the next access overwrites
/// it. Called at the top of `aether_mmu_store` / `aether_mmu_xlate`.
#[inline(always)]
#[allow(unsafe_code)]
fn watch_capture_pending() {
    // SAFETY: EL2-private single-vCPU diagnostic; the stashed pa was in-window.
    unsafe {
        let p = *core::ptr::addr_of!(WATCH_XLW_PENDING);
        if p != 0 {
            *core::ptr::addr_of_mut!(WATCH_XLW_VAL) =
                core::ptr::read_volatile(p as *const u64);
            *core::ptr::addr_of_mut!(WATCH_XLW_PENDING) = 0;
        }
    }
}

#[allow(unsafe_code)]
pub unsafe extern "C" fn aether_mmu_store(ctx: *mut u64, va: u64, size: u64, value: u64) -> u64 {
    // SAFETY: caller's contract — ctx is the register-file base.
    let sysregs = unsafe { core::slice::from_raw_parts(ctx, CTX_U64S) };
    let mmu_on = sysregs[SYSREG_SLOT0 + SLOT_SCTLR] & SCTLR_M != 0;
    // TBI normalization (see aether_mmu_xlate): strip the ignored top byte so a
    // tagged STORE (Scudo writes through `0xb4..` pointers) keys the TLB, walks,
    // checks windows/spans, and — on fault — records FAR identically to its
    // untagged twin. Masking before the watch/span/fault logic keeps them aligned.
    let va = tbi_mask_va(sysregs, va);

    // (SLAB cpu-partial self-cycle catcher removed — the CAS-width fix resolved
    // the put_cpu_partial deadlock; boot now proceeds into Android userspace.)

    // [svwatch] store-VALUE watch — catch where the corrupted code pointer is
    // written (low 56 bits, so a tagged/sign-variant still matches).
    // SAFETY: EL2-private statics, single-vCPU.
    if MMU_DIAG { unsafe {
        let sw = *core::ptr::addr_of!(SV_WATCH);
        if sw != 0 && (value & 0x00FF_FFFF_FFFF_FFFF) == sw {
            let i = (*core::ptr::addr_of!(SV_WATCH_IDX) % 8) as usize;
            (*core::ptr::addr_of_mut!(SV_WATCH_PC))[i] = *core::ptr::addr_of!(FAULT_OP_PC);
            (*core::ptr::addr_of_mut!(SV_WATCH_ADDR))[i] = va;
            (*core::ptr::addr_of_mut!(SV_WATCH_VAL))[i] = value;
            (*core::ptr::addr_of_mut!(SV_WATCH_X30))[i] = *ctx.add(30);
            *core::ptr::addr_of_mut!(SV_WATCH_IDX) =
                (*core::ptr::addr_of!(SV_WATCH_IDX)).wrapping_add(1);
            *core::ptr::addr_of_mut!(SV_WATCH_HITS) =
                (*core::ptr::addr_of!(SV_WATCH_HITS)).saturating_add(1);
        }
    }}
    // Materialise any deferred cross-page STORE scatter before this store runs.
    flush_scatter();
    if MMU_DIAG {
        watch_capture_pending();
    }

    let pa = if !mmu_on {
        va
    } else {
        match xlate_page(sysregs, va, true) {
            Ok(pa) => pa,
            Err((kind, level)) => return record_pending_fault(ctx, va, kind, level, true),
        }
    };
    // [wstore] watch: record writes to the watched PTE slot (set from the [uflt]
    // loop dump). The kernel's WRITE_ONCE(*ptep, pte) is a single 8-byte STR.
    if MMU_DIAG { unsafe {
        let wpa = *core::ptr::addr_of!(WATCH_PA);
        if wpa != 0 && (pa & !7) == wpa {
            *core::ptr::addr_of_mut!(WATCH_VAL) = value;
            *core::ptr::addr_of_mut!(WATCH_HITS) =
                (*core::ptr::addr_of!(WATCH_HITS)).saturating_add(1);
            *core::ptr::addr_of_mut!(WATCH_STORE_PC) =
                *core::ptr::addr_of!(LAST_GUEST_PC);
        }
        // [vwatch] VA-based watchpoint: the corruptor stores garbage to the vma
        // freepointer (object_VA+0x60) while it's free; nothing else writes there
        // before the fatal alloc-read, so the LAST store captured here is it.
        let wva = *core::ptr::addr_of!(WATCH_VA);
        if wva != 0 && (va & !7) == wva {
            *core::ptr::addr_of_mut!(WATCH_VA_VAL) = value;
            *core::ptr::addr_of_mut!(WATCH_VA_PC) = *core::ptr::addr_of!(LAST_GUEST_PC);
            *core::ptr::addr_of_mut!(WATCH_VA_X30) = sysregs[30];
            *core::ptr::addr_of_mut!(WATCH_VA_HITS) =
                (*core::ptr::addr_of!(WATCH_VA_HITS)).saturating_add(1);
            let ri = (*core::ptr::addr_of!(WATCH_VA_RING_IDX) % 8) as usize;
            (*core::ptr::addr_of_mut!(WATCH_VA_RING_PC))[ri] =
                *core::ptr::addr_of!(LAST_GUEST_PC);
            (*core::ptr::addr_of_mut!(WATCH_VA_RING_VAL))[ri] = value;
            *core::ptr::addr_of_mut!(WATCH_VA_RING_IDX) =
                (*core::ptr::addr_of!(WATCH_VA_RING_IDX)).wrapping_add(1);
        }
    }}

    if is_mmio(pa) {
        let _ = mmio_dispatch(pa, size.max(1), true, value);
        return MMIO_STORE_OK;
    }

    // RAM: cross-page contiguity (walked path only) then a sized write.
    let sz = size.max(1);
    if mmu_on {
        let span = sz - 1;
        let last = va.wrapping_add(span);
        if (va >> 12) != (last >> 12) {
            let pa_last = match xlate_page(sysregs, last, true) {
                Ok(pa) => pa,
                // Report the SECOND page's fault at `last`, not the access start
                // `va` — see the matching note in the load path. A cross-page STORE
                // whose second page is unmapped otherwise loops forever (kernel
                // faults in the already-present first page).
                Err((kind, level)) => return record_pending_fault(ctx, last, kind, level, true),
            };
            if is_mmio(pa_last) {
                return record_pending_fault(ctx, va, FaultKind::Translation, 3, true);
            }
            if pa_last != pa.wrapping_add(span) {
                // DISCONTIGUOUS RAM: both pages are mapped, so faulting would
                // just spin the guest on the straddling store. We hold the
                // value here — split it across the two pages byte-wise (LE).
                let n1 = 0x1000 - (va & 0xFFF);
                let pa2_base = pa_last & !0xFFFu64;
                if MMU_DIAG {
                    vmm_trace_record(va, pa, value, sz as u8, 1);
                    ebpf_store_record(va, value, sz as u8);
                }
                // SAFETY: both PAs were confined to the guest window by the
                // walk; `sz <= 8` so the shift never exceeds 56.
                unsafe {
                    let mut i = 0u64;
                    while i < sz {
                        let b = (value >> (8 * i)) as u8;
                        let dst = if i < n1 { pa + i } else { pa2_base + (i - n1) };
                        core::ptr::write_volatile(dst as *mut u8, b);
                        i += 1;
                    }
                }
                return MMIO_STORE_OK;
            }
        }
    } else {
        // FLAT (MMU off): No-Boundary clamp on the WRITE primitive — the whole
        // span must lie in the pinned guest window (MMIO already handled+
        // returned above). Without it a flat STR to a host address (hypervisor
        // .text, the JIT cache, VMCB/HSAVE, NPT/EPT tables) is an arbitrary host
        // WRITE in VMX-root / SVM-host mode = total compromise (Ch.3). The
        // window is a single contiguous range so both-endpoints suffices.
        let last = va.wrapping_add(sz - 1);
        if !in_window(va) || !in_window(last) {
            return record_pending_fault(ctx, va, FaultKind::Translation, 0, true);
        }
    }
    // Phase-E: vmemmap store tracer — record (va, pa, value, size) so the
    // hypervisor can verify the kernel's store actually landed where the
    // load expects to read it from.
    if MMU_DIAG {
        vmm_trace_record(va, pa, value, sz as u8, 1);
        ebpf_store_record(va, value, sz as u8);
    }
    // SAFETY: `pa` is an in-window guest PA == identity host RAM (the walk /
    // flat path established it is not MMIO and, when walked, is in-window).
    unsafe {
        match sz {
            1 => core::ptr::write_volatile(pa as *mut u8, value as u8),
            2 => core::ptr::write_volatile(pa as *mut u16, value as u16),
            4 => core::ptr::write_volatile(pa as *mut u32, value as u32),
            _ => core::ptr::write_volatile(pa as *mut u64, value),
        }
        // Phase-E: immediate read-back verification. If the host store
        // didn't persist (cache type / unmapped / dropped write), record
        // a SECOND ring entry with kind=2 (MISMATCH) and the actual
        // value read. The dumper distinguishes kinds. Purely diagnostic
        // (records a trace entry; no guest-visible effect), so gated off
        // on the production hot path — it doubled every store with a read.
        if MMU_DIAG {
            let readback: u64 = match sz {
                1 => core::ptr::read_volatile(pa as *const u8) as u64,
                2 => core::ptr::read_volatile(pa as *const u16) as u64,
                4 => core::ptr::read_volatile(pa as *const u32) as u64,
                _ => core::ptr::read_volatile(pa as *const u64),
            };
            let expect_mask: u64 = match sz {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFFFFFF,
                _ => !0u64,
            };
            if (readback & expect_mask) != (value & expect_mask) {
                vmm_trace_record(va, pa, readback, sz as u8, 2);
            }
        }
    }
    MMIO_STORE_OK
}

/// Translate a guest VA `pc` to a host PA for an INSTRUCTION FETCH.
///
/// This is the fetch-path counterpart to [`aether_mmu_xlate`] (the data path).
/// M4b-2c: once the guest enables its MMU (`SCTLR_EL1.M == 1`) the PC at an NPF
/// is a VIRTUAL address, so the instruction bytes to translate must be read
/// from the WALKED physical address, not the raw PC. The DBT dispatcher calls
/// this to obtain the PA, then reads the guest instruction stream from the host
/// window at that PA. The JIT block-cache key stays the VA `pc` — ONLY the byte
/// source changes here.
///
/// Behaviour:
///   * `SCTLR_EL1.M == 0` (early boot, MMU off): returns `pc` unchanged (flat).
///   * `M == 1`, walk succeeds: returns the host PA (== guest PA in the handoff
///     identity window), reusing the same 256-entry software TLB as the data
///     path. The walk is page-granular, so a 4-byte instruction never spans the
///     page boundary the PA encodes.
///   * `M == 1`, walk faults: returns [`XLATE_FAULT`] (0) after recording a
///     pending abort in the pending-fault slots — but re-stamped as an
///     INSTRUCTION Abort (`ESR_EL1.EC = 0x21`) rather than the Data Abort
///     (`EC = 0x25`) the underlying [`aether_mmu_xlate`] writes, so M4b-3 routes
///     it to the instruction-abort handling with the correct syndrome. FAR_EL1
///     still carries the faulting VA (`pc`).
///
/// NOTE (deferred, documented follow-up): this reuses the data-side walk, which
/// checks the access flag and `AP[2]` (write permission) but NOT the execute
/// permissions (`PXN`/`UXN`). A fetch from an XN page would therefore translate
/// rather than fault here. A stricter exec-permission check is a follow-up; for
/// the GKI bring-up path (text pages are executable) this is correct.
///
/// # Safety
/// Same contract as [`aether_mmu_xlate`]: `ctx` must point at a valid context
/// buffer of `>= CTX_U64S` u64s whose page tables lie in host-readable RAM.
#[allow(unsafe_code)]
pub unsafe extern "C" fn aether_mmu_fetch_pa(ctx: *mut u64, pc: u64) -> u64 {
    // Delegate the actual walk/TLB to the proven data path (is_write = 0,
    // size = 4 — one ARM64 instruction).
    // SAFETY: caller's contract is forwarded verbatim.
    let pa = unsafe { aether_mmu_xlate(ctx, pc, 0, 4) };
    if pa != XLATE_FAULT {
        return pa;
    }
    // Fault: aether_mmu_xlate has already set PEND_PENDING/FAR and an ESR with
    // EC = Data Abort. Re-stamp the EC to Instruction Abort, leaving the fault
    // class / level (xFSC) and IL bits intact. FAR already holds `pc`.
    // SAFETY: the data path established the pending slots are populated and the
    // ctx has the free pending-fault sysreg slots; we only rewrite the ESR slot.
    unsafe {
        let esr_slot = ctx.add(SYSREG_SLOT0 + SLOT_PEND_ESR);
        let esr = *esr_slot;
        *esr_slot = esr_with_ec(esr, ESR_EC_INST_ABORT_SAME_EL);
    }
    XLATE_FAULT
}

#[cfg(test)]
#[allow(unsafe_code)] // tests build real page tables in host memory + call the FFI entry
mod tests {
    use super::*;
    use crate::runtime::context::CTX_U64S;
    use std::alloc::{alloc_zeroed, Layout};
    use std::sync::Mutex;

    // The walker uses process-global state (the software TLB + the configured
    // window), so the tests must run serially. This mutex serializes them and
    // recovers from poison (a panicking test must not wedge the rest).
    static MMU_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the serialization lock, flush the TLB, and open the window wide
    /// so geometry tests can use host-allocated tables (whose addresses are not
    /// in the production guest window). Clamp tests re-narrow the window after.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = MMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Flush the process-global software TLB so a prior test's cached
        // translations cannot leak into this one. (This line previously read
        // `let _g = setup();` — an unconditional self-recursive call that
        // dead-locked/overflowed every MMU test before it could run.)
        aether_mmu_flush_all();
        // SAFETY: serialized by the lock; drop any cross-page scatter a prior
        // test queued but did not flush, so it cannot apply into this test.
        unsafe { *core::ptr::addr_of_mut!(SCATTER_PENDING) = false; }
        aether_mmu_set_window(0, u64::MAX); // clamp effectively disabled
        g
    }

    /// A 4 KiB-aligned page of 512 u64 descriptors whose host address doubles
    /// as the "guest PA" (the handoff-window identity invariant). Leaked for
    /// the test's lifetime so the pointer stays valid.
    fn alloc_table() -> (u64, &'static mut [u64]) {
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: non-zero layout; we leak the allocation for the test run.
        let p = unsafe { alloc_zeroed(layout) } as *mut u64;
        assert!(!p.is_null());
        let slice = unsafe { core::slice::from_raw_parts_mut(p, 512) };
        (p as u64, slice)
    }

    /// A contiguous, 4 KiB-aligned arena of `pages` descriptor pages, returned
    /// as (base_pa, [page0, page1, ...]). Used by the clamp tests so all tables
    /// fit inside a narrow window the test then pins.
    fn alloc_arena(pages: usize) -> (u64, Vec<&'static mut [u64]>) {
        let layout = Layout::from_size_align(4096 * pages, 4096).unwrap();
        // SAFETY: non-zero layout; leaked for the test run.
        let base = unsafe { alloc_zeroed(layout) } as u64;
        assert!(base != 0);
        let mut tables = Vec::with_capacity(pages);
        for i in 0..pages {
            let p = (base + (i as u64) * 4096) as *mut u64;
            // SAFETY: in-bounds page of the arena.
            tables.push(unsafe { core::slice::from_raw_parts_mut(p, 512) });
        }
        (base, tables)
    }

    fn table_desc(next_pa: u64) -> u64 {
        (next_pa & ADDR_MASK) | 0b11 // valid + table
    }
    /// Leaf page/block: valid + (page bit at L3) + AF, optional read-only.
    fn leaf_desc(oa: u64, page_bit: bool, read_only: bool) -> u64 {
        let mut d = (oa & ADDR_MASK) | 0b01 | (1 << 10); // valid + AF
        if page_bit {
            d |= 0b10; // level-3 page (bit1=1)
        }
        if read_only {
            d |= 1 << 7; // AP[2]
        }
        d
    }

    fn ctx_with_ttbr0(ttbr0: u64, mmu_on: bool) -> Vec<u64> {
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_TTBR0] = ttbr0;
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = if mmu_on { SCTLR_M } else { 0 };
        ctx
    }

    /// Build a 4-level table chain mapping `va` to a 4 KiB page at `pa`.
    /// Returns (ttbr0, ctx). `read_only` sets AP[2] on the leaf.
    fn map_4k(va: u64, pa: u64, read_only: bool) -> (u64, Vec<u64>) {
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(pa, true, read_only);
        (l0_pa, ctx_with_ttbr0(l0_pa, true))
    }

    /// Build a 4-level chain mapping `va` AND `va + 0x1000` to PHYSICALLY
    /// CONTIGUOUS pages `pa` and `pa + 0x1000`, sharing L0/L1/L2/L3 (so `va`
    /// must not be the last 4 KiB page of its L3 table). Used by the cross-page
    /// span tests. Returns (ttbr0, ctx) with the MMU on.
    fn map_4k_2pages(va: u64, pa: u64) -> (u64, Vec<u64>) {
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(pa, true, false);
        l3[(((va + 0x1000) >> 12) & 0x1FF) as usize] = leaf_desc(pa + 0x1000, true, false);
        (l0_pa, ctx_with_ttbr0(l0_pa, true))
    }

    #[test]
    fn walk_4k_page() {
        let _g = setup();
        let va = 0x1234_5678_9000;
        let pa = 0x8042_3000;
        let (_ttbr, ctx) = map_4k(va, pa, false);
        let (got, w) = walk(&ctx, va, false).expect("4K walk");
        assert_eq!(got, pa | 0x000, "page base");
        assert!(w, "RW leaf");
        // offset preserved within the page
        let (got2, _) = walk(&ctx, va | 0xABC, false).expect("4K walk off");
        assert_eq!(got2, pa | 0xABC, "page offset preserved");
    }

    /// TBI (Top-Byte-Ignore) normalization: with `TCR_EL1.TBI0 = 1` a TAGGED
    /// low VA (top byte != 0 — e.g. Scudo's `0xb4..` heap tag) must resolve to
    /// the SAME PA as its untagged form. This is the highest-priority signal-11
    /// fix: a tagged access and its untagged twin previously got different TLB
    /// entries / divergent FAR, producing the intermittent tagged-pointer
    /// SEGV_ACCERR. The walk must strip bits [63:56] for translation.
    #[test]
    fn walk_tbi_tagged_va_resolves_like_untagged() {
        let _g = setup();
        // A TTBR0 (low) VA — bit 55 clear so the TTBR0 regime + TBI0 apply.
        let va = 0x0000_5678_9ABC_D000;
        let pa = 0x8054_2000;
        let (_ttbr, mut ctx) = map_4k(va, pa, false);
        // Enable TBI0 (TCR_EL1 bit 37). Without this the top byte is significant
        // and the tagged VA would (correctly) NOT match — so the bit gates the mask.
        ctx[SYSREG_SLOT0 + SLOT_TCR] |= TCR_TBI0;

        // Baseline: untagged resolves.
        let (untagged, _) = walk(&ctx, va, false).expect("untagged walk");
        assert_eq!(untagged, pa, "untagged VA resolves to PA");

        // Tag the top byte (0xb4 — the exact Scudo tag from the apexd crash) and
        // add an in-page offset; the tagged access must resolve to the same page.
        let tagged = (0xB4u64 << 56) | va | 0x123;
        let (got, w) = walk(&ctx, tagged, false).expect("tagged walk resolves");
        assert_eq!(got, pa | 0x123, "tagged VA resolves to same PA (TBI strips tag)");
        assert!(w, "writability preserved across tag strip");

        // And it goes through the full xlate path identically (TLB key untagged).
        let mut c = ctx.clone();
        let host = unsafe {
            aether_mmu_xlate(c.as_mut_ptr(), tagged, 0, 8)
        };
        assert_ne!(host, XLATE_FAULT, "tagged xlate must not fault");
        assert_eq!(host, pa | 0x123, "tagged xlate resolves to untagged PA");

        // The mask is GATED on the TBI bit. With TBI0 set, the helper strips the
        // top byte; with it clear, the VA is returned verbatim. (The software
        // walker only indexes bits [47:0], so the gate is observable via the
        // helper, which is what keys the TLB and the injected FAR.)
        assert_eq!(
            tbi_mask_va(&ctx, tagged),
            va | 0x123,
            "TBI0 set: top byte stripped, bit 55 + low bits preserved"
        );
        let mut ctx_off = ctx.clone();
        ctx_off[SYSREG_SLOT0 + SLOT_TCR] &= !TCR_TBI0;
        assert_eq!(
            tbi_mask_va(&ctx_off, tagged),
            tagged,
            "TBI0 clear: VA returned unchanged (mask gated)"
        );
        // A high (TTBR1) VA uses TBI1, not TBI0: with only TBI0 set, a tagged
        // kernel VA is NOT stripped; bit 55 (regime selector) is never cleared.
        let kva_tagged = (0xAAu64 << 56) | 0x0080_0000_0000_1000;
        assert_eq!(
            tbi_mask_va(&ctx, kva_tagged),
            kva_tagged,
            "TBI0 set but high VA uses TBI1 (off) → unchanged"
        );
    }

    /// TBI staleness guard: a tagged STORE and an untagged LOAD of the same
    /// architectural page must hit ONE TLB entry (the entry is keyed on the
    /// untagged page). Exercises the `xlate_page` TLB key under TBI.
    #[test]
    fn xlate_tbi_tagged_and_untagged_share_tlb_entry() {
        let _g = setup();
        let va = 0x0000_0001_2233_4000;
        let pa = 0x8061_0000;
        let (_ttbr, mut ctx) = map_4k(va, pa, false);
        ctx[SYSREG_SLOT0 + SLOT_TCR] |= TCR_TBI0;

        // Untagged xlate first (fills the TLB on the untagged page).
        let h0 = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), va, 0, 8) };
        assert_eq!(h0, pa, "untagged fills TLB");
        // Differently-tagged access to the same page resolves identically (hit).
        let tagged = (0x7Fu64 << 56) | va;
        let h1 = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), tagged, 0, 8) };
        assert_eq!(h1, pa, "tagged hits the same untagged TLB entry");
    }

    /// Forked-process TTBR0 staleness guard: a low-VA entry cached under one
    /// TTBR0 (the parent) must NOT be served to a different TTBR0 (a forked
    /// child) at the same page#, even without an intervening flush. The TLB
    /// carries the live TTBR0 as an address-space tag.
    #[test]
    fn xlate_ttbr0_asid_tag_isolates_forked_child() {
        let _g = setup();
        let va = 0x0000_0000_4455_6000;
        let pa_parent = 0x8070_0000;
        let pa_child = 0x8071_0000;
        // Parent address space.
        let (parent_ttbr, mut parent_ctx) = map_4k(va, pa_parent, false);
        let hp = unsafe { aether_mmu_xlate(parent_ctx.as_mut_ptr(), va, 0, 8) };
        assert_eq!(hp, pa_parent, "parent resolves + caches");

        // Child: SAME va, DIFFERENT TTBR0 base → different PA. Build a separate
        // table chain mapping the same VA to the child's page, then point a fresh
        // ctx at it WITHOUT flushing the software TLB.
        let (child_ttbr, child_ctx_full) = map_4k(va, pa_child, false);
        assert_ne!(parent_ttbr, child_ttbr, "distinct address spaces");
        let mut child_ctx = child_ctx_full;
        let hc = unsafe { aether_mmu_xlate(child_ctx.as_mut_ptr(), va, 0, 8) };
        assert_eq!(
            hc, pa_child,
            "child must walk fresh (ASID tag rejects the parent's stale entry)"
        );
    }

    #[test]
    fn walk_2m_block() {
        let _g = setup();
        let va = 0x0000_0040_0000_0000 | (3 << 21); // some 2M-aligned-ish VA
        let block_pa = 0x8060_0000; // 2 MiB aligned
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        // level-2 BLOCK descriptor (bit1 == 0).
        l2[((va >> 21) & 0x1FF) as usize] = leaf_desc(block_pa, false, false);
        let ctx = ctx_with_ttbr0(l0_pa, true);
        let off = 0x1_5000u64; // within the 2 MiB block
        let (got, _) = walk(&ctx, va | off, false).expect("2M walk");
        assert_eq!(got, block_pa | off, "2 MiB block PA + offset");
    }

    #[test]
    fn walk_1g_block() {
        let _g = setup();
        // VA aligned to 1 GiB region 5 — no bits below bit 30 so the only block
        // offset comes from `off` (a VA with sub-1GB bits would, correctly,
        // carry them into the PA: that earlier mistake was the test's, not the
        // walker's).
        let va = 5u64 << 30;
        let block_pa = 0x4000_0000; // 1 GiB aligned
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        // level-1 BLOCK descriptor (bit1 == 0) -> 1 GiB.
        l1[((va >> 30) & 0x1FF) as usize] = leaf_desc(block_pa, false, false);
        let ctx = ctx_with_ttbr0(l0_pa, true);
        let off = 0x0123_4000u64;
        let (got, _) = walk(&ctx, va | off, false).expect("1G walk");
        assert_eq!(got, block_pa | off, "1 GiB block PA + offset");
    }

    #[test]
    fn fault_invalid_descriptor() {
        let _g = setup();
        let (l0_pa, _l0) = alloc_table(); // all-zero -> level-0 entry invalid
        let ctx = ctx_with_ttbr0(l0_pa, true);
        let err = walk(&ctx, 0x4000, false).unwrap_err();
        assert_eq!(err, (FaultKind::Translation, 0), "invalid L0 desc -> xlation L0");
    }

    #[test]
    fn fault_access_flag() {
        let _g = setup();
        let va = 0x9_0000u64;
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        // leaf valid+page but AF (bit10) cleared.
        l3[((va >> 12) & 0x1FF) as usize] = (0x8055_0000 & ADDR_MASK) | 0b11;
        let ctx = ctx_with_ttbr0(l0_pa, true);
        let err = walk(&ctx, va, false).unwrap_err();
        assert_eq!(err, (FaultKind::AccessFlag, 3), "AF clear -> access-flag L3");
    }

    #[test]
    fn fault_permission_on_write() {
        let _g = setup();
        let va = 0xA_0000u64;
        let pa = 0x8077_0000;
        let (_ttbr, ctx) = map_4k(va, pa, true); // read-only leaf
        // read OK
        assert!(walk(&ctx, va, false).is_ok(), "RO page readable");
        // write faults
        let err = walk(&ctx, va, true).unwrap_err();
        assert_eq!(err, (FaultKind::Permission, 3), "write to RO -> permission L3");
    }

    #[test]
    fn ttbr1_selected_by_va55() {
        let _g = setup();
        // high VA (bit55 set) must use TTBR1.
        let va = (1u64 << 55) | 0xB_0000;
        let pa = 0x8088_0000;
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(pa, true, false);
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
        ctx[SYSREG_SLOT0 + SLOT_TTBR1] = l0_pa; // only TTBR1 set
        // TCR_EL1 for the TTBR1 regime: TG1=0b10 (4 KiB — note TG1's 4 KiB code
        // is 0b10, NOT TG0's 0b00) at bits[31:30], and T1SZ=16 at bits[21:16]
        // (<=24 -> start level 0, the 4-level walk this test's tables assume).
        // A zero TCR would encode TG1=0b00 (a reserved/non-4-KiB granule for the
        // high regime) and correctly fault out before the walk.
        ctx[SYSREG_SLOT0 + SLOT_TCR] = (0b10u64 << 30) | (16u64 << 16);
        let (got, _) = walk(&ctx, va, false).expect("TTBR1 walk");
        assert_eq!(got, pa, "VA[55]=1 selects TTBR1");
    }

    #[test]
    fn xlate_flat_when_mmu_off() {
        let _g = setup();
        let ctx = ctx_with_ttbr0(0, false); // M=0
        let va = 0x8123_4567u64;
        // SAFETY: ctx is CTX_U64S long.
        let pa = unsafe { aether_mmu_xlate(ctx.as_ptr() as *mut u64, va, 0, 8) };
        assert_eq!(pa, va, "MMU off -> flat VA==PA");
    }

    #[test]
    fn xlate_walks_and_caches_then_faults_pending() {
        let _g = setup();
        let va = 0xC_3000u64;
        let pa = 0x8099_0000;
        let (_ttbr, mut ctx) = map_4k(va, pa, false);
        let p = ctx.as_mut_ptr();
        // first access walks
        let got = unsafe { aether_mmu_xlate(p, va | 0x10, 0, 8) };
        assert_eq!(got, pa | 0x10, "xlate returns PA+offset");
        // second access (same page) is a TLB hit -> same answer
        let got2 = unsafe { aether_mmu_xlate(p, va | 0x20, 0, 8) };
        assert_eq!(got2, pa | 0x20, "TLB hit");
        // an unmapped VA faults: returns sentinel + sets pending ABI
        let bad = unsafe { aether_mmu_xlate(p, 0x5555_0000, 0, 8) };
        assert_eq!(bad, XLATE_FAULT, "unmapped -> fault sentinel");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 1, "pending set");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_FAR], 0x5555_0000, "FAR = faulting VA");
        // ESR: Data Abort EC=0x25, translation fault.
        let esr = ctx[SYSREG_SLOT0 + SLOT_PEND_ESR];
        assert_eq!((esr >> 26) & 0x3F, 0x25, "ESR.EC = Data Abort (same EL)");
    }

    /// 2b cross-page (CONTIGUOUS): an 8-byte access straddling a page boundary
    /// where the two pages map to PHYSICALLY CONTIGUOUS PAs resolves to the
    /// first page's PA — a single host access of 8 bytes spans both correctly.
    #[test]
    fn xlate_spanning_contiguous_pages_ok() {
        let _g = setup();
        let va = 0x20_0000u64; // 2 MiB-aligned: L3 indices 0 and 1 share a table
        let pa = 0x80AA_0000u64;
        let (_ttbr, mut ctx) = map_4k_2pages(va, pa);
        let acc = va | 0xFFC; // 8-byte access starting 4 bytes before the page end
        // SAFETY: ctx is CTX_U64S long.
        let got = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), acc, 0, 8) };
        assert_eq!(got, pa | 0xFFC, "contiguous cross-page span -> first-page PA");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault for a contiguous span");
    }

    /// Build a 4-level chain mapping `va` and `va + 0x1000` to two REAL,
    /// physically NON-contiguous host pages (separate allocations). Returns
    /// (ctx, page1_pa, page2_pa). Used by the cross-page bounce-buffer tests:
    /// the demand-paged anon pages a guest actually straddles are rarely
    /// PA-adjacent, and the bytes must be dereferenced (gathered/scattered), so
    /// the leaves must point at backed memory — not the fake PAs the older
    /// fault-only test could get away with.
    fn map_4k_2pages_discontig(va: u64) -> (Vec<u64>, u64, u64) {
        let (p1_pa, _) = alloc_table();
        let (p2_pa, _) = alloc_table();
        assert_ne!(p2_pa, p1_pa + 0x1000, "test needs non-adjacent backing pages");
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(p1_pa, true, false);
        l3[(((va + 0x1000) >> 12) & 0x1FF) as usize] = leaf_desc(p2_pa, true, false);
        (ctx_with_ttbr0(l0_pa, true), p1_pa, p2_pa)
    }

    /// 2b cross-page (DISCONTIGUOUS) LOAD: an 8-byte read straddling a boundary
    /// whose two pages are physically non-adjacent is served by GATHERING both
    /// halves into the bounce buffer (NOT faulting — both pages are mapped, so a
    /// fault would just spin the guest on the straddling LDP forever).
    #[test]
    fn xlate_spanning_discontiguous_load_gathers() {
        let _g = setup();
        let va = 0x22_0000u64;
        let (mut ctx, p1_pa, p2_pa) = map_4k_2pages_discontig(va);
        // Known LE bytes: page-1 [0xFFC..0x1000] = 11 22 33 44 (-> 0x44332211 read
        // as the low 4 bytes), page-2 [0..4] = 55 66 77 88.
        // SAFETY: both pages are real 4 KiB allocations.
        unsafe {
            let b1 = p1_pa as *mut u8;
            b1.add(0xFFC).write(0x11);
            b1.add(0xFFD).write(0x22);
            b1.add(0xFFE).write(0x33);
            b1.add(0xFFF).write(0x44);
            let b2 = p2_pa as *mut u8;
            b2.add(0).write(0x55);
            b2.add(1).write(0x66);
            b2.add(2).write(0x77);
            b2.add(3).write(0x88);
        }
        let acc = va | 0xFFC; // 8-byte load, 4 bytes each side of the boundary
        // SAFETY: ctx is CTX_U64S long.
        let got = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), acc, 0, 8) };
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no fault for a gathered span");
        assert_ne!(got, XLATE_FAULT, "gathered load returns a buffer, not the fault sentinel");
        // SAFETY: `got` is the in-ctx bounce buffer; read the contiguous 8 bytes.
        let gathered = unsafe { core::ptr::read_unaligned(got as *const u64) };
        assert_eq!(gathered, 0x8877_6655_4433_2211, "gathered LE 8-byte spanning value");
    }

    /// 2b cross-page (DISCONTIGUOUS) STORE: an 8-byte write straddling a boundary
    /// whose two pages are non-adjacent returns the bounce buffer and DEFERS the
    /// scatter; the next MMU entry flushes the written bytes back to both pages.
    #[test]
    fn xlate_spanning_discontiguous_store_scatters() {
        let _g = setup();
        let va = 0x24_0000u64;
        let (mut ctx, p1_pa, p2_pa) = map_4k_2pages_discontig(va);
        let acc = va | 0xFFC;
        // Store-xlate hands back the bounce buffer + queues a deferred scatter.
        // SAFETY: ctx is CTX_U64S long.
        let dst = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), acc, 1, 8) };
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "store-xlate must not fault");
        assert_ne!(dst, XLATE_FAULT, "store-xlate returns a buffer");
        // The lowered movs write the value into the buffer (here, directly).
        // SAFETY: `dst` is the 16-byte in-ctx bounce buffer.
        unsafe { core::ptr::write_unaligned(dst as *mut u64, 0xAABB_CCDD_1122_3344) };
        // Not yet scattered: page-1's straddled bytes are still zero.
        // SAFETY: real page.
        assert_eq!(unsafe { core::ptr::read_unaligned((p1_pa + 0xFFC) as *const u32) }, 0,
            "bytes are buffered, not yet in RAM");
        // Any later entry flushes the scatter. A harmless 1-byte re-xlate does it.
        // SAFETY: ctx is CTX_U64S long.
        let _ = unsafe { aether_mmu_xlate(ctx.as_mut_ptr(), va, 0, 1) };
        // SAFETY: real pages; low 4 bytes -> page 1, high 4 -> page 2 (LE).
        let lo = unsafe { core::ptr::read_unaligned((p1_pa + 0xFFC) as *const u32) };
        let hi = unsafe { core::ptr::read_unaligned(p2_pa as *const u32) };
        assert_eq!(lo, 0x1122_3344, "low 4 bytes scattered to page 1");
        assert_eq!(hi, 0xAABB_CCDD, "high 4 bytes scattered to page 2");
    }

    /// must-fix #1: a 39-bit-VA / 3-level / start-L1 regime (the Android GKI
    /// `CONFIG_ARM64_VA_BITS_39` default) must walk correctly. Only L1/L2/L3
    /// tables exist — a walker that still started at L0 would read a bogus
    /// descriptor and the kernel would die at `__enable_mmu`.
    #[test]
    fn walk_39bit_3level_start_l1() {
        let _g = setup();
        let va = 0x12_3456_7000u64 & 0x7F_FFFF_FFFF; // within 39 bits
        let pa = 0x80AB_C000;
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        // NO L0 table — start level is 1 for a 39-bit VA.
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(pa, true, false);
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
        ctx[SYSREG_SLOT0 + SLOT_TTBR0] = l1_pa;
        // TCR_EL1.T0SZ = 25 (64-25 = 39-bit), TG0 = 0b00 (4 KiB).
        ctx[SYSREG_SLOT0 + SLOT_TCR] = 25;
        assert_eq!(regime_start_level(25, false), Some(1), "T0SZ=25 -> start L1");
        let (got, _) = walk(&ctx, va, false).expect("39-bit 3-level walk");
        assert_eq!(got, pa | (va & 0xFFF), "3-level walk resolves the page");
    }

    /// must-fix #1: a non-4 KiB granule (TG0 = 0b01 = 64 KiB) is unsupported and
    /// must be rejected loudly rather than mis-walked.
    #[test]
    fn fault_unsupported_granule() {
        let _g = setup();
        assert_eq!(regime_start_level(16, false), Some(0), "4 KiB ok");
        assert_eq!(regime_start_level((0b01 << 14) | 16, false), None, "64 KiB TG0 rejected");
        // TG1 uses a different encoding: 0b10 = 4 KiB.
        assert_eq!(regime_start_level((0b10 << 30) | (16 << 16), true), Some(0), "TG1=4KiB ok");
        assert_eq!(regime_start_level((0b11 << 30) | (16 << 16), true), None, "TG1=64KiB rejected");
    }

    /// must-fix #2 (No-Boundary): a TTBR pointing OUTSIDE the guest window must
    /// fault before any host dereference — never read host memory.
    #[test]
    fn clamp_rejects_out_of_window_table_base() {
        let _g = setup();
        aether_mmu_set_window(GUEST_PA_BASE, GUEST_PA_SIZE); // production window
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
        // TTBR0 below the window — must not be dereferenced.
        ctx[SYSREG_SLOT0 + SLOT_TTBR0] = 0x1000;
        let err = walk(&ctx, 0x4000, false).unwrap_err();
        assert_eq!(err.0, FaultKind::Translation, "out-of-window TTBR -> fault, no host read");
    }

    /// must-fix #2 (No-Boundary): a leaf whose output address escapes the window
    /// must fault — the consumer never gets an out-of-window host PA.
    #[test]
    fn clamp_rejects_out_of_window_leaf() {
        let _g = setup();
        // Arena of 3 pages for L1/L2/L3; pin the window to exactly the arena.
        let (base, mut t) = alloc_arena(3);
        aether_mmu_set_window(base, 3 * 4096);
        let va = 0x40_0000u64;
        // 39-bit regime (start L1) so we only need L1/L2/L3 (arena pages 0/1/2).
        let l2_pa = base + 4096;
        let l3_pa = base + 8192;
        t[0][((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        t[1][((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        // leaf OA points 1 MiB above the arena — OUTSIDE the pinned window.
        let bad_oa = base + 0x10_0000;
        t[2][((va >> 12) & 0x1FF) as usize] = leaf_desc(bad_oa, true, false);
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
        ctx[SYSREG_SLOT0 + SLOT_TTBR0] = base; // L1 table at arena base (in window)
        ctx[SYSREG_SLOT0 + SLOT_TCR] = 25; // T0SZ=25 -> start L1
        let err = walk(&ctx, va, false).unwrap_err();
        assert_eq!(err, (FaultKind::Translation, 3), "out-of-window leaf -> fault at L3");
    }

    // ── M4b-2c: instruction fetch through the walker ─────────────────────────

    /// MMU off (`SCTLR.M == 0`, early boot): the fetch PA is the flat PC, so the
    /// dispatcher reads instruction bytes straight out of the NPT window — the
    /// behaviour the live boot path had before the walker was wired in.
    #[test]
    fn fetch_flat_when_mmu_off() {
        let _g = setup();
        let ctx = ctx_with_ttbr0(0, false); // M = 0
        let pc = 0x8040_1234u64;
        // SAFETY: ctx is CTX_U64S long.
        let pa = unsafe { aether_mmu_fetch_pa(ctx.as_ptr() as *mut u64, pc) };
        assert_eq!(pa, pc, "MMU off -> flat fetch PA == PC");
    }

    /// MMU on, valid mapping: walk the PC to a host PA, then assert the
    /// instruction bytes PLACED at the mapped PA are exactly what a reader at the
    /// fetch PA sees. This is the core M4b-2c property — once SCTLR.M==1 the PC
    /// is virtual and the bytes must come from the WALKED physical address.
    #[test]
    fn fetch_walks_va_to_pa_and_reads_mapped_bytes() {
        let _g = setup();
        // Map a virtual text page to a host-allocated physical page; treat the
        // host allocation's address as the "guest PA" (handoff identity window).
        let (phys_pa, phys) = alloc_table(); // a 4 KiB page we control
        let va = 0x12_3456_7000u64; // virtual text address (page-aligned)
        let (l0_pa, l0) = alloc_table();
        let (l1_pa, l1) = alloc_table();
        let (l2_pa, l2) = alloc_table();
        let (l3_pa, l3) = alloc_table();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(phys_pa, true, false);

        // Place a known ARM64 instruction word at offset 0x10 of the phys page.
        // 0xD2800540 = MOVZ X0, #0x2A — a recognisable, non-trivial pattern.
        const FETCH_OFF: u64 = 0x10;
        const INSN: u32 = 0xD280_0540;
        phys[(FETCH_OFF / 8) as usize] = INSN as u64; // low 4 bytes of slot

        let mut ctx = ctx_with_ttbr0(l0_pa, true);
        let pc = va | FETCH_OFF;
        let fetch_pa = unsafe { aether_mmu_fetch_pa(ctx.as_mut_ptr(), pc) };
        assert_ne!(fetch_pa, XLATE_FAULT, "valid mapping must not fault");
        assert_eq!(fetch_pa, phys_pa | FETCH_OFF, "fetch PA = walked phys + page offset");

        // Read the instruction word back from the FETCH PA (what the dispatcher
        // would hand the translator) and assert it equals the placed bytes.
        // SAFETY: fetch_pa is the host address of our own leaked page.
        let read = unsafe { core::ptr::read_volatile(fetch_pa as *const u32) };
        assert_eq!(read, INSN, "bytes at walked PA match bytes placed at the mapped PA");

        // No fault was recorded.
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 0, "no pending fault on success");
    }

    /// MMU on, unmapped PC: the fetch faults and records an INSTRUCTION Abort
    /// (`ESR_EL1.EC == 0x21`), NOT the Data Abort (0x25) the data path records —
    /// proving the fetch helper re-stamps the EC. FAR_EL1 carries the PC.
    #[test]
    fn fetch_fault_records_instruction_abort_esr() {
        let _g = setup();
        // A table chain that maps some OTHER va; the fetch PC is unmapped.
        let mapped_va = 0x40_0000u64;
        let pa = 0x8033_0000;
        let (_ttbr, mut ctx) = map_4k(mapped_va, pa, false);
        let unmapped_pc = 0x7777_0000u64;
        let r = unsafe { aether_mmu_fetch_pa(ctx.as_mut_ptr(), unmapped_pc) };
        assert_eq!(r, XLATE_FAULT, "unmapped fetch -> fault sentinel");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 1, "pending set");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_FAR], unmapped_pc, "FAR = faulting PC");
        let esr = ctx[SYSREG_SLOT0 + SLOT_PEND_ESR];
        assert_eq!(
            (esr >> 26) & 0x3F,
            ESR_EC_INST_ABORT_SAME_EL,
            "fetch fault -> ESR.EC = Instruction Abort (0x21), not Data Abort (0x25)"
        );
        // The xFSC (low 6 bits) must still describe a translation fault, and IL
        // (bit 25) must survive the EC re-stamp.
        assert_eq!(esr & 0b11_1100, 0b00_0100, "IFSC = translation fault class");
        assert_eq!((esr >> 25) & 1, 1, "IL bit preserved across EC re-stamp");
    }

    /// `esr_with_ec` rewrites ONLY the EC field, leaving every other bit intact.
    #[test]
    fn esr_with_ec_rewrites_only_ec() {
        // Start from a data abort (write, permission fault at L3).
        let data = data_abort_esr(FaultKind::Permission, 3, true);
        assert_eq!((data >> 26) & 0x3F, ESR_EC_DATA_ABORT_SAME_EL);
        let inst = esr_with_ec(data, ESR_EC_INST_ABORT_SAME_EL);
        assert_eq!((inst >> 26) & 0x3F, ESR_EC_INST_ABORT_SAME_EL, "EC swapped");
        // Every NON-EC bit identical.
        assert_eq!(inst & !(0x3F << 26), data & !(0x3F << 26), "non-EC bits unchanged");
    }

    /// M4b-5 No-Boundary fix: with the MMU OFF (flat path, pa == va), a store or
    /// load to an address OUTSIDE the pinned guest window must FAULT, not perform
    /// a wild host write/read. Before the fix the flat path returned `va` / wrote
    /// `va` with no `in_window` clamp = an arbitrary host R/W primitive during
    /// early boot.
    #[test]
    fn flat_mmu_off_access_outside_window_faults_not_wild_rw() {
        let _g = setup();
        // Two distinct, host-writable, 4 KiB-aligned pages. Their host address
        // doubles as the "guest PA" (handoff identity invariant). Pin the window
        // to ONLY the first.
        let (in_pa, _t0) = alloc_table();
        let (out_pa, out_slice) = alloc_table();
        assert_ne!(in_pa, out_pa);
        aether_mmu_set_window(in_pa, 4096);

        let mut ctx = ctx_with_ttbr0(0, /*mmu_on=*/ false); // SCTLR.M = 0 → flat
        let ctxp = ctx.as_mut_ptr();

        // In-window flat store SUCCEEDS and actually writes host memory.
        let ok = unsafe { aether_mmu_store(ctxp, in_pa, 8, 0xABCD_1234_5678_9ABC) };
        assert_eq!(ok, MMIO_STORE_OK, "in-window flat store should succeed");
        assert_eq!(
            unsafe { core::ptr::read_volatile(in_pa as *const u64) },
            0xABCD_1234_5678_9ABC,
            "in-window flat store must land in host RAM"
        );

        // Out-of-window flat store is CLAMPED: returns XLATE_FAULT, does NOT
        // touch the (real, but out-of-window) page, and records a Data Abort.
        out_slice[0] = 0;
        let r = unsafe { aether_mmu_store(ctxp, out_pa, 8, 0xDEAD_BEEF_DEAD_BEEF) };
        assert_eq!(r, XLATE_FAULT, "out-of-window flat store must fault, not write");
        assert_eq!(out_slice[0], 0, "out-of-window page must be untouched (no wild write)");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_PENDING], 1, "pending Data Abort recorded");
        assert_eq!(ctx[SYSREG_SLOT0 + SLOT_PEND_FAR], out_pa, "FAR = faulting VA");

        // The load primitive (aether_mmu_xlate) shares the same flat-path clamp.
        let x = unsafe { aether_mmu_xlate(ctxp, out_pa, 0, 8) };
        assert_eq!(x, XLATE_FAULT, "out-of-window flat load must fault, not read");
        // In-window load returns the (identity) host PA so the deref reads RAM.
        let p = unsafe { aether_mmu_xlate(ctxp, in_pa, 0, 8) };
        assert_eq!(p, in_pa, "in-window flat load returns identity host PA");
    }
}
