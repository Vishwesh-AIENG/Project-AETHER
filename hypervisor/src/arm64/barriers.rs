// ch04: ARM64 memory and instruction barriers
//
// ARM64 has a weakly ordered memory model. Loads and stores can be reordered
// by the processor relative to their program order. Hypervisor code that
// manipulates shared data structures (page tables, interrupt routing tables,
// configuration records) must use explicit barriers to enforce ordering.
//
// Three barrier types exist:
//
//   DSB — Data Synchronization Barrier
//     Ensures all memory accesses before the barrier complete before any
//     instruction after the barrier executes. Required after writing page
//     tables before enabling the MMU, and before/after TLB invalidation.
//
//   DMB — Data Memory Barrier
//     Ensures ordering of memory accesses relative to each other, but does
//     not wait for completion of non-memory instructions. Weaker than DSB.
//
//   ISB — Instruction Synchronization Barrier
//     Flushes the instruction pipeline and instruction prefetch. Required
//     after writing system registers that affect instruction fetch behavior
//     (SCTLR_EL2, VBAR_EL2) and after TLB invalidation sequences.
//
// The operand after each barrier specifies the "shareability domain":
//   SY  — full system (outer shareable + inner shareable + local)
//   ISH — inner shareable only (all cores in the same coherency cluster)
//   NSH — non-shareable (processor only, no broadcast)
//
// Primary reference: ARM ARM DDI0487 Section B2.3 (memory ordering model),
//                    Section B2.7 (barrier instructions)
// Skill guide warning: incorrect barrier operands are one of the hardest
// bugs to diagnose. Use SY conservatively when in doubt.

use core::arch::asm;

// ─────────────────────────────────────────────────────────────────────────────
// DSB variants
// ─────────────────────────────────────────────────────────────────────────────

/// DSB SY — full system data synchronization barrier.
///
/// The heaviest and safest choice. All memory accesses visible to the full
/// system complete before anything after this barrier executes.
///
/// Use before:
/// - Enabling Stage 2 translation (HCR_EL2.VM = 1)
/// - TLB invalidation sequences (before the TLBI instruction)
///
/// Use after:
/// - Writing Stage 2 page table entries
/// - TLB invalidation sequences (after the TLBI instruction)
#[inline(always)]
pub fn dsb_sy() {
    unsafe { asm!("dsb sy", options(nomem, nostack, preserves_flags)) }
}

/// DSB ISH — inner-shareable domain data synchronization barrier.
///
/// Ensures completion of memory accesses within the inner-shareable domain
/// (all CPUs in the same coherency cluster, which is all CPUs on Snapdragon
/// X Elite). Cheaper than SY. Appropriate for TLB maintenance when we know
/// all relevant CPUs share a single coherency domain.
#[inline(always)]
pub fn dsb_ish() {
    unsafe { asm!("dsb ish", options(nomem, nostack, preserves_flags)) }
}

/// DSB ISHST — inner-shareable domain, stores only.
///
/// Orders stores within the inner-shareable domain. Used after writing
/// descriptors into page tables before the table walk hardware reads them.
#[inline(always)]
pub fn dsb_ishst() {
    unsafe { asm!("dsb ishst", options(nomem, nostack, preserves_flags)) }
}

// ─────────────────────────────────────────────────────────────────────────────
// ISB
// ─────────────────────────────────────────────────────────────────────────────

/// ISB SY — instruction synchronization barrier.
///
/// Flushes the instruction pipeline and any prefetched instructions.
/// After this barrier, all subsequent instructions are fetched from memory
/// using the updated system state.
///
/// Required after:
/// - Writing SCTLR_EL2 (MMU enable/disable affects instruction fetch)
/// - Writing VBAR_EL2 (new vector table must be visible before next exception)
/// - Completing a TLB invalidation sequence
/// - Writing to any register that affects translation or instruction fetch
///
/// Always the correct choice after system register writes that affect
/// instruction-level behavior.
#[inline(always)]
pub fn isb() {
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) }
}

// ─────────────────────────────────────────────────────────────────────────────
// DMB variants
// ─────────────────────────────────────────────────────────────────────────────

/// DMB ISH — inner-shareable domain data memory barrier.
///
/// Ensures memory access ordering without the heavier completion guarantee
/// of DSB. Appropriate for ordering access to shared data structures between
/// CPUs when we do not also need to synchronize with instruction execution.
#[inline(always)]
pub fn dmb_ish() {
    unsafe { asm!("dmb ish", options(nomem, nostack, preserves_flags)) }
}

/// DMB ISHST — inner-shareable domain, stores only.
///
/// Lighter than DMB ISH — only orders stores. Use when a producer writes
/// data and needs stores visible before setting a flag another CPU reads.
#[inline(always)]
pub fn dmb_ishst() {
    unsafe { asm!("dmb ishst", options(nomem, nostack, preserves_flags)) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Composite sequences used by higher modules
// ─────────────────────────────────────────────────────────────────────────────

/// The required barrier sequence after writing page table entries and
/// before activating or relying on them.
///
/// Sequence: DSB ISHST (stores complete) → ISB (pipeline flush).
///
/// Used by: memory module (Chapter 8) after populating Stage 2 tables.
#[inline(always)]
pub fn page_table_write_barrier() {
    dsb_ishst();
    isb();
}

/// The required barrier sequence surrounding a TLB invalidation instruction.
///
/// Sequence: DSB ISH (prior stores complete) → TLBI → DSB ISH → ISB.
///
/// Callers issue the TLBI instruction themselves between `tlbi_pre_barrier`
/// and `tlbi_post_barrier` so that the TLBI operand can vary per call site.
///
/// Reference: ARM ARM DDI0487 Section D5.10 (TLB maintenance requirements)
#[inline(always)]
pub fn tlbi_pre_barrier() {
    dsb_ish();
}

#[inline(always)]
pub fn tlbi_post_barrier() {
    dsb_ish();
    isb();
}
