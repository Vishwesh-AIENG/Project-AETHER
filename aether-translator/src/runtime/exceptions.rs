//! M4b-3: AArch64 exception injection for the x86 host-mode DBT.
//!
//! When a translated block faults (the MMU walker recorded a pending Data /
//! Instruction Abort in the pending-fault ABI) or the platform raises an IRQ
//! (M4b-4 timer/GIC), the guest must take an EL1 exception: save PSTATE + the
//! resume PC, set ESR/FAR, mask interrupts, and jump to `VBAR_EL1` + a
//! type/source-specific vector offset. This module performs that architectural
//! exception entry by mutating the guest register-file / sysreg slots in the
//! R15 context; the dispatcher calls it after a block (or on a fetch fault) and
//! then re-dispatches at the new PC (the handler).
//!
//! It is the INVERSE of the ERET lowering (`lift/mod.rs` `Eret`), which restores
//! `PC <- ELR_EL1` and `NZCV <- SPSR_EL1[31:28]`. The two compose: inject then
//! ERET returns to the interrupted PC with NZCV restored.
//!
//! DBT PSTATE model (matches the ERET dual): only NZCV is functionally live (at
//! `[R15+0x108]`); DAIF / CurrentEL / SPSel are STORED in their sysreg slots and
//! consulted by dispatcher policy (e.g. "inject an IRQ only if DAIF.I is clear"),
//! not enforced by executed code. Injection writes those slots for faithfulness
//! (a handler that reads `SPSR_EL1`/`CurrentEL` sees correct values) but the
//! execution engine does not gate on them.
//!
//! `no_std` + no-alloc; pure register-file manipulation on the caller-owned
//! `ctx` slice (no raw pointers).

use crate::runtime::context::{CTX_U64S, NZCV_OFFSET, PC_OFFSET, SP_OFFSET, SYSREG_SLOT0};
use crate::runtime::mmu::{SLOT_PEND_ESR, SLOT_PEND_FAR, SLOT_PEND_PENDING};

// ── Context slot indices (u64 indices into the flat R15 context) ─────────────
/// Guest PC (next-PC / resume address). GPR-file region, byte 0x100.
const PC_SLOT: usize = PC_OFFSET / 8; // 32
/// Packed NZCV (N@31 Z@30 C@29 V@28). GPR-file region, byte 0x108.
const NZCV_SLOT: usize = NZCV_OFFSET / 8; // 33
/// Active stack pointer (the SP of whichever bank the current EL/SPSel selects).
/// GPR-file region, byte 0x0F8.
const SP_SLOT: usize = SP_OFFSET / 8; // 31

/// Last observed kernel-image (real) VBAR_EL1 base — the vector table the kernel
/// uses when NOT in the KPTI entry-trampoline window. Snapshotted in [`inject`]
/// whenever VBAR is a kernel-image VA (top32 == 0xFFFFFFC0), and used to redirect
/// EL1-source exceptions that would otherwise hit the trampoline's zero EL1
/// vector slots. Atomic so no `unsafe` is needed under the crate's
/// `deny(unsafe_code)`; single-vCPU, so Relaxed ordering suffices.
static REAL_VECTORS_EL1: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// Sysreg sub-indices — MUST match `backend/lower_int.rs` `sysreg_read_idx`.
const SR_VBAR: usize = 6;
const SR_ESR: usize = 12;
const SR_ELR: usize = 13;
const SR_SPSR: usize = 14;
const SR_FAR: usize = 15;
/// Banked SP_EL0 — at EL1 this slot holds `current` (task pointer) between
/// exceptions; just before an ERET to EL0 the kernel sets it to the user SP.
const SR_SP_EL0: usize = 16;
/// Banked SP_EL1 — where the kernel SP is parked while the guest runs at EL0.
const SR_SP_EL1: usize = 17;
const SR_DAIF: usize = 22;
const SR_SPSEL: usize = 23;
const SR_CURRENTEL: usize = 42;

/// True iff the (EL, SPSel) state selects the SP_EL0 bank as the active SP.
/// EL0 always uses SP_EL0 (SPSel is ignored at EL0); at EL1, SP_EL0 is the
/// active bank only when SPSel==0 (the EL1t state), SP_EL1 when SPSel==1 (EL1h).
#[inline]
fn uses_sp0_bank(cur_el: u64, spsel: u64) -> bool {
    cur_el == 0 || (spsel & 1) == 0
}

/// Byte/index of sysreg sub-slot `i` in the flat context.
#[inline]
fn sr(i: usize) -> usize {
    SYSREG_SLOT0 + i
}

// ── PSTATE / SPSR field masks ────────────────────────────────────────────────
/// NZCV occupies bits [31:28] of both the packed flag word and SPSR.
const NZCV_MASK: u64 = 0xF000_0000;
/// DAIF occupies bits [9:6] of SPSR / the DAIF register (D@9 A@8 I@7 F@6).
const DAIF_MASK: u64 = 0b1111 << 6; // 0x3C0
/// `SPSR.I` — IRQ mask bit (bit 7). The dispatcher checks this before an IRQ.
pub const PSTATE_I: u64 = 1 << 7;
/// AArch64 mode field `SPSR[4:0]`: EL0t / EL1t / EL1h (the only modes the guest
/// kernel uses).
const MODE_EL0T: u64 = 0b0_0000;
const MODE_EL1T: u64 = 0b0_0100;
const MODE_EL1H: u64 = 0b0_0101;

// ── Exception kinds ──────────────────────────────────────────────────────────

/// The four AArch64 exception types. Each selects a vector slot 0x80 apart
/// within a source-EL group (ARM ARM D1.10.2, "Exception vectors").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExceptionKind {
    /// Synchronous (Data/Instruction Abort, SVC, undefined, …).
    Sync,
    /// IRQ (the virtual timer + GIC path).
    Irq,
    /// FIQ.
    Fiq,
    /// SError (asynchronous abort).
    SError,
}

impl ExceptionKind {
    /// Type offset within a vector group: Sync 0x00, IRQ 0x80, FIQ 0x100,
    /// SError 0x180.
    fn type_offset(self) -> u64 {
        match self {
            ExceptionKind::Sync => 0x000,
            ExceptionKind::Irq => 0x080,
            ExceptionKind::Fiq => 0x100,
            ExceptionKind::SError => 0x180,
        }
    }
}

/// VBAR-relative vector offset for an exception of `kind` taken TO EL1, given
/// the CURRENT (pre-entry) state read from `ctx`:
///   * source EL0 (lower EL, AArch64): group base 0x400
///   * source EL1 with SP_EL0 (EL1t):  group base 0x000
///   * source EL1 with SP_EL1 (EL1h):  group base 0x200  (the bring-up case)
fn vector_offset(ctx: &[u64], kind: ExceptionKind) -> u64 {
    let cur_el = (ctx[sr(SR_CURRENTEL)] >> 2) & 0b11;
    let group = if cur_el == 0 {
        0x400 // lower EL using AArch64 (e.g. a userspace fault)
    } else if ctx[sr(SR_SPSEL)] & 1 == 0 {
        0x000 // current EL with SP0 (EL1t)
    } else {
        0x200 // current EL with SPx (EL1h)
    };
    group + kind.type_offset()
}

/// Build the saved SPSR (a PSTATE snapshot) from the current context: NZCV
/// [31:28] from the live flag word, DAIF [9:6] from the DAIF slot, mode [4:0]
/// from the current EL/SPSel.
fn build_spsr(ctx: &[u64]) -> u64 {
    let nzcv = ctx[NZCV_SLOT] & NZCV_MASK;
    let daif = ctx[sr(SR_DAIF)] & DAIF_MASK;
    let cur_el = (ctx[sr(SR_CURRENTEL)] >> 2) & 0b11;
    let mode = if cur_el == 0 {
        MODE_EL0T
    } else if ctx[sr(SR_SPSEL)] & 1 == 0 {
        MODE_EL1T
    } else {
        MODE_EL1H
    };
    nzcv | daif | mode
}

/// Perform an AArch64 EL1 exception entry against the guest context.
///
/// Saves PSTATE → SPSR_EL1 and the resume PC (the current PC slot) → ELR_EL1,
/// sets ESR_EL1 = `esr` and (for aborts) FAR_EL1 = `far`, masks DAIF, switches
/// to EL1h, and sets the PC slot to `VBAR_EL1 + vector_offset`. After this the
/// dispatcher re-dispatches at the new PC (the handler entry).
///
/// `set_far` is true for Data/Instruction Aborts (which update FAR_EL1) and
/// false for IRQ/FIQ/SError (FAR_EL1 is UNKNOWN per the architecture for those,
/// so we leave it intact).
pub fn inject(ctx: &mut [u64], kind: ExceptionKind, esr: u64, far: u64, set_far: bool) {
    debug_assert!(ctx.len() >= CTX_U64S, "context buffer too small for injection");
    // Snapshot BEFORE mutating any state used by the snapshot.
    let spsr = build_spsr(ctx);
    let offset = vector_offset(ctx, kind);
    let raw_vbar = ctx[sr(SR_VBAR)];
    let cur_el = (ctx[sr(SR_CURRENTEL)] >> 2) & 0b11;
    let cur_spsel = ctx[sr(SR_SPSEL)] & 1;

    // KPTI trampoline EL1-vector redirect. With page-table isolation on,
    // VBAR_EL1 points at the entry trampoline (a fixmap VA, top32 != 0xFFFFFFC0)
    // whose EL1-from-EL1 vector slots (offsets 0x000/0x200) are ZEROS (mainline
    // `tramp_vectors` reserves them with `.space 0x400` — an EL1 exception there
    // is never expected). If our injected EL1-source abort lands while VBAR is
    // the trampoline, the guest fetches a zero (UDF) vector and storms. The real
    // (kernel-image) vectors live at the 0xFFFFFFC0_******** base the kernel uses
    // when NOT in the trampoline window; snapshot it whenever we see it and use
    // it for EL1-source exceptions taken with a trampoline VBAR.
    let vbar = {
        use core::sync::atomic::Ordering;
        let is_kimg = (raw_vbar >> 32) == 0xFFFF_FFC0;
        if is_kimg {
            REAL_VECTORS_EL1.store(raw_vbar, Ordering::Relaxed);
            raw_vbar
        } else if cur_el != 0 {
            // EL1-source + trampoline VBAR → the zero EL1 slot; use real vectors.
            let real = REAL_VECTORS_EL1.load(Ordering::Relaxed);
            if real != 0 { real } else { raw_vbar }
        } else {
            // EL0-source: the trampoline's lower-EL slots (0x400+) ARE valid.
            raw_vbar
        }
    };

    // Correct the abort syndrome's source-EL: a Data/Instruction Abort taken
    // from EL0 (a lower EL) uses the *_LOW EC (0x24 DABT / 0x20 IABT); from EL1
    // (same EL) the *_CUR EC (0x25 / 0x21). The same/lower distinction is EC bit
    // 0 (= ESR bit 26). The walker hard-codes the same-EL form (it has no EL
    // context), so flip bit 26 to match the actual source EL here — otherwise a
    // demand-paging fault from userspace reaches the kernel's `el0_sync` switch
    // with EC=DABT_CUR/IABT_CUR, fails to match DABT_LOW/IABT_LOW, and the
    // kernel takes `bad_el0_sync` → kills the faulting process. SVC (EC=0x15)
    // and IRQ (ESR=0) have no same/lower EC variant and are left untouched.
    let esr = {
        let ec = (esr >> 26) & 0x3F;
        let is_abort = ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25;
        if kind == ExceptionKind::Sync && is_abort {
            if cur_el == 0 {
                esr & !(1 << 26) // lower EL → *_LOW (bit 26 clear)
            } else {
                esr | (1 << 26) // same EL → *_CUR (bit 26 set)
            }
        } else {
            esr
        }
    };

    // Save the interrupted state.
    ctx[sr(SR_SPSR)] = spsr;
    ctx[sr(SR_ELR)] = ctx[PC_SLOT];
    ctx[sr(SR_ESR)] = esr;
    if set_far {
        ctx[sr(SR_FAR)] = far;
    }

    // SP banking: exception entry to EL1 always lands at EL1h, which uses the
    // SP_EL1 bank. If the interrupted state was using the SP_EL0 bank (a fault
    // from EL0, or the rare EL1t), the live SP currently mirrors SP_EL0 — park
    // it back into the SP_EL0 slot and load the SP_EL1 slot into the active SP
    // so the handler runs on the kernel stack. This is exactly how hardware
    // banks the two SPs across an EL0→EL1 entry; SP_EL0 then holds the user SP
    // for the kernel's `mrs x, sp_el0` save (until it overwrites it with the
    // task pointer). A fault already at EL1h keeps SP_EL1 — no swap.
    if uses_sp0_bank(cur_el, cur_spsel) {
        let active = ctx[SP_SLOT];
        ctx[sr(SR_SP_EL0)] = active; // park interrupted SP into SP_EL0 bank
        ctx[SP_SLOT] = ctx[sr(SR_SP_EL1)]; // load the kernel SP from SP_EL1 bank
    }

    // New PSTATE on entry: DAIF all masked, EL1h (EL1 + SP_EL1). NZCV is NOT
    // altered by exception entry — the handler manages it. We update the stored
    // CurrentEL/SPSel/DAIF slots so a handler reading them is correct.
    ctx[sr(SR_DAIF)] = DAIF_MASK; // D=A=I=F=1
    ctx[sr(SR_CURRENTEL)] = 0b01 << 2; // EL1
    ctx[sr(SR_SPSEL)] = 1; // SP_EL1

    // Vector to the handler.
    ctx[PC_SLOT] = vbar.wrapping_add(offset);
}

/// If a Data/Instruction Abort is pending (the MMU walker set `PEND_PENDING`),
/// inject it as a Synchronous exception and clear the pending slots. Returns
/// true iff an exception was taken.
///
/// FAR_EL1 is set from `PEND_FAR`. The ESR already encodes EC=0x25 (Data Abort)
/// or 0x21 (Instruction Abort) — the fetch path re-stamps it — and both share
/// the Sync vector, so the handler routes off `ESR_EL1.EC` exactly as on real
/// hardware.
pub fn take_pending_abort(ctx: &mut [u64]) -> bool {
    if ctx[sr(SLOT_PEND_PENDING)] == 0 {
        return false;
    }
    let esr = ctx[sr(SLOT_PEND_ESR)];
    let far = ctx[sr(SLOT_PEND_FAR)];
    inject(ctx, ExceptionKind::Sync, esr, far, true);
    ctx[sr(SLOT_PEND_PENDING)] = 0;
    true
}

/// True iff IRQs are currently unmasked in the guest (PSTATE.I clear), so the
/// dispatcher may deliver a pending IRQ. Reads the DAIF slot (bit 7 = I).
pub fn irqs_unmasked(ctx: &[u64]) -> bool {
    ctx[sr(SR_DAIF)] & PSTATE_I == 0
}

/// Current guest exception level (0 = EL0/userspace, 1 = EL1/kernel). The
/// dispatcher uses this to rate-limit kernel-mode (EL1) timer preemption — see
/// the IRQ-injection deferral in `boot_x86.rs`.
pub fn guest_el(ctx: &[u64]) -> u64 {
    (ctx[sr(SR_CURRENTEL)] >> 2) & 0b11
}

/// Inject an IRQ exception (vector group + 0x80). ESR is UNKNOWN for an IRQ (0)
/// and FAR is unchanged. The caller has already decided the IRQ is deliverable
/// (`irqs_unmasked` + a GIC interrupt pending above PMR).
pub fn inject_irq(ctx: &mut [u64]) {
    inject(ctx, ExceptionKind::Irq, 0, 0, false);
}

/// Perform an AArch64 exception return (ERET) against the guest context — the
/// architectural inverse of [`inject`]. Restores:
///   * `PC      <- ELR_EL1`
///   * `NZCV    <- SPSR_EL1[31:28]` (the live flag word the lowering aliases)
///   * `DAIF    <- SPSR_EL1[9:6]`
///   * target exception level + SPSel from `SPSR_EL1.M[4:0]`
///   * the SP_EL0/SP_EL1 bank: if the target uses a different bank than the
///     current state, park the active SP into the current bank's slot and load
///     the target bank's slot into the active SP.
///
/// This replaces the old primitive ERET lowering (which restored only PC and
/// NZCV and could not model an EL change or the SP swap), making a return to
/// EL0 — the kernel→userspace handoff — correct. An EL1h→EL1h return (the
/// kernel resuming its own context after handling a fault) decodes mode=EL1h,
/// so no SP swap occurs and behaviour matches the previous lowering plus the
/// now-correct DAIF restore.
pub fn eret(ctx: &mut [u64]) {
    debug_assert!(ctx.len() >= CTX_U64S, "context buffer too small for ERET");
    let spsr = ctx[sr(SR_SPSR)];
    let elr = ctx[sr(SR_ELR)];

    // Decode the target mode from SPSR.M[4:0]. Only the three modes the guest
    // kernel uses are valid; an illegal value is treated as EL1h (the bring-up
    // state) rather than faulting, matching how the kernel only ever writes
    // these three.
    let mode = spsr & 0b1_1111;
    let (tgt_el, tgt_spsel) = match mode {
        MODE_EL0T => (0u64, 0u64),
        MODE_EL1T => (1, 0),
        MODE_EL1H => (1, 1),
        _ => (1, 1),
    };

    // SP bank swap, only when the active bank actually changes.
    let cur_el = (ctx[sr(SR_CURRENTEL)] >> 2) & 0b11;
    let cur_spsel = ctx[sr(SR_SPSEL)] & 1;
    let cur_sp0 = uses_sp0_bank(cur_el, cur_spsel);
    let tgt_sp0 = uses_sp0_bank(tgt_el, tgt_spsel);
    if cur_sp0 != tgt_sp0 {
        let active = ctx[SP_SLOT];
        if cur_sp0 {
            // Leaving an SP_EL0-bank state (e.g. EL1t) for an SP_EL1-bank state.
            ctx[sr(SR_SP_EL0)] = active;
            ctx[SP_SLOT] = ctx[sr(SR_SP_EL1)];
        } else {
            // Leaving EL1h (SP_EL1 bank) for EL0/EL1t (SP_EL0 bank): park the
            // kernel SP into SP_EL1 and load SP_EL0 (which kernel_exit set to
            // the user SP via `msr sp_el0, x`) into the active SP.
            ctx[sr(SR_SP_EL1)] = active;
            ctx[SP_SLOT] = ctx[sr(SR_SP_EL0)];
        }
    }

    // Restore PSTATE and resume.
    ctx[NZCV_SLOT] = spsr & NZCV_MASK;
    ctx[sr(SR_DAIF)] = spsr & DAIF_MASK;
    ctx[sr(SR_CURRENTEL)] = tgt_el << 2;
    ctx[sr(SR_SPSEL)] = tgt_spsel;
    ctx[PC_SLOT] = elr;
}

/// FFI entry for the SVC lowering: a guest `SVC #imm16` takes a synchronous
/// exception to EL1. The lift stored the return address (`PC of SVC + 4`) into
/// the PC slot via a `WritePc` immediately before the call, so `inject` saves
/// it as `ELR_EL1`. ESR encodes EC=0x15 (SVC from AArch64), IL=1, ISS=imm16.
/// `inject` selects the vector group from the *current* EL (0x400 for a
/// userspace SVC) and performs the SP bank swap, so this covers EL0 syscalls.
///
/// # Safety
/// `ctx` must point to a guest register file at least `CTX_U64S` u64s long
/// (the dispatch loop's R15 context) — the same contract as every other
/// `aether_*` FFI helper the emitted code calls.
/// Syscall histogram (count per ARM64 syscall number 0..511) — diagnostic for
/// "what is /init parked on". Plus the last (nr, pc). Dumped by the hypervisor
/// at the iteration-cap halt. `pc` is the /init VA AFTER the SVC (the lift
/// WritePc'd SVC+4 before the Svc op) so it disassembles in `_init.elf`.
pub static mut SYSCALL_TOTAL: u64 = 0;
/// Ring of the last 32 syscalls: each row = [nr(x8), x0, x1, x2, x30(caller)].
/// x30 is the /init return address INTO the calling function (the syscall stub's
/// `ret` target), so it disassembles in `_init.elf` to reveal WHAT /init is
/// doing (e.g. the read's fd in x0 + the caller pins the file/socket).
pub static mut SYSCALL_RING: [[u64; 5]; 32] = [[0; 5]; 32];
pub static mut SYSCALL_RING_IDX: usize = 0;

/// mmap (nr 222) probe. Captures the request args at the SVC and the kernel's
/// *actual* return (x0) at the ERET back to EL0, so the hypervisor can print
/// "what mmap returned" next to "what /init then dereferenced". This splits a
/// corrupted return value (x0 mangled after the syscall) from a kernel-side
/// mapping failure (kernel returns a valid address but installs no VMA).
pub static mut MMAP_REQ: [u64; 4] = [0; 4]; // [addr, len, prot, flags]
pub static mut MMAP_RET: u64 = 0;
pub static mut MMAP_PENDING: bool = false;
pub static mut MMAP_RET_VALID: bool = false;

#[allow(unsafe_code)]
pub extern "C" fn aether_svc_enter(ctx: *mut u64, imm16: u64) {
    // SAFETY: caller's contract — ctx is the register-file base.
    let slice = unsafe { core::slice::from_raw_parts_mut(ctx, CTX_U64S) };
    // Diagnostic: record (nr, x0, x1, x2, x30) into the ring.
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        let i = *core::ptr::addr_of!(SYSCALL_RING_IDX) % 32;
        let ring = core::ptr::addr_of_mut!(SYSCALL_RING);
        (*ring)[i] = [slice[8], slice[0], slice[1], slice[2], slice[30]];
        *core::ptr::addr_of_mut!(SYSCALL_RING_IDX) =
            (*core::ptr::addr_of!(SYSCALL_RING_IDX)).wrapping_add(1);
        *core::ptr::addr_of_mut!(SYSCALL_TOTAL) =
            (*core::ptr::addr_of!(SYSCALL_TOTAL)).saturating_add(1);
        // mmap probe: stash the request; the matching ERET-to-EL0 records x0.
        if slice[8] == 222 {
            *core::ptr::addr_of_mut!(MMAP_REQ) = [slice[0], slice[1], slice[2], slice[3]];
            *core::ptr::addr_of_mut!(MMAP_PENDING) = true;
        }
    }
    // (The prctl(PR_SET_VMA)→-EINVAL intercept that briefly lived here was a RED
    // HERRING. The "intermittent EL0-write SIGSEGV" it tried to dodge was really
    // the cross-page NON-CONTIGUOUS LDP/STP/LDR-Q loop — fixed in mmu.rs via a
    // gather/scatter bounce buffer. PR_SET_VMA only CORRELATED (bionic names the
    // VMA right before the straddling memcpy). Faking -EINVAL is a fingerprint
    // deviation and is no longer needed, so the syscall now falls through to the
    // kernel's real (no-op, returns 0) handler.)
    let esr = (0x15u64 << 26) | (1 << 25) | (imm16 & 0xFFFF);
    inject(slice, ExceptionKind::Sync, esr, 0, false);
}

/// FFI entry for the `EretRt` lowering: perform a full guest ERET. See
/// [`eret`]. A block terminator, so it is the last side effect in its block;
/// the dispatcher reads the resulting PC slot to continue at `ELR_EL1`.
///
/// # Safety
/// Same `ctx` contract as [`aether_svc_enter`].
#[allow(unsafe_code)]
pub extern "C" fn aether_eret_enter(ctx: *mut u64) {
    // SAFETY: caller's contract — ctx is the register-file base.
    let slice = unsafe { core::slice::from_raw_parts_mut(ctx, CTX_U64S) };
    eret(slice);
    // mmap probe: the first ERET back to EL0 after an mmap SVC carries the
    // syscall's return value in x0 (IRQs return to EL1 and don't match).
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        if *core::ptr::addr_of!(MMAP_PENDING) && ((slice[sr(SR_CURRENTEL)] >> 2) & 0b11) == 0 {
            *core::ptr::addr_of_mut!(MMAP_RET) = slice[0];
            *core::ptr::addr_of_mut!(MMAP_RET_VALID) = true;
            *core::ptr::addr_of_mut!(MMAP_PENDING) = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::context::CTX_U64S;

    const SCTLR_M: u64 = 1 << 0;
    const VBAR: u64 = 0xFFFF_0000_1000_0000;

    /// A ctx in the bring-up state: MMU on, EL1h, VBAR set, NZCV + PC seeded.
    fn el1h_ctx(pc: u64, nzcv: u64) -> Vec<u64> {
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + 0] = SCTLR_M; // SCTLR.M (not used here, realism)
        ctx[sr(SR_VBAR)] = VBAR;
        ctx[sr(SR_CURRENTEL)] = 0b01 << 2; // EL1
        ctx[sr(SR_SPSEL)] = 1; // SP_EL1 -> EL1h
        ctx[PC_SLOT] = pc;
        ctx[NZCV_SLOT] = nzcv;
        ctx
    }

    #[test]
    fn inject_data_abort_sets_every_field() {
        let pc = 0xFFFF_8000_0040_1234u64;
        let nzcv = 0b1010 << 28; // N=1 Z=0 C=1 V=0
        let mut ctx = el1h_ctx(pc, nzcv);
        // pre-set DAIF unmasked.
        ctx[sr(SR_DAIF)] = 0;
        let esr = 0x25 << 26 | (1 << 25) | 0b0100; // Data Abort, translation L0
        let far = 0x0000_1234_5678_9000u64;
        inject(&mut ctx, ExceptionKind::Sync, esr, far, true);

        assert_eq!(ctx[sr(SR_ELR)], pc, "ELR_EL1 = interrupted PC");
        assert_eq!(ctx[sr(SR_ESR)], esr, "ESR_EL1 set");
        assert_eq!(ctx[sr(SR_FAR)], far, "FAR_EL1 set for an abort");
        // SPSR: NZCV[31:28] preserved, mode EL1h (0b00101), DAIF was 0.
        assert_eq!(ctx[sr(SR_SPSR)] & NZCV_MASK, nzcv, "SPSR keeps NZCV");
        assert_eq!(ctx[sr(SR_SPSR)] & 0b1_1111, MODE_EL1H, "SPSR mode = EL1h");
        // New PSTATE: DAIF masked, EL1h, PC = VBAR + 0x200 (current EL SPx sync).
        assert_eq!(ctx[sr(SR_DAIF)], DAIF_MASK, "entry masks DAIF");
        assert_eq!(ctx[PC_SLOT], VBAR + 0x200, "PC = VBAR + sync(SPx) offset");
        // NZCV (live flag word) is unchanged by entry.
        assert_eq!(ctx[NZCV_SLOT], nzcv, "live NZCV untouched on entry");
    }

    #[test]
    fn vector_offset_selects_group_and_type() {
        // EL1h (SP_EL1): sync 0x200, irq 0x280, fiq 0x300, serror 0x380.
        let ctx = el1h_ctx(0, 0);
        assert_eq!(vector_offset(&ctx, ExceptionKind::Sync), 0x200);
        assert_eq!(vector_offset(&ctx, ExceptionKind::Irq), 0x280);
        assert_eq!(vector_offset(&ctx, ExceptionKind::Fiq), 0x300);
        assert_eq!(vector_offset(&ctx, ExceptionKind::SError), 0x380);
        // EL1t (SP_EL0): group base 0x000.
        let mut t = el1h_ctx(0, 0);
        t[sr(SR_SPSEL)] = 0;
        assert_eq!(vector_offset(&t, ExceptionKind::Sync), 0x000);
        assert_eq!(vector_offset(&t, ExceptionKind::Irq), 0x080);
        // Lower EL (EL0 source): group base 0x400.
        let mut e0 = el1h_ctx(0, 0);
        e0[sr(SR_CURRENTEL)] = 0; // EL0
        assert_eq!(vector_offset(&e0, ExceptionKind::Sync), 0x400);
        assert_eq!(vector_offset(&e0, ExceptionKind::Irq), 0x480);
    }

    #[test]
    fn take_pending_abort_consumes_and_clears() {
        let pc = 0xFFFF_8000_0000_2000u64;
        let mut ctx = el1h_ctx(pc, 0);
        // Walker recorded a pending Data Abort.
        ctx[sr(SLOT_PEND_PENDING)] = 1;
        ctx[sr(SLOT_PEND_FAR)] = 0xDEAD_0000u64;
        ctx[sr(SLOT_PEND_ESR)] = 0x25 << 26;
        assert!(take_pending_abort(&mut ctx), "pending abort -> injected");
        assert_eq!(ctx[sr(SLOT_PEND_PENDING)], 0, "pending slot cleared");
        assert_eq!(ctx[sr(SR_FAR)], 0xDEAD_0000, "FAR from PEND_FAR");
        assert_eq!(ctx[sr(SR_ELR)], pc, "ELR = interrupted PC");
        assert_eq!(ctx[PC_SLOT], VBAR + 0x200, "vectored to sync handler");
        // No pending -> no injection.
        assert!(!take_pending_abort(&mut ctx), "no pending -> false");
    }

    /// The inject/ERET duality: after injection, an ERET (PC<-ELR, NZCV<-SPSR
    /// [31:28]) returns to the interrupted PC with NZCV restored.
    #[test]
    fn inject_then_eret_roundtrips_pc_and_nzcv() {
        let pc = 0xFFFF_8000_0011_2233u64;
        let nzcv = 0b0101 << 28; // N=0 Z=1 C=0 V=1
        let mut ctx = el1h_ctx(pc, nzcv);
        inject(&mut ctx, ExceptionKind::Irq, 0, 0, false);
        // Simulate ERET exactly as lift/mod.rs Eret lowers it.
        let restored_pc = ctx[sr(SR_ELR)];
        let restored_nzcv = ctx[sr(SR_SPSR)] & 0xF000_0000;
        assert_eq!(restored_pc, pc, "ERET returns to the interrupted PC");
        assert_eq!(restored_nzcv, nzcv, "ERET restores the saved NZCV");
        // IRQ vector was 0x280 and FAR was untouched (set_far=false).
        // (FAR started 0; assert it stayed 0.)
        assert_eq!(ctx[sr(SR_FAR)], 0, "IRQ entry leaves FAR unchanged");
    }

    #[test]
    fn irq_mask_gate() {
        let mut ctx = el1h_ctx(0, 0);
        ctx[sr(SR_DAIF)] = 0;
        assert!(irqs_unmasked(&ctx), "DAIF.I clear -> deliverable");
        ctx[sr(SR_DAIF)] = PSTATE_I;
        assert!(!irqs_unmasked(&ctx), "DAIF.I set -> masked");
    }

    #[test]
    fn inject_irq_uses_irq_vector() {
        let mut ctx = el1h_ctx(0xFFFF_8000_0000_9000, 0);
        inject_irq(&mut ctx);
        assert_eq!(ctx[PC_SLOT], VBAR + 0x280, "IRQ -> VBAR + 0x280 (SPx IRQ)");
        assert_eq!(ctx[sr(SR_ESR)], 0, "IRQ ESR is 0 (UNKNOWN)");
    }

    // ── SP banking + ERET ────────────────────────────────────────────────────

    /// An EL1h→EL0 ERET parks the kernel SP into SP_EL1 and loads SP_EL0 (the
    /// user SP the kernel staged) into the active SP, and switches CurrentEL/
    /// SPSel to EL0t. A following EL0→EL1 entry restores the kernel SP exactly.
    #[test]
    fn eret_to_el0_then_entry_banks_sp() {
        const KSP: u64 = 0xFFFF_8000_DEAD_0000; // kernel stack
        const USP: u64 = 0x0000_007F_F000_0000; // user stack
        let mut ctx = el1h_ctx(0xFFFF_8000_0011_0000, 0);
        ctx[SP_SLOT] = KSP; // running on the kernel stack at EL1h
        // Kernel staged the return: ELR=user PC, SPSR mode=EL0t, SP_EL0=user SP.
        ctx[sr(SR_ELR)] = 0x0000_0000_0040_1000;
        ctx[sr(SR_SPSR)] = MODE_EL0T; // NZCV/DAIF zero, mode EL0t
        ctx[sr(SR_SP_EL0)] = USP;

        eret(&mut ctx);

        assert_eq!(ctx[PC_SLOT], 0x0040_1000, "ERET resumes at ELR (user PC)");
        assert_eq!((ctx[sr(SR_CURRENTEL)] >> 2) & 3, 0, "now at EL0");
        assert_eq!(ctx[sr(SR_SPSEL)] & 1, 0, "EL0 selects SP_EL0");
        assert_eq!(ctx[SP_SLOT], USP, "active SP is the user SP");
        assert_eq!(ctx[sr(SR_SP_EL1)], KSP, "kernel SP parked in SP_EL1");

        // Userspace runs, moves its stack, then takes an exception (e.g. SVC).
        ctx[SP_SLOT] = USP - 0x40;
        ctx[PC_SLOT] = 0x0040_1004; // address after the SVC
        inject(&mut ctx, ExceptionKind::Sync, (0x15 << 26) | (1 << 25), 0, false);

        assert_eq!((ctx[sr(SR_CURRENTEL)] >> 2) & 3, 1, "entry lands at EL1");
        assert_eq!(ctx[sr(SR_SPSEL)] & 1, 1, "EL1h selects SP_EL1");
        assert_eq!(ctx[SP_SLOT], KSP, "kernel SP restored from SP_EL1 bank");
        assert_eq!(ctx[sr(SR_SP_EL0)], USP - 0x40, "user SP parked in SP_EL0");
        assert_eq!(ctx[PC_SLOT], VBAR + 0x400, "SVC from EL0 -> lower-EL sync vector");
        assert_eq!(ctx[sr(SR_ELR)], 0x0040_1004, "ELR = address after SVC");
    }

    /// An EL1h→EL1h ERET (the kernel resuming its own context) must NOT swap SP
    /// banks and must restore PC, NZCV, and DAIF from SPSR.
    #[test]
    fn eret_to_el1h_no_swap_restores_pstate() {
        const KSP: u64 = 0xFFFF_8000_C0DE_0000;
        let mut ctx = el1h_ctx(0, 0);
        ctx[SP_SLOT] = KSP;
        ctx[sr(SR_SP_EL1)] = 0xBADBAD; // must be ignored (no swap)
        ctx[sr(SR_ELR)] = 0xFFFF_8000_0022_0000;
        let nzcv = 0b1001 << 28; // N=1 Z=0 C=0 V=1
        ctx[sr(SR_SPSR)] = nzcv | (0b1111 << 6) | MODE_EL1H; // DAIF all set
        ctx[sr(SR_DAIF)] = 0; // handler had unmasked

        eret(&mut ctx);

        assert_eq!(ctx[SP_SLOT], KSP, "no SP swap on EL1h->EL1h");
        assert_eq!(ctx[PC_SLOT], 0xFFFF_8000_0022_0000, "PC restored from ELR");
        assert_eq!(ctx[NZCV_SLOT], nzcv, "NZCV restored from SPSR");
        assert_eq!(ctx[sr(SR_DAIF)], 0b1111 << 6, "DAIF restored from SPSR");
        assert_eq!((ctx[sr(SR_CURRENTEL)] >> 2) & 3, 1, "still EL1");
        assert_eq!(ctx[sr(SR_SPSEL)] & 1, 1, "still SP_EL1");
    }

    /// `aether_svc_enter` builds the SVC ESR (EC=0x15) and vectors via `inject`.
    #[test]
    fn svc_enter_injects_sync_with_ec_0x15() {
        let mut ctx = el1h_ctx(0, 0);
        ctx[PC_SLOT] = 0xFFFF_8000_0033_0044; // return address staged by WritePc
        aether_svc_enter(ctx.as_mut_ptr(), 0);
        assert_eq!(ctx[sr(SR_ELR)], 0xFFFF_8000_0033_0044, "ELR = return address");
        let esr = ctx[sr(SR_ESR)];
        assert_eq!((esr >> 26) & 0x3F, 0x15, "ESR.EC = 0x15 (SVC AArch64)");
        assert_eq!(ctx[PC_SLOT], VBAR + 0x200, "SVC from EL1h -> SPx sync vector");
    }

    /// A Data Abort taken from EL0 must carry the *_LOW EC (0x24), and from EL1
    /// the *_CUR EC (0x25), regardless of which form the walker recorded — the
    /// kernel's el0_sync / el1_sync switches route on it. SVC (0x15) is left
    /// untouched (no same/lower variant).
    #[test]
    fn inject_fixes_abort_ec_for_source_el() {
        // Walker always records the same-EL Data Abort (EC=0x25).
        let walker_dabt = 0x25u64 << 26 | (1 << 25) | 0b0100;
        // From EL0 → EC must become 0x24 (DABT_LOW).
        let mut e0 = el1h_ctx(0xFFFF_0000_0000_1000, 0);
        e0[sr(SR_CURRENTEL)] = 0; // source EL0
        inject(&mut e0, ExceptionKind::Sync, walker_dabt, 0xDEAD_0000, true);
        assert_eq!((e0[sr(SR_ESR)] >> 26) & 0x3F, 0x24, "EL0 abort -> EC=0x24 (DABT_LOW)");
        // From EL1h → EC stays 0x25 (DABT_CUR).
        let mut e1 = el1h_ctx(0xFFFF_0000_0000_2000, 0);
        inject(&mut e1, ExceptionKind::Sync, walker_dabt, 0xDEAD_0000, true);
        assert_eq!((e1[sr(SR_ESR)] >> 26) & 0x3F, 0x25, "EL1 abort -> EC=0x25 (DABT_CUR)");
        // SVC from EL0: EC=0x15 must NOT be altered (no same/lower form).
        let mut s0 = el1h_ctx(0xFFFF_0000_0000_3000, 0);
        s0[sr(SR_CURRENTEL)] = 0;
        let svc_esr = 0x15u64 << 26 | (1 << 25);
        inject(&mut s0, ExceptionKind::Sync, svc_esr, 0, false);
        assert_eq!((s0[sr(SR_ESR)] >> 26) & 0x3F, 0x15, "SVC EC unchanged");
    }

    /// The inject/eret duality holds through the new full ERET: NZCV and PC
    /// round-trip, and an IRQ entry/return at EL1h leaves the SP untouched.
    #[test]
    fn inject_then_full_eret_roundtrips() {
        let pc = 0xFFFF_8000_0055_6677u64;
        let nzcv = 0b0110 << 28;
        let mut ctx = el1h_ctx(pc, nzcv);
        const KSP: u64 = 0xFFFF_8000_5150_0000;
        ctx[SP_SLOT] = KSP;
        inject(&mut ctx, ExceptionKind::Irq, 0, 0, false);
        assert_eq!(ctx[SP_SLOT], KSP, "EL1h IRQ entry keeps the kernel SP");
        eret(&mut ctx);
        assert_eq!(ctx[PC_SLOT], pc, "ERET returns to the interrupted PC");
        assert_eq!(ctx[NZCV_SLOT], nzcv, "ERET restores NZCV");
        assert_eq!(ctx[SP_SLOT], KSP, "SP unchanged across EL1h round-trip");
    }
}
