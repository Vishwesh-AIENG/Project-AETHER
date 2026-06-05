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

use crate::runtime::context::{CTX_U64S, NZCV_OFFSET, PC_OFFSET, SYSREG_SLOT0};
use crate::runtime::mmu::{SLOT_PEND_ESR, SLOT_PEND_FAR, SLOT_PEND_PENDING};

// ── Context slot indices (u64 indices into the flat R15 context) ─────────────
/// Guest PC (next-PC / resume address). GPR-file region, byte 0x100.
const PC_SLOT: usize = PC_OFFSET / 8; // 32
/// Packed NZCV (N@31 Z@30 C@29 V@28). GPR-file region, byte 0x108.
const NZCV_SLOT: usize = NZCV_OFFSET / 8; // 33

// Sysreg sub-indices — MUST match `backend/lower_int.rs` `sysreg_read_idx`.
const SR_VBAR: usize = 6;
const SR_ESR: usize = 12;
const SR_ELR: usize = 13;
const SR_SPSR: usize = 14;
const SR_FAR: usize = 15;
const SR_DAIF: usize = 22;
const SR_SPSEL: usize = 23;
const SR_CURRENTEL: usize = 42;

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
    let vbar = ctx[sr(SR_VBAR)];

    // Save the interrupted state.
    ctx[sr(SR_SPSR)] = spsr;
    ctx[sr(SR_ELR)] = ctx[PC_SLOT];
    ctx[sr(SR_ESR)] = esr;
    if set_far {
        ctx[sr(SR_FAR)] = far;
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

/// Inject an IRQ exception (vector group + 0x80). ESR is UNKNOWN for an IRQ (0)
/// and FAR is unchanged. The caller has already decided the IRQ is deliverable
/// (`irqs_unmasked` + a GIC interrupt pending above PMR).
pub fn inject_irq(ctx: &mut [u64]) {
    inject(ctx, ExceptionKind::Irq, 0, 0, false);
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
}
