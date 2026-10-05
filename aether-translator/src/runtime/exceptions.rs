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

/// Telemetry: how many times the KPTI TTBR1 entry/exit switch actually fired
/// (packed: low 32 = inject→swapper, high 32 = eret→tramp). Read by the boot
/// heartbeat to confirm the switch engages.
pub static TTBR1_SWITCH_FIRED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// Sysreg sub-indices — MUST match `backend/lower_int.rs` `sysreg_read_idx`.
/// TTBR1_EL1 (kernel translation base). `sysreg_read_idx` maps `TtbrEl1_1 => 2`.
const SR_TTBR1: usize = 2;
const SR_VBAR: usize = 6;
/// Page-frame mask (bits [47:12]) for extracting a pgd base from TTBR1_EL1.
const TTBR_BASE_MASK: u64 = 0x0000_FFFF_FFFF_F000;
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

// [eretw] one-shot snapshot of the kernel state at the ERET that returns init to
// the corrupted resume PC (0x7ce8274c08) — used to pin the exception-return-path
// DBT miscompile. Dumped by boot_x86 at the PSCI halt.
pub static mut ERETW_LATCH: u64 = 0;
pub static mut ERETW_OP_PC: u64 = 0;
pub static mut ERETW_SPSR: u64 = 0;
pub static mut ERETW_ELR: u64 = 0;
pub static mut ERETW_SP_EL0: u64 = 0;
pub static mut ERETW_SP_EL1: u64 = 0;
pub static mut ERETW_X: [u64; 31] = [0; 31];

// [eretil] el0_undef corruptor hunt (2026-06-30). The fatal init SIGILL is an
// `el0_undef` (ESR_EL1 EC=0x00), which covers BOTH "unknown instruction" AND
// "illegal execution state (PSTATE.IL=1)". One mechanism for the latter is an
// ERET that restores a SPSR with IL set (bit 20) or an illegal/unexpected mode
// field — a miscompiled block that wrote a bad SPSR_EL1, or a corrupted SPSR
// slot. `eret()` latches the FIRST such return so the hypervisor heartbeat can
// print it: the restored SPSR, the ELR (the EL0 PC that will immediately raise
// el0_undef), the target EL, and the op PC of the faulting block. The
// translator is `no_std` and cannot call the hypervisor's `dual_puts`, so it
// surfaces statics (mirroring ERETW_* above) that boot_x86 dumps.
pub static mut ERETIL_LATCH: u64 = 0;
pub static mut ERETIL_SPSR: u64 = 0;
pub static mut ERETIL_ELR: u64 = 0;
pub static mut ERETIL_TGT_EL: u64 = 0;
pub static mut ERETIL_OP_PC: u64 = 0;

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
            // Source-EL stamp: lower-EL (*_LOW, bit 26 clear) when the
            // interrupted state was EL0, else same-EL (*_CUR, bit 26 set).
            //
            // NOTE (signal-11 audit): the originally-proposed "override to
            // lower-EL when FAR is a user address but cur_el reads 1" fix was
            // DELIBERATELY NOT APPLIED. A user-range FAR taken from EL1 is the
            // signature of LEGITIMATE kernel-uaccess (copy_to/from_user / CoW),
            // which MUST stay same-EL (0x25) so the kernel routes el1_abort /
            // do_page_fault as a kernel access of a user page — forcing it to
            // lower-EL would break that load-bearing path. `cur_el` is tracked
            // accurately by the dispatcher (EL0 faults record CURRENTEL=0, the
            // EL1-uaccess CoW faults record CURRENTEL=1 — see the [uflt] dumps),
            // so `cur_el` is the correct source of truth and no override is safe.
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

    // KPTI TTBR1 switch — emulate `tramp_map_kernel`. With page-table isolation
    // the entry trampoline switches TTBR1_EL1 from the trampoline pgd
    // (tramp_pg_dir, which maps only the trampoline) to swapper_pg_dir on every
    // EL0→EL1 entry, so the kernel runs with its real page tables (vmalloc, vmap
    // stacks, linear map). The DBT redirects exception entry straight to the
    // real vectors and never runs that trampoline, so do it here. KERNEL_PGD_
    // SNAPSHOT is the PROVEN swapper base (set only by the mmu fallback's
    // differential tramp↔swapper resolve, never by a transient pgd), and tramp =
    // swapper - 0x2000 (arm64 linker: tramp,reserved,swapper are consecutive
    // PAGE_SIZE pgds). Switch ONLY on a real EL0→EL1 entry whose live TTBR1
    // actually holds the trampoline pgd; ASID/CnP high bits are preserved.
    if cur_el == 0 {
        let snap = crate::runtime::mmu::kernel_pgd_snapshot();
        if snap != 0 {
            let cur_base = ctx[sr(SR_TTBR1)] & TTBR_BASE_MASK;
            if cur_base == snap.wrapping_sub(0x2000) {
                ctx[sr(SR_TTBR1)] = (ctx[sr(SR_TTBR1)] & !TTBR_BASE_MASK) | snap;
                TTBR1_SWITCH_FIRED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
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
#[allow(unsafe_code)]
pub fn eret(ctx: &mut [u64]) {
    debug_assert!(ctx.len() >= CTX_U64S, "context buffer too small for ERET");
    let spsr = ctx[sr(SR_SPSR)];
    let elr = ctx[sr(SR_ELR)];

    // [eretw] one-shot: when the ERET target is the corrupted init resume PC
    // (SV_WATCH = 0x7ce8274c08), snapshot the kernel GPR file + SPs so the
    // register holding the bad value + its neighbours reveal how the kernel
    // computed it (the DBT miscompile in the exception-return path).
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        let w = *core::ptr::addr_of!(crate::runtime::mmu::SV_WATCH);
        if w != 0 && (elr & 0x00FF_FFFF_FFFF_FFFF) == w
            && *core::ptr::addr_of!(ERETW_LATCH) == 0
        {
            *core::ptr::addr_of_mut!(ERETW_LATCH) = 1;
            *core::ptr::addr_of_mut!(ERETW_OP_PC) =
                *core::ptr::addr_of!(crate::runtime::mmu::FAULT_OP_PC);
            *core::ptr::addr_of_mut!(ERETW_SPSR) = spsr;
            *core::ptr::addr_of_mut!(ERETW_ELR) = elr;
            *core::ptr::addr_of_mut!(ERETW_SP_EL0) = ctx[sr(SR_SP_EL0)];
            *core::ptr::addr_of_mut!(ERETW_SP_EL1) = ctx[sr(SR_SP_EL1)];
            let mut i = 0usize;
            while i < 31 {
                (*core::ptr::addr_of_mut!(ERETW_X))[i] = ctx[i];
                i += 1;
            }
        }
    }

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

    // [eretil] Latch the FIRST ERET whose restored SPSR has PSTATE.IL set
    // (bit 20) or an illegal mode field (none of EL0t/EL1t/EL1h). Either makes
    // the guest take `el0_undef`/`el1_undef` on the very next instruction — the
    // SPSR-corruption flavour of the intermittent init SIGILL. Reading addr_of!
    // of EL2-private statics in a single-vCPU dispatch is sound.
    // SAFETY: EL2-private statics, single-vCPU.
    #[allow(unsafe_code)]
    unsafe {
        let il = (spsr >> 20) & 1;
        let bad_mode = !matches!(mode, MODE_EL0T | MODE_EL1T | MODE_EL1H);
        if (il == 1 || bad_mode) && *core::ptr::addr_of!(ERETIL_LATCH) == 0 {
            *core::ptr::addr_of_mut!(ERETIL_LATCH) = 1;
            *core::ptr::addr_of_mut!(ERETIL_SPSR) = spsr;
            *core::ptr::addr_of_mut!(ERETIL_ELR) = elr;
            *core::ptr::addr_of_mut!(ERETIL_TGT_EL) = tgt_el;
            *core::ptr::addr_of_mut!(ERETIL_OP_PC) =
                *core::ptr::addr_of!(crate::runtime::mmu::FAULT_OP_PC);
        }
    }

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

    // KPTI TTBR1 switch — emulate `tramp_unmap_kernel` (inverse of the entry
    // switch): on an ERET back to EL0 restore TTBR1 to the trampoline pgd
    // (swapper - 0x2000) so userspace runs with the kernel half unmapped. Only
    // when TTBR1 currently holds the proven swapper; ASID/CnP bits preserved.
    if tgt_el == 0 {
        let snap = crate::runtime::mmu::kernel_pgd_snapshot();
        if snap != 0 {
            let cur_base = ctx[sr(SR_TTBR1)] & TTBR_BASE_MASK;
            if cur_base == snap {
                ctx[sr(SR_TTBR1)] =
                    (ctx[sr(SR_TTBR1)] & !TTBR_BASE_MASK) | snap.wrapping_sub(0x2000);
                TTBR1_SWITCH_FIRED.fetch_add(1 << 32, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
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

/// Diagnostic capture, resolved AT SVC TIME (TTBR0 still live), of the last
/// connect() sockaddr path and the last writev()-to-stderr message. By the time
/// an "Attempted to kill init" panic reaches the PSCI halt, init's address space
/// is already torn down (exit_mm), so the hypervisor cannot walk these userspace
/// VAs then — it reads these statics instead to name WHY init exit(1)'d.
pub static mut LAST_CONNECT_PATH: [u8; 128] = [0; 128];
pub static mut LAST_CONNECT_LEN: usize = 0;
pub static mut LAST_STDERR_MSG: [u8; 256] = [0; 256];
pub static mut LAST_STDERR_LEN: usize = 0;
/// Ring of the last 8 small writes to fd 1/2/3 — first-stage init's crash text
/// (LOG(FATAL) / __fortify_fatal / __stack_chk_fail) before logd exists.
pub const WRITE_RING_N: usize = 16;
pub static mut WRITE_RING: [[u8; 120]; WRITE_RING_N] = [[0; 120]; WRITE_RING_N];
pub static mut WRITE_RING_LEN: [u16; WRITE_RING_N] = [0; WRITE_RING_N];
pub static mut WRITE_RING_FD: [u8; WRITE_RING_N] = [0; WRITE_RING_N];
pub static mut WRITE_RING_IDX: usize = 0;
/// Kept for the existing psci-exit dump (the most recent write).
pub static mut LAST_WRITE_MSG: [u8; 256] = [0; 256];
pub static mut LAST_WRITE_LEN: usize = 0;
pub static mut LAST_WRITE_FD: u64 = 0;
/// mknodat(2) accounting: total device nodes init created, and whether it ever
/// created /dev/null. If init exits with "failed to open /dev/null" but
/// DEVNULL_MKNOD_SEEN is true, the node exists in the main namespace and a forked
/// process simply can't see it (mount-namespace/devtmpfs); if false, init never
/// made it (its /dev setup path was skipped or the syscall mis-handled).
pub static mut MKNOD_COUNT: u64 = 0;
pub static mut DEVNULL_MKNOD_SEEN: bool = false;
/// mount(2) accounting: total mounts + the fstype init put on /dev (tmpfs vs
/// devtmpfs). If /dev is tmpfs but mknod_count==0, init's first-stage node setup
/// is being skipped/failing before the mknod section; if devtmpfs, the kernel
/// device-model isn't creating /dev/null; if LEN==0, init never mounted /dev.
pub static mut MOUNT_COUNT: u64 = 0;
/// Count of empty MS_MOVE mounts whose result was faked to success (root-skip).
pub static mut MOVE_PATCHED: u64 = 0;
/// Set when the current SVC is an empty-source MS_MOVE — its ERET fakes x0=0.
pub static mut MOVE_FAKE_PENDING: u64 = 0;
/// B36: syscall-correlation token for [`MOVE_FAKE_PENDING`] — the ELR_EL1 (return
/// address) captured when the fake is armed. The fake is consumed ONLY at the ERET
/// whose ELR matches, so an intervening signal/IRQ delivery to EL0 (a different
/// ELR) can't steal the fake and zero an unrelated syscall's x0.
pub static mut MOVE_FAKE_ELR: u64 = 0;
/// Ring of init opens matching device-tree/fstab/firmware + their returns.
pub static mut OPEN_RING_PATH: [[u8; 96]; 12] = [[0; 96]; 12];
pub static mut OPEN_RING_LEN: [usize; 12] = [0; 12];
pub static mut OPEN_RING_RET: [u64; 12] = [0; 12];
pub static mut OPEN_RING_IDX: usize = 0;
/// idx+1 of the in-flight openat whose ERET will record the return; 0 = none.
pub static mut OPEN_RING_PENDING: usize = 0;
pub static mut DEV_MOUNT_FSTYPE: [u8; 32] = [0; 32];
pub static mut DEV_MOUNT_FSTYPE_LEN: usize = 0;
/// Capture of init's /proc/mounts read content (the getmntent source) — to
/// decide whether the empty mnt_dir is a malformed proc line or a parse bug.
pub static mut READ_PEND_BUF: u64 = 0;
pub static mut READ_PEND_LEN: u64 = 0;
pub static mut READ_PEND: u64 = 0;
pub static mut PROC_MOUNTS_BUF: [u8; 400] = [0; 400];
pub static mut PROC_MOUNTS_LEN: usize = 0;
/// Ring of the last mount() (src, target, flags) — to see the failing MS_MOVE.
pub const MOUNT_RING_N: usize = 8;
pub static mut MOUNT_RING_SRC: [[u8; 64]; MOUNT_RING_N] = [[0; 64]; MOUNT_RING_N];
pub static mut MOUNT_RING_TGT: [[u8; 64]; MOUNT_RING_N] = [[0; 64]; MOUNT_RING_N];
pub static mut MOUNT_RING_FLAGS: [u64; MOUNT_RING_N] = [0; MOUNT_RING_N];
pub static mut MOUNT_RING_IDX: usize = 0;

#[allow(unsafe_code)]
pub extern "C" fn aether_svc_enter(ctx: *mut u64, imm16: u64) {
    // SAFETY: caller's contract — ctx is the register-file base.
    let slice = unsafe { core::slice::from_raw_parts_mut(ctx, CTX_U64S) };
    // B19: snapshot the three PEND slots so the diagnostic arg-string probes below
    // are PEND-transparent. They call aether_mmu_xlate on USER pointers; an unmapped
    // page makes the walker record a SPURIOUS pending Data Abort. Restoring the
    // snapshot at the single exit (rather than a blanket clear) guarantees the
    // probes leak no fault into the dispatcher regardless of control flow, while
    // preserving any abort that was genuinely pending at entry.
    let pend_snapshot = [
        slice[sr(SLOT_PEND_PENDING)],
        slice[sr(SLOT_PEND_FAR)],
        slice[sr(SLOT_PEND_ESR)],
    ];
    // Diagnostic: record (nr, x0, x1, x2, x30) into the ring.
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        // Mark the probe window: a fault taken here is spurious (cleared by the
        // PEND restore below) and must not be mistaken for init's real death.
        *core::ptr::addr_of_mut!(crate::runtime::mmu::IN_DIAG_PROBE) = 1;
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
        // connect(fd, sockaddr_un* @ x1, len): capture the socket path (after the
        // 2-byte sa_family) so a failing connect (ENOENT on a missing /dev/socket
        // entry) is named at the halt. These VAs are live (init just passed them).
        if slice[8] == 203 {
            let mut va = slice[1].wrapping_add(2);
            let out = core::ptr::addr_of_mut!(LAST_CONNECT_PATH);
            let mut j = 0usize;
            while j < 127 {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { break; }
                let b = *(pa as *const u8);
                if b == 0 { break; }
                (*out)[j] = b;
                va = va.wrapping_add(1);
                j += 1;
            }
            *core::ptr::addr_of_mut!(LAST_CONNECT_LEN) = j;
        }
        // writev(2=stderr, iovec* @ x1, cnt @ x2): concatenate the iov strings —
        // init's own error text right before exit_group(1).
        if slice[8] == 66 && slice[0] == 2 {
            let iov = slice[1];
            let cnt = if slice[2] < 8 { slice[2] } else { 8 };
            let out = core::ptr::addr_of_mut!(LAST_STDERR_MSG);
            let mut o = 0usize;
            let mut v = 0u64;
            while v < cnt && o < 255 {
                let bpa = crate::runtime::mmu::aether_mmu_xlate(ctx, iov + v * 16, 0, 8);
                let lpa = crate::runtime::mmu::aether_mmu_xlate(ctx, iov + v * 16 + 8, 0, 8);
                if bpa == 0 || lpa == 0 { break; }
                let base = *(bpa as *const u64);
                let len = *(lpa as *const u64);
                let mut va = base;
                let mut j = 0u64;
                while j < len && o < 255 {
                    let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                    if pa == 0 { break; }
                    (*out)[o] = *(pa as *const u8);
                    o += 1;
                    va = va.wrapping_add(1);
                    j += 1;
                }
                v += 1;
            }
            *core::ptr::addr_of_mut!(LAST_STDERR_LEN) = o;
        }
        // write(fd, buf @ x1, len @ x2): capture the text of any small write to a
        // low fd (1/2/3) — first-stage init's LOG(FATAL) message (the abort/
        // SIGABRT reason) goes here before logd exists. Keep the LAST one.
        if slice[8] == 64 && slice[0] <= 3 && slice[2] > 0 && slice[2] <= 255 {
            let buf = slice[1];
            let len = slice[2];
            let out = core::ptr::addr_of_mut!(LAST_WRITE_MSG);
            let mut o = 0usize;
            let mut va = buf;
            while (o as u64) < len && o < 255 {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { break; }
                (*out)[o] = *(pa as *const u8);
                o += 1;
                va = va.wrapping_add(1);
            }
            *core::ptr::addr_of_mut!(LAST_WRITE_LEN) = o;
            *core::ptr::addr_of_mut!(LAST_WRITE_FD) = slice[0];
            // Also push into the ring so the crash message (overwritten by the
            // later backtrace + reboot notice in the single buffer) is preserved.
            let ri = *core::ptr::addr_of!(WRITE_RING_IDX) % WRITE_RING_N;
            let rout = core::ptr::addr_of_mut!(WRITE_RING[ri]);
            let mut k = 0usize;
            let mut rva = buf;
            while (k as u64) < len && k < 120 {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, rva, 0, 1);
                if pa == 0 { break; }
                (*rout)[k] = *(pa as *const u8);
                k += 1;
                rva = rva.wrapping_add(1);
            }
            *core::ptr::addr_of_mut!(WRITE_RING_LEN[ri]) = k as u16;
            *core::ptr::addr_of_mut!(WRITE_RING_FD[ri]) = slice[0] as u8;
            *core::ptr::addr_of_mut!(WRITE_RING_IDX) =
                (*core::ptr::addr_of!(WRITE_RING_IDX)).wrapping_add(1);
        }
        // mknodat(dirfd, path @ x1, mode, dev): count device-node creations and
        // flag the /dev/null one (exact match incl. NUL terminator).
        if slice[8] == 33 {
            *core::ptr::addr_of_mut!(MKNOD_COUNT) =
                (*core::ptr::addr_of!(MKNOD_COUNT)).wrapping_add(1);
            let mut va = slice[1];
            let t = b"/dev/null\0";
            let mut m = 0usize;
            let mut ok = true;
            while m < t.len() {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { ok = false; break; }
                if *(pa as *const u8) != t[m] { ok = false; break; }
                va = va.wrapping_add(1);
                m += 1;
            }
            if ok {
                *core::ptr::addr_of_mut!(DEVNULL_MKNOD_SEEN) = true;
            }
        }
        // mount(source @ x0, target @ x1, fstype @ x2, ...): capture the fstype of
        // the /dev mount — tmpfs vs devtmpfs explains why /dev/null is absent.
        if slice[8] == 40 {
            *core::ptr::addr_of_mut!(MOUNT_COUNT) =
                (*core::ptr::addr_of!(MOUNT_COUNT)).wrapping_add(1);
            // switch_root root-skip fix. init's getmntent mis-parses the root
            // mnt_dir ("/") as "" (DBT sscanf bug), so SwitchRoot's `mnt_dir == "/"
            // -> continue` skip MISSES the root and init wrongly does
            // mount("", "/first_stage_ramdisk", MS_MOVE). The root must NOT be moved
            // (moving it under its own subtree is impossible — EINVAL/ELOOP). So
            // when the MS_MOVE source is empty, flag this SVC to return SUCCESS at
            // its ERET: a no-op that exactly matches the correct "skip the root"
            // behaviour, letting the sub-mount moves + final pivot proceed.
            // (MS_MOVE = 0x2000.) The underlying getmntent miscompile is the real
            // bug; this unblocks the pivot until it is found+fixed.
            if slice[3] & 0x2000 != 0 && slice[0] != 0 {
                let spa = crate::runtime::mmu::aether_mmu_xlate(ctx, slice[0], 0, 1);
                if spa != 0 && *(spa as *const u8) == 0 {
                    // Empty MS_MOVE source from the getmntent bug. Reconstruct the
                    // real mount point from the TARGET: switch_root moves each
                    // mnt_dir to new_root + mnt_dir, so for
                    // target = "/first_stage_ramdisk/<sub>" the source must be
                    // "/<sub>". For target == "/first_stage_ramdisk" exactly it is
                    // the rootfs move (skip — can't move root under its subtree).
                    const PFX: &[u8] = b"/first_stage_ramdisk";
                    let mut tgt = [0u8; 64];
                    let mut va = slice[1];
                    let mut tl = 0usize;
                    while tl < 63 {
                        let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                        if pa == 0 { break; }
                        let b = *(pa as *const u8);
                        if b == 0 { break; }
                        tgt[tl] = b;
                        va = va.wrapping_add(1);
                        tl += 1;
                    }
                    let is_pfx = tl >= PFX.len() && &tgt[..PFX.len()] == PFX;
                    let src_len = if is_pfx { tl - PFX.len() } else { 0 };
                    // B7/B35: NEVER overrun the libc++ char SSO inline buffer
                    // (~22 bytes incl. NUL) — a longer reconstructed path would
                    // scribble past it into the string's size/capacity/heap-ptr
                    // union. AOSP first-stage submounts are short (the longest,
                    // "/sys/fs/selinux", is 15). Cap the in-place write at 15
                    // bytes; for anything longer fall back to the no-op skip.
                    if is_pfx && src_len > 0 && src_len <= 15 {
                        // sub-mount: write src into the empty SSO buffer, NUL-term.
                        let src = &tgt[PFX.len()..tl];
                        let mut k = 0usize;
                        let mut ok = true;
                        while k < src.len() {
                            let pa = crate::runtime::mmu::aether_mmu_xlate(
                                ctx, slice[0].wrapping_add(k as u64), 1, 1);
                            if pa == 0 { ok = false; break; }
                            *(pa as *mut u8) = src[k];
                            k += 1;
                        }
                        if ok {
                            let pa = crate::runtime::mmu::aether_mmu_xlate(
                                ctx, slice[0].wrapping_add(src.len() as u64), 1, 1);
                            if pa != 0 { *(pa as *mut u8) = 0; }
                        }
                        *core::ptr::addr_of_mut!(MOVE_PATCHED) =
                            (*core::ptr::addr_of!(MOVE_PATCHED)).wrapping_add(1);
                    } else {
                        // exact "/first_stage_ramdisk" (rootfs) — fake success.
                        // B36: tag the fake with this syscall's return ELR so only
                        // its own ERET-to-EL0 consumes it.
                        *core::ptr::addr_of_mut!(MOVE_FAKE_PENDING) = 1;
                        *core::ptr::addr_of_mut!(MOVE_FAKE_ELR) = slice[sr(SR_ELR)];
                        *core::ptr::addr_of_mut!(MOVE_PATCHED) =
                            (*core::ptr::addr_of!(MOVE_PATCHED)).wrapping_add(1);
                    }
                }
            }
            let mut va = slice[1];
            let t = b"/dev\0";
            let mut m = 0usize;
            let mut ok = true;
            while m < t.len() {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { ok = false; break; }
                if *(pa as *const u8) != t[m] { ok = false; break; }
                va = va.wrapping_add(1);
                m += 1;
            }
            if ok {
                let mut fva = slice[2];
                let out = core::ptr::addr_of_mut!(DEV_MOUNT_FSTYPE);
                let mut j = 0usize;
                while j < 31 {
                    let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, fva, 0, 1);
                    if pa == 0 { break; }
                    let b = *(pa as *const u8);
                    if b == 0 { break; }
                    (*out)[j] = b;
                    fva = fva.wrapping_add(1);
                    j += 1;
                }
                *core::ptr::addr_of_mut!(DEV_MOUNT_FSTYPE_LEN) = j;
            }
            // Capture EVERY mount() call's (src, target, flags) into a ring so the
            // failing switch_root MS_MOVE — mount("", "/first_stage_ramdisk",
            // MS_MOVE) = EINVAL — is visible: is the empty source init's own
            // getmntent parse, or a DBT-mistranslated arg?
            let ri = *core::ptr::addr_of!(MOUNT_RING_IDX) % MOUNT_RING_N;
            let rd = |va0: u64, out: *mut [u8; 64]| {
                let mut va = va0;
                let mut k = 0usize;
                while k < 63 {
                    let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                    if pa == 0 { break; }
                    let b = *(pa as *const u8);
                    if b == 0 { break; }
                    (*out)[k] = b;
                    va = va.wrapping_add(1);
                    k += 1;
                }
                (*out)[k] = 0;
            };
            (*core::ptr::addr_of_mut!(MOUNT_RING_SRC))[ri] = [0; 64];
            (*core::ptr::addr_of_mut!(MOUNT_RING_TGT))[ri] = [0; 64];
            rd(slice[0], core::ptr::addr_of_mut!(MOUNT_RING_SRC[ri]));
            rd(slice[1], core::ptr::addr_of_mut!(MOUNT_RING_TGT[ri]));
            *core::ptr::addr_of_mut!(MOUNT_RING_FLAGS[ri]) = slice[3];
            *core::ptr::addr_of_mut!(MOUNT_RING_IDX) =
                (*core::ptr::addr_of!(MOUNT_RING_IDX)).wrapping_add(1);
        }
        // read(fd, buf @ x1, len @ x2): stash the buffer for the matching ERET so
        // the FILLED content can be inspected for the /proc/mounts table.
        if slice[8] == 63 && slice[2] >= 128 {
            *core::ptr::addr_of_mut!(READ_PEND_BUF) = slice[1];
            *core::ptr::addr_of_mut!(READ_PEND_LEN) = slice[2];
            *core::ptr::addr_of_mut!(READ_PEND) = 1;
        }
        // openat(dirfd@x0, path@x1, ...): if the path mentions fstab/device-tree,
        // stash it + flag the SVC so its ERET records the fd/-errno. Reveals which
        // fstab path the FirstStageMount opendir/open hits and whether it succeeds.
        // openat(56) / faccessat(48) / newfstatat(79) — all take the path at x1.
        if slice[8] == 56 || slice[8] == 48 || slice[8] == 79 {
            let mut tmp = [0u8; 96];
            let mut va = slice[1];
            let mut j = 0usize;
            while j < 95 {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { break; }
                let b = *(pa as *const u8);
                if b == 0 { break; }
                tmp[j] = b;
                va = va.wrapping_add(1);
                j += 1;
            }
            // match "tree" / "fstab" / "firmware" substring (device-tree, fstab.*,
            // firmware/android, /sys/firmware).
            let has = |pat: &[u8]| -> bool {
                if pat.len() > j { return false; }
                let mut i = 0usize;
                while i + pat.len() <= j {
                    if &tmp[i..i + pat.len()] == pat { return true; }
                    i += 1;
                }
                false
            };
            if has(b"tree") || has(b"fstab") || has(b"firmware")
                || has(b"cmdline") || has(b"bootconfig") || has(b"/proc/mounts")
            {
                let idx = *core::ptr::addr_of!(OPEN_RING_IDX) % 12;
                let out = core::ptr::addr_of_mut!(OPEN_RING_PATH);
                let mut k = 0usize;
                while k < j { (*out)[idx][k] = tmp[k]; k += 1; }
                (*core::ptr::addr_of_mut!(OPEN_RING_LEN))[idx] = j;
                (*core::ptr::addr_of_mut!(OPEN_RING_RET))[idx] = 0xDEAD;
                *core::ptr::addr_of_mut!(OPEN_RING_PENDING) = idx + 1;
            }
        }
    }
    // (The prctl(PR_SET_VMA)→-EINVAL intercept that briefly lived here was a RED
    // HERRING. The "intermittent EL0-write SIGSEGV" it tried to dodge was really
    // the cross-page NON-CONTIGUOUS LDP/STP/LDR-Q loop — fixed in mmu.rs via a
    // gather/scatter bounce buffer. PR_SET_VMA only CORRELATED (bionic names the
    // VMA right before the straddling memcpy). Faking -EINVAL is a fingerprint
    // deviation and is no longer needed, so the syscall now falls through to the
    // kernel's real (no-op, returns 0) handler.)
    // The diagnostic path-string probes above (connect/writev/mknodat/mount)
    // call aether_mmu_xlate on USER pointers; when a string page is not mapped
    // the walker records a SPURIOUS pending Data Abort in the PEND slots. Left
    // set, the dispatcher injects it on a LATER block — at ret_to_user with
    // SP_EL0 = the user SP — and enter_from_kernel_mode then loops forever
    // dereferencing current=SP_EL0 (a user address). An SVC is not itself a
    // fault, so any probe-induced PEND must not survive into the syscall entry.
    // (This was the mount()-time enter_from_kernel_mode nested-abort wedge.)
    // B19: restore the entry snapshot — discards probe-induced PEND, keeps a
    // genuinely-pending abort (normally none, since SVC is not itself a fault).
    slice[sr(SLOT_PEND_PENDING)] = pend_snapshot[0];
    slice[sr(SLOT_PEND_FAR)] = pend_snapshot[1];
    slice[sr(SLOT_PEND_ESR)] = pend_snapshot[2];
    // SAFETY: EL2-private static, single-vCPU. End the probe window.
    unsafe { *core::ptr::addr_of_mut!(crate::runtime::mmu::IN_DIAG_PROBE) = 0; }
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
    // B19 (HV-side): the leftover /proc-mounts + openat investigation diagnostics
    // below aether_mmu_xlate GUEST buffers (READ_PEND_BUF) with no PEND guard. If
    // init's read buffer is bad/lazily-mapped (the kernel would return EFAULT),
    // the xlate records a SPURIOUS pending Data Abort that the dispatcher then
    // injects → init SIGSEGV → kill init. Snapshot the PEND slots here and restore
    // before return so these diagnostics are PEND-transparent.
    let pend_snap_ee = [
        slice[sr(SLOT_PEND_PENDING)],
        slice[sr(SLOT_PEND_FAR)],
        slice[sr(SLOT_PEND_ESR)],
    ];
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        // Root-skip: fake the empty-source MS_MOVE (the mis-parsed root mount) to
        // return 0 (success) so init's switch_root proceeds instead of FATAL-ing
        // on EINVAL. Only on the ERET back to EL0 after that syscall.
        if *core::ptr::addr_of!(MOVE_FAKE_PENDING) != 0
            && ((slice[sr(SR_CURRENTEL)] >> 2) & 0b11) == 0
            && slice[sr(SR_ELR)] == *core::ptr::addr_of!(MOVE_FAKE_ELR)
        {
            *core::ptr::addr_of_mut!(MOVE_FAKE_PENDING) = 0;
            slice[0] = 0;
        }
        // openat(device-tree/fstab/firmware) return capture into the ring.
        let pend = *core::ptr::addr_of!(OPEN_RING_PENDING);
        if pend != 0 && ((slice[sr(SR_CURRENTEL)] >> 2) & 0b11) == 0 {
            let idx = pend - 1;
            (*core::ptr::addr_of_mut!(OPEN_RING_RET))[idx] = slice[0];
            *core::ptr::addr_of_mut!(OPEN_RING_IDX) =
                (*core::ptr::addr_of!(OPEN_RING_IDX)).wrapping_add(1);
            *core::ptr::addr_of_mut!(OPEN_RING_PENDING) = 0;
        }
    }
    // mmap probe: the first ERET back to EL0 after an mmap SVC carries the
    // syscall's return value in x0 (IRQs return to EL1 and don't match).
    // SAFETY: EL2-private statics, single-vCPU.
    unsafe {
        if *core::ptr::addr_of!(MMAP_PENDING) && ((slice[sr(SR_CURRENTEL)] >> 2) & 0b11) == 0 {
            *core::ptr::addr_of_mut!(MMAP_RET) = slice[0];
            *core::ptr::addr_of_mut!(MMAP_RET_VALID) = true;
            *core::ptr::addr_of_mut!(MMAP_PENDING) = false;
        }
        // read() ERET: the buffer is now filled. If it looks like the mount table
        // (contains "tmpfs"), snapshot it — reveals whether /proc/mounts has an
        // empty mount-point field (kernel) or getmntent mis-parsed (DBT).
        if *core::ptr::addr_of!(READ_PEND) != 0
            && ((slice[sr(SR_CURRENTEL)] >> 2) & 0b11) == 0
        {
            *core::ptr::addr_of_mut!(READ_PEND) = 0;
            let buf = *core::ptr::addr_of!(READ_PEND_BUF);
            let len = *core::ptr::addr_of!(READ_PEND_LEN);
            let n = if len > 396 { 396 } else { len as usize };
            let mut tmp = [0u8; 396];
            let mut k = 0usize;
            let mut va = buf;
            while k < n {
                let pa = crate::runtime::mmu::aether_mmu_xlate(ctx, va, 0, 1);
                if pa == 0 { break; }
                tmp[k] = *(pa as *const u8);
                k += 1;
                va = va.wrapping_add(1);
            }
            // Commit only if it contains "tmpfs" (mount-table marker).
            let mut has = false;
            let mut i = 0usize;
            while i + 5 <= k {
                if &tmp[i..i + 5] == b"tmpfs" { has = true; break; }
                i += 1;
            }
            if has {
                let out = core::ptr::addr_of_mut!(PROC_MOUNTS_BUF);
                let mut j = 0usize;
                while j < k {
                    (*out)[j] = tmp[j];
                    j += 1;
                }
                *core::ptr::addr_of_mut!(PROC_MOUNTS_LEN) = k;
            }
        }
    }
    // Restore PEND: a diagnostic xlate of a bad/unmapped guest buffer above must
    // not leak a spurious Data Abort into the guest (would spuriously kill init).
    slice[sr(SLOT_PEND_PENDING)] = pend_snap_ee[0];
    slice[sr(SLOT_PEND_FAR)] = pend_snap_ee[1];
    slice[sr(SLOT_PEND_ESR)] = pend_snap_ee[2];
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

    /// EC source-EL stamp (signal-11 audit). The abort EC's same/lower bit
    /// (ESR bit 26) MUST follow the interrupted EL (`cur_el`), NOT the FAR:
    ///   * EL0 source  → *_LOW (0x24), bit 26 clear — userspace demand-paging.
    ///   * EL1 source  → *_CUR (0x25), bit 26 set — INCLUDING a user-range FAR
    ///     (legitimate kernel-uaccess copy_to/from_user / CoW must route el1).
    /// This locks the decision to NOT override EL1+user-FAR to lower-EL (that
    /// would break the load-bearing kernel-uaccess path).
    #[test]
    fn abort_ec_follows_source_el_not_far() {
        let user_far = 0x0000_007E_D22F_1000u64; // a user (TTBR0, bit55=0) address
        let kern_far = 0xFFFF_FF80_3EE2_0000u64; // a kernel (TTBR1, bit55=1) address

        // EL0 source, user FAR → lower-EL (bit 26 clear → EC 0x24).
        let mut e0 = el1h_ctx(0x0040_1000, 0);
        e0[sr(SR_CURRENTEL)] = 0; // EL0
        inject(&mut e0, ExceptionKind::Sync, (0x25 << 26) | (1 << 25) | 0b0100, user_far, true);
        assert_eq!((e0[sr(SR_ESR)] >> 26) & 0x3F, 0x24, "EL0 user fault → DABT_LOW");

        // EL1 source, USER FAR → same-EL (kernel-uaccess stays 0x25). The key
        // assertion: the FAR being a user address does NOT downgrade the EC.
        let mut e1u = el1h_ctx(0xFFFF_FFC0_0810_0000, 0);
        inject(&mut e1u, ExceptionKind::Sync, (0x25 << 26) | (1 << 25) | 0b0100, user_far, true);
        assert_eq!(
            (e1u[sr(SR_ESR)] >> 26) & 0x3F, 0x25,
            "EL1 kernel-uaccess of a user VA must stay DABT_CUR (no override)"
        );

        // EL1 source, kernel FAR → same-EL (0x25).
        let mut e1k = el1h_ctx(0xFFFF_FFC0_0810_0000, 0);
        inject(&mut e1k, ExceptionKind::Sync, (0x24 << 26) | (1 << 25) | 0b0100, kern_far, true);
        assert_eq!((e1k[sr(SR_ESR)] >> 26) & 0x3F, 0x25, "EL1 kernel fault → DABT_CUR");
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
