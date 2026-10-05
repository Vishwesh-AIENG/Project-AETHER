//! AT-12: Integer IR lowering — IR ops → x86_64 instruction sequences.
//!
//! Maps integer ALU / load / store / branch / flag ops to x86_64 code using
//! the register assignments produced by the AT-9 linear-scan allocator.
//!
//! Gate: hello-world (`ConstI64 {val:0}; Return`) translates to a byte-exact
//! x86_64 sequence that zero-extends RAX and returns.
//!
//! Spilled values reside at [context_base + slot * 8].  `context_base` is a
//! caller-supplied register holding the per-thread ARM context block.

use crate::ir::{IrBlock, IrValueId, IrOp};
use crate::ir::memory::{AtomicOp, LoadTy, StoreTy};
use crate::regalloc::linear_scan::{AllocResult, Assignment};
use crate::regalloc::x86_regs::{ALLOCATABLE_GPRS, ALLOCATABLE_XMMS};
use super::encode::X86Encoder;

// x86 condition codes (low nibble of Jcc / SETcc / CMOVcc).
pub mod cc {
    pub const O:   u8 = 0x0; // overflow
    pub const NO:  u8 = 0x1;
    pub const B:   u8 = 0x2; // below (unsigned <)
    pub const NB:  u8 = 0x3; // not below (unsigned >=)
    pub const Z:   u8 = 0x4; // zero / equal
    pub const NZ:  u8 = 0x5;
    pub const BE:  u8 = 0x6; // below or equal
    pub const NBE: u8 = 0x7;
    pub const S:   u8 = 0x8; // sign
    pub const NS:  u8 = 0x9;
    pub const P:   u8 = 0xA; // parity
    pub const NP:  u8 = 0xB;
    pub const L:   u8 = 0xC; // less (signed <)
    pub const NL:  u8 = 0xD;
    pub const LE:  u8 = 0xE;
    pub const NLE: u8 = 0xF;
}

/// Mapping from ARM64 condition code to x86 condition code nibble.
/// ARM Cond encoding: EQ=0, NE=1, CS=2, CC=3, MI=4, PL=5, VS=6, VC=7,
/// HI=8, LS=9, GE=10, LT=11, GT=12, LE=13, AL=14, NV=15.
const ARM_COND_TO_X86: [u8; 16] = [
    cc::Z,   // EQ → ZF=1
    cc::NZ,  // NE → ZF=0
    cc::NB,  // CS (unsigned >=) → CF=0
    cc::B,   // CC (unsigned <)  → CF=1
    cc::S,   // MI → SF=1
    cc::NS,  // PL → SF=0
    cc::O,   // VS → OF=1
    cc::NO,  // VC → OF=0
    cc::NBE, // HI → CF=0 && ZF=0
    cc::BE,  // LS → CF=1 || ZF=1
    cc::NL,  // GE → SF=OF
    cc::L,   // LT → SF≠OF
    cc::NLE, // GT → ZF=0 && SF=OF
    cc::LE,  // LE → ZF=1 || SF≠OF
    cc::NB,  // AL → always (use JMP, not Jcc — caller handles)
    cc::NB,  // NV → never (treated as AL here)
];

/// Context register (R15) holds base of the per-thread ARM guest context block.
/// Spill slots live at [R15 + slot * 8].  This matches the AT-19 context layout.
pub const CONTEXT_REG: u8 = 15; // R15

/// GuestRegisterFile field displacements from CONTEXT_REG (must match
/// runtime/context.rs SP_OFFSET / PC_OFFSET). GPRs are at reg*8 from base.
const SP_DISP: i32 = 0x0F8; // runtime::context::SP_OFFSET
const PC_DISP: i32 = 0x100; // runtime::context::PC_OFFSET
const NZCV_DISP: i32 = 0x108; // runtime::context::NZCV_OFFSET

/// Reserved spill-materialization scratch GPRs (removed from ALLOCATABLE_GPRS).
/// An op with two spilled inputs needs both: input A -> SCRATCH0, B -> SCRATCH1.
const SCRATCH0: u8 = 0; // RAX
const SCRATCH1: u8 = 1; // RCX

/// MMU-walker side effect of an `MSR <sysreg>, Xn` write. Translation-control
/// registers require the software TLB to be flushed; everything else is inert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MsrMmuEffect {
    /// No software-TLB action needed (e.g. SCTLR — `M` is read live every xlate).
    None,
    /// TTBR0/1_EL1, TCR_EL1, or MAIR_EL1 changed: invalidate the whole soft TLB.
    FlushTlb,
}

/// Integer lowering pass.  Stateless; call [`IntLower::lower_block`] per block.
pub struct IntLower;

impl IntLower {
    /// Lower all ops in `blk` to x86_64, appending bytes to `enc`.
    ///
    /// `alloc` maps `IrValueId → Assignment`; `context_reg` is the GPR that
    /// holds the base of the per-thread ARM context block (used for spill
    /// loads/stores).  Patch offsets for forward branches are collected into
    /// `branch_patches`.
    pub fn lower_block(
        blk: &IrBlock,
        alloc: &AllocResult,
        enc: &mut X86Encoder,
        branch_patches: &mut alloc::vec::Vec<(usize, crate::ir::BlockId)>,
    ) {
        Self::lower_block_with_pc(blk, 0, alloc, enc, branch_patches);
    }

    /// Phase-E variant: also stamps `LAST_GUEST_PC` with the block's
    /// guest entry PC at block prologue. Reserved scratch RAX is used
    /// for the staging move (no live value can occupy RAX — see
    /// ALLOCATABLE_GPRS), so the prologue is safe to inject before any
    /// op. Two instructions, ~22 bytes per block; only emitted when
    /// `entry_pc != 0` (callers pass 0 from unit tests where no kernel
    /// PC exists).
    pub fn lower_block_with_pc(
        blk: &IrBlock,
        entry_pc: u64,
        alloc: &AllocResult,
        enc: &mut X86Encoder,
        branch_patches: &mut alloc::vec::Vec<(usize, crate::ir::BlockId)>,
    ) {
        if entry_pc != 0 {
            const RAX: u8 = 0;
            const RCX: u8 = 1;
            // RAX = entry_pc
            enc.emit_mov_r64_imm64(RAX, entry_pc as i64);
            // RCX = &LAST_GUEST_PC
            let pc_addr = core::ptr::addr_of_mut!(
                crate::runtime::mmu::LAST_GUEST_PC
            ) as usize as i64;
            enc.emit_mov_r64_imm64(RCX, pc_addr);
            // [RCX] = RAX
            enc.emit_mov_mem_r64(RCX, 0, RAX);
        }
        for op in &blk.ops {
            Self::lower_op(op, alloc, enc, branch_patches);
        }
    }

    fn gpr(alloc: &AllocResult, vid: IrValueId) -> u8 {
        match alloc.assignments.get(&vid.0) {
            Some(Assignment::Gpr(idx)) => ALLOCATABLE_GPRS[*idx as usize] as u8,
            Some(Assignment::Spill(slot)) => {
                // POINTER-CLOBBER HAZARD (silent near-null deref): returning
                // SCRATCH0 (==RAX==0) for a SPILLED value means a spilled guest
                // POINTER read via bare gpr() becomes RAX — which the MMU-call
                // sequence treats as the guest VA (≈0) → walker returns a
                // near-zero host PA → the load/store faults at far≈small-offset.
                // Every callsite that can receive a spilled operand MUST either
                // route it through `src_in`/`dest_work` (correct) or guard with
                // `requires_gpr`/`is_spilled` → UD2 (fail loud) BEFORE calling
                // gpr(). Reaching this arm means a callsite forgot that guard, so
                // fail loud in debug to surface the miscompile during host tests.
                let _ = slot;
                debug_assert!(
                    false,
                    "gpr() reached for a SPILLED value (vid={}): callsite must \
                     route through src_in/dest_work or guard with requires_gpr; \
                     returning RAX would silently zero a pointer",
                    vid.0
                );
                SCRATCH0
            }
            _ => {
                // `None` (value never assigned). This is REACHABLE and benign for
                // the ctx-template SIMD/FP structural lowering, which is exercised
                // with an EMPTY alloc (every value resolves to None) because those
                // ops compute in XMM scratch + ctx memory and never need the GPR
                // assignment — see the `empty_alloc()` tests in at13_simd_ctx. So we
                // do NOT assert here (it would break that legitimate pattern).
                //
                // The DANGEROUS case — a `None`-assigned value used as a memory-op
                // ADDRESS (a used-but-never-defined POINTER) — is intercepted
                // UPSTREAM by `requires_gpr`/`addr_in` at every memory & runtime-call
                // arm (they UD2 / fail-loud on a non-Gpr address), so a `None`
                // pointer can never silently reach a near-null deref through this
                // fallback. Returning RAX here only ever feeds the SIMD ctx-template
                // path, which ignores the value.
                SCRATCH0
            }
        }
    }

    /// True iff `vid` is in a real allocatable GPR (NOT spilled, NOT unassigned).
    /// The correct fail-loud guard for any arm that marshals a POINTER (or value)
    /// out of a bare `gpr()` into an MMU/runtime call: `!requires_gpr(..)` must
    /// UD2. Unlike `is_spilled`, this ALSO rejects the `None`/unassigned case,
    /// closing the silent `gpr()→RAX(0)` near-null-deref hole.
    fn requires_gpr(alloc: &AllocResult, vid: IrValueId) -> bool {
        matches!(alloc.assignments.get(&vid.0), Some(Assignment::Gpr(_)))
    }

    // ── M4a spill materialization ─────────────────────────────────────────────
    // Two reserved scratch GPRs (RAX/RCX, removed from ALLOCATABLE_GPRS) let the
    // lowering load a spilled operand before use and store a spilled dest after
    // a def. Spill slots live at [R15 + SPILL_BASE + slot*8].

    /// True if `vid` was assigned a spill slot (not a physical reg).
    fn is_spilled(alloc: &AllocResult, vid: IrValueId) -> bool {
        matches!(alloc.assignments.get(&vid.0), Some(Assignment::Spill(_)))
    }

    /// Byte displacement of `vid`'s spill slot from CONTEXT_REG (R15).
    fn spill_disp(alloc: &AllocResult, vid: IrValueId) -> i32 {
        if let Some(Assignment::Spill(slot)) = alloc.assignments.get(&vid.0) {
            debug_assert!((*slot as usize) < crate::runtime::context::SPILL_SLOTS);
            crate::runtime::context::SPILL_BASE as i32 + (*slot as i32) * 8
        } else {
            0
        }
    }

    /// Get `vid` into a usable register for reading. If spilled, load it into
    /// `scratch` from its spill slot and return `scratch`; else return its reg.
    fn src_in(alloc: &AllocResult, enc: &mut X86Encoder, vid: IrValueId, scratch: u8) -> u8 {
        if Self::is_spilled(alloc, vid) {
            enc.emit_mov_r64_mem(scratch, CONTEXT_REG, Self::spill_disp(alloc, vid));
            scratch
        } else {
            Self::gpr(alloc, vid)
        }
    }

    /// Pick a working register for writing `vid`: its assigned reg if in-register,
    /// else `scratch`. Returns (work_reg, spilled). Caller MUST call store_dest
    /// after the defining instruction when spilled is true.
    fn dest_work(alloc: &AllocResult, vid: IrValueId, scratch: u8) -> (u8, bool) {
        if Self::is_spilled(alloc, vid) {
            (scratch, true)
        } else {
            (Self::gpr(alloc, vid), false)
        }
    }

    /// Store a spilled dest's working register back to its slot. No-op if not spilled.
    fn store_dest(alloc: &AllocResult, enc: &mut X86Encoder, vid: IrValueId, work: u8, spilled: bool) {
        if spilled {
            enc.emit_mov_mem_r64(CONTEXT_REG, Self::spill_disp(alloc, vid), work);
        }
    }

    /// Materialize a memory-op ADDRESS (or runtime-call value) operand into a
    /// register usable as the source for `emit_mmu_xlate_call` / `emit_mmu_store_call`
    /// / a runtime CALL.
    ///
    /// - `Gpr` → its allocated register (returned directly).
    /// - `Spill` → loaded from its spill slot into `scratch`, which is returned.
    ///   `scratch` MUST be a reserved scratch GPR (RAX/RCX) that the subsequent
    ///   call-arg marshalling reads BEFORE clobbering — the integer Load/Store
    ///   arms use SCRATCH0 (RAX) for exactly this; the call reads it into RDX
    ///   first (RAX is never in MMU_SAVE_REGS so the push set doesn't disturb it).
    /// - `None` (unassigned) → falls back to `gpr()` (returns RAX). In PRODUCTION
    ///   `regalloc::allocate` assigns every used value (Gpr or Spill), so a `None`
    ///   address never arises there; it occurs only in the ctx-template SIMD/FP
    ///   structural tests that lower with an EMPTY alloc (the value is irrelevant to
    ///   those XMM/ctx-memory ops). The keystore2 `far=0x502558` bug was a SPILLED
    ///   pointer (a real-but-clobbered register), which this materializes — `None`
    ///   is a separate, latent regalloc concern, not this signature, so it is NOT
    ///   forced to UD2 here (that would wall the structural-test path).
    ///
    /// This is the spill-SAFE replacement for a bare `gpr()` on an address operand:
    /// a spilled pointer base now dereferences the REAL pointer (loaded from its
    /// slot) instead of silently using RAX≈0 (the keystore2 `far=0x502558` bug) or
    /// UD2-walling a perfectly recoverable spilled access.
    fn addr_in(alloc: &AllocResult, enc: &mut X86Encoder, vid: IrValueId, scratch: u8) -> Option<u8> {
        match alloc.assignments.get(&vid.0) {
            Some(Assignment::Spill(_)) => {
                enc.emit_mov_r64_mem(scratch, CONTEXT_REG, Self::spill_disp(alloc, vid));
                Some(scratch)
            }
            // Gpr → its register; None → gpr()'s RAX fallback (structural tests).
            _ => Some(Self::gpr(alloc, vid)),
        }
    }

    // ── M4a NZCV materialization ──────────────────────────────────────────────
    // build_nzcv: called IMMEDIATELY after an x86 ALU op (EFLAGS live). Packs the
    // 4 ARM flags into [R15+0x108] (N@31 Z@30 C@29 V@28). N=SF, Z=ZF straight from
    // EFLAGS; for ADD-kind C=CF (SETC) V=OF (SETO); for SUB-kind C=NOT-borrow
    // (SETNC — ARM carry = !x86 borrow) V=OF; for LOGICAL C=V=0 (skipped).
    // Uses RAX/RCX (reserved scratch) + RBX/RDX as byte scratch saved via push/pop
    // (push/pop preserve EFLAGS and the saved regs' live values).
    const NZCV_ADD: u8 = 0;
    const NZCV_SUB: u8 = 1;
    const NZCV_LOG: u8 = 2;

    fn build_nzcv(enc: &mut X86Encoder, kind: u8) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        const RBX: u8 = 3;
        enc.emit_push_r64(RBX);
        enc.emit_push_r64(RDX);
        // Capture flags (SETcc does not modify EFLAGS).
        enc.emit_setcc_r8(cc::S, RAX); // AL = N (SF)
        enc.emit_setcc_r8(cc::Z, RCX); // CL = Z (ZF)
        if kind != Self::NZCV_LOG {
            let c_cc = if kind == Self::NZCV_SUB { cc::NB } else { cc::B };
            enc.emit_setcc_r8(c_cc, RBX); // BL = C  (NB=SETNC for sub, B=SETC for add)
            enc.emit_setcc_r8(cc::O, RDX); // DL = V (OF)
        }
        // Assemble packed word in RAX (movzx/shl/or clobber EFLAGS — done capturing).
        enc.emit_movzx_r64_r8(RAX, RAX);
        enc.emit_shl_r64_imm8(RAX, 31); // N@31
        enc.emit_movzx_r64_r8(RCX, RCX);
        enc.emit_shl_r64_imm8(RCX, 30); // Z@30
        enc.emit_or_rr64(RAX, RCX);
        if kind != Self::NZCV_LOG {
            enc.emit_movzx_r64_r8(RCX, RBX);
            enc.emit_shl_r64_imm8(RCX, 29); // C@29
            enc.emit_or_rr64(RAX, RCX);
            enc.emit_movzx_r64_r8(RCX, RDX);
            enc.emit_shl_r64_imm8(RCX, 28); // V@28
            enc.emit_or_rr64(RAX, RCX);
        }
        enc.emit_mov_mem_r64(CONTEXT_REG, NZCV_DISP, RAX);
        enc.emit_pop_r64(RDX);
        enc.emit_pop_r64(RBX);
    }

    // ── M4b-2b MMU translation call (guest VA → host PA via aether_mmu_xlate) ──
    // Every translated Load/Store routes its guest address through the software
    // page-table walker so that once the guest sets SCTLR_EL1.M=1 the access
    // lands at the walked host PA (and, while M==0, at the flat VA — the walker
    // returns `va` unchanged). The walker also confines every PA to the guest
    // window (No-Boundary) and reflects out-of-window / unmapped / permission
    // faults as a pending Data Abort, returning XLATE_FAULT (0).
    //
    // ABI: Win64 (the hypervisor target x86_64-unknown-uefi is Microsoft x64).
    //   aether_mmu_xlate(ctx=RCX, va=RDX, is_write=R8, size=R9) -> RAX (host PA)
    // RAX/RCX/RDX/R8..R11 are volatile; we therefore preserve every allocatable
    // GPR that may hold a block-live value across the call (RAX/RCX are reserved
    // scratch and never hold a live value, so they are NOT preserved — RAX is in
    // fact our return register). The 12-register save set has even parity, so it
    // does not change RSP's 16-byte alignment relative to block entry; the
    // `sub rsp, 0x28` then realigns to 16 and reserves the 32-byte shadow space.

    /// Allocatable GPRs that may hold a live value across an MMU call. RAX(0) and
    /// RCX(1) are reserved scratch (return reg + arg-build), so excluded. RSP(4)
    /// is never allocatable. 12 entries → even parity (push set leaves RSP%16
    /// unchanged from block entry).
    const MMU_SAVE_REGS: [u8; 12] = [
        2,  // RDX
        3,  // RBX
        5,  // RBP
        6,  // RSI
        7,  // RDI
        8,  // R8
        9,  // R9
        10, // R10
        11, // R11
        12, // R12
        13, // R13
        14, // R14
    ];

    /// Emit a Win64 CALL to `aether_mmu_xlate(R15, addr_reg, is_write, size)`,
    /// leaving the translated host PA in RAX. On a fault (`RAX == XLATE_FAULT ==
    /// 0`, with the pending-fault sysreg slots already set by the walker) the
    /// emitted code performs an early `RET` so the dispatcher (M4b-3) sees the
    /// pending Data Abort. `addr_reg` is read BEFORE the save set is clobbered.
    ///
    /// `addr_reg` MUST be a real allocated GPR (not a spilled value resolving to
    /// SCRATCH0); the Load/Store arms fail loud (UD2) before calling this if the
    /// address (or store value) is spilled, so a stale-scratch address can never
    /// reach the call.
    fn emit_mmu_xlate_call(enc: &mut X86Encoder, addr_reg: u8, is_write: bool, size: i32) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        const R8: u8 = 8;
        const R9: u8 = 9;
        // 1. Save every block-live allocatable GPR (RSP unchanged mod 16; 12 push).
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // 2. Marshal arguments. `addr_reg` still holds the guest VA here (the
        //    push above only spilled COPIES to the stack; the registers retain
        //    their values until we overwrite them). Set RDX (=va) FIRST while
        //    addr_reg is guaranteed live, then the others.
        //    NOTE: if addr_reg == RDX this is `mov rdx, rdx` (harmless); addr_reg
        //    is never RAX/RCX (reserved, never allocated to a real value).
        if addr_reg != RDX {
            enc.emit_mov_rr64(RDX, addr_reg); // RDX = va
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // RCX = ctx (R15)
        enc.emit_mov_r64_imm32(R8, if is_write { 1 } else { 0 }); // R8 = is_write
        enc.emit_mov_r64_imm32(R9, size); // R9 = access size in bytes
        // 3. Reserve 32-byte shadow space + realign RSP to 16 (entry%16==8, +12
        //    pushes still ==8, then -0x28 == 0). Issue the absolute Win64 call.
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::mmu_xlate_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        // 4. Fault check: RAX==0 (XLATE_FAULT) → restore the save set and early
        //    RET. The walker already recorded the pending Data Abort. RAX (the
        //    PA) is NOT in the save set, so it survives the pops on the success
        //    path. We branch on the test BEFORE popping so the fault path can pop
        //    + RET with a balanced stack.
        enc.emit_test_rr64(RAX, RAX); // ZF=1 iff RAX==0 (fault)
        let jnz_ok = enc.emit_jcc_rel32(cc::NZ); // success → skip the fault RET
        // fault path: restore the save set (reverse order) and RET. Last byte of
        // the whole block is still a RET elsewhere; an early RET mid-block keeps
        // block_bytes_are_safe happy (no UD2; the block still ends in RET).
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
        enc.emit_ret();
        // success path:
        let ok_pos = enc.pos();
        enc.patch_rel32(jnz_ok, ok_pos);
        // 5. Restore the save set (RAX/PA preserved). After this RAX = host PA
        //    and every block-live GPR is back to its pre-call value.
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// [dcache-hunt] Runtime address of `aether_fpstore_trace(pa, low64)`.
    fn fpstore_trace_addr() -> usize {
        crate::runtime::mmu::aether_fpstore_trace as *const () as usize
    }

    /// [dcache-hunt] After a Vec128/F64 store, call the FP-store trap with the
    /// host PA (in RAX/SCRATCH0, preserved by emit_mmu_xlate_call + movdqu) and
    /// the low 64 bits of the stored value (in VFP=XMM15, callee-saved). Catches
    /// the mistranslated FP/vector store that corrupts a dentry pointer.
    fn emit_fpstore_trace(enc: &mut X86Encoder) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        let vfp = crate::regalloc::x86_regs::VFP;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // RAX still holds the PA (not in the save set; movdqu didn't clobber it).
        enc.emit_mov_rr64(RCX, RAX); // arg0 = PA
        enc.emit_movq_r64_xmm(RDX, vfp); // arg1 = low64(VFP) (RDX was saved above)
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::fpstore_trace_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of the `aether_mmu_xlate` FFI helper, baked into the
    /// emitted `MOV RAX, imm64`. The host test crate and the hypervisor link the
    /// same symbol, so this resolves correctly in both contexts. Coercing the
    /// `unsafe extern "C" fn` to a fn pointer then to `usize` is a plain address
    /// read (no call); kept in one place so the cast site is auditable.
    #[inline]
    fn mmu_xlate_addr() -> usize {
        crate::runtime::mmu::aether_mmu_xlate as *const () as usize
    }

    /// Width-honouring zero-extending load of `size` bytes from `[base]` into
    /// `rd` (atomic RMW/CAS old-value read). 32-bit form zero-extends to 64 per
    /// W-register semantics; matches the `LoadExclusive` width dispatch.
    fn emit_w_load(enc: &mut X86Encoder, rd: u8, base: u8, size: u8) {
        match size {
            1 => enc.emit_movzx_r64_mem8(rd, base, 0),
            2 => enc.emit_movzx_r64_mem16(rd, base, 0),
            4 => enc.emit_mov_r32_mem(rd, base, 0),
            _ => enc.emit_mov_r64_mem(rd, base, 0),
        }
    }

    /// Width-honouring store of the low `size` bytes of `rv` to `[base]`.
    fn emit_w_store(enc: &mut X86Encoder, base: u8, rv: u8, size: u8) {
        match size {
            1 => enc.emit_mov_mem8_r64(base, 0, rv),
            2 => enc.emit_mov_mem16_r64(base, 0, rv),
            4 => enc.emit_mov_mem32_r64(base, 0, rv),
            _ => enc.emit_mov_mem_r64(base, 0, rv),
        }
    }

    /// Runtime address of the `aether_mmu_store` FFI helper (M4b-5). Single
    /// `STR` lowers to a Win64 call to this — it translates AND performs the
    /// store, so an MMIO target (UART/GIC) emulates correctly (the value is only
    /// known at store time). Same linkage guarantee as [`Self::mmu_xlate_addr`].
    #[inline]
    fn mmu_store_addr() -> usize {
        crate::runtime::mmu::aether_mmu_store as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_mmu_store(R15, va, size, value)` (M4b-5).
    /// On success (`RAX != 0`) the store has been performed (RAM write or MMIO
    /// emulation) and the block continues; on fault (`RAX == XLATE_FAULT == 0`,
    /// pending Data Abort set by the walker) it performs an early `RET`.
    ///
    /// Marshals two block-live values (`addr_reg` → va, `val_reg` → value), so
    /// both are staged through the reserved scratch `RAX` to avoid any
    /// parallel-move hazard regardless of which allocatable GPRs they occupy
    /// (including `R8`/`R9`). Both MUST be real allocated GPRs (the Store arm
    /// fails loud / UD2 on a spilled operand before calling this).
    fn emit_mmu_store_call(enc: &mut X86Encoder, addr_reg: u8, val_reg: u8, size: i32) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        const R8: u8 = 8;
        const R9: u8 = 9;
        // 1. Save every block-live allocatable GPR (RSP unchanged mod 16; 12 push).
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // 2. Marshal args. RAX/RCX are reserved scratch (never an allocated
        //    value), so staging `addr_reg` through RAX is always safe; reading
        //    `val_reg` into R9 before R8 is set covers `val_reg == R8`, and
        //    staging addr through RAX before R9 is written covers `addr_reg == R9`.
        enc.emit_mov_rr64(RAX, addr_reg); // RAX = va (stash; addr_reg still live)
        enc.emit_mov_rr64(R9, val_reg); // R9  = value
        enc.emit_mov_rr64(RDX, RAX); // RDX = va
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // RCX = ctx (R15)
        enc.emit_mov_r64_imm32(R8, size); // R8  = access size in bytes
        // 3. Shadow space + 16-byte realign (entry%16==8, +12 push ==8, -0x28==0).
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::mmu_store_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        // 4. Fault check: RAX==0 (XLATE_FAULT) → restore + early RET (the block
        //    still ends in RET, so block_bytes_are_safe stays happy).
        enc.emit_test_rr64(RAX, RAX);
        let jnz_ok = enc.emit_jcc_rel32(cc::NZ);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
        enc.emit_ret();
        let ok_pos = enc.pos();
        enc.patch_rel32(jnz_ok, ok_pos);
        // 5. Success: restore the save set. The store is already done; the block
        //    proceeds to its next op (no deref).
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of the `aether_mmu_flush_all` FFI helper (no args), baked
    /// into the emitted `MOV RAX, imm64`. Same linkage guarantee as
    /// [`Self::mmu_xlate_addr`].
    #[inline]
    fn mmu_flush_addr() -> usize {
        crate::runtime::mmu::aether_mmu_flush_all as *const () as usize
    }

    /// Runtime address of the `aether_mmu_tlbi_va` FFI helper (one u64 arg, no
    /// return value), baked into the emitted `MOV RAX, imm64`. Used by the
    /// single-VA `TLBI` lowering to invalidate one 4 KiB page from the software
    /// TLB. Same linkage guarantee as [`Self::mmu_xlate_addr`].
    #[inline]
    fn mmu_tlbi_va_addr() -> usize {
        crate::runtime::mmu::aether_mmu_tlbi_va as *const () as usize
    }

    /// Runtime address of the `aether_dbt_invalidate_all` FFI helper (no args),
    /// baked into the emitted `MOV RAX, imm64`. Used by the `TLBI` lowering to
    /// drop the whole JIT block cache (a guest page-table edit can change what
    /// bytes a VA maps to). Safe to call mid-block — it only clears the lookup
    /// table, not the code arena the caller is executing from. Same linkage
    /// guarantee as [`Self::mmu_xlate_addr`].
    #[inline]
    fn dbt_invalidate_addr() -> usize {
        crate::dbt::aether_dbt_invalidate_all as *const () as usize
    }

    /// Runtime address of `aether_sysreg_read` (one u32 `reg_id` arg → value in
    /// RAX). Baked into the `MRS` of a live sysreg (timer / GIC CPU interface).
    #[inline]
    fn sysreg_read_addr() -> usize {
        crate::runtime::sysreg_rt::aether_sysreg_read as *const () as usize
    }
    /// Runtime address of `aether_sysreg_write` (u32 `reg_id` + u64 `val` args).
    /// Baked into the `MSR` of a live sysreg.
    #[inline]
    fn sysreg_write_addr() -> usize {
        crate::runtime::sysreg_rt::aether_sysreg_write as *const () as usize
    }

    // ── M4b-2dpre MMU TLB-flush call (aether_mmu_flush_all on translation-control
    // MSR) ────────────────────────────────────────────────────────────────────
    // When the guest writes a translation-control sysreg (TTBR0/1_EL1, TCR_EL1,
    // MAIR_EL1) the software TLB inside the walker can hold stale VA→PA mappings
    // computed under the old tables/control bits, so it MUST be invalidated. We
    // emit a Win64 CALL to `aether_mmu_flush_all()` (no args, no return value)
    // AFTER the new sysreg value has been stored to its slot. SCTLR_EL1 writes
    // need NO flush — `aether_mmu_xlate` reads SCTLR.M live each call, so toggling
    // M takes effect immediately without touching the TLB.
    //
    // ABI: Win64. The callee clobbers the volatile set (RAX/RCX/RDX/R8..R11), so
    // we preserve the same 12-register block-live save set as the xlate call
    // (even parity → RSP's 16-byte alignment relative to block entry is
    // unchanged; the `sub rsp,0x28` then realigns to 16 and reserves the 32-byte
    // shadow space). No arguments are marshalled and no fault/return handling is
    // needed — `aether_mmu_flush_all` cannot fail and returns nothing.

    /// Emit a Win64 CALL to `aether_mmu_flush_all()`. Preserves every block-live
    /// allocatable GPR across the call. Used by the `Msr` lowering after a write
    /// to a translation-control register so the next translated access re-walks
    /// the guest page tables instead of trusting a stale software-TLB entry.
    fn emit_mmu_flush_call(enc: &mut X86Encoder) {
        const RAX: u8 = 0;
        // 1. Save every block-live allocatable GPR (12 push → RSP%16 unchanged).
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // 2. Reserve 32-byte shadow space + realign RSP to 16, then call.
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::mmu_flush_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        // 3. Restore the save set (reverse order). The flush returns nothing, so
        //    no register need survive the pops.
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Emit a Win64 CALL to `aether_dbt_invalidate_all()` (no args, no return
    /// value). Used by the `TLBI` lowering to drop the whole JIT block cache.
    /// Same save/realign discipline as [`Self::emit_mmu_flush_call`] (12-reg
    /// even-parity save set + `sub rsp,0x28` shadow/realign). The callee only
    /// clears the PC→host-offset lookup table, NOT the code arena this block is
    /// executing from, so returning into the in-flight block is safe.
    fn emit_dbt_invalidate_call(enc: &mut X86Encoder) {
        const RAX: u8 = 0;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::dbt_invalidate_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Emit a Win64 CALL to `aether_mmu_tlbi_va(va)` (one u64 arg in RCX, no
    /// return value). Used by the single-VA `TLBI` lowering. `va_reg` is read
    /// (into RCX) AFTER the save set is pushed but is itself preserved — it is
    /// in `MMU_SAVE_REGS`, so the pushed COPY on the stack restores it, and the
    /// `mov rcx, va_reg` below reads the live register value before the call
    /// clobbers RCX (RCX is volatile). Same save/realign discipline as
    /// [`Self::emit_mmu_flush_call`].
    /// Runtime address of `aether_mmu_at_s1e1` (Phase-E).
    fn mmu_at_s1e1_addr() -> usize {
        crate::runtime::mmu::aether_mmu_at_s1e1 as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_mmu_at_s1e1(ctx, va, is_write, at_el0)`.
    /// 4 args: RCX=ctx (R15), RDX=va, R8=is_write, R9=at_el0. Same
    /// save/realign discipline as `emit_mmu_xlate_call`.
    fn emit_mmu_at_call(
        enc: &mut X86Encoder,
        va_reg: u8,
        is_write: bool,
        at_el0: bool,
    ) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        const R8: u8 = 8;
        const R9: u8 = 9;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // Marshal: RDX=va FIRST (while va_reg still live), then the
        // others which don't alias va_reg.
        if va_reg != RDX {
            enc.emit_mov_rr64(RDX, va_reg);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG);
        enc.emit_mov_r64_imm32(R8, if is_write { 1 } else { 0 });
        enc.emit_mov_r64_imm32(R9, if at_el0 { 1 } else { 0 });
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::mmu_at_s1e1_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    fn emit_mmu_tlbi_va_call(enc: &mut X86Encoder, va_reg: u8) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        // 1. Save every block-live allocatable GPR (12 push → RSP%16 unchanged).
        //    `va_reg` is one of these (it's an allocated value reg, never the
        //    reserved RAX/RCX), so its value is preserved on the stack.
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // 2. Marshal arg: RCX = va. The pushes above only spilled COPIES; the
        //    registers retain their live values, so `va_reg` is still the VA.
        //    `va_reg` is never RAX/RCX (reserved, never allocated), so this is a
        //    real `mov rcx, <reg>`.
        enc.emit_mov_rr64(RCX, va_reg);
        // 3. Reserve 32-byte shadow space + realign RSP to 16, then call.
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::mmu_tlbi_va_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        // 4. Restore the save set (reverse order). Returns nothing.
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    // ── M4b-4 live-sysreg runtime calls (timer + GIC CPU interface) ───────────
    // A handful of sysregs are not plain storage: CNTVCT_EL0 must advance,
    // CNTV_TVAL_EL0 is count-relative, ICC_IAR1_EL1 read ACKs the top IRQ,
    // ICC_EOIR1_EL1 write ENDs it. MRS/MSR of these lower to a Win64 CALL to
    // aether_sysreg_read/write (runtime::sysreg_rt) keyed by a baked reg_id,
    // dispatching to the live VirtualTimer/VirtualGic. Same save/realign
    // discipline as the MMU calls (12-reg even-parity save set + 0x28 shadow).

    /// Emit a Win64 CALL to `aether_sysreg_read(reg_id)`; the value lands in RAX.
    /// The caller moves RAX into the (real, non-spilled) `MRS` destination.
    fn emit_sysreg_read_call(enc: &mut X86Encoder, reg_id: u32) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_r64_imm32(RCX, reg_id as i32); // arg0 = reg_id
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::sysreg_read_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Emit a Win64 CALL to `aether_sysreg_write(reg_id, val)`. `val_reg` holds
    /// the value (preserved across the call by the save set); it is a real GPR,
    /// never RAX/RCX.
    fn emit_sysreg_write_call(enc: &mut X86Encoder, reg_id: u32, val_reg: u8) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // Marshal arg1 = val (RDX) while `val_reg` is still live (the pushes only
        // copied it to the stack), then arg0 = reg_id. `val_reg == RDX` makes the
        // mov a harmless `mov rdx, rdx`.
        if val_reg != RDX {
            enc.emit_mov_rr64(RDX, val_reg);
        }
        enc.emit_mov_r64_imm32(RCX, reg_id as i32); // arg0 = reg_id
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::sysreg_write_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of `aether_hvc_dispatch` (one `*mut u64` ctx arg, no
    /// return). Baked into the `HVC`/`SMC` (PSCI) call.
    #[inline]
    fn hvc_dispatch_addr() -> usize {
        crate::runtime::psci::aether_hvc_dispatch as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_hvc_dispatch(ctx = R15)` — service a guest
    /// `HVC`/`SMC` (PSCI). Same save/realign discipline as the MMU calls. The
    /// callee reads/writes the guest GPRs through R15 (the context base, a
    /// non-volatile register in Win64 that therefore survives the call), so the
    /// PSCI result lands in the guest x0 slot for the next instruction to read.
    fn emit_hvc_call(enc: &mut X86Encoder) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // arg0 = ctx (R15)
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::hvc_dispatch_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of `aether_crypto_sha256(ctx, packed)` — ARMv8 SHA-256.
    fn crypto_sha256_addr() -> usize {
        crate::runtime::crypto_rt::aether_crypto_sha256 as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_crypto_sha256(ctx = R15, packed)`. `packed` =
    /// `kind | (d<<8) | (n<<16) | (m<<24)`. Same save / shadow-space / realign
    /// discipline as `emit_hvc_call`; the helper reads/writes the guest q-regs
    /// through R15 (callee-saved, survives the call).
    fn emit_crypto_sha256_call(enc: &mut X86Encoder, packed: u32) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // arg0 = ctx (R15)
        enc.emit_mov_r64_imm32(RDX, packed as i32); // arg1 = packed (bit31 clear)
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::crypto_sha256_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of `aether_crypto_sha1(ctx, packed)` — ARMv8 SHA-1.
    fn crypto_sha1_addr() -> usize {
        crate::runtime::crypto_rt::aether_crypto_sha1 as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_crypto_sha1(ctx = R15, packed)` — identical
    /// discipline to `emit_crypto_sha256_call`, different helper.
    fn emit_crypto_sha1_call(enc: &mut X86Encoder, packed: u32) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG);
        enc.emit_mov_r64_imm32(RDX, packed as i32);
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::crypto_sha1_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Runtime address of `aether_crc32_iso(crc, data, size) -> u32` — ISO-3309
    /// CRC32 (no native x86 instruction; Castagnoli-only `crc32` can't do it).
    fn crc32_iso_addr() -> usize {
        crate::runtime::crypto_rt::aether_crc32_iso as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_crc32_iso(crc=ECX, data=RDX, size=R8B)`,
    /// leaving the 32-bit result in EAX. The caller has already materialized the
    /// accumulator into RCX and the data into RDX (both reserved/volatile here);
    /// `size` is a compile-time constant. Same save / shadow-space / realign
    /// discipline as `emit_hvc_call`. RAX (return) and RCX/RDX (args) are NOT in
    /// MMU_SAVE_REGS — but R8 IS, so its live value is preserved by the save set;
    /// we set arg2 (R8) AFTER the pushes, so the pushed copy keeps the old value
    /// and is restored on return.
    fn emit_crc32_iso_call(enc: &mut X86Encoder, size: u8) {
        const RAX: u8 = 0;
        const R8: u8 = 8;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        // arg0 (RCX) = crc, arg1 (RDX) = data already in place by the caller.
        enc.emit_mov_r64_imm32(R8, size as i32); // arg2 = size
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::crc32_iso_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
        // Result is in EAX (RAX); caller moves it to dst.
    }

    /// Runtime address of `aether_svc_enter(ctx, imm16)` (the SVC exception entry).
    fn svc_enter_addr() -> usize {
        crate::runtime::exceptions::aether_svc_enter as *const () as usize
    }

    /// Runtime address of `aether_eret_enter(ctx)` (the full ERET return).
    fn eret_enter_addr() -> usize {
        crate::runtime::exceptions::aether_eret_enter as *const () as usize
    }

    /// Emit a Win64 CALL to `aether_svc_enter(ctx = R15, imm16)`. Same save /
    /// shadow-space / realign discipline as `emit_hvc_call`; arg1 (imm16) is a
    /// compile-time constant moved into RDX (32-bit move zero-extends, and
    /// imm16 < 2^16 so the upper bits are clean).
    fn emit_svc_call(enc: &mut X86Encoder, imm16: u16) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        const RDX: u8 = 2;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // arg0 = ctx (R15)
        enc.emit_mov_r64_imm32(RDX, imm16 as i32); // arg1 = imm16
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::svc_enter_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Emit a Win64 CALL to `aether_eret_enter(ctx = R15)`. One arg; identical
    /// shape to `emit_hvc_call`.
    fn emit_eret_call(enc: &mut X86Encoder) {
        const RAX: u8 = 0;
        const RCX: u8 = 1;
        for &r in Self::MMU_SAVE_REGS.iter() {
            enc.emit_push_r64(r);
        }
        enc.emit_mov_rr64(RCX, CONTEXT_REG); // arg0 = ctx (R15)
        enc.emit_sub_r64_imm32(4 /* RSP */, 0x28);
        enc.emit_mov_r64_imm64(RAX, Self::eret_enter_addr() as i64);
        enc.emit_call_r64(RAX);
        enc.emit_add_r64_imm32(4 /* RSP */, 0x28);
        for &r in Self::MMU_SAVE_REGS.iter().rev() {
            enc.emit_pop_r64(r);
        }
    }

    /// Side-effect class of a sysreg `MSR` write that the software MMU walker
    /// observes. The walker keeps a software TLB keyed on the active page-table
    /// configuration; writes to a translation-control register invalidate it.
    fn msr_mmu_side_effect(reg: crate::decoder::sysreg::SysReg) -> MsrMmuEffect {
        // The dense slot index IS the walker's SLOT_* contract (lower_int's
        // sysreg_read_idx and mmu.rs SLOT_SCTLR/TTBR0/TTBR1/TCR/MAIR are the same
        // 0..4 numbering by construction — see the comment in mmu.rs).
        match Self::sysreg_read_idx(reg) {
            i if i == crate::runtime::mmu::SLOT_TTBR0 as i32
                || i == crate::runtime::mmu::SLOT_TTBR1 as i32
                || i == crate::runtime::mmu::SLOT_TCR as i32
                || i == crate::runtime::mmu::SLOT_MAIR as i32 => MsrMmuEffect::FlushTlb,
            // SCTLR (SLOT_SCTLR == 0) and every other register: no TLB flush.
            _ => MsrMmuEffect::None,
        }
    }

    /// Extract bit `pos` of `src` into `dst` as a 0/1 value: dst = (src >> pos) & 1.
    /// Clobbers EFLAGS. `dst` must differ from `src` unless src is dead after.
    fn emit_bit(enc: &mut X86Encoder, dst: u8, src: u8, pos: u8) {
        if dst != src {
            enc.emit_mov_rr64(dst, src);
        }
        enc.emit_shr_r64_imm8(dst, pos);
        enc.emit_and_r64_imm32(dst, 1);
    }

    /// Evaluate an ARM condition from the packed NZCV in `nzcv` (clobberable),
    /// producing 0/1 in `out`. Uses RDX as a temp (saved via push/pop) for the
    /// composite conditions. N@31 Z@30 C@29 V@28.
    pub(crate) fn emit_arm_cond_to_bool(enc: &mut X86Encoder, nzcv: u8, out: u8, cond: crate::decoder::Cond) {
        use crate::decoder::Cond::*;
        const RDX: u8 = 2;
        match cond {
            Eq => Self::emit_bit(enc, out, nzcv, 30),
            Ne => { Self::emit_bit(enc, out, nzcv, 30); enc.emit_xor_r64_imm32(out, 1); }
            Cs => Self::emit_bit(enc, out, nzcv, 29),
            Cc => { Self::emit_bit(enc, out, nzcv, 29); enc.emit_xor_r64_imm32(out, 1); }
            Mi => Self::emit_bit(enc, out, nzcv, 31),
            Pl => { Self::emit_bit(enc, out, nzcv, 31); enc.emit_xor_r64_imm32(out, 1); }
            Vs => Self::emit_bit(enc, out, nzcv, 28),
            Vc => { Self::emit_bit(enc, out, nzcv, 28); enc.emit_xor_r64_imm32(out, 1); }
            Hi => {
                // C && !Z
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 29); // C
                Self::emit_bit(enc, RDX, nzcv, 30); // Z
                enc.emit_xor_r64_imm32(RDX, 1); // !Z
                enc.emit_and_rr64(out, RDX);
                enc.emit_pop_r64(RDX);
            }
            Ls => {
                // !(C && !Z)
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 29);
                Self::emit_bit(enc, RDX, nzcv, 30);
                enc.emit_xor_r64_imm32(RDX, 1);
                enc.emit_and_rr64(out, RDX);
                enc.emit_pop_r64(RDX);
                enc.emit_xor_r64_imm32(out, 1);
            }
            Ge => {
                // N == V
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 31); // N
                Self::emit_bit(enc, RDX, nzcv, 28); // V
                enc.emit_xor_rr64(out, RDX); // N ^ V
                enc.emit_pop_r64(RDX);
                enc.emit_xor_r64_imm32(out, 1); // == (1 when equal)
            }
            Lt => {
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 31);
                Self::emit_bit(enc, RDX, nzcv, 28);
                enc.emit_xor_rr64(out, RDX);
                enc.emit_pop_r64(RDX);
            }
            Gt => {
                // !Z && (N == V)
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 31);
                Self::emit_bit(enc, RDX, nzcv, 28);
                enc.emit_xor_rr64(out, RDX);
                enc.emit_xor_r64_imm32(out, 1); // N==V
                Self::emit_bit(enc, RDX, nzcv, 30); // Z
                enc.emit_xor_r64_imm32(RDX, 1); // !Z
                enc.emit_and_rr64(out, RDX);
                enc.emit_pop_r64(RDX);
            }
            Le => {
                enc.emit_push_r64(RDX);
                Self::emit_bit(enc, out, nzcv, 31);
                Self::emit_bit(enc, RDX, nzcv, 28);
                enc.emit_xor_rr64(out, RDX);
                enc.emit_xor_r64_imm32(out, 1);
                Self::emit_bit(enc, RDX, nzcv, 30);
                enc.emit_xor_r64_imm32(RDX, 1);
                enc.emit_and_rr64(out, RDX);
                enc.emit_pop_r64(RDX);
                enc.emit_xor_r64_imm32(out, 1); // !GT
            }
            Al | Nv => {
                // Always (Nv historically "never" but treated as always here, as
                // the ARM_COND_TO_X86 table does). Callers should special-case AL
                // to an unconditional path; this fallback yields true.
                enc.emit_xor_zero_r32(out);
                enc.emit_or_r64_imm32(out, 1);
            }
        }
    }

    // ── M4a system-register displacement map ──────────────────────────────────
    // Maps a decoded SysReg to its byte displacement from CONTEXT_REG. Modeled
    // regs get a dense slot in [SYSREG_BASE..]; NzcvEl0 aliases the GPR-file nzcv;
    // RO/ID regs read their seeded slot but writes sink to slot 63; unmodeled
    // regs read/write the sink. See runtime/context.rs seed_sysregs.
    fn sysreg_read_idx(reg: crate::decoder::sysreg::SysReg) -> i32 {
        use crate::decoder::sysreg::SysReg::*;
        match reg {
            SctlrEl1 => 0, TtbrEl1_0 => 1, TtbrEl1_1 => 2, TcrEl1 => 3,
            MairEl1 => 4, AmairEl1 => 5, VbarEl1 => 6, CpacrEl1 => 7,
            ContextidrEl1 => 8, TpidrEl0 => 9, TpidrEl1 => 10, TpidrroEl0 => 11,
            EsrEl1 => 12, ElrEl1 => 13, SpsrEl1 => 14, FarEl1 => 15,
            SpEl0 => 16, SpEl1 => 17, Afsr0El1 => 18, Afsr1El1 => 19,
            ActlrEl1 => 20, CsselrEl1 => 21, DaifEl0 => 22, SpselEl1 => 23,
            Mdscr_El1 => 24, OslarEl1 => 25,
            // Phase-E: PAR_EL1 — slot 26. Written by aether_mmu_at_s1e1
            // (the AT runtime), read by the kernel's
            // is_spurious_el1_translation_fault. MUST match SLOT_PAR_EL1
            // in runtime/mmu.rs.
            ParEl1 => 26,
            MidrEl1 => 40, MpidrEl1 => 41, CurrentEl => 42, CtrEl0 => 43,
            DczidEl0 => 44, CntfrqEl0 => 45,
            IdAa64Pfr0El1 => 46, IdAa64Pfr1El1 => 47,
            IdAa64Mmfr0El1 => 48, IdAa64Mmfr1El1 => 49, IdAa64Mmfr2El1 => 50,
            IdAa64Isar0El1 => 51, IdAa64Isar1El1 => 52,
            ClidrEl1 => 53, RevidrEl1 => 54, AidrEl1 => 55,
            NzcvEl0 => -1, // alias of GPR-file NZCV at 0x108
            _ => crate::runtime::context::SYSREG_SINK_IDX as i32,
        }
    }

    /// Map a decoded sysreg to a live-sysreg runtime `reg_id` (timer / GIC CPU
    /// interface) when it requires a runtime CALL rather than a ctx-slot
    /// load/store. `None` => plain storage (the slot path). CNTFRQ_EL0 stays
    /// slot-based (seeded read-only at 24 MHz); only the live timer + the GIC
    /// CPU interface route here.
    fn sysreg_runtime_id(reg: crate::decoder::sysreg::SysReg) -> Option<u32> {
        use crate::decoder::sysreg::SysReg::*;
        use crate::runtime::sysreg_rt::regid;
        Some(match reg {
            CntvctEl0 => regid::CNTVCT_EL0,
            CntpctEl0 => regid::CNTPCT_EL0,
            CntvCtlEl0 => regid::CNTV_CTL_EL0,
            CntvCvalEl0 => regid::CNTV_CVAL_EL0,
            CntvTvalEl0 => regid::CNTV_TVAL_EL0,
            CntpCtlEl0 => regid::CNTP_CTL_EL0,
            CntpCvalEl0 => regid::CNTP_CVAL_EL0,
            CntpTvalEl0 => regid::CNTP_TVAL_EL0,
            IccPmrEl1 => regid::ICC_PMR_EL1,
            IccIar1El1 => regid::ICC_IAR1_EL1,
            IccEoir1El1 => regid::ICC_EOIR1_EL1,
            IccHppir1El1 => regid::ICC_HPPIR1_EL1,
            IccIgrpen1El1 => regid::ICC_IGRPEN1_EL1,
            IccCtlrEl1 => regid::ICC_CTLR_EL1,
            IccSreEl1 => regid::ICC_SRE_EL1,
            IccBpr1El1 => regid::ICC_BPR1_EL1,
            IccDirEl1 => regid::ICC_DIR_EL1,
            _ => return None,
        })
    }

    fn sysreg_read_disp(reg: crate::decoder::sysreg::SysReg) -> i32 {
        let idx = Self::sysreg_read_idx(reg);
        if idx < 0 {
            NZCV_DISP
        } else {
            crate::runtime::context::SYSREG_BASE as i32 + idx * 8
        }
    }

    fn sysreg_write_disp(reg: crate::decoder::sysreg::SysReg) -> i32 {
        let idx = Self::sysreg_read_idx(reg);
        if idx < 0 {
            NZCV_DISP // NZCV alias is writable
        } else if idx >= 40 {
            // RO/ID register: writes sink to slot 63 (never corrupt the seed).
            crate::runtime::context::SYSREG_BASE as i32
                + crate::runtime::context::SYSREG_SINK_IDX as i32 * 8
        } else {
            crate::runtime::context::SYSREG_BASE as i32 + idx * 8
        }
    }

    fn xmm(alloc: &AllocResult, vid: IrValueId) -> u8 {
        match alloc.assignments.get(&vid.0) {
            Some(Assignment::Xmm(idx)) => ALLOCATABLE_XMMS[*idx as usize] as u8,
            _ => 0,
        }
    }

    fn lower_op(
        op: &IrOp,
        alloc: &AllocResult,
        enc: &mut X86Encoder,
        branch_patches: &mut alloc::vec::Vec<(usize, crate::ir::BlockId)>,
    ) {
        use IrOp::*;

        match op {
            // ── Diagnostic: per-instruction PC stamp ─────────────────────
            StampFaultPc(pc) => {
                // Diagnostics: record the guest ARM PC of the instruction whose
                // ops follow, so any `emit_ud2` during this instruction's
                // lowering snapshots the EXACT offending PC (the block-safety
                // gate reads it back). Translation-time only; no emitted code.
                crate::backend::encode::set_cur_lower_pc(*pc);
                // mov RAX, pc ; mov RCX, &FAULT_OP_PC ; mov [RCX], RAX.
                // RAX/RCX are reserved scratch (same as the block-entry stamp);
                // not live across IR ops, so clobbering between ops is safe.
                const RAX: u8 = 0;
                const RCX: u8 = 1;
                enc.emit_mov_r64_imm64(RAX, *pc as i64);
                let addr = core::ptr::addr_of_mut!(crate::runtime::mmu::FAULT_OP_PC)
                    as usize as i64;
                enc.emit_mov_r64_imm64(RCX, addr);
                enc.emit_mov_mem_r64(RCX, 0, RAX);
            }
            // ── Constants ─────────────────────────────────────────────────
            ConstI32 { dst, val } => {
                let (r, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if *val == 0 {
                    enc.emit_xor_zero_r32(r);
                } else {
                    enc.emit_mov_r32_imm32(r, *val as u32);
                }
                Self::store_dest(alloc, enc, *dst, r, sp);
            }
            ConstI64 { dst, val } => {
                let (r, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if *val == 0 {
                    enc.emit_xor_zero_r32(r); // zero-extend, sets flags
                } else if *val >= i32::MIN as i64 && *val <= i32::MAX as i64 {
                    enc.emit_mov_r64_imm32(r, *val as i32);
                } else {
                    enc.emit_mov_r64_imm64(r, *val);
                }
                Self::store_dest(alloc, enc, *dst, r, sp);
            }
            ConstF32 { .. } | ConstF64 { .. } | ConstVec128 { .. } => {
                // SSA-register FP/SIMD constants: the lifter never emits these
                // (live SIMD goes through the ctx-addressed Vec* ops in
                // lower_simd_ctx). Fail loud if one ever appears.
                enc.emit_ud2();
            }

            // ── Pure integer ALU ───────────────────────────────────────────
            // Spill discipline: input A -> SCRATCH0, B -> SCRATCH1 (distinct so
            // two spilled inputs don't collide); dest works in SCRATCH0 when
            // spilled, stored back after. `if rd != ra` skips the redundant
            // copy when the dest already holds A (incl. the SCRATCH0==SCRATCH0
            // spilled-A/spilled-dest case).
            Add { dst, a, b } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_add_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Sub { dst, a, b } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_sub_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Neg { dst, a } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_neg_r64(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            And { dst, a, b } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_and_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Or { dst, a, b } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_or_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Xor { dst, a, b } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_xor_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Not { dst, a } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_not_r64(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            // Phase C find: variable-amount shifts (Shl/LShr/AShr) had a
            // latent spill bug. Bare Self::gpr(alloc, *vid) returns SCRATCH0
            // (RAX) for a SPILLED value, NOT the spilled value itself. Under
            // spill pressure (e.g. the kernel's pre-relocation jump-table
            // dispatch at image+0x19e887c) the prior lowering shifted by
            // garbage, x10 landed at the wrong case, BR x10 reached the
            // wrong PC, ldrb [x0=9] faulted with VBAR=0 -> fetch-abort loop.
            // Route every operand through src_in/dest_work so spilled values
            // materialize via the scratch path. SCRATCH0=RAX, SCRATCH1=RCX;
            // x86 shifts use CL so the shift amount must be in RCX.
            Shl { dst, a, b } => {
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_shl_r64_cl(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            LShr { dst, a, b } => {
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_shr_r64_cl(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            AShr { dst, a, b } => {
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_sar_r64_cl(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Ror { dst, a, b } => {
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_ror_r64_cl(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Mul { dst, a, b } => {
                // NOTE: dead on the live path (the lift maps MUL -> Madd with
                // Ra=XZR); kept spill-safe for the cold/opt path + correctness.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            MulHU { dst, a, b } => {
                // Phase-E correctness fix. Previously this used Self::gpr (the
                // legacy non-spill-aware helper that returns RAX for a spilled
                // value), so a spilled `a` or `b` silently miscompiled (the
                // operand reads landed on the scratch register before the MUL
                // ran). It also clobbered RDX without preservation — any live
                // value the allocator placed in RDX (RDX is in ALLOCATABLE_GPRS)
                // was destroyed by every MulHU. Both paths matter for the
                // kernel: pcpu_build_alloc_info's overflow check at fc6b0
                // `umulh x8, x8, x10` lowers via this arm under high register
                // pressure (16+ live values). Caught when the prior MulHigh
                // bug (lifted as Madd; fixed in the same commit) was repaired
                // and the second-order bug surfaced — kernel BUG at percpu.c
                // 2617 ai->static_size == 0 because x19 (= aligned base_size)
                // ended up 0 from a bad NE flag from the wrong umulh result.
                //
                // Marshal: RAX = a (load through SCRATCH0 if `a` spilled),
                // SCRATCH1 = b (load through SCRATCH1 if `b` spilled — covers
                // the b-in-RAX case too because src_in for a non-spilled value
                // returns its allocated reg which is never RAX). Save RDX
                // before the MUL (RDX may hold a live value); store dst from
                // RDX after; restore RDX if dst is not RDX itself.
                const RAX: u8 = 0;
                const RCX: u8 = 1;
                const RDX: u8 = 2;
                let ra = Self::src_in(alloc, enc, *a, RAX);
                if ra != RAX { enc.emit_mov_rr64(RAX, ra); }
                let rb = Self::src_in(alloc, enc, *b, RCX);
                // If `b` resolved to RAX (impossible by allocator rules but
                // defensive), copy through RCX so MUL doesn't read RAX twice.
                let rb_safe = if rb == RAX { enc.emit_mov_rr64(RCX, RAX); RCX } else { rb };
                let (rd, sp) = Self::dest_work(alloc, *dst, RDX);
                // Preserve RDX if it could hold a live (non-dst) value.
                let preserve_rdx = rd != RDX;
                if preserve_rdx { enc.emit_push_r64(RDX); }
                enc.emit_mul_r64(rb_safe);
                if rd != RDX { enc.emit_mov_rr64(rd, RDX); }
                if preserve_rdx { enc.emit_pop_r64(RDX); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            MulHS { dst, a, b } => {
                // Same rationale and shape as MulHU (signed variant: IMUL r64).
                const RAX: u8 = 0;
                const RCX: u8 = 1;
                const RDX: u8 = 2;
                let ra = Self::src_in(alloc, enc, *a, RAX);
                if ra != RAX { enc.emit_mov_rr64(RAX, ra); }
                let rb = Self::src_in(alloc, enc, *b, RCX);
                let rb_safe = if rb == RAX { enc.emit_mov_rr64(RCX, RAX); RCX } else { rb };
                let (rd, sp) = Self::dest_work(alloc, *dst, RDX);
                let preserve_rdx = rd != RDX;
                if preserve_rdx { enc.emit_push_r64(RDX); }
                enc.emit_imul1_r64(rb_safe);
                if rd != RDX { enc.emit_mov_rr64(rd, RDX); }
                if preserve_rdx { enc.emit_pop_r64(RDX); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            SDiv { dst, a, b } => {
                // idiv RDX:RAX / rb -> RAX quotient. Spill-safe: force the divisor
                // into SCRATCH1 (RCX) so it can never alias RAX/RDX (which idiv
                // overwrites), then materialize the dividend into RAX.
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                if ra != 0 { enc.emit_mov_rr64(0, ra); } // RAX = dividend
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                // RDX PRESERVATION (D1, mirrors MulHU/MulHS). `cqo`/`idiv` and the
                // INT_MIN-guard constant load all CLOBBER RDX, which is an
                // ALLOCATABLE register (index 2). In today's per-instruction lift
                // path no live value can be stranded in RDX across a div (every
                // guest reg round-trips through ctx memory), but the opt/SSA-
                // promotion path CAN leave a long-lived value in RDX, so an
                // unconditional clobber is a latent silent miscompile (same class
                // the MulHU/MulHS arms already guard). Save+restore RDX unless the
                // destination itself IS RDX (then it is being overwritten anyway).
                // push/pop are stack-balanced across every exit edge below.
                const RDX: u8 = 2;
                let preserve_rdx = rd != RDX;
                if preserve_rdx { enc.emit_push_r64(RDX); }
                // B26: ARM SDIV is non-trapping — divide-by-zero yields 0. The
                // host idiv would #DE, so guard with a divisor==0 test.
                enc.emit_test_rr64(SCRATCH1, SCRATCH1);
                let jz_zero = enc.emit_jcc_rel32(cc::Z);
                // B27: ARM SDIV of INT_MIN / -1 is defined to return the dividend
                // (INT_MIN), NOT trap; the host `idiv` would #DE (quotient
                // unrepresentable). The lift already 64-bit sign-extends BOTH
                // operands (W-form too — see lift Div), so the ONLY overflow that
                // reaches this 64-bit idiv is dividend==i64::MIN && divisor==-1
                // (the W-form's sign-extended i32::MIN ÷ -1 = 0x8000_0000 fits in
                // i64 and is truncated correctly by the WriteGpr). Guard it: when
                // both hold, the result is the dividend (already in RAX). 2 cmp +
                // branch; the common path falls straight through to cqo/idiv.
                // RDX holds the i64::MIN constant here (already saved above if it
                // carried a live value); cqo overwrites it again on the fall-
                // through path. SCRATCH1 (the divisor) stays intact for the idiv.
                enc.emit_cmp_r64_imm32(SCRATCH1, -1); // divisor == -1 ?
                let jne_div = enc.emit_jcc_rel32(cc::NZ);
                enc.emit_mov_r64_imm64(RDX, i64::MIN); // RDX = i64::MIN
                enc.emit_cmp_rr64(0, RDX); // dividend (RAX) == i64::MIN ?
                let jne_div2 = enc.emit_jcc_rel32(cc::NZ);
                // Overflow: quotient = dividend (RAX). rd = RAX, restore RDX, end.
                if rd != 0 { enc.emit_mov_rr64(rd, 0); }
                if preserve_rdx { enc.emit_pop_r64(RDX); }
                let jmp_ovf_end = enc.emit_jmp_rel32();
                // Normal division path.
                let div_pos = enc.pos();
                enc.patch_rel32(jne_div, div_pos);
                enc.patch_rel32(jne_div2, div_pos);
                enc.emit_cqo(); // sign-extend RAX into RDX:RAX
                enc.emit_idiv_r64(SCRATCH1);
                if rd != 0 { enc.emit_mov_rr64(rd, 0); } // rd = RAX quotient
                if preserve_rdx { enc.emit_pop_r64(RDX); } // restore after last RDX use
                let jmp_end = enc.emit_jmp_rel32();
                let zero_pos = enc.pos();
                enc.patch_rel32(jz_zero, zero_pos);
                // Div-by-zero join: RDX was NOT clobbered on this edge (the test/jz
                // ran before any RDX write), but the push is still outstanding, so
                // restore it here too before writing rd to keep the stack balanced.
                if preserve_rdx { enc.emit_pop_r64(RDX); }
                enc.emit_xor_zero_r32(rd); // rd = 0
                let end_pos = enc.pos();
                enc.patch_rel32(jmp_end, end_pos);
                enc.patch_rel32(jmp_ovf_end, end_pos);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            UDiv { dst, a, b } => {
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                if ra != 0 { enc.emit_mov_rr64(0, ra); } // RAX = dividend
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                // RDX PRESERVATION (D1, mirrors MulHU/MulHS + the SDiv arm above):
                // `xor edx,edx` + `div` clobber RDX (allocatable index 2). Save it
                // unless rd IS RDX. Balanced push/pop on both exit edges.
                const RDX: u8 = 2;
                let preserve_rdx = rd != RDX;
                if preserve_rdx { enc.emit_push_r64(RDX); }
                // B26: UDIV ÷0 = 0 (non-trapping). Guard the host div (#DE).
                enc.emit_test_rr64(SCRATCH1, SCRATCH1);
                let jz_zero = enc.emit_jcc_rel32(cc::Z);
                enc.emit_xor_zero_r32(RDX); // zero RDX
                enc.emit_div_r64(SCRATCH1);
                if rd != 0 { enc.emit_mov_rr64(rd, 0); }
                if preserve_rdx { enc.emit_pop_r64(RDX); } // restore after last RDX use
                let jmp_end = enc.emit_jmp_rel32();
                let zero_pos = enc.pos();
                enc.patch_rel32(jz_zero, zero_pos);
                // Div-by-zero join: RDX not yet clobbered on this edge, but the
                // push is outstanding — restore before writing rd.
                if preserve_rdx { enc.emit_pop_r64(RDX); }
                enc.emit_xor_zero_r32(rd);
                let end_pos = enc.pos();
                enc.patch_rel32(jmp_end, end_pos);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Madd { dst, a, b, c } => {
                // dst = a * b + c. This is the LIVE multiply path: the lift maps
                // both MADD and MUL (MUL = MADD with Ra=XZR) here, so `n=n*10+d`
                // accumulation in bionic vsscanf/strtoul flows through this arm.
                // 4 SSA operands, 2 scratch regs (RAX/RCX): materialize a+b, run
                // the multiply (which consumes b), then reuse SCRATCH1 for c.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb); // rd = a*b (b now dead)
                let rc = Self::src_in(alloc, enc, *c, SCRATCH1);
                enc.emit_add_rr64(rd, rc);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Msub { dst, a, b, c } => {
                // dst = c - a * b
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb); // rd = a*b (b now dead)
                enc.emit_neg_r64(rd); // rd = -(a*b)
                let rc = Self::src_in(alloc, enc, *c, SCRATCH1);
                enc.emit_add_rr64(rd, rc); // rd = c - a*b
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Clz { dst, a, sf } => {
                // Phase-E correctness fix. ARM64 CLZ has two width-forms:
                //   CLZ Xd, Xn — 64-bit, result 0..64 (64 means Xn=0)
                //   CLZ Wd, Wn — 32-bit, result 0..32 (32 means Wn=0)
                // The prior lowering always emitted `lzcnt_r64`. For the
                // W-form (Wn is the low 32 of Xn, upper 32 zero by ARM
                // convention), lzcnt_64 returns `32 + clz_32(low32)` —
                // result in [32..64]. The W-write then truncated to low
                // 32, giving wrong values. Real failure: __kmalloc's
                // `kmalloc_index(size)` uses `fls = 32 - clz_w(size)`;
                // the bug made fls land in [-32..0] → out-of-range slab
                // index → UBSAN BRK #0x5512 at __kmalloc+0x190 (Code
                // sequence ending in `cmp w8, #0xd; b.ls; brk 0x5512`).
                //
                // Fix: for !sf, follow the 64-bit lzcnt with `sub rd, 32`.
                // For Wn=0 the lzcnt is 64, sub-32 = 32 = correct clz_32(0).
                // For Wn=0xFFFFFFFF the lzcnt is 32, sub-32 = 0 = correct.
                // (B6 ReadGpr now zero-extends a W-read, so the W-form lzcnt no
                // longer sees stale upper bits.) Spill-safe: load `a` into
                // SCRATCH1, compute into a working reg, store back.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                enc.emit_lzcnt_r64(rd, ra);
                if !*sf {
                    enc.emit_sub_r64_imm32(rd, 32);
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Cls { dst, a, sf } => {
                // Count leading sign bits (ARM C6.2.41): "the number of
                // consecutive bits following the most significant bit that are
                // the same as it". Architectural identity:
                //
                //     CLS(x) = CLZ( (x ^ (x << 1)) >> 1 ) - 1
                //
                // `x ^ (x<<1)` sets bit i to 1 where x[i] != x[i-1] (an adjacent
                // differ), for i in [N-1:1], PLUS a spurious bit 0 (= x[0]) that
                // the left-shift admits at the bottom. The logical `>> 1` drops
                // that spurious bit 0 and lands the differ-bits in [N-2:0], so
                // CLZ then measures exactly the leading run of sign bits — and
                // it is also correct for the all-same inputs (x = 0 or all-ones),
                // where the shifted value is 0, CLZ = N, and CLS = N-1.
                //
                // The `>> 1` was MISSING before: `CLZ(x ^ (x<<1)) - 1` is one too
                // low for every input with a real sign run, e.g. it returned 54
                // for CLS(0xFFFF_FFFF_FFFF_FF00) where ARM defines 55, and 62 for
                // CLS(all-ones) where ARM defines 63.
                //
                // W-form: mask to 32 bits AFTER the xor (and BEFORE the shift) so
                // the 64-bit `shl` cannot leak W[31] up into bit 32 — that leak
                // corrupted the count for negative W. `sub 32` then maps the
                // 64-bit lzcnt to the 32-bit width, as in the Clz arm.
                //
                // Spill-safe: `a` stays live in `ra` across the xor.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_shl_r64_imm8(rd, 1);
                enc.emit_xor_rr64(rd, ra); // rd = x ^ (x << 1)
                if !*sf {
                    // W-form: zero bits [63:32] so the bit-32 leak can't survive
                    // into the shift/lzcnt (mov r32 zero-extends the upper half).
                    enc.emit_mov_rr32(rd, rd);
                }
                enc.emit_shr_r64_imm8(rd, 1); // rd = (x ^ (x << 1)) >> 1
                enc.emit_lzcnt_r64(rd, rd);
                if !*sf {
                    enc.emit_sub_r64_imm32(rd, 32);
                }
                // CLS = CLZ((x ^ (x<<1)) >> 1) - 1.
                enc.emit_sub_r64_imm32(rd, 1);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Rbit { dst, a, sf } => {
                // Phase-E correctness fix. The prior lowering emitted BSWAP +
                // NOP, dropping the per-byte bit-reverse step entirely (the
                // comment literally said "stubbed as NOP for AT-12 gate;
                // full implementation in AT-13/14 helper"). RBIT(1) therefore
                // returned 0x0100_0000_0000_0000 (a byte swap) instead of
                // 0x8000_0000_0000_0000 (the true bit reversal). Real failure:
                // `_find_first_bit` (mm/percpu's for_each_cpu helper) uses
                // `RBIT; CLZ` to locate the first set bit — the bug made it
                // return 7 instead of 0, so `pcpu_build_alloc_info`'s outer
                // `for (group = 0; !cpumask_empty(...); group++)` loop never
                // entered the body for cpu 0, leaving nr_groups=0 and tripping
                // `kernel BUG at mm/percpu.c:2615` (ai->nr_groups <= 0).
                //
                // Algorithm (classic 64-bit bit reversal): three rounds of
                // swap-adjacent (1-bit, 2-bit, 4-bit) followed by a BSWAP for
                // the final byte-level reverse. ~25 x86 insns, ~80 bytes.
                //
                // SF: for the W-form (sf=false) the input W-register sits in
                // the low 32 bits with the upper 32 zero. A 64-bit reversal
                // would land the reversed bits in the UPPER 32, then the
                // WriteGpr's mov_rr32 zero-extend would truncate them to 0.
                // Compensate with a SHR rd,32 after the reverse so the bits
                // come back to the low 32 (where the W-write expects them).
                //
                // Spilled operands are rare for a single-source op; fail loud
                // (UD2) rather than miscompute (RAX/RCX scratch collision).
                if !Self::requires_gpr(alloc, *dst) || !Self::requires_gpr(alloc, *a) {
                    enc.emit_ud2_spill();
                } else {
                    let rd = Self::gpr(alloc, *dst);
                    let ra = Self::gpr(alloc, *a);
                    const RAX: u8 = 0;
                    const RCX: u8 = 1;
                    if rd != ra { enc.emit_mov_rr64(rd, ra); }
                    // Three swap rounds. Mask + shift width per round:
                    //   round 0: mask 0x5555_5555_5555_5555, shift 1
                    //   round 1: mask 0x3333_3333_3333_3333, shift 2
                    //   round 2: mask 0x0F0F_0F0F_0F0F_0F0F, shift 4
                    const MASKS: [(i64, u8); 3] = [
                        (0x5555_5555_5555_5555u64 as i64, 1),
                        (0x3333_3333_3333_3333u64 as i64, 2),
                        (0x0F0F_0F0F_0F0F_0F0Fu64 as i64, 4),
                    ];
                    for &(mask, sh) in MASKS.iter() {
                        // RAX = mask
                        enc.emit_mov_r64_imm64(RAX, mask);
                        // RCX = rd
                        enc.emit_mov_rr64(RCX, rd);
                        // RCX >>= sh
                        enc.emit_shr_r64_imm8(RCX, sh);
                        // RCX &= mask
                        enc.emit_and_rr64(RCX, RAX);
                        // rd &= mask
                        enc.emit_and_rr64(rd, RAX);
                        // rd <<= sh
                        enc.emit_shl_r64_imm8(rd, sh);
                        // rd |= RCX
                        enc.emit_or_rr64(rd, RCX);
                    }
                    // Final BSWAP (byte-level reverse of the bit-swapped result).
                    enc.emit_bswap_r64(rd);
                    if !*sf {
                        // W-form: bring the reversed low-32-bits back to the
                        // low half so the W-write zero-extension reaches them.
                        enc.emit_shr_r64_imm8(rd, 32);
                    }
                }
            }
            Rev { dst, a, bytes } => {
                // `bytes` encodes the variant (the lift folds in sf):
                //   2 = REV16 Wd (2 halfword swaps over low 32)
                //   3 = REV16 Xd (4 halfword swaps over 64)
                //   4 = REV   Wd (bswap32; zero-extends bits 63:32)
                //   5 = REV32 Xd (byte-reverse EACH 32-bit word, both kept)
                //   8 = REV   Xd (bswap64)
                // Spilled operands are rare for a 1-source op + we need RAX/RCX
                // as temps; fail loud (UD2) rather than miscompute (like Rbit).
                if !Self::requires_gpr(alloc, *dst) || !Self::requires_gpr(alloc, *a) {
                    enc.emit_ud2_spill();
                } else {
                    let rd = Self::gpr(alloc, *dst);
                    let ra = Self::gpr(alloc, *a);
                    const RAX: u8 = 0;
                    const RCX: u8 = 1;
                    if rd != ra { enc.emit_mov_rr64(rd, ra); }
                    match *bytes {
                        2 | 3 => {
                            // REV16: swap the two bytes within each 16-bit lane.
                            //   rd = ((v & M) << 8) | ((v >> 8) & M)
                            // M = 0x00FF00FF (W, 2 lanes) or repeated (X, 4 lanes).
                            let mask: i64 = if *bytes == 2 {
                                0x0000_0000_00FF_00FFu64 as i64
                            } else {
                                0x00FF_00FF_00FF_00FFu64 as i64
                            };
                            enc.emit_mov_r64_imm64(RAX, mask);
                            enc.emit_mov_rr64(RCX, rd);
                            enc.emit_shr_r64_imm8(RCX, 8);
                            enc.emit_and_rr64(RCX, RAX); // RCX = (v>>8) & M
                            enc.emit_and_rr64(rd, RAX); // rd  = v & M
                            enc.emit_shl_r64_imm8(rd, 8); // rd  = (v & M) << 8
                            enc.emit_or_rr64(rd, RCX); // rd  = swapped (W-write zero-extends for bytes==2)
                        }
                        4 => enc.emit_bswap_r32(rd), // REV Wd
                        5 => {
                            // REV32 Xd: byte-reverse each 32-bit word in place.
                            // bswap64 reverses all 8 bytes -> the two reversed
                            // words land in the WRONG lanes; swap the halves back.
                            enc.emit_bswap_r64(rd);
                            enc.emit_mov_rr64(RAX, rd);
                            enc.emit_shl_r64_imm8(RAX, 32);
                            enc.emit_shr_r64_imm8(rd, 32);
                            enc.emit_or_rr64(rd, RAX);
                        }
                        8 => enc.emit_bswap_r64(rd), // REV Xd
                        _ => {}
                    }
                }
            }
            // Bswap16/32/64 are DEAD on the live path (no lift callers — REV/REV16
            // route through `Rev` above). Kept fail-loud on spill for hygiene.
            Bswap16 { dst, a } => {
                if !Self::requires_gpr(alloc, *dst) || !Self::requires_gpr(alloc, *a) {
                    enc.emit_ud2_spill();
                } else {
                    let rd = Self::gpr(alloc, *dst);
                    let ra = Self::gpr(alloc, *a);
                    const RAX: u8 = 0;
                    const RCX: u8 = 1;
                    if rd != ra { enc.emit_mov_rr64(rd, ra); }
                    enc.emit_mov_r64_imm64(RAX, 0x0000_0000_00FF_00FFu64 as i64);
                    enc.emit_mov_rr64(RCX, rd);
                    enc.emit_shr_r64_imm8(RCX, 8);
                    enc.emit_and_rr64(RCX, RAX);
                    enc.emit_and_rr64(rd, RAX);
                    enc.emit_shl_r64_imm8(rd, 8);
                    enc.emit_or_rr64(rd, RCX);
                }
            }
            Bswap32 { dst, a } => {
                // Single x86 BSWAP — no internal scratch, so fully spill-safe via
                // src_in/dest_work (route a spilled operand through SCRATCH0/1).
                let ra = Self::src_in(alloc, enc, *a, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_bswap_r32(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Bswap64 { dst, a } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_bswap_r64(rd);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }

            // ── Flag-producing ALU (M4a: materialize NZCV to [R15+0x108]) ──────
            // Each computes its x86 result then build_nzcv captures EFLAGS. For a
            // spilled dst, store_dest runs BEFORE build_nzcv (mov-to-mem preserves
            // EFLAGS; build_nzcv then freely clobbers the scratch).
            // W-form (sf=false) ops emit 32-bit x86 ALU so EFLAGS (N=bit31, Z/C/V
            // over 32 bits) are correct; the result zero-extends into the dest
            // (matching ARM W-write semantics). build_nzcv is width-agnostic (it
            // reads the flags the ALU op set).
            AddS { dst, flags: _, a, b, sf } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                if *sf { enc.emit_add_rr64(rd, rb); } else { enc.emit_add_rr32(rd, rb); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
                Self::build_nzcv(enc, Self::NZCV_ADD);
            }
            SubS { dst, flags: _, a, b, sf } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                if *sf { enc.emit_sub_rr64(rd, rb); } else { enc.emit_sub_rr32(rd, rb); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
                Self::build_nzcv(enc, Self::NZCV_SUB);
            }
            AndS { dst, flags: _, a, b, sf } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                if *sf { enc.emit_and_rr64(rd, rb); } else { enc.emit_and_rr32(rd, rb); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
                Self::build_nzcv(enc, Self::NZCV_LOG);
            }
            Cmp { flags: _, a, b, sf } => {
                // SUBS-discard: x86 CMP sets EFLAGS without a dest.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if *sf { enc.emit_cmp_rr64(ra, rb); } else { enc.emit_cmp_rr32(ra, rb); }
                Self::build_nzcv(enc, Self::NZCV_SUB);
            }
            Cmn { flags: _, a, b, sf } => {
                // ADDS-discard: compute a+b into SCRATCH0 (don't disturb a/b regfile).
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if ra != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, ra); }
                if *sf { enc.emit_add_rr64(SCRATCH0, rb); } else { enc.emit_add_rr32(SCRATCH0, rb); }
                Self::build_nzcv(enc, Self::NZCV_ADD);
            }
            Tst { flags: _, a, b, sf } => {
                // ANDS-discard: x86 TEST sets EFLAGS without a dest. Logical C=V=0.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if *sf { enc.emit_test_rr64(ra, rb); } else { enc.emit_test_rr32(ra, rb); }
                Self::build_nzcv(enc, Self::NZCV_LOG);
            }
            Adcs { dst, a, b, sf, .. } | Sbcs { dst, a, b, sf, .. } => {
                // M4b-1: real carry-in. Seed x86 CF from the stored ARM NZCV C
                // bit (bit 29 of [R15+0x108]) via BT, then ADC/SBB, then
                // build_nzcv. BT must be the LAST flag-affecting op before
                // ADC/SBB (it sets CF and clears OF; the mov rd,ra in between
                // does not touch flags). Spilled dest stored before build_nzcv
                // (mov-to-mem preserves CF/EFLAGS).
                let is_sbc = matches!(op, IrOp::Sbcs { .. });
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra {
                    enc.emit_mov_rr64(rd, ra);
                }
                // Seed x86 CF from the ARM C bit (bit 29). The two ops need
                // OPPOSITE carry polarity because x86 CF means different things:
                //   ADCS: result = a + b + C. x86 ADC = dst + src + CF, so
                //         CF = ARM C directly. BT alone suffices.
                //   SBCS: result = a + ~b + C = a - b - (1 - C). x86 SBB =
                //         dst - src - CF where CF is the BORROW, so we need
                //         CF = (1 - C) = !C. BT sets CF = C, then CMC flips it
                //         to the borrow. (Seeding CF = C and using SBB would
                //         compute a - b - C — the bit-exact INVERSE — and poison
                //         build_nzcv's re-derived carry-out. Caught by the M4b-1
                //         adversarial review; covered by m4b_sbcs_borrow_chain.)
                // BT (and CMC) are the LAST flag-affecting ops before ADC/SBB;
                // the mov rd,ra above does not touch flags.
                enc.emit_bt_mem(CONTEXT_REG, NZCV_DISP, 29);
                if is_sbc {
                    enc.emit_cmc(); // CF = !ARM_C = x86 borrow
                    if *sf { enc.emit_sbb_rr64(rd, rb); } else { enc.emit_sbb_rr32(rd, rb); }
                } else if *sf {
                    enc.emit_adc_rr64(rd, rb);
                } else {
                    enc.emit_adc_rr32(rd, rb);
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
                Self::build_nzcv(enc, if is_sbc { Self::NZCV_SUB } else { Self::NZCV_ADD });
            }
            Csel { dst, a, b, cond, flags: _, variant } => {
                // dst = cond ? a : transform(b), where transform is
                //   CSEL=id / CSINC=+1 / CSINV=~ / CSNEG=- .
                //
                // SPILL-SAFE (2026-06-30). The prior lowering fail-loud-UD2'd
                // whenever ANY of dst/a/b spilled, because the 2-scratch model
                // (RAX/RCX) collided with the NZCV-eval scratch. Csel is one of
                // the most common ops in bionic/libbase, and a high-pressure
                // libc block (e.g. the one starting `add x9,x10,x1,lsl#1`) spills
                // routinely → that UD2 path injected an EL0 undefined-instruction
                // and killed init. New sequence keeps EVERY value off the
                // allocated registers and on the two scratch regs + the stack, so
                // a spilled dst/a/b materializes correctly instead of walling:
                //
                //   mov  SCRATCH0, [R15+NZCV]
                //   <cond→bool in SCRATCH1>   (clobbers RAX/RCX, push/pops RDX)
                //   push SCRATCH1             ; save the boolean
                //   SCRATCH0 = transform(b)   ; else-value
                //   SCRATCH1 = a              ; then-value
                //   pop  RDX ; test RDX,RDX ; cmov NZ SCRATCH0, SCRATCH1
                //   store SCRATCH0 → dst
                //
                // The transform clobbers EFLAGS, but the boolean is already
                // captured (and re-tested from the popped RDX after), so the
                // ordering hazard the M4a comment guarded against cannot recur.
                // RDX is borrowed as a THIRD temp to hold the boolean across
                // operand materialization. RDX is allocatable (it may hold a live
                // value), so it is push/pop-saved around the whole sequence — the
                // only stack traffic, balanced. emit_arm_cond_to_bool's own
                // internal RDX push/pop (Hi/Ls/Ge/… conditions) stays balanced
                // and nests cleanly below our saved copy.
                const RDX: u8 = 2;
                enc.emit_push_r64(RDX); // save a possibly-live RDX
                // 1. Evaluate the ARM condition into a 0/1 boolean (SCRATCH1),
                //    then park it in RDX (SCRATCH0/SCRATCH1 are needed for values).
                enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, NZCV_DISP);
                Self::emit_arm_cond_to_bool(enc, SCRATCH0, SCRATCH1, *cond);
                enc.emit_mov_rr64(RDX, SCRATCH1); // RDX = boolean (survives steps 2-3)
                // 2. else-value = transform(b) into SCRATCH0 (force-materialized,
                //    so a spilled or any-register b lands in the fixed cmov reg).
                //    The transform clobbers EFLAGS, but the boolean is already in
                //    RDX, so the M4a flag-ordering hazard cannot recur.
                let rb = Self::src_in(alloc, enc, *b, SCRATCH0);
                if rb != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, rb); }
                match *variant {
                    1 => enc.emit_add_r64_imm32(SCRATCH0, 1), // CSINC
                    2 => enc.emit_not_r64(SCRATCH0),          // CSINV
                    3 => enc.emit_neg_r64(SCRATCH0),          // CSNEG
                    _ => {}                                    // CSEL
                }
                // 3. then-value = a into SCRATCH1 (force-materialized). src_in for
                //    a spilled `a` loads from its slot; SCRATCH0(=b) is untouched.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH1);
                if ra != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, ra); }
                // 4. Test the boolean and select a iff cond true. None of the
                //    src_in/transform ops above touch RDX, so the boolean is intact.
                enc.emit_test_rr64(RDX, RDX);          // NZ iff cond true
                enc.emit_cmov_rr64(cc::NZ, SCRATCH0, SCRATCH1); // SCRATCH0 = result
                enc.emit_pop_r64(RDX);                 // restore the saved RDX
                // 5. Store the result to dst (honouring a spilled dst). Done AFTER
                //    the RDX restore so a dst that lives in RDX gets the result.
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != SCRATCH0 { enc.emit_mov_rr64(rd, SCRATCH0); }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            CCmp { a, b, cond, nzcv_if_false, is_neg, sf, .. } => {
                // M4b-1: real branched CCMP/CCMN. If `cond` holds, NZCV = flags
                // of (a - b) for CCMP or (a + b) for CCMN; else NZCV = the 4-bit
                // nzcv_if_false immediate. ARM NZCV bits [N,Z,C,V] map to packed
                // bits [31,30,29,28], so the literal goes to (nzcv_if_false<<28).
                //
                //   eval cond -> bool in SCRATCH1; if FALSE (ZF=1) jump to literal
                //   true:  cmp/add a,b ; build_nzcv(SUB|ADD) ; jmp end
                //   false: [R15+NZCV] = nzcv_if_false << 28
                //   end:
                // Local forward jumps patched in-place (independent of the
                // cross-block branch_patches map).
                enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, NZCV_DISP);
                Self::emit_arm_cond_to_bool(enc, SCRATCH0, SCRATCH1, *cond);
                enc.emit_test_rr64(SCRATCH1, SCRATCH1); // ZF=1 iff cond FALSE
                let jz_to_false = enc.emit_jcc_rel32(cc::Z);
                // true path: real compare -> NZCV with the right polarity.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                if *is_neg {
                    // CCMN: flags of (a + b). ADD is destructive, so work in a
                    // clobberable SCRATCH0 copy (CMN discards the sum, but a's
                    // home register may be live afterward). rb is never SCRATCH0
                    // (RAX/RCX are reserved scratch, never allocated; src_in only
                    // loads a spilled `b` into SCRATCH1), so this is collision-safe.
                    if ra != SCRATCH0 {
                        enc.emit_mov_rr64(SCRATCH0, ra);
                    }
                    if *sf { enc.emit_add_rr64(SCRATCH0, rb); } else { enc.emit_add_rr32(SCRATCH0, rb); }
                    Self::build_nzcv(enc, Self::NZCV_ADD);
                } else {
                    // CCMP: flags of (a - b). CMP is non-destructive.
                    if *sf { enc.emit_cmp_rr64(ra, rb); } else { enc.emit_cmp_rr32(ra, rb); }
                    Self::build_nzcv(enc, Self::NZCV_SUB);
                }
                let jmp_to_end = enc.emit_jmp_rel32();
                // false path: store the literal NZCV.
                let false_pos = enc.pos();
                enc.patch_rel32(jz_to_false, false_pos);
                enc.emit_mov_r64_imm32(SCRATCH0, *nzcv_if_false as i32);
                enc.emit_shl_r64_imm8(SCRATCH0, 28);
                enc.emit_mov_mem_r64(CONTEXT_REG, NZCV_DISP, SCRATCH0);
                // end:
                let end_pos = enc.pos();
                enc.patch_rel32(jmp_to_end, end_pos);
            }
            NzcvBitOp { .. } => {
                // PSTATE bit set/clear (e.g. MSR DAIFSet). Rare in early boot;
                // not a flag-comparison result. Left as a no-op placeholder.
                enc.emit_nop();
            }

            // ── Sign / zero extension ─────────────────────────────────────
            // ARM SBFX/UBFX produce arbitrary widths (1..63), and the dest
            // can be either W (32-bit) or X (64-bit). The Linux printk
            // `struct printf_spec` packs field_width as a SIGNED 24-bit at
            // byte offset 1, extracted by `sbfx x?, x?, #8, #0x18` (sf=1)
            // and also `sbfx w?, w?, #0, #0x18` (sf=0). With Sext a no-op
            // for arbitrary widths the negative widths stayed as huge
            // positive ints (~16M) — every printk hit the slow pad loop.
            // General fix: shl by (64-w) then arith-shr by (64-w) to sign-
            // extend any from_bits within the 64-bit reg; if to_bits==32
            // follow with mov_rr32 so the high 32 are zeroed per ARM W-reg
            // semantics (x86 32-bit moves zero-extend).
            Sext { dst, a, from_bits, to_bits } => {
                // Spill-safe: route operands through src_in/dest_work.
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                match (*from_bits, *to_bits) {
                    (8, 64)  => enc.emit_movsx_r64_r8(rd, ra),
                    (16, 64) => enc.emit_movsx_r64_r16(rd, ra),
                    (32, 64) => enc.emit_movsxd_r64_r32(rd, ra),
                    (w, _) if w > 0 && w < 64 => {
                        if rd != ra { enc.emit_mov_rr64(rd, ra); }
                        let shift = 64 - w;
                        enc.emit_shl_r64_imm8(rd, shift);
                        enc.emit_sar_r64_imm8(rd, shift);
                        if *to_bits == 32 {
                            // ARM W-reg semantics: high 32 bits are zero.
                            enc.emit_mov_rr32(rd, rd);
                        }
                    }
                    _        => { if rd != ra { enc.emit_mov_rr64(rd, ra); } }
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Zext { dst, a, from_bits, to_bits } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                match (*from_bits, *to_bits) {
                    (8, 64)  => enc.emit_movzx_r64_r8(rd, ra),
                    (16, 64) => enc.emit_movzx_r64_r16(rd, ra),
                    (32, 64) => enc.emit_mov_rr32(rd, ra), // zero-extend implicit
                    (w, _) if w > 0 && w < 64 => {
                        if rd != ra { enc.emit_mov_rr64(rd, ra); }
                        let shift = 64 - w;
                        enc.emit_shl_r64_imm8(rd, shift);
                        enc.emit_shr_r64_imm8(rd, shift);
                    }
                    _        => { if rd != ra { enc.emit_mov_rr64(rd, ra); } }
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            Trunc { dst, a, to_bits } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                // Mask to the target width via AND.
                match *to_bits {
                    8  => enc.emit_and_r64_imm32(rd, 0xFF),
                    16 => enc.emit_and_r64_imm32(rd, 0xFFFF),
                    32 => enc.emit_mov_rr32(rd, rd), // zero upper 32 bits
                    _  => {}
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }

            // ── Memory (M4b-2b: guest VA → host PA via aether_mmu_xlate) ──────
            // The guest address in `ra` is translated through the software MMU
            // walker; the actual load/store then uses the returned host PA in
            // RAX as its base ([RAX+0]). When the guest MMU is off the walker
            // returns the VA unchanged, so the flat-mapping case is identical.
            // A fault makes emit_mmu_xlate_call early-RET (pending Data Abort
            // recorded by the walker), so the access below is only reached on a
            // successful (in-window) translation — never an out-of-window PA.
            //
            // SPILL-SAFE ADDRESS: a spilled pointer base is materialized from its
            // spill slot into SCRATCH0 (RAX) via `addr_in` BEFORE the call — the
            // call reads it into RDX first (RAX is never in MMU_SAVE_REGS, so the
            // push set leaves it intact), so a spilled base dereferences the REAL
            // pointer, exactly like the integer Load/Store path. Only an
            // `Assignment::None` address (used-but-never-defined — an upstream
            // regalloc bug, no spill slot to load from) fails loud (UD2). The
            // `addr_in() == None` arm below is that fail-loud case.
            // LDR Q (128-bit) — M4b-6 ctx-template FPR load. lift emits this as
            // Load{Vec128} immediately followed by WriteFpr{rt}, which commits
            // VFP -> q[rt]. The xlate call is issued FIRST so the subsequent
            // movdqu into VFP (XMM15, Win64 non-volatile) is never clobbered.
            // LDR/LDP {Q,D,S} element — Vec128 (movdqu, 16B), F64 (movsd, 8B,
            // upper 64 zeroed), or F32 (movss, 4B, upper 96 zeroed) into VFP.
            // The narrow forms zero the high lanes, matching ARM LDR d/s
            // semantics; the following WriteFpr commits VFP -> q[rt].
            Load { addr, ty: ty @ (LoadTy::Vec128 | LoadTy::F64 | LoadTy::F32), .. } => {
                // Spill-safe: materialize a spilled pointer base from its slot into
                // SCRATCH0 (the call reads it into RDX before clobbering RAX). Only
                // an unassigned (None) address fails loud.
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    let size: i32 = match ty {
                        LoadTy::F32 => 4,
                        LoadTy::F64 => 8,
                        _ => 16,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, false, size); // RAX = host PA
                    let vfp = crate::regalloc::x86_regs::VFP;
                    match ty {
                        LoadTy::F32 => enc.emit_movss_load(vfp, SCRATCH0, 0),
                        LoadTy::F64 => enc.emit_movsd_load(vfp, SCRATCH0, 0),
                        _ => enc.emit_movdqu_load(vfp, SCRATCH0, 0),
                    }
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            Load { dst, addr, ty, .. } => {
                let is_fp = matches!(ty, LoadTy::F32 | LoadTy::F64 | LoadTy::Vec128);
                if is_fp {
                    enc.emit_ud2();
                } else {
                    // Phase-F: handle spilled addr / dst. Spilled addr → load
                    // from spill slot into SCRATCH0 before the MMU call (call
                    // copies SCRATCH0→RDX, then RCX/R8/R9 setup doesn't
                    // clobber SCRATCH0 until after copy). Spilled dst → load
                    // into SCRATCH1 then store to spill slot. RAX (=SCRATCH0)
                    // holds host PA after the call, so it MUST be used as
                    // the [base] for the actual load.
                    let ra = Self::src_in(alloc, enc, *addr, SCRATCH0);
                    let size: i32 = match ty {
                        LoadTy::U8 | LoadTy::I8 => 1,
                        LoadTy::U16 | LoadTy::I16 => 2,
                        LoadTy::U32 | LoadTy::I32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, false, size); // RAX = host PA
                    // Pick a dest register that isn't SCRATCH0 (=RAX, the PA).
                    let (rd_final, sp) = Self::dest_work(alloc, *dst, SCRATCH1);
                    let rd_work = if rd_final == SCRATCH0 { SCRATCH1 } else { rd_final };
                    match ty {
                        LoadTy::U8  => enc.emit_movzx_r64_mem8(rd_work, SCRATCH0, 0),
                        LoadTy::I8  => enc.emit_movsx_r64_mem8(rd_work, SCRATCH0, 0),
                        LoadTy::U16 => enc.emit_movzx_r64_mem16(rd_work, SCRATCH0, 0),
                        LoadTy::I16 => enc.emit_movsx_r64_mem16(rd_work, SCRATCH0, 0),
                        LoadTy::U32 => enc.emit_mov_r32_mem(rd_work, SCRATCH0, 0),
                        LoadTy::I32 => enc.emit_movsxd_r64_mem32(rd_work, SCRATCH0, 0),
                        LoadTy::U64 => enc.emit_mov_r64_mem(rd_work, SCRATCH0, 0),
                        // FP handled by the is_fp UD2 guard above.
                        LoadTy::F32 | LoadTy::F64 | LoadTy::Vec128 => enc.emit_ud2(),
                    }
                    if rd_work != rd_final { enc.emit_mov_rr64(rd_final, rd_work); }
                    Self::store_dest(alloc, enc, *dst, rd_final, sp);
                }
            }
            // STR Q (128-bit) — M4b-6 ctx-template FPR store. lift emits this as
            // ReadFpr{rt} (loads VFP <- q[rt]) immediately followed by
            // Store{Vec128}. VFP is XMM15 (Win64 non-volatile) so it survives the
            // write-xlate call; we then movdqu it to the returned host PA.
            // (MMIO Q-stores are not modeled — NEON never targets device memory
            // in the kernel/bionic paths; a device VA would fault in the walker.)
            // STR/STP {Q,D,S} element — store VFP's low 128/64/32 bits to the
            // resolved host PA (movdqu / movsd / movss). VFP was primed by the
            // preceding ReadFpr (q[rt] -> VFP).
            Store { addr, ty: ty @ (StoreTy::Vec128 | StoreTy::F64 | StoreTy::F32), .. } => {
                // Spill-safe address (VFP holds the data, so the address is the only
                // GPR operand). A spilled base materializes from its slot; only an
                // unassigned (None) address fails loud.
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    let size: i32 = match ty {
                        StoreTy::F32 => 4,
                        StoreTy::F64 => 8,
                        _ => 16,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, true, size); // RAX = host PA
                    let vfp = crate::regalloc::x86_regs::VFP;
                    match ty {
                        StoreTy::F32 => enc.emit_movss_store(SCRATCH0, 0, vfp),
                        StoreTy::F64 => enc.emit_movsd_store(SCRATCH0, 0, vfp),
                        _ => enc.emit_movdqu_store(SCRATCH0, 0, vfp),
                    }
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            Store { val, addr, ty, .. } => {
                let is_fp = matches!(ty, StoreTy::F32 | StoreTy::F64 | StoreTy::Vec128);
                if is_fp {
                    enc.emit_ud2();
                } else {
                    // Phase-F: handle spilled addr/val by loading them into
                    // scratch regs before the runtime CALL. emit_mmu_store_call
                    // expects addr in arg-2 (RDX) and val in arg-3 (R8) per
                    // the Win64 ABI; both copies happen after we materialize
                    // the spilled values into SCRATCH0/SCRATCH1.
                    let ra = Self::src_in(alloc, enc, *addr, SCRATCH0);
                    let rv = Self::src_in(alloc, enc, *val, SCRATCH1);
                    let size: i32 = match ty {
                        StoreTy::U8 => 1,
                        StoreTy::U16 => 2,
                        StoreTy::U32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_store_call(enc, ra, rv, size);
                }
            }
            // M4b-2b: LDP/STP and the exclusives route their address through the
            // walker too. Without this, every LDP/STP — i.e. every function
            // prologue/epilogue stack frame — would hit the RAW VA the instant
            // the guest sets SCTLR.M=1, and the kernel would die at the first
            // `stp x29,x30,[sp,#-N]!`. SPILL-SAFE: the address materializes from
            // its slot via `addr_in` (SCRATCH0, read into RDX by the call before
            // RAX is reused), and each spilled dst/val element is shuttled through
            // SCRATCH1 (RCX) — RAX holds the PA base after the call, so SCRATCH1
            // is the only free scratch, used one element at a time. Only an
            // unassigned (None) address fails loud.
            LoadPair { dst_a, dst_b, addr, ty } => {
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    // Per-element width; the pair spans 2×width bytes (passed as
                    // the access size so the walker's cross-page check covers it).
                    let width: i32 = if matches!(ty, LoadTy::U64) { 8 } else { 4 };
                    Self::emit_mmu_xlate_call(enc, ra, false, 2 * width); // RAX = host PA
                    // Each element: load [PA+off] into a work reg (SCRATCH1 if the
                    // dst is spilled — never RAX, which is the PA base), then store
                    // back to the spill slot. A non-spilled dst loads directly.
                    let load_elem = |enc: &mut X86Encoder, dst: IrValueId, off: i32| {
                        let (rd, sp) = Self::dest_work(alloc, dst, SCRATCH1);
                        match ty {
                            LoadTy::U64 => enc.emit_mov_r64_mem(rd, SCRATCH0, off),
                            LoadTy::I32 => enc.emit_movsxd_r64_mem32(rd, SCRATCH0, off),
                            _ => enc.emit_mov_r32_mem(rd, SCRATCH0, off),
                        }
                        Self::store_dest(alloc, enc, dst, rd, sp);
                    };
                    load_elem(enc, *dst_a, 0);
                    load_elem(enc, *dst_b, width);
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            StorePair { val_a, val_b, addr, ty } => {
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    let width: i32 = if matches!(ty, StoreTy::U64) { 8 } else { 4 };
                    Self::emit_mmu_xlate_call(enc, ra, true, 2 * width); // RAX = host PA
                    // Each value: materialize a spilled element into SCRATCH1 (never
                    // RAX, which is the PA base) before storing to [PA+off].
                    let store_elem = |enc: &mut X86Encoder, val: IrValueId, off: i32| {
                        let rv = Self::src_in(alloc, enc, val, SCRATCH1);
                        if width == 8 {
                            enc.emit_mov_mem_r64(SCRATCH0, off, rv);
                        } else {
                            enc.emit_mov_mem32_r64(SCRATCH0, off, rv);
                        }
                    };
                    store_elem(enc, *val_a, 0);
                    store_elem(enc, *val_b, width);
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            // DC ZVA — zero the 64-byte block containing `addr` with ONE walk +
            // 8 inline 8-byte zero stores. Align the VA down to 64 in SCRATCH0
            // (a COPY — the architectural source reg, e.g. x0 in clear_page, must
            // stay live for the following `add x0,x0,x1`), translate it (write,
            // 64 B; the whole block is within one page so a single contiguous PA
            // serves all 8 stores), then store zero 8× to [PA + k*8]. RAX holds
            // the PA after the call; RCX (SCRATCH1) is the zero source.
            ZeroBlock { addr } => {
                let ra = Self::src_in(alloc, enc, *addr, SCRATCH0);
                if ra != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, ra); }
                enc.emit_and_r64_imm32(SCRATCH0, !63i32); // align down to 64-byte block
                Self::emit_mmu_xlate_call(enc, SCRATCH0, true, 64); // RAX = host PA
                enc.emit_xor_rr64(SCRATCH1, SCRATCH1); // RCX = 0
                let mut k: i32 = 0;
                while k < 8 {
                    enc.emit_mov_mem_r64(SCRATCH0, k * 8, SCRATCH1);
                    k += 1;
                }
            }
            LoadExclusive { dst, addr, ty } => {
                // Exclusive load routed through the walker (the monitor
                // reservation itself is still AT-14 future work, but the ADDRESS
                // must be correct under the guest MMU). Size from `ty`. SPILL-SAFE:
                // address materializes via addr_in(SCRATCH0); a spilled dst loads
                // into SCRATCH1 (never RAX = the PA base) then stores back. Only an
                // unassigned (None) address fails loud.
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    let size: i32 = match ty {
                        LoadTy::U8 | LoadTy::I8 => 1,
                        LoadTy::U16 | LoadTy::I16 => 2,
                        LoadTy::U32 | LoadTy::I32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, false, size); // RAX = host PA
                    let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH1);
                    match ty {
                        LoadTy::U8  => enc.emit_movzx_r64_mem8(rd, SCRATCH0, 0),
                        LoadTy::I8  => enc.emit_movsx_r64_mem8(rd, SCRATCH0, 0),
                        LoadTy::U16 => enc.emit_movzx_r64_mem16(rd, SCRATCH0, 0),
                        LoadTy::I16 => enc.emit_movsx_r64_mem16(rd, SCRATCH0, 0),
                        LoadTy::U32 => enc.emit_mov_r32_mem(rd, SCRATCH0, 0),
                        LoadTy::I32 => enc.emit_movsxd_r64_mem32(rd, SCRATCH0, 0),
                        LoadTy::U64 => enc.emit_mov_r64_mem(rd, SCRATCH0, 0),
                        LoadTy::F32 | LoadTy::F64 | LoadTy::Vec128 => enc.emit_ud2(),
                    }
                    Self::store_dest(alloc, enc, *dst, rd, sp);
                    // B25: no reservation is recorded — the matching STXR always
                    // succeeds on single-vCPU (see StoreExclusive). The address is
                    // still routed through the walker so the load itself is correct.
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            StoreExclusive { status, val, addr, ty } => {
                // Exclusive store routed through the walker; `status = 0`
                // (success) remains the AT-12 placeholder (the real STXR monitor
                // is AT-14). SPILL-SAFE: address via addr_in(SCRATCH0); value via
                // src_in(SCRATCH1); a spilled status writes 0 to its slot. Only an
                // unassigned (None) address fails loud.
                if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    let size: i32 = match ty {
                        StoreTy::U8 => 1,
                        StoreTy::U16 => 2,
                        StoreTy::U32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, true, size); // RAX = host PA
                    // Materialize a spilled value into SCRATCH1 (never RAX = PA base).
                    let rv = Self::src_in(alloc, enc, *val, SCRATCH1);
                    match ty {
                        StoreTy::U8  => enc.emit_mov_mem8_r64(SCRATCH0, 0, rv),
                        StoreTy::U16 => enc.emit_mov_mem16_r64(SCRATCH0, 0, rv),
                        StoreTy::U32 => enc.emit_mov_mem32_r64(SCRATCH0, 0, rv),
                        StoreTy::U64 => enc.emit_mov_mem_r64(SCRATCH0, 0, rv),
                        StoreTy::F32 | StoreTy::F64 | StoreTy::Vec128 => enc.emit_ud2(),
                    }
                    // B25: STXR/STLXR report status = 0 (success). On a SINGLE-vCPU
                    // DBT this is the CORRECT exclusive-store semantics, not a
                    // placeholder: no other agent exists to clear the reservation
                    // between the matching LDXR and this STXR, so the store must
                    // always succeed. A real address/valid monitor only matters
                    // under SMP (multiple vCPUs racing the same granule); it is
                    // intentionally deferred until SMP lands. (An earlier in-tree
                    // monitor using ctx reservation slots regressed early-kernel
                    // boot — every spinlock retry hung — confirming always-succeed
                    // is what the single-vCPU kernel requires.) For a spilled
                    // status, zero a working reg then store it to the slot.
                    let (rs, ssp) = Self::dest_work(alloc, *status, SCRATCH1);
                    enc.emit_xor_zero_r32(rs);
                    Self::store_dest(alloc, enc, *status, rs, ssp);
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }

            // ── Control flow ───────────────────────────────────────────────
            Branch { target } => {
                let patch = enc.emit_jmp_rel32();
                branch_patches.push((patch, *target));
            }
            CondBranch { cond, flags: _, taken, fallthru: _ } => {
                use crate::decoder::Cond as C;
                // CRITICAL: Read ARM NZCV from memory, NOT x86 EFLAGS.
                // ARM b.cond consumes the ARM C/Z/N/V flags committed by the
                // last ARM flag-setting op (Cmp/SubS/AddS/Tst/etc.) via
                // build_nzcv → [R15+NZCV]. Between that op and this b.cond,
                // OTHER IR ops can run (Tbz/Tbnz lowers to `shr; test`; Cbz
                // to `test`; Load to MMU helper calls that clobber every
                // x86 flag). x86 EFLAGS are gone. We must rebuild the ARM
                // condition from the in-memory NZCV byte.
                //
                // Pattern: load packed NZCV → bit-test → setcc bool → test
                // bool, bool → jcc NZ.
                if matches!(cond, C::Al | C::Nv) {
                    let patch = enc.emit_jmp_rel32();
                    branch_patches.push((patch, *taken));
                    return;
                }
                // Load packed NZCV word into SCRATCH0.
                enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, NZCV_DISP);
                // emit_arm_cond_to_bool: bit 0 of `out` reg = ARM condition.
                Self::emit_arm_cond_to_bool(enc, SCRATCH0, SCRATCH1, *cond);
                // test scratch1, scratch1 → ZF = (cond == 0).
                enc.emit_test_rr64(SCRATCH1, SCRATCH1);
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.push((patch, *taken));
                // fallthru falls through — no emit needed.
            }
            // NOTE: IrOp::Cbz/Cbnz/Tbz/Tbnz are dead on the live path — the lift
            // lowers CBZ/CBNZ/TBZ/TBNZ to Cmp+Csel+WritePc (see lift/mod.rs
            // ~1540-1575). These arms are reached only via the cold opt/serialize
            // path; kept spill-safe + non-destructive for correctness.
            Cbz { a, taken, .. } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                enc.emit_test_rr64(ra, ra);
                let patch = enc.emit_jcc_rel32(cc::Z);
                branch_patches.push((patch, *taken));
            }
            Cbnz { a, taken, .. } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                enc.emit_test_rr64(ra, ra);
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.push((patch, *taken));
            }
            Tbz { a, bit, taken, .. } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                // Copy into SCRATCH0 before the destructive shr: ARM TBZ/TBNZ must
                // not modify any register, so never `shr` an allocated source reg.
                if ra != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, ra); }
                enc.emit_shr_r64_imm8(SCRATCH0, *bit);
                enc.emit_test_rr64(SCRATCH0, SCRATCH0);
                let patch = enc.emit_jcc_rel32(cc::Z);
                branch_patches.push((patch, *taken));
            }
            Tbnz { a, bit, taken, .. } => {
                let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                if ra != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, ra); }
                enc.emit_shr_r64_imm8(SCRATCH0, *bit);
                enc.emit_test_rr64(SCRATCH0, SCRATCH0);
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.push((patch, *taken));
            }
            IndirectBranch { target } => {
                // CRITICAL: target may be SPILLED (high reg pressure in
                // jump-table dispatch blocks: ADRP+ADD+ADD+ADR+LDRB+ADD-shifted
                // before the BR). Bare gpr() returns SCRATCH0=RAX for spills,
                // so JMP would go to whatever RAX last contained. Route through
                // src_in so a spilled target gets loaded from its slot first.
                let r = Self::src_in(alloc, enc, *target, SCRATCH0);
                enc.emit_jmp_r64(r);
            }
            Call { target, .. } => {
                let r = Self::src_in(alloc, enc, *target, SCRATCH0);
                enc.emit_call_r64(r);
            }
            Return { target } => {
                // In the ARM→x86 JIT, Return means "jump to the link register
                // value" — which after AT-19 context restore becomes JMP to
                // x30's assigned register.  For AT-12 gate the simplest correct
                // emit is JMP r (indirect return). Same spill-safety as above.
                let r = Self::src_in(alloc, enc, *target, SCRATCH0);
                enc.emit_jmp_r64(r);
            }

            // ── x86 TSO lowered barrier ops (from AT-10) ──────────────────
            IrOp::X86Mfence => enc.emit_mfence(),
            IrOp::X86Cpuid  => enc.emit_isb_sequence(),

            // ── Atomics (LSE: SWP / LDADD / CAS …) ─────────────────────────
            // CRITICAL: these were a silent `nop` ("handled by lower_atomic"),
            // but lower_atomic is NOT in the live path — so every LSE atomic did
            // NOTHING. The kernel survived (it uses LL/SC), but bionic's locks
            // use SWP/CAS: the no-op never touched memory, so the lock page never
            // demand-paged and /init spun forever on the next plain load (the
            // 0x514d5c loop). Implemented here as a single-core load-op-store
            // through the guest MMU — no LOCK needed (one vCPU), width-honoured
            // (a 64-bit op on a 32-bit lock would clobber the adjacent word), and
            // the xlate call early-RETs with a pending Data Abort on a fault, so
            // atomics now demand-page exactly like Load/Store.
            AtomicRmw { dst, op, addr, val, order, size } => {
                let _ = order; // x86-TSO single-core: acquire/release are no-ops
                // SPILL-SAFE ADDRESS (the keystore2 Rust-Arc case): a spilled base
                // materializes from its slot via addr_in(SCRATCH0) — the call reads
                // it into RDX before reusing RAX as the PA. The dst (result) and val
                // operands share the 2-scratch budget with SCRATCH0=PA / SCRATCH1=
                // compute, so a spilled dst/val still fails loud (UD2) — those stay
                // in-register in practice (the lift keeps them live across the op).
                if !Self::requires_gpr(alloc, *dst) || !Self::requires_gpr(alloc, *val) {
                    enc.emit_ud2_spill();
                } else if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    Self::emit_mmu_xlate_call(enc, ra, true, *size as i32); // SCRATCH0 = host PA
                    // dst and val have overlapping live ranges here, so regalloc
                    // gives them distinct registers (rd != rv) — and neither is
                    // RAX/RCX (reserved scratch).
                    let rd = Self::gpr(alloc, *dst);
                    let rv = Self::gpr(alloc, *val);
                    // Load old value (the result) into rd.
                    Self::emit_w_load(enc, rd, SCRATCH0, *size);
                    // Compute the new value to store, in SCRATCH1.
                    match op {
                        AtomicOp::Swp => enc.emit_mov_rr64(SCRATCH1, rv),
                        AtomicOp::Add => { enc.emit_mov_rr64(SCRATCH1, rd); enc.emit_add_rr64(SCRATCH1, rv); }
                        AtomicOp::Set => { enc.emit_mov_rr64(SCRATCH1, rd); enc.emit_or_rr64(SCRATCH1, rv); }
                        AtomicOp::Eor => { enc.emit_mov_rr64(SCRATCH1, rd); enc.emit_xor_rr64(SCRATCH1, rv); }
                        // Clr = old & ~val.
                        AtomicOp::Clr => { enc.emit_mov_rr64(SCRATCH1, rv); enc.emit_not_r64(SCRATCH1); enc.emit_and_rr64(SCRATCH1, rd); }
                        // {S,U}{max,min}: cmp old,val → cmov val into result when
                        // val is the wanted extreme.
                        AtomicOp::Smax | AtomicOp::Smin | AtomicOp::Umax | AtomicOp::Umin => {
                            enc.emit_mov_rr64(SCRATCH1, rd);
                            // Width-correct compare (see AtomicCas): a 64-bit cmp on
                            // a 32-bit atomic max/min reads stale upper bits of `rv`.
                            if *size == 8 {
                                enc.emit_cmp_rr64(rd, rv);
                            } else {
                                enc.emit_cmp_rr32(rd, rv);
                            }
                            let take_val = match op {
                                AtomicOp::Smax => cc::L,    // old <  val (signed)
                                AtomicOp::Smin => cc::NLE,  // old >  val (signed)
                                AtomicOp::Umax => cc::B,    // old <  val (unsigned)
                                AtomicOp::Umin => cc::NBE,  // old >  val (unsigned)
                                _ => cc::Z,
                            };
                            enc.emit_cmov_rr64(take_val, SCRATCH1, rv);
                        }
                    }
                    Self::emit_w_store(enc, SCRATCH0, SCRATCH1, *size);
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            AtomicCas { dst, addr, expected, new, order, size } => {
                let _ = order;
                // SPILL-SAFE ADDRESS via addr_in(SCRATCH0); dst/expected/new share
                // the 2-scratch budget (SCRATCH0=PA, SCRATCH1=candidate), so a
                // spilled value operand still fails loud. Address is the realistic
                // spill (the BoringSSL/Arc CAS keeps its value operands live).
                if !Self::requires_gpr(alloc, *dst)
                    || !Self::requires_gpr(alloc, *expected)
                    || !Self::requires_gpr(alloc, *new)
                {
                    enc.emit_ud2_spill();
                } else if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    Self::emit_mmu_xlate_call(enc, ra, true, *size as i32); // SCRATCH0 = host PA
                    let rd = Self::gpr(alloc, *dst);
                    let re = Self::gpr(alloc, *expected);
                    let rn = Self::gpr(alloc, *new);
                    // Load current value → rd (= old, the result, returned always).
                    // emit_w_load zero-extends rd to `size` (movzx/mov32), so rd's
                    // bits above the access width are 0.
                    Self::emit_w_load(enc, rd, SCRATCH0, *size);
                    // WIDTH-CORRECT COMPARE. The compare MUST be at the access
                    // width: `re` (expected) is a guest register that may carry
                    // STALE upper bits (the DBT doesn't always zero-extend W-writes
                    // — same root as the LSRV W-form bug). A 64-bit compare of a
                    // 32-bit CAS then spuriously mismatches whenever those upper
                    // bits differ → the CAS does the wrong thing → e.g. the
                    // qspinlock / SLUB `atomic_t` (32-bit) state machine corrupts
                    // and PID 1 deadlocks in ___slab_alloc. For sub-64-bit sizes,
                    // mask `re` into SCRATCH1 (zero-extend to `size`) so only the
                    // relevant bits are compared; the following `mov SCRATCH1,new`
                    // (a plain MOV) preserves the resulting flags into the cmov.
                    match *size {
                        8 => enc.emit_cmp_rr64(rd, re),
                        4 => enc.emit_cmp_rr32(rd, re),
                        2 => {
                            enc.emit_movzx_r64_r16(SCRATCH1, re);
                            enc.emit_cmp_rr32(rd, SCRATCH1);
                        }
                        _ => {
                            enc.emit_movzx_r64_r8(SCRATCH1, re);
                            enc.emit_cmp_rr32(rd, SCRATCH1);
                        }
                    }
                    // Branch-free single-core CAS: candidate = new; if cur !=
                    // expected, candidate = cur (store the value back unchanged —
                    // harmless with one vCPU). Then store the candidate.
                    enc.emit_mov_rr64(SCRATCH1, rn);
                    enc.emit_cmov_rr64(cc::NZ, SCRATCH1, rd);
                    Self::emit_w_store(enc, SCRATCH0, SCRATCH1, *size);
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }
            AtomicCasPair { dst_a, dst_b, addr, expected_a, expected_b, new_a, new_b, order, size } => {
                let _ = order; // single-vCPU: no real atomicity needed
                // SPILL-SAFE ADDRESS via addr_in(SCRATCH0). The four value regs +
                // two dst regs (all reused as in-place scratch by the cmpxchg_double
                // sequence) exhaust the budget, so a spilled value/dst still fails
                // loud — the SLUB cmpxchg_double keeps them all live in-register.
                if !Self::requires_gpr(alloc, *dst_a) || !Self::requires_gpr(alloc, *dst_b)
                    || !Self::requires_gpr(alloc, *expected_a) || !Self::requires_gpr(alloc, *expected_b)
                    || !Self::requires_gpr(alloc, *new_a) || !Self::requires_gpr(alloc, *new_b)
                {
                    enc.emit_ud2_spill();
                } else if let Some(ra) = Self::addr_in(alloc, enc, *addr, SCRATCH0) {
                    // CASP {dst_a,dst_b} ← [addr]; if equals {exp_a,exp_b} store
                    // {new_a,new_b}. Single-vCPU non-atomic load/compare/store —
                    // this is the SLUB cmpxchg_double primitive, so a half-store or
                    // spurious mismatch double-allocates a slab object.
                    // xlate the WHOLE pair (2×elem) for write → SCRATCH0 = host PA.
                    Self::emit_mmu_xlate_call(enc, ra, true, (*size as i32) * 2);
                    let rda = Self::gpr(alloc, *dst_a);
                    let rdb = Self::gpr(alloc, *dst_b);
                    let rea = Self::gpr(alloc, *expected_a);
                    let reb = Self::gpr(alloc, *expected_b);
                    let rna = Self::gpr(alloc, *new_a);
                    let rnb = Self::gpr(alloc, *new_b);
                    // HARDENING (in-place-source-mutation hunt, 2026-07-01). The
                    // prior sequence reused `rea`/`reb` (the expected_a/expected_b
                    // ALLOCATED HOME registers) as in-place scratch —
                    //   xor reb, rdb ; mov rea, new_a ; mov reb, new_b …
                    // — on the "expected is dead after the CASP" assumption. That
                    // holds on the current live path (each expected_a/b is a
                    // single-use ReadGpr with last_use == this op), but it is the
                    // exact class of latent corruptor that cost boots via the
                    // WriteGpr{sf:false} `mov rs32,rs32` truncation: the instant a
                    // future lift/opt change makes an expected value multi-use (or
                    // a copy-prop remap aliases it), mutating its home register
                    // silently clobbers the later consumer. Rewrite to a
                    // NON-MUTATING branch form that only READS the six operand home
                    // regs (rea/reb/rna/rnb/rda/rdb) and writes SCRATCH1 (reserved
                    // scratch) + the destination home regs rda/rdb (which we OWN —
                    // they carry the loaded old pair, the CASP result). No source
                    // home register is ever written. Needs no extra temp: compare
                    // the two halves sequentially, branch to the store choice.
                    // Load the old pair into the result regs (returned always) —
                    // rda/rdb must still hold these at the end of the op (the
                    // following WriteGpr commits them to the guest x-regs).
                    let (jne1, jne2, jmp_done);
                    if *size == 8 {
                        enc.emit_mov_r64_mem(rda, SCRATCH0, 0);
                        enc.emit_mov_r64_mem(rdb, SCRATCH0, 8);
                        // Compare old_a vs exp_a and old_b vs exp_b. `cmp` is
                        // non-destructive; `SCRATCH1 = exp_x` is a scratch copy so
                        // the expected home regs stay pristine. Any mismatch jumps
                        // to the "store old back" path (single-vCPU: unchanged).
                        enc.emit_mov_rr64(SCRATCH1, rea);
                        enc.emit_cmp_rr64(SCRATCH1, rda);
                        jne1 = enc.emit_jcc_rel32(cc::NZ);
                        enc.emit_mov_rr64(SCRATCH1, reb);
                        enc.emit_cmp_rr64(SCRATCH1, rdb);
                        jne2 = enc.emit_jcc_rel32(cc::NZ);
                        // match: store {new_a,new_b} (read-only on rna/rnb).
                        enc.emit_mov_mem_r64(SCRATCH0, 0, rna);
                        enc.emit_mov_mem_r64(SCRATCH0, 8, rnb);
                        jmp_done = enc.emit_jmp_rel32();
                        // mismatch: store the old pair back unchanged (rda/rdb).
                        let mis = enc.pos();
                        enc.patch_rel32(jne1, mis);
                        enc.patch_rel32(jne2, mis);
                        enc.emit_mov_mem_r64(SCRATCH0, 0, rda);
                        enc.emit_mov_mem_r64(SCRATCH0, 8, rdb);
                        let done = enc.pos();
                        enc.patch_rel32(jmp_done, done);
                    } else {
                        // 32-bit pair (CASPW). 32-bit loads zero-extend rda/rdb;
                        // zero-extend each expected half into SCRATCH1 (scratch) so
                        // stale upper bits can't cause a spurious mismatch, then
                        // compare at 32 bits. Same non-mutating branch shape.
                        enc.emit_mov_r32_mem(rda, SCRATCH0, 0);
                        enc.emit_mov_r32_mem(rdb, SCRATCH0, 4);
                        enc.emit_mov_rr32(SCRATCH1, rea); // SCRATCH1 = zext32(exp_a)
                        enc.emit_cmp_rr32(SCRATCH1, rda);
                        jne1 = enc.emit_jcc_rel32(cc::NZ);
                        enc.emit_mov_rr32(SCRATCH1, reb); // SCRATCH1 = zext32(exp_b)
                        enc.emit_cmp_rr32(SCRATCH1, rdb);
                        jne2 = enc.emit_jcc_rel32(cc::NZ);
                        enc.emit_mov_mem32_r64(SCRATCH0, 0, rna);
                        enc.emit_mov_mem32_r64(SCRATCH0, 4, rnb);
                        jmp_done = enc.emit_jmp_rel32();
                        let mis = enc.pos();
                        enc.patch_rel32(jne1, mis);
                        enc.patch_rel32(jne2, mis);
                        enc.emit_mov_mem32_r64(SCRATCH0, 0, rda);
                        enc.emit_mov_mem32_r64(SCRATCH0, 4, rdb);
                        let done = enc.pos();
                        enc.patch_rel32(jmp_done, done);
                    }
                } else {
                    enc.emit_ud2_spill(); // unassigned (None) address — no slot to load
                }
            }

            // ── FP / SIMD ─────────────────────────────────────────────────
            FAdd { .. } | FSub { .. } | FMul { .. } | FDiv { .. }
            | FNeg { .. } | FAbs { .. } | FSqrt { .. } | FCvt { .. }
            | FToInt { .. } | IntToF { .. } | FCmp { .. }
            | VAdd { .. } | VSub { .. } | VMul { .. }
            | VAnd { .. } | VOr { .. } | VXor { .. }
            | VShl { .. } | VLShr { .. } | VAShr { .. }
            | VNeg { .. } | VAbs { .. } | VMin { .. } | VMax { .. }
            | VCmp { .. } | VDup { .. } | VInsLane { .. }
            | VExtractLane { .. } | VPermute { .. } | VTbl { .. } | VTbx { .. }
            | VModImm { .. } | VConvert { .. }
            | VFAdd { .. } | VFSub { .. } | VFMul { .. } | VFDiv { .. } | VFMa { .. } => {
                // SSA-register SIMD ops: never emitted by the lifter (live SIMD
                // is lower_simd_ctx's Vec* ops). Fail loud rather than silently
                // dropping the operation.
                enc.emit_ud2();
            }

            // ── Crypto / system ───────────────────────────────────────────
            // SHA-256 family: a Win64 CALL to the runtime helper that applies the
            // exact ARM ARM pseudocode to the guest q-regs in ctx memory.
            CryptoSha256 { kind, d, n, m } => {
                let packed = (*kind as u32)
                    | ((*d as u32) << 8)
                    | ((*n as u32) << 16)
                    | ((*m as u32) << 24);
                Self::emit_crypto_sha256_call(enc, packed);
            }
            // CRC32B/H/W/X and CRC32CB/H/W/X. The lift produces this for ALL eight
            // (ID_AA64ISAR0 advertises CRC32, so ext4/f2fs metadata, zlib, and dex
            // checksums emit them). `a` = accumulator (Wn, running 32-bit CRC),
            // `b` = data operand. `size` is the ARM `sz` ENCODING (0=B 1=H 2=W 3=X),
            // NOT a byte count — the data width in bytes is `1 << size`.
            // castagnoli=true → x86 SSE4.2 `crc32` (NATIVE Castagnoli poly
            // 0x1EDC6F41). castagnoli=false → ISO-3309 poly 0x04C11DB7, which x86
            // `crc32` can't do, so a Win64 CALL to the software table-driven helper.
            // (Was a silent NOP: every CRC returned its stale destination — corrupt
            // checksums.)
            Crc32 { dst, a, b, size, castagnoli } => {
                if *castagnoli {
                    // crc32 <work>, <data>: the accumulator must be IN the
                    // destination register and the data MUST be a DIFFERENT
                    // register (else `crc32 rd, rd` after `mov rd, acc` would crc
                    // the accumulator with itself). Force the data into SCRATCH1
                    // (RCX, reserved — never a dest), the accumulator into SCRATCH0
                    // (RAX), then move the accumulator into rd. rd is never RAX/RCX,
                    // so rd, SCRATCH1, and the accumulator copy never alias.
                    let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                    if ra != SCRATCH0 { enc.emit_mov_rr64(SCRATCH0, ra); }
                    let rb = Self::src_in(alloc, enc, *b, SCRATCH1);
                    if rb != SCRATCH1 { enc.emit_mov_rr64(SCRATCH1, rb); }
                    let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                    if rd != SCRATCH0 { enc.emit_mov_rr64(rd, SCRATCH0); } // rd = acc
                    // Size-correct CRC32 keyed on the sz ENCODING (0=B/1=H/2=W/3=X).
                    // The B/H/W forms use the 32-bit-destination encodings (no
                    // REX.W), which read ONLY the relevant low bytes of the data
                    // register and zero-extend the 32-bit CRC into r64. The X form
                    // is the genuine r64,r/m64.
                    match *size {
                        0 => enc.emit_crc32_r32_r8(rd, SCRATCH1),
                        1 => enc.emit_crc32_r32_r16(rd, SCRATCH1),
                        2 => enc.emit_crc32_r32_r32(rd, SCRATCH1),
                        3 => enc.emit_crc32_r64_r64(rd, SCRATCH1),
                        _ => enc.emit_ud2(), // impossible (decoder constrains sz to 0..3)
                    }
                    Self::store_dest(alloc, enc, *dst, rd, sp);
                } else {
                    // ISO poly: Win64 CALL aether_crc32_iso(crc=RCX, data=RDX,
                    // size=R8B) -> EAX. Materialize args into the arg registers
                    // BEFORE the save set is pushed (RCX/RDX are volatile and not
                    // preserved). Both args read through reserved scratch so a
                    // spilled value is safely loaded first.
                    const RCX: u8 = 1;
                    const RDX: u8 = 2;
                    let ra = Self::src_in(alloc, enc, *a, SCRATCH0);
                    if ra != RCX { enc.emit_mov_rr64(RCX, ra); }
                    // Load data; src_in may reuse SCRATCH0 (RAX) if `b` is spilled —
                    // RAX is free now (a is already copied to RCX). Then move to RDX.
                    let rb = Self::src_in(alloc, enc, *b, SCRATCH0);
                    if rb != RDX { enc.emit_mov_rr64(RDX, rb); }
                    // `size` is the sz encoding (0=B/1=H/2=W/3=X); the helper takes
                    // a BYTE count, so pass 1 << size (1/2/4/8).
                    Self::emit_crc32_iso_call(enc, 1u8 << *size);
                    // Result in EAX. Store to dst (work reg = RAX path: copy then
                    // store, honouring spill).
                    let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                    if rd != 0 { enc.emit_mov_rr64(rd, 0); } // rd = RAX (result)
                    Self::store_dest(alloc, enc, *dst, rd, sp);
                }
            }
            // Legacy crypto IR variants (AesE/AesD/AesMc/AesImc/Sha1*/Sha256h*/
            // Sha256su*/Pmull). The LIVE lift emits CryptoAesR / CryptoSha256 /
            // VecPmull instead (which lower elsewhere), so these arms are DEAD —
            // confirmed: nothing in src/lift constructs them. Fail LOUD (UD2) so a
            // future regression that routes a cipher here is caught immediately
            // instead of silently NOP-ing the encryption (was emit_nop()).
            AesE { .. } | AesD { .. } | AesMc { .. } | AesImc { .. }
            | Sha1c { .. } | Sha1m { .. } | Sha1p { .. }
            | Sha256h { .. } | Sha256h2 { .. } | Sha256su0 { .. } | Sha256su1 { .. }
            | Pmull { .. } => {
                enc.emit_ud2();
            }

            // M4b-4: HVC/SMC are the PSCI conduit — serviced synchronously by a
            // runtime call (aether_hvc_dispatch reads x0..x3 from the ctx, runs
            // PSCI, writes x0). The lift emits WritePc(pc+4) after, so the block
            // resumes at the next instruction. No UD2 -> the block passes the
            // entry safety gate and actually executes.
            Hvc { .. } | Smc { .. } => {
                Self::emit_hvc_call(enc);
            }
            // SVC — a guest syscall (EL0→EL1, or EL1→EL1). A runtime CALL into
            // `aether_svc_enter(ctx, imm16)` takes the synchronous exception:
            // it builds the SVC ESR (EC=0x15), saves the WritePc-staged return
            // address as ELR_EL1, performs the SP_EL0/SP_EL1 bank swap, and
            // vectors to VBAR + the source-EL sync offset. SVC is a block
            // terminator, so the call is the last side effect before the RET
            // and clobbering the volatile set is harmless. No longer UD2.
            Svc { imm16 } => {
                Self::emit_svc_call(enc, *imm16);
            }
            // ERET — exception return. A runtime CALL into `aether_eret_enter`
            // (see lift `Eret` → IrOp::EretRt) applies the full architectural
            // return (PC/NZCV/DAIF/EL/SPSel + SP bank). Also a terminator.
            EretRt => {
                Self::emit_eret_call(enc);
            }
            // BRK/HLT (debug/halt) still trap. BRK is recognised pre-translation
            // by the dispatch loop (it injects an EL1 debug exception); HLT
            // halts. Fail loud (the block is rejected at the safety gate).
            Brk { .. } | Hlt { .. } => {
                enc.emit_ud2(); // real exception → hypervisor handles via EPT/NPT fault.
            }

            // ── Architectural hints (NOP/YIELD/WFE/WFI/SEV/SEVL/PAC*/BTI*/CSDB)
            //    and cache/system *maintenance* (DC/IC/AT) ──────────────────────
            // The lifter assigns these imm < 200 (see lift/mod.rs). On a single
            // host core with x86's coherent, strongly-ordered memory model they
            // advance pc with NO state change: BTI/PAC are pointer/branch-target
            // hints irrelevant to a translator (PACIASP+AUTIASP are a sign/auth
            // pair that, both being no-ops, leave LR unchanged); DC/IC/AT cache
            // ops need no action on a coherent core. A real GKI kernel emits BTI
            // at every function entry and DC/IC during MMU bring-up, so these
            // MUST NOT trap. imm >= 200 is the "unimplemented opcode" catch-all
            // (SIMD/FP/system skeleton) and stays fail-loud (UD2) so the boot
            // loop surfaces the next genuine instruction gap.
            Hint { imm } if *imm >= 200 => {
                enc.emit_ud2();
            }
            Hint { .. } => {
                enc.emit_nop(); // architectural no-op; pc advances to next insn.
            }

            // ── Memory barriers (M4b-2d) ──────────────────────────────────────
            // The ARM→x86 JIT runs on a single host core in a strongly-ordered
            // (x86-TSO) memory model, so most ARM barriers need no fence; but
            // x86-TSO still allows store→load reordering, so a full DMB/DSB maps
            // to MFENCE (the only x86 fence that serialises store-then-load).
            // ISB/SB are context-synchronising; x86 has no architectural ISB, so
            // we use the CPUID serialising sequence (matches the AT-10 X86Cpuid
            // lowering). All four are in-block, no-control-flow ops — the kernel
            // issues them constantly during MMU bring-up, so they MUST NOT trap.
            Dmb { .. } | Dsb { .. } => enc.emit_mfence(),
            Isb | Sb => enc.emit_isb_sequence(),

            // ── TLB invalidate (M4b-2d) ───────────────────────────────────────
            // A guest TLBI must (1) drop the matching software-MMU TLB entries so
            // the next translated access re-walks the (possibly just-rewritten)
            // page tables, and (2) invalidate the JIT block cache, because a
            // page-table edit can change which bytes a given guest VA maps to —
            // a previously-translated block keyed on that VA is now potentially
            // stale. Both effects are Win64 CALLs to FFI helpers.
            //
            // Broad form (VMALLE1/ALLE1/ASIDE1, `va == None`): flush the whole
            // software TLB + the whole block cache.
            // Single-VA form (VAE1/VALE1/…, `va == Some`): flush just that page
            // from the software TLB (finer-grained, exact), but conservatively
            // flush the ENTIRE block cache — we don't track which JIT blocks were
            // translated from which guest VA page, so a per-VA block invalidate
            // isn't available; full invalidate is correct (never stale), only
            // costing a cold re-translate of unrelated blocks. This is the
            // documented "full invalidate as a conservative first cut" choice.
            //
            // SPILL-SAFE: the single-VA form marshals the page VA into RCX. A
            // spilled VA materializes from its slot into SCRATCH0 (emit_mmu_tlbi_va_call
            // moves it to RCX before the call clobbers RAX); only an unassigned
            // (None-assigned IR value) VA fails loud — distinct from `va == None`,
            // which is the broad (whole-TLB) form. `addr_in` returns None for the
            // unassigned case.
            TlbInval { va } => {
                match va {
                    Some(v) => {
                        if let Some(ra) = Self::addr_in(alloc, enc, *v, SCRATCH0) {
                            Self::emit_mmu_tlbi_va_call(enc, ra);
                            Self::emit_dbt_invalidate_call(enc);
                        } else {
                            // Unassigned VA value → no slot to load. Fail loud.
                            enc.emit_ud2();
                        }
                    }
                    None => {
                        Self::emit_mmu_flush_call(enc);
                        Self::emit_dbt_invalidate_call(enc);
                    }
                }
            }
            AtS1E1 { va, is_write, at_el0 } => {
                // Phase-E: `AT S1E1*` runtime CALL. Handles spilled VA by
                // loading it into SCRATCH0 first (Win64 RDX gets it after
                // the save set is pushed).
                let ra = Self::src_in(alloc, enc, *va, SCRATCH0);
                Self::emit_mmu_at_call(enc, ra, *is_write, *at_el0);
            }

            // ── System-register access (M4a) ──────────────────────────────────
            // MRS Xd, <sysreg>  -> load  [R15 + sysreg_disp(reg)] into Xd
            // MSR <sysreg>, Xn  -> store Xn into [R15 + sysreg_disp(reg)]
            // The sysreg array lives at R15+SYSREG_BASE (0x328); RO/ID regs are
            // hypervisor-seeded and MSR to them sinks to slot 63; NzcvEl0 aliases
            // the GPR-file nzcv at 0x108. Side effects (e.g. SCTLR.M enabling the
            // MMU) are NOT yet honored — store/return only (deferred to M4b).
            Mrs { dst, reg } => {
                if let Some(reg_id) = Self::sysreg_runtime_id(*reg) {
                    // M4b-4 live sysreg (timer / GIC): runtime CALL. The call
                    // returns the value in RAX; a SPILLED dst shuttles it through
                    // SCRATCH1 (RCX) and stores to its slot (spill-safe). Only an
                    // unassigned (None) dst fails loud.
                    if Self::requires_gpr(alloc, *dst) || Self::is_spilled(alloc, *dst) {
                        Self::emit_sysreg_read_call(enc, reg_id); // RAX = value
                        // dst is never RAX (reserved). Move the result out of RAX
                        // into the dst's reg (or SCRATCH1 if spilled), then store.
                        let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH1);
                        enc.emit_mov_rr64(rd, SCRATCH0);
                        Self::store_dest(alloc, enc, *dst, rd, sp);
                    } else {
                        enc.emit_ud2_spill(); // unassigned (None) dst
                    }
                } else {
                    let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                    let disp = Self::sysreg_read_disp(*reg);
                    enc.emit_mov_r64_mem(rd, CONTEXT_REG, disp);
                    Self::store_dest(alloc, enc, *dst, rd, sp);
                }
            }
            Msr { reg, val } => {
                if let Some(reg_id) = Self::sysreg_runtime_id(*reg) {
                    // M4b-4 live sysreg: runtime CALL. A SPILLED value materializes
                    // into SCRATCH0 (emit_sysreg_write_call moves it to RDX after
                    // pushing the save set, before clobbering RAX); only an
                    // unassigned (None) value fails loud.
                    if Self::requires_gpr(alloc, *val) || Self::is_spilled(alloc, *val) {
                        let rv = Self::src_in(alloc, enc, *val, SCRATCH0);
                        Self::emit_sysreg_write_call(enc, reg_id, rv);
                    } else {
                        enc.emit_ud2_spill(); // unassigned (None) value
                    }
                    // Timer/GIC writes are not translation-control: no TLB flush.
                    return;
                }
                let rs = Self::src_in(alloc, enc, *val, SCRATCH0);
                let disp = Self::sysreg_write_disp(*reg);
                enc.emit_mov_mem_r64(CONTEXT_REG, disp, rs);
                // M4b-2dpre: a write to a translation-control register makes the
                // software MMU TLB stale (it cached VA→PA under the old tables /
                // control bits). Flush it AFTER the store so the next translated
                // access re-walks. `rs` is dead here, so the flush call clobbering
                // the volatile set (incl. RAX/RCX) is harmless. SCTLR.M toggles
                // are read live by the walker → no flush needed for SCTLR.
                //
                // M4b-2d: ALSO invalidate the JIT block cache. A TTBR0/1 switch
                // (and a TCR/MAIR change that alters the effective mapping) can
                // change which bytes a given guest VA maps to, so a previously-
                // translated block keyed on that VA may now be stale — drop it so
                // the next dispatch re-walks the current tables. Conservative (a
                // TCR/MAIR write rarely remaps text) but always correct, and these
                // writes are rare (a handful during MMU bring-up), so the cost of
                // a cold re-translate is negligible. The invalidate clears only
                // the lookup table, never the in-flight code arena (see
                // DbtRuntime::invalidate_all), so it is safe mid-block.
                if Self::msr_mmu_side_effect(*reg) == MsrMmuEffect::FlushTlb {
                    Self::emit_mmu_flush_call(enc);
                    Self::emit_dbt_invalidate_call(enc);
                }
            }

            // ── Guest register-file access (R15-relative memory) ──────────────
            // Baseline template-JIT model: instead of requiring the SSA
            // promotion pass to eliminate these, lower them directly to
            // loads/stores against the GuestRegisterFile based at CONTEXT_REG
            // (R15). The register allocator already maps each SSA value to an
            // x86 GPR; ReadGpr loads the guest reg into that x86 GPR, WriteGpr
            // stores it back. This makes every block executable. Offsets match
            // runtime/context.rs GuestRegisterFile (#[repr(C)]):
            //   gpr[31] @ 0x000, sp @ 0x0F8, pc @ 0x100, nzcv @ 0x108.
            // reg==31 is XZR/WZR on the GPR path (reads 0, writes discarded);
            // the SP-context forms use the dedicated ReadSp/WriteSp ops.
            ReadGpr { dst, reg, sf } => {
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if *reg == 31 {
                    // XZR reads as zero (zero-extended via 32-bit xor).
                    enc.emit_xor_zero_r32(rd);
                } else if !*sf {
                    // W-read: a 32-bit load zero-extends bits [63:32] per ARM
                    // W-register semantics. ReadGpr previously ignored `sf` and
                    // always did a full 64-bit load, so a `read_reg(_,false)`
                    // returned the stale upper 32 of the X slot — the root enabler
                    // of every W-form upper-bit leak (shifted-register operands,
                    // EXTR, CLS/CLZ, W-form divide). Honor the width at the source.
                    enc.emit_mov_r32_mem(rd, CONTEXT_REG, (*reg as i32) * 8);
                } else {
                    enc.emit_mov_r64_mem(rd, CONTEXT_REG, (*reg as i32) * 8);
                }
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            WriteGpr { reg, src, sf } => {
                if *reg != 31 {
                    let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                    if !*sf {
                        // W-register write: zero-extend low 32 bits (mov r32,r32
                        // clears the upper 32 of the 64-bit reg) before storing,
                        // matching ARM 32-bit-write-zeroes-upper semantics.
                        //
                        // HARDENING (control-flow corruptor hunt): do the zero-
                        // extend into SCRATCH0 instead of MUTATING `rs` in place.
                        // `rs` is the SSA value's ALLOCATED register; if that value
                        // is still live later in the block (its reg is shared), an
                        // in-place `mov rs32,rs32` would truncate the live value to
                        // 32 bits — a silent miscompile that can clobber a return
                        // address / frame pointer being written by a W-form store.
                        // Copying to a scratch first is non-mutating and is a no-op
                        // when `rs` already IS SCRATCH0 (the spilled-source case).
                        let z = SCRATCH0;
                        enc.emit_mov_rr32(z, rs); // z = zero_ext(rs[31:0]); rs untouched
                        enc.emit_mov_mem_r64(CONTEXT_REG, (*reg as i32) * 8, z);
                    } else {
                        enc.emit_mov_mem_r64(CONTEXT_REG, (*reg as i32) * 8, rs);
                    }
                }
                // reg==31 → WZR/XZR: write discarded.
            }
            ReadSp { dst, sf: _ } => {
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                enc.emit_mov_r64_mem(rd, CONTEXT_REG, SP_DISP);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            WriteSp { src, sf } => {
                let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                if !*sf {
                    // Same non-mutating hardening as WriteGpr{sf:false}: zero-extend
                    // into SCRATCH0 rather than truncating the live source register
                    // in place. A WSP write that truncated a still-live SSA value
                    // would corrupt every later use of it in the block.
                    let z = SCRATCH0;
                    enc.emit_mov_rr32(z, rs); // z = zero_ext(rs[31:0]); rs untouched
                    enc.emit_mov_mem_r64(CONTEXT_REG, SP_DISP, z);
                } else {
                    enc.emit_mov_mem_r64(CONTEXT_REG, SP_DISP, rs);
                }
            }
            ReadPc { dst } => {
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                enc.emit_mov_r64_mem(rd, CONTEXT_REG, PC_DISP);
                Self::store_dest(alloc, enc, *dst, rd, sp);
            }
            WritePc { src } => {
                let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                enc.emit_mov_mem_r64(CONTEXT_REG, PC_DISP, rs);
            }

            // ── NZCV flag access (M4a) ────────────────────────────────────────
            // Flag state lives ONLY in memory at [R15+0x108] (packed ARM word:
            // N@31 Z@30 C@29 V@28). Flag-PRODUCING ops (AddS/SubS/AndS/Cmp/Cmn/
            // Tst) write it directly via build_nzcv; flag-CONSUMING ops (Csel/
            // CondBranch) read it directly and evaluate the ARM condition by
            // bit-test (emit_arm_cond_to_bool). The IrFlagsId carried by these
            // ops is therefore vestigial, so ReadFlags/WriteFlags are no-ops:
            // the producer already stored 0x108 and the consumer reads it.
            ReadFlags { .. } | WriteFlags { .. } => {}

            // ── FPR register-file access (M4b-6 ctx-template model) ───────────
            // The guest q-register file in ctx ([R15 + vec_disp(reg)]) is
            // authoritative. ReadFpr primes scratch VS0 with Vreg; WriteFpr
            // commits VS0 back to Vreg. Used by the LDR/STR Q lift path and as
            // the load/store bracket around SIMD blocks.
            ReadFpr { reg, .. } => {
                enc.emit_movdqu_load(
                    crate::regalloc::x86_regs::VFP,
                    CONTEXT_REG,
                    crate::runtime::context::vec_disp(*reg),
                );
            }
            WriteFpr { reg, .. } => {
                enc.emit_movdqu_store(
                    CONTEXT_REG,
                    crate::runtime::context::vec_disp(*reg),
                    crate::regalloc::x86_regs::VFP,
                );
            }

            // NEON MOVI/MVNI — store the resolved 128-bit immediate to the ctx
            // q-slot for V`d`. No SSA operands, so SCRATCH0 (RAX) is free to use
            // as the imm64 staging register for the two 8-byte stores.
            VecMoviImm { d, lo, hi } => {
                let disp = crate::runtime::context::vec_disp(*d);
                enc.emit_mov_r64_imm64(SCRATCH0, *lo as i64);
                enc.emit_mov_mem_r64(CONTEXT_REG, disp, SCRATCH0);
                enc.emit_mov_r64_imm64(SCRATCH0, *hi as i64);
                enc.emit_mov_mem_r64(CONTEXT_REG, disp + 8, SCRATCH0);
            }
            // ── NEON copy family → direct ctx-memory ops on the q-reg file ──────
            // The guest q-registers live in ctx at vec_disp(reg); UMOV/SMOV read a
            // lane, INS writes a lane, DUP(general) broadcasts a GPR to all lanes —
            // all as plain memory loads/stores, no XMM. `size` is element BYTES.
            VecExtractLane { dst, n, lane, size, signed } => {
                let (rd, spilled) = Self::dest_work(alloc, *dst, SCRATCH0);
                let disp = crate::runtime::context::vec_disp(*n)
                    + (*lane as i32) * (*size as i32);
                match (*size, *signed) {
                    (1, false) => enc.emit_movzx_r64_mem8(rd, CONTEXT_REG, disp),
                    (1, true) => enc.emit_movsx_r64_mem8(rd, CONTEXT_REG, disp),
                    (2, false) => enc.emit_movzx_r64_mem16(rd, CONTEXT_REG, disp),
                    (2, true) => enc.emit_movsx_r64_mem16(rd, CONTEXT_REG, disp),
                    (4, false) => enc.emit_mov_r32_mem(rd, CONTEXT_REG, disp), // zero-extends
                    (4, true) => enc.emit_movsxd_r64_mem32(rd, CONTEXT_REG, disp),
                    _ => enc.emit_mov_r64_mem(rd, CONTEXT_REG, disp), // 8 = dword
                }
                Self::store_dest(alloc, enc, *dst, rd, spilled);
            }
            VecInsGpr { d, lane, src, size } => {
                let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                let disp = crate::runtime::context::vec_disp(*d)
                    + (*lane as i32) * (*size as i32);
                match *size {
                    1 => enc.emit_mov_mem8_r64(CONTEXT_REG, disp, rs),
                    2 => enc.emit_mov_mem16_r64(CONTEXT_REG, disp, rs),
                    4 => enc.emit_mov_mem32_r64(CONTEXT_REG, disp, rs),
                    _ => enc.emit_mov_mem_r64(CONTEXT_REG, disp, rs),
                }
            }
            VecDupGpr { d, src, size, q } => {
                // Store gpr(src)'s low `size` bytes to every lane (unrolled).
                let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                let disp = crate::runtime::context::vec_disp(*d);
                let total: i32 = if *q { 16 } else { 8 };
                let mut off = 0i32;
                while off < total {
                    match *size {
                        1 => enc.emit_mov_mem8_r64(CONTEXT_REG, disp + off, rs),
                        2 => enc.emit_mov_mem16_r64(CONTEXT_REG, disp + off, rs),
                        4 => enc.emit_mov_mem32_r64(CONTEXT_REG, disp + off, rs),
                        _ => enc.emit_mov_mem_r64(CONTEXT_REG, disp + off, rs),
                    }
                    off += *size as i32;
                }
                if !*q {
                    enc.emit_xor_zero_r32(SCRATCH1); // zero the upper 64 bits
                    enc.emit_mov_mem_r64(CONTEXT_REG, disp + 8, SCRATCH1);
                }
            }
            // ── NEON CNT / UADDLV → scalar ctx-memory SWAR (no XMM) ─────────────
            // bionic's power-of-2 check: `cnt v0.8b, v0.8b; uaddlv h0, v0.8b`.
            VecCnt { d, n, q } => {
                // Per-byte population count via the classic SWAR on each 64-bit
                // half: x-=(x>>1)&0x55; x=(x&0x33)+((x>>2)&0x33); x=(x+(x>>4))&0x0f.
                let dn = crate::runtime::context::vec_disp(*n);
                let dd = crate::runtime::context::vec_disp(*d);
                enc.emit_push_r64(2); // RDX is allocatable — save for the constants
                let halves: i32 = if *q { 2 } else { 1 };
                let mut h = 0i32;
                while h < halves {
                    let off = h * 8;
                    enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, dn + off);
                    // x -= (x >> 1) & 0x5555_5555_5555_5555
                    enc.emit_mov_rr64(SCRATCH1, SCRATCH0);
                    enc.emit_shr_r64_imm8(SCRATCH1, 1);
                    enc.emit_mov_r64_imm64(2, 0x5555_5555_5555_5555u64 as i64);
                    enc.emit_and_rr64(SCRATCH1, 2);
                    enc.emit_sub_rr64(SCRATCH0, SCRATCH1);
                    // x = (x & 0x3333..) + ((x >> 2) & 0x3333..)
                    enc.emit_mov_r64_imm64(2, 0x3333_3333_3333_3333u64 as i64);
                    enc.emit_mov_rr64(SCRATCH1, SCRATCH0);
                    enc.emit_and_rr64(SCRATCH0, 2);
                    enc.emit_shr_r64_imm8(SCRATCH1, 2);
                    enc.emit_and_rr64(SCRATCH1, 2);
                    enc.emit_add_rr64(SCRATCH0, SCRATCH1);
                    // x = (x + (x >> 4)) & 0x0F0F..
                    enc.emit_mov_rr64(SCRATCH1, SCRATCH0);
                    enc.emit_shr_r64_imm8(SCRATCH1, 4);
                    enc.emit_add_rr64(SCRATCH0, SCRATCH1);
                    enc.emit_mov_r64_imm64(2, 0x0F0F_0F0F_0F0F_0F0Fu64 as i64);
                    enc.emit_and_rr64(SCRATCH0, 2);
                    enc.emit_mov_mem_r64(CONTEXT_REG, dd + off, SCRATCH0);
                    h += 1;
                }
                if !*q {
                    enc.emit_xor_zero_r32(SCRATCH1);
                    enc.emit_mov_mem_r64(CONTEXT_REG, dd + 8, SCRATCH1);
                }
                enc.emit_pop_r64(2);
            }
            VecAddvLong { d, n, esize, q, signed } => {
                // Add-long across lanes: accumulate every lane (sign/zero-extended)
                // into RAX, zero Vd, store the 2×-wide scalar to lane 0.
                let dn = crate::runtime::context::vec_disp(*n);
                let dd = crate::runtime::context::vec_disp(*d);
                let total: i32 = if *q { 16 } else { 8 };
                let es = *esize as i32;
                enc.emit_xor_zero_r32(SCRATCH0); // accumulator = 0 (clears all of RAX)
                let mut i = 0i32;
                while i < total {
                    let disp = dn + i;
                    match (*esize, *signed) {
                        (1, false) => enc.emit_movzx_r64_mem8(SCRATCH1, CONTEXT_REG, disp),
                        (1, true) => enc.emit_movsx_r64_mem8(SCRATCH1, CONTEXT_REG, disp),
                        (2, false) => enc.emit_movzx_r64_mem16(SCRATCH1, CONTEXT_REG, disp),
                        (2, true) => enc.emit_movsx_r64_mem16(SCRATCH1, CONTEXT_REG, disp),
                        (4, true) => enc.emit_movsxd_r64_mem32(SCRATCH1, CONTEXT_REG, disp),
                        _ => enc.emit_mov_r32_mem(SCRATCH1, CONTEXT_REG, disp), // 4, unsigned
                    }
                    enc.emit_add_rr64(SCRATCH0, SCRATCH1);
                    i += es;
                }
                enc.emit_xor_zero_r32(SCRATCH1);
                enc.emit_mov_mem_r64(CONTEXT_REG, dd, SCRATCH1);
                enc.emit_mov_mem_r64(CONTEXT_REG, dd + 8, SCRATCH1);
                match es * 2 {
                    2 => enc.emit_mov_mem16_r64(CONTEXT_REG, dd, SCRATCH0),
                    4 => enc.emit_mov_mem32_r64(CONTEXT_REG, dd, SCRATCH0),
                    _ => enc.emit_mov_mem_r64(CONTEXT_REG, dd, SCRATCH0), // 8
                }
            }
            VecReduceAdd { d, n, esize, q } => {
                // ADDV — sum all lanes (same width) into RAX, store the low `esize`
                // bytes to V[d] lane 0 (rest zeroed; ADDV result is a scalar).
                let dn = crate::runtime::context::vec_disp(*n);
                let dd = crate::runtime::context::vec_disp(*d);
                let total: i32 = if *q { 16 } else { 8 };
                let es = *esize as i32;
                enc.emit_xor_zero_r32(SCRATCH0); // accumulator
                let mut i = 0i32;
                while i < total {
                    let disp = dn + i;
                    match *esize {
                        1 => enc.emit_movzx_r64_mem8(SCRATCH1, CONTEXT_REG, disp),
                        2 => enc.emit_movzx_r64_mem16(SCRATCH1, CONTEXT_REG, disp),
                        4 => enc.emit_mov_r32_mem(SCRATCH1, CONTEXT_REG, disp), // zero-extends
                        _ => enc.emit_mov_r64_mem(SCRATCH1, CONTEXT_REG, disp),
                    }
                    enc.emit_add_rr64(SCRATCH0, SCRATCH1);
                    i += es;
                }
                enc.emit_xor_zero_r32(SCRATCH1);
                enc.emit_mov_mem_r64(CONTEXT_REG, dd, SCRATCH1);
                enc.emit_mov_mem_r64(CONTEXT_REG, dd + 8, SCRATCH1);
                match *esize {
                    1 => enc.emit_mov_mem8_r64(CONTEXT_REG, dd, SCRATCH0),
                    2 => enc.emit_mov_mem16_r64(CONTEXT_REG, dd, SCRATCH0),
                    4 => enc.emit_mov_mem32_r64(CONTEXT_REG, dd, SCRATCH0),
                    _ => enc.emit_mov_mem_r64(CONTEXT_REG, dd, SCRATCH0),
                }
            }
            VecBicOrrImm { d, imm, is_bic, q } => {
                // RMW Vd: BIC = Vd & ~imm, ORR = Vd | imm (per 64-bit half). The
                // D-form (q=false) zeroes the upper 64 (FP register-write rule).
                let disp = crate::runtime::context::vec_disp(*d);
                let mask = if *is_bic { !*imm } else { *imm };
                enc.emit_mov_r64_imm64(SCRATCH1, mask as i64);
                enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, disp);
                if *is_bic {
                    enc.emit_and_rr64(SCRATCH0, SCRATCH1);
                } else {
                    enc.emit_or_rr64(SCRATCH0, SCRATCH1);
                }
                enc.emit_mov_mem_r64(CONTEXT_REG, disp, SCRATCH0);
                if *q {
                    enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, disp + 8);
                    if *is_bic {
                        enc.emit_and_rr64(SCRATCH0, SCRATCH1);
                    } else {
                        enc.emit_or_rr64(SCRATCH0, SCRATCH1);
                    }
                    enc.emit_mov_mem_r64(CONTEXT_REG, disp + 8, SCRATCH0);
                } else {
                    enc.emit_xor_zero_r32(SCRATCH0);
                    enc.emit_mov_mem_r64(CONTEXT_REG, disp + 8, SCRATCH0);
                }
            }

            // ── M4b-6 V-register-numbered SIMD/FP/crypto ops ──────────────────
            // SCVTF/UCVTF: convert the GPR `src` (resolved via alloc) to a scalar
            // FP register. cvtsi2ss/sd into a zeroed XMM keeps the scalar in the
            // low 32/64 bits with the rest cleared (FP-write semantics), then store
            // the 128-bit reg. Signed cvt; unsigned is exact for values < 2^63
            // (array sizes / counts — the realistic UCVTF inputs).
            FpCvtIntScalar { d, src, to_dbl, signed, src_64 } => {
                use crate::regalloc::x86_regs::VS1;
                let rs = Self::src_in(alloc, enc, *src, SCRATCH0);
                let disp = crate::runtime::context::vec_disp(*d);
                enc.emit_pxor(VS1, VS1);
                if *signed {
                    // SCVTF. `src_64` selects the ARM source width. The W-form
                    // (sf=0) MUST sign-interpret the low 32 bits: ReadGpr(sf=false)
                    // zero-extends the W value into the 64-bit x86 GPR, so a bare
                    // 64-bit signed convert of 0xFFFFFFFF gives +2^32 instead of the
                    // ARM-correct −1.0. Use the 32-bit signed convert (cvtsi2s{s,d}
                    // r/m32), which reads only the low 32 bits with sign.
                    match (*src_64, *to_dbl) {
                        (true, true) => enc.emit_cvtsi2sd_r64(VS1, rs),
                        (true, false) => enc.emit_cvtsi2ss_r64(VS1, rs),
                        (false, true) => enc.emit_cvtsi2sd_r32(VS1, rs),
                        (false, false) => enc.emit_cvtsi2ss_r32(VS1, rs),
                    }
                } else if !*src_64 {
                    // UCVTF Wn (unsigned 32-bit): ReadGpr(sf=false) zero-extends the
                    // W value into bits [63:32], so it fits exactly in the signed
                    // i64 range and a plain 64-bit signed convert is exact (u32 max
                    // = 4294967295 < 2^63). No high-bit fixup needed.
                    if *to_dbl {
                        enc.emit_cvtsi2sd_r64(VS1, rs);
                    } else {
                        enc.emit_cvtsi2ss_r64(VS1, rs);
                    }
                } else {
                    // UCVTF Xn — unsigned u64 → FP (B31). If the high bit is clear
                    // the signed convert is exact; otherwise halve (round-to-odd) →
                    // convert → double (the classic two-path lowering).
                    enc.emit_mov_rr64(SCRATCH0, rs); // RAX = value (mutable copy)
                    enc.emit_test_rr64(SCRATCH0, SCRATCH0);
                    let jns = enc.emit_jcc_rel32(cc::NS); // high bit clear → direct
                    enc.emit_mov_rr64(SCRATCH1, SCRATCH0);
                    enc.emit_and_r64_imm32(SCRATCH1, 1); // RCX = value & 1
                    enc.emit_shr_r64_imm8(SCRATCH0, 1); // RAX = value >> 1
                    enc.emit_or_rr64(SCRATCH0, SCRATCH1); // (value>>1)|(value&1)
                    if *to_dbl {
                        enc.emit_cvtsi2sd_r64(VS1, SCRATCH0);
                        enc.emit_addsd(VS1, VS1);
                    } else {
                        enc.emit_cvtsi2ss_r64(VS1, SCRATCH0);
                        enc.emit_addss(VS1, VS1);
                    }
                    let jmp_done = enc.emit_jmp_rel32();
                    let pos = enc.pos();
                    enc.patch_rel32(jns, pos);
                    if *to_dbl {
                        enc.emit_cvtsi2sd_r64(VS1, SCRATCH0);
                    } else {
                        enc.emit_cvtsi2ss_r64(VS1, SCRATCH0);
                    }
                    let done = enc.pos();
                    enc.patch_rel32(jmp_done, done);
                }
                enc.emit_movdqu_store(CONTEXT_REG, disp, VS1);
            }
            // FCVT{N,P,M,Z,A}{S,U}: scalar FP → int GPR. Load the FP reg, round per
            // mode (roundss/sd; Zero needs none — cvtt* truncates), then convert
            // WITH ARM SATURATION. ARM FCVTZS/ZU (and the rounding variants) clamp:
            //   signed:   +overflow/+inf → INT_MAX, −overflow/−inf → INT_MIN, NaN → 0
            //   unsigned: +overflow/+inf → UINT_MAX, ≤0/−inf → 0,           NaN → 0
            // x86 cvtt* returns the "integer indefinite" (0x8000…) on any out-of-
            // range / ±inf / NaN, so a bare cvtt* is a silent miscompile on the
            // positive-overflow / +inf / NaN direction. We add explicit FP-compare
            // clamps below. (Negative-overflow for the signed case coincides with
            // the x86 indefinite == INT_MIN, so it needs no fixup.)
            //
            // Helper constant bit-patterns (exactly representable in the FP type):
            //   f32: 2^31 = 0x4F00_0000  2^32 = 0x4F80_0000  2^63 = 0x5F00_0000  2^64 = 0x5F80_0000
            //   f64: 2^31 = 0x41E0_..    2^32 = 0x41F0_..     2^63 = 0x43E0_..    2^64 = 0x43F0_..
            FpCvtToIntScalar { dst, n, from_dbl, to_64, round, signed } => {
                use crate::regalloc::x86_regs::{VS0, VS1, VS2, VS3};
                use crate::ir::ops::RoundMode;
                let disp = crate::runtime::context::vec_disp(*n);
                let (rd, spilled) = Self::dest_work(alloc, *dst, SCRATCH0);
                let from_dbl = *from_dbl;
                let to_64 = *to_64;
                // roundss/sd imm: 0=nearest 1=-inf 2=+inf 3=trunc, |0x08 suppresses inexact.
                // NearestTiesAway (FCVTA{S,U}) has NO x86 rounding mode — mapping it to
                // nearest-EVEN (0x08) silently rounds every halfway case wrong (2.5→2 not
                // 3). Handle it with an explicit ties-away pre-round below; the other
                // modes use the direct roundss/sd immediate.
                let ties_away = matches!(round, RoundMode::NearestTiesAway);
                let pre: Option<u8> = match round {
                    RoundMode::Zero | RoundMode::Current | RoundMode::NearestTiesAway => None,
                    RoundMode::Nearest => Some(0x08),
                    RoundMode::PosInf => Some(0x0A),
                    RoundMode::NegInf => Some(0x09),
                };
                if from_dbl {
                    enc.emit_movsd_load(VS0, CONTEXT_REG, disp);
                    if let Some(m) = pre { enc.emit_roundsd(VS0, VS0, m); }
                } else {
                    enc.emit_movss_load(VS0, CONTEXT_REG, disp);
                    if let Some(m) = pre { enc.emit_roundss(VS0, VS0, m); }
                }
                if ties_away {
                    // Ties-away pre-round on the low element (VS0), single rounding:
                    // t = trunc(x); diff = x - t; if |diff| >= 0.5 add copysign(1.0, x).
                    // NaN stays NaN (diff=NaN → mask true, but adding to NaN keeps NaN,
                    // and the downstream NaN→0 saturation clamp still fires). Uses the
                    // reserved scratch VS1/VS2/VS3 (SCRATCH1 for the constants).
                    enc.emit_movdqa_rr(VS1, VS0); // VS1 = t
                    if from_dbl { enc.emit_roundsd(VS1, VS1, 0x0B) } else { enc.emit_roundss(VS1, VS1, 0x0B) }
                    enc.emit_movdqa_rr(VS2, VS0); // VS2 = |diff|
                    if from_dbl { enc.emit_subsd(VS2, VS1) } else { enc.emit_subss(VS2, VS1) }
                    enc.emit_pcmpeqd(VS3, VS3);
                    if from_dbl { enc.emit_psrlq_imm(VS3, 1) } else { enc.emit_psrld_imm(VS3, 1) }
                    enc.emit_pand(VS2, VS3);      // VS2 = |diff|
                    if from_dbl {
                        enc.emit_mov_r64_imm64(SCRATCH1, 0x3FE0_0000_0000_0000u64 as i64);
                        enc.emit_movq_xmm_r64(VS3, SCRATCH1);
                        enc.emit_cmpsd(VS2, VS3, 5); // mask: |diff| >= 0.5
                    } else {
                        enc.emit_mov_r64_imm32(SCRATCH1, 0x3F00_0000u32 as i32);
                        enc.emit_movd_xmm_r32(VS3, SCRATCH1);
                        enc.emit_cmpss(VS2, VS3, 5);
                    }
                    // VS3 = copysign(1.0, x) = (x & signmask) | 1.0.
                    enc.emit_movdqa_rr(VS3, VS0);
                    if from_dbl {
                        enc.emit_mov_r64_imm64(SCRATCH1, 0x8000_0000_0000_0000u64 as i64);
                        enc.emit_movq_xmm_r64(VS0, SCRATCH1);
                        enc.emit_pand(VS3, VS0);
                        enc.emit_mov_r64_imm64(SCRATCH1, 0x3FF0_0000_0000_0000u64 as i64);
                        enc.emit_movq_xmm_r64(VS0, SCRATCH1);
                        enc.emit_por(VS3, VS0);
                        enc.emit_pand(VS3, VS2); // 0 where |diff| < 0.5
                        enc.emit_addsd(VS1, VS3);
                    } else {
                        enc.emit_mov_r64_imm32(SCRATCH1, 0x8000_0000u32 as i32);
                        enc.emit_movd_xmm_r32(VS0, SCRATCH1);
                        enc.emit_pand(VS3, VS0);
                        enc.emit_mov_r64_imm32(SCRATCH1, 0x3F80_0000u32 as i32);
                        enc.emit_movd_xmm_r32(VS0, SCRATCH1);
                        enc.emit_por(VS3, VS0);
                        enc.emit_pand(VS3, VS2);
                        enc.emit_addss(VS1, VS3);
                    }
                    enc.emit_movdqa_rr(VS0, VS1); // VS0 = rounded value; convert proceeds below
                }
                // Load an FP constant `bits` into VS1 (f64 movq / f32 movd).
                let load_fp_const = |enc: &mut X86Encoder, bits: u64| {
                    if from_dbl {
                        enc.emit_mov_r64_imm64(SCRATCH1, bits as i64);
                        enc.emit_movq_xmm_r64(VS1, SCRATCH1);
                    } else {
                        enc.emit_mov_r64_imm32(SCRATCH1, bits as u32 as i32);
                        enc.emit_movd_xmm_r32(VS1, SCRATCH1);
                    }
                };
                // 2^(w-1) and 2^w as the source FP type — the signed / unsigned
                // positive-overflow thresholds.
                let (pow_signbit, pow_full) = match (to_64, from_dbl) {
                    (false, false) => (0x4F00_0000u64, 0x4F80_0000u64), // 2^31, 2^32 (f32)
                    (false, true)  => (0x41E0_0000_0000_0000, 0x41F0_0000_0000_0000), // (f64)
                    (true, false)  => (0x5F00_0000, 0x5F80_0000),       // 2^63, 2^64 (f32)
                    (true, true)   => (0x43E0_0000_0000_0000, 0x43F0_0000_0000_0000), // (f64)
                };
                let ucomi = |enc: &mut X86Encoder, a: u8, b: u8| {
                    if from_dbl { enc.emit_ucomisd(a, b) } else { enc.emit_ucomiss(a, b) }
                };
                let cvtt_r64 = |enc: &mut X86Encoder, d: u8, s: u8| {
                    if from_dbl { enc.emit_cvttsd2si_r64(d, s) } else { enc.emit_cvttss2si_r64(d, s) }
                };

                if *signed {
                    // SIGNED. Raw truncating convert first (r32 for W, r64 for X).
                    if to_64 {
                        cvtt_r64(enc, rd, VS0);
                    } else if from_dbl {
                        enc.emit_cvttsd2si_r32(rd, VS0);
                    } else {
                        enc.emit_cvttss2si_r32(rd, VS0);
                    }
                    // Clamp: S is NaN → 0; S >= 2^(w-1) (+overflow/+inf) → INT_MAX.
                    // (S <= −2^(w-1) already gave INT_MIN via the x86 indefinite.)
                    load_fp_const(enc, pow_signbit);
                    ucomi(enc, VS0, VS1); // CF=1 if VS0<bound OR unordered; PF=1 if NaN
                    let jp_nan = enc.emit_jcc_rel32(cc::P);   // NaN → 0
                    let jnb_ovf = enc.emit_jcc_rel32(cc::NB); // ordered & VS0>=bound → INT_MAX
                    let jmp_keep = enc.emit_jmp_rel32();      // in range / neg-overflow: keep raw
                    // NaN → 0.
                    let nan = enc.pos();
                    enc.patch_rel32(jp_nan, nan);
                    enc.emit_xor_zero_r32(rd);
                    let jmp_done_nan = enc.emit_jmp_rel32();
                    // +overflow → INT_MAX.
                    let ovf = enc.pos();
                    enc.patch_rel32(jnb_ovf, ovf);
                    if to_64 {
                        enc.emit_mov_r64_imm64(rd, 0x7FFF_FFFF_FFFF_FFFFu64 as i64);
                    } else {
                        enc.emit_mov_r64_imm32(rd, 0x7FFF_FFFF);
                    }
                    let done = enc.pos();
                    enc.patch_rel32(jmp_keep, done);
                    enc.patch_rel32(jmp_done_nan, done);
                } else {
                    // UNSIGNED. Clamp the two easy ends first, then convert the
                    // remaining (0, 2^w) range.
                    //   S <= 0 (incl −inf, −0) OR NaN → 0.
                    //   S >= 2^w (incl +inf)          → UINT_MAX.
                    enc.emit_pxor(VS1, VS1); // VS1 = +0.0
                    ucomi(enc, VS0, VS1);
                    // jbe = CF|ZF: VS0<0 (CF), VS0==0 (ZF), or NaN (CF) → all → 0.
                    let jbe_zero = enc.emit_jcc_rel32(cc::BE);
                    // Positive: overflow vs 2^w → UINT_MAX.
                    load_fp_const(enc, pow_full);
                    ucomi(enc, VS0, VS1);
                    let jnb_ovf = enc.emit_jcc_rel32(cc::NB); // VS0 >= 2^w → UINT_MAX
                    // In-range (0, 2^w): real convert.
                    if !to_64 {
                        // Wd: 64-bit signed convert is exact across [0, 2^32); low 32 = u32 result.
                        cvtt_r64(enc, rd, VS0);
                    } else {
                        // Xd: < 2^63 direct; [2^63, 2^64) subtract 2^63, convert, add the bit.
                        load_fp_const(enc, pow_signbit); // VS1 = (f)2^63
                        ucomi(enc, VS0, VS1);
                        let jnb_big = enc.emit_jcc_rel32(cc::NB); // >= 2^63
                        cvtt_r64(enc, rd, VS0);
                        let jmp_after = enc.emit_jmp_rel32();
                        let big = enc.pos();
                        enc.patch_rel32(jnb_big, big);
                        if from_dbl { enc.emit_subsd(VS0, VS1); } else { enc.emit_subss(VS0, VS1); }
                        cvtt_r64(enc, rd, VS0);
                        enc.emit_mov_r64_imm64(SCRATCH1, 0x8000_0000_0000_0000u64 as i64);
                        enc.emit_add_rr64(rd, SCRATCH1);
                        let after = enc.pos();
                        enc.patch_rel32(jmp_after, after);
                    }
                    let jmp_done = enc.emit_jmp_rel32();
                    // → 0.
                    let zero = enc.pos();
                    enc.patch_rel32(jbe_zero, zero);
                    enc.emit_xor_zero_r32(rd);
                    let jmp_done2 = enc.emit_jmp_rel32();
                    // → UINT_MAX.
                    let ovf = enc.pos();
                    enc.patch_rel32(jnb_ovf, ovf);
                    if to_64 {
                        enc.emit_mov_r64_imm64(rd, 0xFFFF_FFFF_FFFF_FFFFu64 as i64);
                    } else {
                        enc.emit_mov_r64_imm32(rd, 0xFFFF_FFFFu32 as i32);
                    }
                    let done = enc.pos();
                    enc.patch_rel32(jmp_done, done);
                    enc.patch_rel32(jmp_done2, done);
                }
                Self::store_dest(alloc, enc, *dst, rd, spilled);
            }
            // Delegated to the ctx-template lowerer (BUILDSPEC §7). These carry
            // no IrValueId/IrFlagsId operands, so neither `alloc` nor
            // `branch_patches` is needed.
            VecBin { .. } | VecUn { .. } | VecShift { .. } | VecShiftAcc { .. } | VecCmp { .. }
            | VecCmpZero { .. } | VecShiftNarrow { .. } | VecShiftLong { .. }
            | VecShiftReg { .. } | VecShiftIns { .. } | VecShiftNarrowSat { .. }
            | VecExt { .. } | VecTbl1 { .. } | VecTblN { .. } | VecDupElem { .. } | VecPmull { .. }
            | VecMulLong { .. } | VecRev64 { .. }
            | VecAddLongPair { .. }
            | VecUnzip { .. }
            | VecPair { .. } | VecReduce { .. } | VecAddLong { .. } | VecFp { .. }
            | VecFpCmp { .. } | VecFpUn { .. }
            | VecByElem { .. } | VecCvtFp { .. } | VecZipTrn { .. } | VecScalarPair { .. }
            | FpFromInt { .. } | FpToIntR { .. } | FpRound { .. } | VecFpRound { .. } | FpCvt2 { .. }
            | FpCsel { .. }
            | FpMov { .. } | FpBin { .. } | FpFma { .. } | FpUn { .. } | FpCmpN { .. }
            | FpToGpr { .. } | FpFromGpr { .. } | CryptoAesR { .. } => {
                crate::backend::lower_simd_ctx::lower(op, enc);
            }

            // SHA-1 family (SHA1C/P/M/H/SU0/SU1) → software runtime helper, same
            // pattern as CryptoSha256. `kind` is the crypto_rt::SHA1_* code.
            CryptoShaR { kind, d, n, m } => {
                let packed = (*kind as u32)
                    | ((*d as u32) << 8)
                    | ((*n as u32) << 16)
                    | ((*m as u32) << 24);
                Self::emit_crypto_sha1_call(enc, packed);
            }

            Unimplemented(_) => {
                enc.emit_ud2();
            }
        }
    }
}
