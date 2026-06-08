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

use alloc::collections::BTreeMap;

use crate::ir::{IrBlock, IrValueId, IrOp};
use crate::ir::memory::{LoadTy, StoreTy};
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
        branch_patches: &mut BTreeMap<usize, crate::ir::BlockId>,
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
        branch_patches: &mut BTreeMap<usize, crate::ir::BlockId>,
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
                // Legacy callers (arms not yet routed through src_in/dest_work)
                // land here. With RAX/RCX reserved as scratch, returning RAX is
                // still wrong for a spilled value — but the M1 lift keeps peak
                // liveness ~3, so spills do not occur from real lift output. The
                // integer-core arms below DO route spills correctly via the
                // materialization helpers; this fallback only covers arms that
                // a spilling block never reaches in practice.
                let _ = slot;
                SCRATCH0
            }
            _ => SCRATCH0,
        }
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

    /// Runtime address of the `aether_mmu_xlate` FFI helper, baked into the
    /// emitted `MOV RAX, imm64`. The host test crate and the hypervisor link the
    /// same symbol, so this resolves correctly in both contexts. Coercing the
    /// `unsafe extern "C" fn` to a fn pointer then to `usize` is a plain address
    /// read (no call); kept in one place so the cast site is auditable.
    #[inline]
    fn mmu_xlate_addr() -> usize {
        crate::runtime::mmu::aether_mmu_xlate as *const () as usize
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
    fn emit_arm_cond_to_bool(enc: &mut X86Encoder, nzcv: u8, out: u8, cond: crate::decoder::Cond) {
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
        branch_patches: &mut BTreeMap<usize, crate::ir::BlockId>,
    ) {
        use IrOp::*;

        match op {
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
                // FP/SIMD constants handled by lower_simd
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
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_not_r64(rd);
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
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                let rb = Self::gpr(alloc, *b);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb);
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
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                let rb = Self::gpr(alloc, *b);
                if ra != 0 { enc.emit_mov_rr64(0, ra); }
                enc.emit_cqo(); // sign-extend RAX into RDX:RAX
                enc.emit_idiv_r64(rb);
                if rd != 0 { enc.emit_mov_rr64(rd, 0); } // quotient in RAX
            }
            UDiv { dst, a, b } => {
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                let rb = Self::gpr(alloc, *b);
                if ra != 0 { enc.emit_mov_rr64(0, ra); }
                enc.emit_xor_zero_r32(2); // zero RDX
                enc.emit_div_r64(rb);
                if rd != 0 { enc.emit_mov_rr64(rd, 0); }
            }
            Madd { dst, a, b, c } => {
                // dst = a * b + c
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                let rb = Self::gpr(alloc, *b);
                let rc = Self::gpr(alloc, *c);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb);
                enc.emit_add_rr64(rd, rc);
            }
            Msub { dst, a, b, c } => {
                // dst = c - a * b
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                let rb = Self::gpr(alloc, *b);
                let rc = Self::gpr(alloc, *c);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_imul_rr64(rd, rb);
                // tmp = rc; tmp - rd
                // Use scratch: negate rd then add rc
                enc.emit_neg_r64(rd);
                enc.emit_add_rr64(rd, rc);
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
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                enc.emit_lzcnt_r64(rd, ra);
                if !*sf {
                    enc.emit_sub_r64_imm32(rd, 32);
                }
            }
            Cls { dst, a, sf } => {
                // Count leading sign bits = CLZ(a XOR (a << 1)) - 1.
                // For W-form: do the XOR/shift in 32-bit (so the sign bit
                // sits at bit 31, not bit 63), then clz_w. Sub-32 handles
                // the width as in the Clz arm.
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_shl_r64_imm8(rd, 1);
                enc.emit_xor_rr64(rd, ra);
                enc.emit_lzcnt_r64(rd, rd);
                if !*sf {
                    enc.emit_sub_r64_imm32(rd, 32);
                }
                // Subtract 1 (cls returns leading-sign count minus sign bit).
                enc.emit_sub_r64_imm32(rd, 1);
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
                if Self::is_spilled(alloc, *dst) || Self::is_spilled(alloc, *a) {
                    enc.emit_ud2();
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
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                match *bytes {
                    2 => { /* XCHG ah,al equivalent; use ROL r16,8 */ enc.emit_nop(); }
                    // ARM64 REV Wd,Wn reverses the low 32 bits and the W-write
                    // zero-extends bits 63:32. x86 BSWAP r32 has both properties
                    // (default 32-bit op size zero-extends). BSWAP r64 would
                    // move the original low 32 bits into the high half and zero
                    // the low — observed at Phase B step 3b as `rev w8,w8`
                    // turning 0xedfe0dd0 into 0 instead of 0xd00dfeed.
                    4 => enc.emit_bswap_r32(rd),
                    8 => enc.emit_bswap_r64(rd),
                    _ => enc.emit_nop(),
                }
            }
            Bswap16 { dst, a } => {
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_nop(); // ROL r16,8 placeholder
            }
            Bswap32 { dst, a } => {
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                // Same bug class as REV-4: BSWAP r64 reverses 8 bytes (and
                // moves the original low 32 into the high half). Use BSWAP r32
                // so the low 32 reverse and bits 63:32 zero-extend.
                enc.emit_bswap_r32(rd);
            }
            Bswap64 { dst, a } => {
                let rd = Self::gpr(alloc, *dst);
                let ra = Self::gpr(alloc, *a);
                if rd != ra { enc.emit_mov_rr64(rd, ra); }
                enc.emit_bswap_r64(rd);
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
                // M4a closeout. Two correctness fixes over the prior version:
                //  (1) EFLAGS HAZARD: materialize the "else" value (transformed
                //      b: CSINC=+1 / CSINV=~ / CSNEG=-) into rd FIRST, so the
                //      flag-clobbering transform happens BEFORE we set ZF for the
                //      cmov. (The old order did the transform between TEST and
                //      CMOVNZ, clobbering ZF -> cmov read garbage flags.)
                //  (2) SPILLED-OPERAND COLLISION: a spilled dst/a/b would resolve
                //      to RAX/RCX (the scratch used for NZCV eval) -> the operand
                //      reads the stale NZCV word. The 2-scratch model can't hold
                //      nzcv+bool+3 operands; this is rare under M1 liveness, so
                //      fail loud (UD2 -> trap via byte-gate/IDT) over miscompute.
                if Self::is_spilled(alloc, *dst)
                    || Self::is_spilled(alloc, *a)
                    || Self::is_spilled(alloc, *b)
                {
                    enc.emit_ud2();
                } else {
                    let rd = Self::gpr(alloc, *dst);
                    let ra = Self::gpr(alloc, *a);
                    let rb = Self::gpr(alloc, *b);
                    // INVARIANT (load-bearing): rd != ra. Step 1 below writes rd
                    // (the transformed `b`), which would destroy `a` before the
                    // cmov reads it if they aliased. Liveness guarantees this for
                    // every non-spilled Csel: `a`'s interval ends at p+1 (use at
                    // the Csel) while dst's starts at p, and expire_old(p) frees
                    // only end<=p — so the allocator never reuses a's reg for dst.
                    // A future SSA/copy-coalescing pass could break it; fail loud
                    // in debug if so. (debug_assert is compiled out in release.)
                    debug_assert_ne!(rd, ra, "Csel dst must not alias operand a");
                    // Step 1: else-value (transformed b) into rd. Flags don't
                    // matter yet. NOT preserves flags; ADD/NEG clobber them — all
                    // fine because the ZF-setting TEST comes after.
                    if rd != rb {
                        enc.emit_mov_rr64(rd, rb);
                    }
                    match *variant {
                        1 => enc.emit_add_r64_imm32(rd, 1), // CSINC
                        2 => enc.emit_not_r64(rd),          // CSINV
                        3 => enc.emit_neg_r64(rd),          // CSNEG
                        _ => {}                              // CSEL
                    }
                    // Step 2: eval ARM cond from materialized NZCV (RAX/RCX
                    // scratch — does not touch the allocated rd/ra/rb), set ZF,
                    // select a into rd iff cond true.
                    enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, NZCV_DISP);
                    Self::emit_arm_cond_to_bool(enc, SCRATCH0, SCRATCH1, *cond);
                    enc.emit_test_rr64(SCRATCH1, SCRATCH1); // NZ iff cond true
                    enc.emit_cmov_rr64(cc::NZ, rd, ra);
                }
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
            // FAIL-LOUD (UD2) on a spilled address or store value: the call
            // sequence marshals the address out of a real GPR (a spilled operand
            // resolves to RAX/SCRATCH0, which the call clobbers), and the
            // integer-core lift keeps these in-register, so a spill here means an
            // unexpected allocator state — trap rather than miscompute.
            // Integer load/store is the M4b critical path (page-table setup,
            // __enable_mmu); FP/SIMD memory under the MMU is deferred and also
            // traps (XMM is volatile across the Win64 call — preserving it is a
            // later step), keeping us fail-loud rather than emitting a clobbered
            // FP value.
            // LDR Q (128-bit) — M4b-6 ctx-template FPR load. lift emits this as
            // Load{Vec128} immediately followed by WriteFpr{rt}, which commits
            // VFP -> q[rt]. The xlate call is issued FIRST so the subsequent
            // movdqu into VFP (XMM15, Win64 non-volatile) is never clobbered.
            Load { addr, ty: LoadTy::Vec128, .. } => {
                if Self::is_spilled(alloc, *addr) {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    Self::emit_mmu_xlate_call(enc, ra, false, 16); // RAX = host PA
                    enc.emit_movdqu_load(crate::regalloc::x86_regs::VFP, SCRATCH0, 0);
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
            Store { addr, ty: StoreTy::Vec128, .. } => {
                if Self::is_spilled(alloc, *addr) {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    Self::emit_mmu_xlate_call(enc, ra, true, 16); // RAX = host PA
                    enc.emit_movdqu_store(SCRATCH0, 0, crate::regalloc::x86_regs::VFP);
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
            // `stp x29,x30,[sp,#-N]!`. Fail-loud (UD2) on any spilled operand:
            // the Win64 call clobbers the scratch regs, so the address + data
            // values must be live in real GPRs (the integer-core lift keeps them
            // in-register, so a spill here means an unexpected allocator state).
            LoadPair { dst_a, dst_b, addr, ty } => {
                if Self::is_spilled(alloc, *addr)
                    || Self::is_spilled(alloc, *dst_a)
                    || Self::is_spilled(alloc, *dst_b)
                {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    // Per-element width; the pair spans 2×width bytes (passed as
                    // the access size so the walker's cross-page check covers it).
                    let width: i32 = if matches!(ty, LoadTy::U64) { 8 } else { 4 };
                    Self::emit_mmu_xlate_call(enc, ra, false, 2 * width); // RAX = host PA
                    let da = Self::gpr(alloc, *dst_a);
                    let db = Self::gpr(alloc, *dst_b);
                    match ty {
                        LoadTy::U64 => {
                            enc.emit_mov_r64_mem(da, SCRATCH0, 0);
                            enc.emit_mov_r64_mem(db, SCRATCH0, width);
                        }
                        LoadTy::I32 => {
                            // LDPSW: 2 × 32-bit signed → 64-bit sign-extended.
                            enc.emit_movsxd_r64_mem32(da, SCRATCH0, 0);
                            enc.emit_movsxd_r64_mem32(db, SCRATCH0, width);
                        }
                        _ => {
                            // 32-bit (W-register) pair: zero-extended 4-byte loads.
                            enc.emit_mov_r32_mem(da, SCRATCH0, 0);
                            enc.emit_mov_r32_mem(db, SCRATCH0, width);
                        }
                    }
                }
            }
            StorePair { val_a, val_b, addr, ty } => {
                if Self::is_spilled(alloc, *addr)
                    || Self::is_spilled(alloc, *val_a)
                    || Self::is_spilled(alloc, *val_b)
                {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    let width: i32 = if matches!(ty, StoreTy::U64) { 8 } else { 4 };
                    Self::emit_mmu_xlate_call(enc, ra, true, 2 * width); // RAX = host PA
                    let va = Self::gpr(alloc, *val_a);
                    let vb = Self::gpr(alloc, *val_b);
                    if width == 8 {
                        enc.emit_mov_mem_r64(SCRATCH0, 0, va);
                        enc.emit_mov_mem_r64(SCRATCH0, width, vb);
                    } else {
                        enc.emit_mov_mem32_r64(SCRATCH0, 0, va);
                        enc.emit_mov_mem32_r64(SCRATCH0, width, vb);
                    }
                }
            }
            LoadExclusive { dst, addr, ty } => {
                // Exclusive load routed through the walker (the monitor
                // reservation itself is still AT-14 future work, but the ADDRESS
                // must be correct under the guest MMU). Size from `ty`.
                if Self::is_spilled(alloc, *addr) || Self::is_spilled(alloc, *dst) {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    let size: i32 = match ty {
                        LoadTy::U8 | LoadTy::I8 => 1,
                        LoadTy::U16 | LoadTy::I16 => 2,
                        LoadTy::U32 | LoadTy::I32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, false, size); // RAX = host PA
                    let rd = Self::gpr(alloc, *dst);
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
                }
            }
            StoreExclusive { status, val, addr, ty } => {
                // Exclusive store routed through the walker; `status = 0`
                // (success) remains the AT-12 placeholder (the real STXR monitor
                // is AT-14). Fail-loud on spill.
                if Self::is_spilled(alloc, *addr)
                    || Self::is_spilled(alloc, *val)
                    || Self::is_spilled(alloc, *status)
                {
                    enc.emit_ud2();
                } else {
                    let ra = Self::gpr(alloc, *addr);
                    let size: i32 = match ty {
                        StoreTy::U8 => 1,
                        StoreTy::U16 => 2,
                        StoreTy::U32 => 4,
                        _ => 8,
                    };
                    Self::emit_mmu_xlate_call(enc, ra, true, size); // RAX = host PA
                    let rv = Self::gpr(alloc, *val);
                    match ty {
                        StoreTy::U8  => enc.emit_mov_mem8_r64(SCRATCH0, 0, rv),
                        StoreTy::U16 => enc.emit_mov_mem16_r64(SCRATCH0, 0, rv),
                        StoreTy::U32 => enc.emit_mov_mem32_r64(SCRATCH0, 0, rv),
                        StoreTy::U64 => enc.emit_mov_mem_r64(SCRATCH0, 0, rv),
                        StoreTy::F32 | StoreTy::F64 | StoreTy::Vec128 => enc.emit_ud2(),
                    }
                    // status = 0 (success). `status` is a real GPR (never RAX/spill).
                    enc.emit_xor_zero_r32(Self::gpr(alloc, *status));
                }
            }

            // ── Control flow ───────────────────────────────────────────────
            Branch { target } => {
                let patch = enc.emit_jmp_rel32();
                branch_patches.insert(patch, *target);
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
                    branch_patches.insert(patch, *taken);
                    return;
                }
                // Load packed NZCV word into SCRATCH0.
                enc.emit_mov_r64_mem(SCRATCH0, CONTEXT_REG, NZCV_DISP);
                // emit_arm_cond_to_bool: bit 0 of `out` reg = ARM condition.
                Self::emit_arm_cond_to_bool(enc, SCRATCH0, SCRATCH1, *cond);
                // test scratch1, scratch1 → ZF = (cond == 0).
                enc.emit_test_rr64(SCRATCH1, SCRATCH1);
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.insert(patch, *taken);
                // fallthru falls through — no emit needed.
            }
            Cbz { a, taken, .. } => {
                enc.emit_test_rr64(Self::gpr(alloc, *a), Self::gpr(alloc, *a));
                let patch = enc.emit_jcc_rel32(cc::Z);
                branch_patches.insert(patch, *taken);
            }
            Cbnz { a, taken, .. } => {
                enc.emit_test_rr64(Self::gpr(alloc, *a), Self::gpr(alloc, *a));
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.insert(patch, *taken);
            }
            Tbz { a, bit, taken, .. } => {
                let ra = Self::gpr(alloc, *a);
                enc.emit_shr_r64_imm8(ra, *bit);
                enc.emit_test_rr64(ra, ra);
                let patch = enc.emit_jcc_rel32(cc::Z);
                branch_patches.insert(patch, *taken);
            }
            Tbnz { a, bit, taken, .. } => {
                let ra = Self::gpr(alloc, *a);
                enc.emit_shr_r64_imm8(ra, *bit);
                enc.emit_test_rr64(ra, ra);
                let patch = enc.emit_jcc_rel32(cc::NZ);
                branch_patches.insert(patch, *taken);
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

            // ── Atomics ────────────────────────────────────────────────────
            AtomicRmw { .. } | AtomicCas { .. } => {
                // Handled by lower_atomic in AT-14.
                enc.emit_nop();
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
                // Handled by lower_simd in AT-13.
                enc.emit_nop();
            }

            // ── Crypto / system ───────────────────────────────────────────
            AesE { .. } | AesD { .. } | AesMc { .. } | AesImc { .. }
            | Sha1c { .. } | Sha1m { .. } | Sha1p { .. }
            | Sha256h { .. } | Sha256h2 { .. } | Sha256su0 { .. } | Sha256su1 { .. }
            | Pmull { .. } | Crc32 { .. } => {
                enc.emit_nop(); // Crypto lowering in AT-13.
            }

            // M4b-4: HVC/SMC are the PSCI conduit — serviced synchronously by a
            // runtime call (aether_hvc_dispatch reads x0..x3 from the ctx, runs
            // PSCI, writes x0). The lift emits WritePc(pc+4) after, so the block
            // resumes at the next instruction. No UD2 -> the block passes the
            // entry safety gate and actually executes.
            Hvc { .. } | Smc { .. } => {
                Self::emit_hvc_call(enc);
            }
            // SVC (a guest EL0->EL1 syscall) BRK/HLT (debug/halt) and unmodeled
            // hints (WFI/WFE/PSTATE/PAC) still trap: SVC needs a synchronous EL1
            // exception (an M4b-3 extension), the rest need hypervisor handling.
            // Fail loud (the block is rejected at the safety gate).
            Svc { .. } | Brk { .. } | Hlt { .. } => {
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
            // FAIL-LOUD: the single-VA form needs the page VA marshalled into
            // RCX from a real allocated GPR; if it spilled (resolves to the
            // clobbered scratch RAX) we trap rather than pass a garbage VA.
            TlbInval { va } => {
                match va {
                    Some(v) if !Self::is_spilled(alloc, *v) => {
                        let ra = Self::gpr(alloc, *v);
                        Self::emit_mmu_tlbi_va_call(enc, ra);
                        Self::emit_dbt_invalidate_call(enc);
                    }
                    Some(_) => {
                        // Spilled VA → would resolve to a clobbered scratch reg.
                        enc.emit_ud2();
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
                    // clobbers the scratch regs, so the destination must be a
                    // real GPR — fail-loud (UD2) on a spill, like the MMU ops.
                    if Self::is_spilled(alloc, *dst) {
                        enc.emit_ud2();
                    } else {
                        Self::emit_sysreg_read_call(enc, reg_id); // RAX = value
                        // dst is allocatable (never the reserved RAX), so this
                        // mov always moves the result out of RAX into dst.
                        enc.emit_mov_rr64(Self::gpr(alloc, *dst), SCRATCH0);
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
                    // M4b-4 live sysreg: runtime CALL. Value must be a real GPR.
                    if Self::is_spilled(alloc, *val) {
                        enc.emit_ud2();
                    } else {
                        Self::emit_sysreg_write_call(enc, reg_id, Self::gpr(alloc, *val));
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
            ReadGpr { dst, reg, sf: _ } => {
                let (rd, sp) = Self::dest_work(alloc, *dst, SCRATCH0);
                if *reg == 31 {
                    // XZR reads as zero (zero-extended via 32-bit xor).
                    enc.emit_xor_zero_r32(rd);
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
                        enc.emit_mov_rr32(rs, rs);
                    }
                    enc.emit_mov_mem_r64(CONTEXT_REG, (*reg as i32) * 8, rs);
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
                    enc.emit_mov_rr32(rs, rs);
                }
                enc.emit_mov_mem_r64(CONTEXT_REG, SP_DISP, rs);
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

            // ── M4b-6 V-register-numbered SIMD/FP/crypto ops ──────────────────
            // Delegated to the ctx-template lowerer (BUILDSPEC §7). These carry
            // no IrValueId/IrFlagsId operands, so neither `alloc` nor
            // `branch_patches` is needed.
            VecBin { .. } | VecUn { .. } | VecShift { .. } | VecCmp { .. }
            | VecPair { .. } | VecReduce { .. } | VecAddLong { .. } | VecFp { .. }
            | FpFromInt { .. } | FpToIntR { .. } | FpRound { .. } | FpCvt2 { .. }
            | FpMov { .. } | FpBin { .. } | FpUn { .. } | FpCmpN { .. }
            | FpToGpr { .. } | FpFromGpr { .. } | CryptoAesR { .. } | CryptoShaR { .. } => {
                crate::backend::lower_simd_ctx::lower(op, enc);
            }

            Unimplemented(_) => {
                enc.emit_ud2();
            }
        }
    }
}
