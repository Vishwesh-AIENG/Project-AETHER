//! Independent ARM64 reference interpreter (the differential oracle's trusted
//! side).
//!
//! WHY HAND-WRITTEN (not unicorn / qemu):
//!   * `unicorn-engine-sys` 2.1.5 does NOT build on this Windows/MSVC host: its
//!     build script runs `bindgen` unconditionally and panics with
//!     "Unable to find libclang" (no LLVM/libclang installed; only MSVC `cl` +
//!     cmake are present). It is also GPL-2.0, which we don't want linked into
//!     an AETHER workspace tool. (Verified 2026-07-01.)
//!   * `qemu-aarch64` user-mode would need WSL + a cross toolchain + a static
//!     ELF harness per block + ptrace/gdbstub readback: a slow cross-process
//!     design, ill-suited to scanning a large corpus, and qemu-user isn't even
//!     installed in the WSL image.
//!   * No mature permissively-licensed pure-Rust ARM64 *execution* emulator
//!     exists on crates.io (only decoders like `disarm64`).
//!
//! So the reference is a small, spec-literal interpreter written from the ARM
//! ARM, INDEPENDENT of the DBT's decoder/lifter. That independence is the whole
//! point: it computes each op's value from the architecture definition, so when
//! it and the DBT disagree, one of them is wrong — and we prove (in main.rs)
//! that it catches a real historical defect (the CMHI signed-vs-unsigned bug).
//!
//! Coverage is the subset AETHER's DBT actually emits for the corpus: integer
//! data-processing (imm + shifted/extended register), logical, moves, shifts,
//! bitfield, multiply/mul-add, conditional select, compares (NZCV), integer
//! loads/stores (unsigned-offset + a few), and the NEON/FP ops that have
//! historically miscompiled (FADD/FMUL scalar, vector ADD/SUB, CMHI/CMGT/CMEQ,
//! DUP, unsigned/signed compares). Anything unrecognised returns
//! `Unsupported` so the driver marks the block SKIPPED rather than reporting a
//! false divergence.

use crate::ctx::OracleState;
use std::sync::atomic::{AtomicBool, Ordering};

/// CATCH-demonstration toggle: when true, the reference computes CMHI as a
/// SIGNED compare (the historical DBT defect). Off in normal differential runs.
/// Lets `--self-test` reconstruct the exact bug and prove the oracle flags it.
static BUGGY_CMHI: AtomicBool = AtomicBool::new(false);

/// Enable/disable the buggy-CMHI reference mode (see `BUGGY_CMHI`).
pub fn set_buggy_cmhi(on: bool) {
    BUGGY_CMHI.store(on, Ordering::SeqCst);
}
fn buggy_cmhi() -> bool {
    BUGGY_CMHI.load(Ordering::SeqCst)
}

/// A tiny flat memory the reference uses for loads/stores. `base` is the guest
/// VA of byte 0 (matches the DBT's flat window base). Accesses outside are a
/// hard error (the DBT would fault -> early RET; we surface it as Unsupported so
/// the block is skipped rather than mis-diffed).
pub struct RefMem {
    pub base: u64,
    pub bytes: Vec<u8>,
}

impl RefMem {
    fn off(&self, va: u64, n: usize) -> Result<usize, StepErr> {
        if va < self.base {
            return Err(StepErr::MemFault(va));
        }
        let o = (va - self.base) as usize;
        if o + n > self.bytes.len() {
            return Err(StepErr::MemFault(va));
        }
        Ok(o)
    }
    fn read(&self, va: u64, n: usize) -> Result<u64, StepErr> {
        let o = self.off(va, n)?;
        let mut v = 0u64;
        for i in 0..n {
            v |= (self.bytes[o + i] as u64) << (8 * i);
        }
        Ok(v)
    }
    fn write(&mut self, va: u64, n: usize, val: u64) -> Result<(), StepErr> {
        let o = self.off(va, n)?;
        for i in 0..n {
            self.bytes[o + i] = (val >> (8 * i)) as u8;
        }
        Ok(())
    }
    fn read128(&self, va: u64) -> Result<u128, StepErr> {
        let lo = self.read(va, 8)?;
        let hi = self.read(va + 8, 8)?;
        Ok((lo as u128) | ((hi as u128) << 64))
    }
    fn write128(&mut self, va: u64, v: u128) -> Result<(), StepErr> {
        self.write(va, 8, v as u64)?;
        self.write(va + 8, 8, (v >> 64) as u64)
    }
}

#[derive(Debug)]
pub enum StepErr {
    /// Instruction not modelled by the reference — block should be SKIPPED.
    Unsupported(u32),
    /// Access outside the seeded scratch region.
    MemFault(u64),
}

/// Reference machine: the architectural state plus an optional flat memory.
pub struct RefCpu {
    /// x0..x30 (index 31 unused; XZR handled specially).
    pub x: [u64; 31],
    pub sp: u64,
    /// NZCV in bits [31:28] (same encoding as OracleState).
    pub nzcv: u64,
    /// q0..q31 as u128.
    pub v: [u128; 32],
    pub mem: Option<RefMem>,
}

impl RefCpu {
    pub fn from_state(s: &OracleState, mem: Option<RefMem>) -> Self {
        let mut v = [0u128; 32];
        for r in 0..32 {
            v[r] = s.vec_u128(r);
        }
        RefCpu { x: s.gpr, sp: s.sp, nzcv: s.nzcv & 0xF000_0000, v, mem }
    }
    pub fn to_state(&self) -> OracleState {
        let mut s = OracleState::zeroed();
        s.gpr = self.x;
        s.sp = self.sp;
        s.nzcv = self.nzcv & 0xF000_0000;
        for r in 0..32 {
            s.set_vec_u128(r, self.v[r]);
        }
        s
    }

    // ── register file with XZR/WZR/SP conventions ────────────────────────────
    /// Read Xn where n==31 reads XZR (0). SP is a separate slot.
    fn xr(&self, n: u32) -> u64 {
        if n == 31 { 0 } else { self.x[n as usize] }
    }
    /// Read Xn where n==31 reads SP (for the load/store base + add-imm forms).
    fn xr_sp(&self, n: u32) -> u64 {
        if n == 31 { self.sp } else { self.x[n as usize] }
    }
    fn wr(&self, n: u32) -> u64 {
        self.xr(n) & 0xFFFF_FFFF
    }
    /// Write Xn (n==31 => XZR discard). `is32` zero-extends from 32 bits.
    fn setx(&mut self, n: u32, val: u64, is32: bool) {
        if n == 31 { return; }
        self.x[n as usize] = if is32 { val & 0xFFFF_FFFF } else { val };
    }
    fn set_sp(&mut self, n: u32, val: u64, is32: bool) {
        let v = if is32 { val & 0xFFFF_FFFF } else { val };
        if n == 31 { self.sp = v; } else { self.x[n as usize] = v; }
    }

    fn set_nzcv(&mut self, n: bool, z: bool, c: bool, v: bool) {
        self.nzcv = ((n as u64) << 31) | ((z as u64) << 30) | ((c as u64) << 29) | ((v as u64) << 28);
    }

    /// Execute one instruction word. `_pc` is available for PC-relative ops.
    pub fn step(&mut self, insn: u32, _pc: u64) -> Result<(), StepErr> {
        let op = insn;
        // Dispatch by top-level encoding groups (ARM ARM C4).
        // We check the most specific patterns first.

        // ── NEON / FP (bit27..25 = 111 with bit28=0 for SIMD, or bit28=1 FP) ──
        if (op & 0x0E00_0000) == 0x0E00_0000 || (op & 0x1E00_0000) == 0x0E00_0000 {
            if let Some(r) = self.try_simd_fp(op)? {
                return r;
            }
        }

        // ── Integer data-processing immediate: op[28:26] = 100 ──
        if (op & 0x1C00_0000) == 0x1000_0000 {
            return self.dp_imm(op);
        }
        // ── Loads/stores: bit 27 = 1, bit 25 = 0 (op[27:25]=1x0) ──
        if (op & 0x0A00_0000) == 0x0800_0000 {
            return self.ldst(op);
        }
        // ── Data-processing register: op[27:25] = 101 ──
        if (op & 0x0E00_0000) == 0x0A00_0000 {
            return self.dp_reg(op);
        }

        Err(StepErr::Unsupported(op))
    }

    // ── Data-processing (immediate) ──────────────────────────────────────────
    fn dp_imm(&mut self, op: u32) -> Result<(), StepErr> {
        let sf = (op >> 31) & 1;
        let is32 = sf == 0;
        let rd = op & 0x1F;
        let rn = (op >> 5) & 0x1F;
        let grp = (op >> 23) & 0x7; // op[25:23]

        // PC-rel addressing (ADR/ADRP) reads PC, which we don't carry as state
        // in the register-only oracle. Mark unsupported so the block is SKIPPED
        // rather than mis-diffed. (op[28:24]=1_0000)
        if (op & 0x1F00_0000) == 0x1000_0000 {
            return Err(StepErr::Unsupported(op));
        }

        match grp {
            // Add/subtract (immediate): op[25:23]=010
            0b010 => {
                let sub = (op >> 30) & 1 == 1;
                let setflags = (op >> 29) & 1 == 1;
                let shift = (op >> 22) & 1;
                let imm12 = (op >> 10) & 0xFFF;
                let mut imm = imm12 as u64;
                if shift == 1 { imm <<= 12; }
                let a = self.xr_sp(rn);
                let (res, nzcv) = addsub(a, imm, sub, is32);
                if setflags {
                    self.nzcv = nzcv;
                    self.setx(rd, res, is32);
                } else {
                    self.set_sp(rd, res, is32);
                }
                Ok(())
            }
            // Logical (immediate): op[25:23]=100
            0b100 => {
                let opc = (op >> 29) & 0x3;
                let n = (op >> 22) & 1;
                let immr = (op >> 16) & 0x3F;
                let imms = (op >> 10) & 0x3F;
                let imm = decode_bitmask(n, imms, immr, is32).ok_or(StepErr::Unsupported(op))?;
                let a = self.xr(rn);
                let res = match opc {
                    0b00 => a & imm,          // AND
                    0b01 => a | imm,          // ORR
                    0b10 => a ^ imm,          // EOR
                    0b11 => a & imm,          // ANDS
                    _ => unreachable!(),
                };
                let res = if is32 { res & 0xFFFF_FFFF } else { res };
                if opc == 0b11 {
                    // ANDS sets NZCV (C=V=0).
                    self.set_nzcv(neg(res, is32), res == 0, false, false);
                    self.setx(rd, res, is32);
                } else {
                    self.set_sp(rd, res, is32); // AND/ORR/EOR imm allow SP dest
                }
                Ok(())
            }
            // Move wide (immediate): op[25:23]=101
            0b101 => {
                let opc = (op >> 29) & 0x3;
                let hw = (op >> 21) & 0x3;
                let imm16 = ((op >> 5) & 0xFFFF) as u64;
                let shift = 16 * hw;
                match opc {
                    0b00 => {
                        // MOVN
                        let v = !(imm16 << shift);
                        self.setx(rd, v, is32);
                    }
                    0b10 => {
                        // MOVZ
                        let v = imm16 << shift;
                        self.setx(rd, v, is32);
                    }
                    0b11 => {
                        // MOVK — keep other bits
                        let cur = self.xr(rd);
                        let mask = 0xFFFFu64 << shift;
                        let v = (cur & !mask) | (imm16 << shift);
                        self.setx(rd, v, is32);
                    }
                    _ => return Err(StepErr::Unsupported(op)),
                }
                Ok(())
            }
            // Bitfield: op[25:23]=110  (SBFM/BFM/UBFM)
            0b110 => {
                let opc = (op >> 29) & 0x3;
                let n = (op >> 22) & 1;
                let immr = (op >> 16) & 0x3F;
                let imms = (op >> 10) & 0x3F;
                let _ = n;
                let width = if is32 { 32u32 } else { 64u32 };
                let src = self.xr(rn);
                let res = bitfield(opc, src, immr, imms, width, self.xr(rd))
                    .ok_or(StepErr::Unsupported(op))?;
                self.setx(rd, res, is32);
                Ok(())
            }
            // Extract (EXTR): op[25:23]=111.  EXTR Rd,Rn,Rm,#lsb:
            //   result = (Rn:Rm) >> lsb  — Rn is the HIGH half, Rm the LOW half.
            0b111 => {
                let rm = (op >> 16) & 0x1F;
                let imms = (op >> 10) & 0x3F; // lsb
                let hi = self.xr(rn); // Rn = high
                let lo = self.xr(rm); // Rm = low
                if is32 {
                    let concat = ((hi & 0xFFFF_FFFF) << 32) | (lo & 0xFFFF_FFFF);
                    let r = ((concat >> imms) as u64) & 0xFFFF_FFFF;
                    self.setx(rd, r, true);
                } else {
                    let c = ((hi as u128) << 64) | (lo as u128);
                    let r = (c >> imms) as u64;
                    self.setx(rd, r, false);
                }
                Ok(())
            }
            _ => Err(StepErr::Unsupported(op)),
        }
    }

    // ── Data-processing (register) ───────────────────────────────────────────
    fn dp_reg(&mut self, op: u32) -> Result<(), StepErr> {
        let sf = (op >> 31) & 1;
        let is32 = sf == 0;
        let rd = op & 0x1F;
        let rn = (op >> 5) & 0x1F;
        let rm = (op >> 16) & 0x1F;

        // Add/subtract (shifted register): op[28:24]=0_1011, bit21=0
        // Add/subtract (extended register): bit21=1
        if (op & 0x1F00_0000) == 0x0B00_0000 {
            let sub = (op >> 30) & 1 == 1;
            let setflags = (op >> 29) & 1 == 1;
            let extended = (op >> 21) & 1 == 1;
            let b = if extended {
                // extended register
                let option = (op >> 13) & 0x7;
                let imm3 = (op >> 10) & 0x7;
                extend_reg(self.xr_sp(rm), option, imm3, is32)
            } else {
                let shift_ty = (op >> 22) & 0x3;
                let amount = (op >> 10) & 0x3F;
                shift_reg(self.xr(rm), shift_ty, amount, is32).ok_or(StepErr::Unsupported(op))?
            };
            let a = if extended { self.xr_sp(rn) } else { self.xr(rn) };
            let (res, nzcv) = addsub(a, b, sub, is32);
            if setflags {
                self.nzcv = nzcv;
                self.setx(rd, res, is32);
            } else if extended {
                self.set_sp(rd, res, is32);
            } else {
                self.setx(rd, res, is32);
            }
            return Ok(());
        }

        // Logical (shifted register): op[28:24]=0_1010
        if (op & 0x1F00_0000) == 0x0A00_0000 {
            let opc = (op >> 29) & 0x3;
            let n = (op >> 21) & 1;
            let shift_ty = (op >> 22) & 0x3;
            let amount = (op >> 10) & 0x3F;
            let mut b = shift_reg(self.xr(rm), shift_ty, amount, is32).ok_or(StepErr::Unsupported(op))?;
            if n == 1 { b = !b; }
            let a = self.xr(rn);
            let res = match opc {
                0b00 => a & b, // AND / BIC(n=1)
                0b01 => a | b, // ORR / ORN
                0b10 => a ^ b, // EOR / EON
                0b11 => a & b, // ANDS / BICS
                _ => unreachable!(),
            };
            let res = if is32 { res & 0xFFFF_FFFF } else { res };
            if opc == 0b11 {
                self.set_nzcv(neg(res, is32), res == 0, false, false);
            }
            self.setx(rd, res, is32);
            return Ok(());
        }

        // Add/subtract with carry: op[28:21]=1101_0000
        if (op & 0x1FE0_0000) == 0x1A00_0000 {
            let sub = (op >> 30) & 1 == 1;
            let setflags = (op >> 29) & 1 == 1;
            let cin = ((self.nzcv >> 29) & 1) as u64; // C flag
            let a = self.xr(rn);
            let bm = self.xr(rm);
            let b = if sub { !bm } else { bm };
            let (res, nzcv) = addsub_carry(a, b, cin, is32);
            if setflags { self.nzcv = nzcv; }
            self.setx(rd, res, is32);
            return Ok(());
        }

        // Conditional select: op[28:21]=1101_0100
        if (op & 0x1FE0_0000) == 0x1A80_0000 {
            let rm = (op >> 16) & 0x1F;
            let cond = (op >> 12) & 0xF;
            // The variant is selected by op = bit30 and o2 = bit10 (NOT bit11):
            //   CSEL  op=0 o2=0  -> Rm
            //   CSINC op=0 o2=1  -> Rm + 1
            //   CSINV op=1 o2=0  -> ~Rm
            //   CSNEG op=1 o2=1  -> -Rm  (= ~Rm + 1)
            let opbit = (op >> 30) & 1;
            let o2 = (op >> 10) & 1;
            let a = self.xr(rn);
            let b = self.xr(rm);
            let taken = cond_holds(cond, self.nzcv);
            let res = if taken {
                a
            } else {
                match (opbit, o2) {
                    (0, 0) => b,                    // CSEL
                    (0, 1) => b.wrapping_add(1),    // CSINC
                    (1, 0) => !b,                   // CSINV
                    (1, 1) => (!b).wrapping_add(1), // CSNEG
                    _ => b,
                }
            };
            self.setx(rd, res, is32);
            return Ok(());
        }

        // Data-processing (3 source): op[28:24]=1_1011  (MADD/MSUB/MUL/UMULH/SMULH...)
        if (op & 0x1F00_0000) == 0x1B00_0000 {
            let ra = (op >> 10) & 0x1F;
            let o0 = (op >> 15) & 1;
            let op31 = (op >> 21) & 0x7;
            let n = self.xr(rn);
            let m = self.xr(rm);
            let a = self.xr(ra);
            let res = match (op31, o0) {
                (0b000, 0) => a.wrapping_add(n.wrapping_mul(m)), // MADD
                (0b000, 1) => a.wrapping_sub(n.wrapping_mul(m)), // MSUB
                (0b001, 0) => {
                    // SMADDL: signed 32*32 + 64
                    let p = (n as i32 as i64).wrapping_mul(m as i32 as i64);
                    (a as i64).wrapping_add(p) as u64
                }
                (0b001, 1) => {
                    let p = (n as i32 as i64).wrapping_mul(m as i32 as i64);
                    (a as i64).wrapping_sub(p) as u64
                }
                (0b010, 0) => {
                    // SMULH
                    ((n as i64 as i128).wrapping_mul(m as i64 as i128) >> 64) as u64
                }
                (0b101, 0) => {
                    // UMADDL
                    let p = (n as u32 as u64).wrapping_mul(m as u32 as u64);
                    a.wrapping_add(p)
                }
                (0b101, 1) => {
                    let p = (n as u32 as u64).wrapping_mul(m as u32 as u64);
                    a.wrapping_sub(p)
                }
                (0b110, 0) => {
                    // UMULH
                    ((n as u128).wrapping_mul(m as u128) >> 64) as u64
                }
                _ => return Err(StepErr::Unsupported(op)),
            };
            self.setx(rd, res, is32);
            return Ok(());
        }

        // Data-processing (2 source): op[28:21]=1101_0110 (UDIV/SDIV/LSLV/...)
        if (op & 0x1FE0_0000) == 0x1AC0_0000 {
            let opc = (op >> 10) & 0x3F;
            let n = self.xr(rn);
            let m = self.xr(rm);
            let res = match opc {
                0b000010 => { // UDIV
                    if is32 {
                        let (a, b) = (n as u32, m as u32);
                        if b == 0 { 0 } else { (a / b) as u64 }
                    } else if m == 0 { 0 } else { n / m }
                }
                0b000011 => { // SDIV
                    if is32 {
                        let (a, b) = (n as i32, m as i32);
                        if b == 0 { 0 } else { a.wrapping_div(b) as u32 as u64 }
                    } else {
                        let (a, b) = (n as i64, m as i64);
                        if b == 0 { 0 } else { a.wrapping_div(b) as u64 }
                    }
                }
                0b001000 => shift_reg(n, 0, (m & if is32 {31} else {63} as u64) as u32, is32).unwrap(), // LSLV
                0b001001 => shift_reg(n, 1, (m & if is32 {31} else {63} as u64) as u32, is32).unwrap(), // LSRV
                0b001010 => shift_reg(n, 2, (m & if is32 {31} else {63} as u64) as u32, is32).unwrap(), // ASRV
                0b001011 => shift_reg(n, 3, (m & if is32 {31} else {63} as u64) as u32, is32).unwrap(), // RORV
                _ => return Err(StepErr::Unsupported(op)),
            };
            self.setx(rd, res, is32);
            return Ok(());
        }

        Err(StepErr::Unsupported(op))
    }

    // ── Loads / stores (integer, unsigned offset + a couple) ─────────────────
    fn ldst(&mut self, op: u32) -> Result<(), StepErr> {
        let mem = match &self.mem {
            Some(_) => {}
            None => return Err(StepErr::Unsupported(op)),
        };
        let _ = mem;
        let size = (op >> 30) & 0x3;
        let rt = op & 0x1F;
        let rn = (op >> 5) & 0x1F;

        // Load/store register (unsigned immediate): op[29:24]=11_1001, bit 27..
        // pattern: 1x1_11001 with opc in [23:22].
        if (op & 0x3B00_0000) == 0x3900_0000 {
            let opc = (op >> 22) & 0x3;
            let imm12 = (op >> 10) & 0xFFF;
            let scaled = (imm12 as u64) << size;
            let base = self.xr_sp(rn);
            let addr = base.wrapping_add(scaled);
            let is_vector = (op >> 26) & 1 == 1; // V bit
            if std::env::var("ORACLE_DEBUG").is_ok() {
                eprintln!("[ref ldst] op=0x{:08x} rn={} base=0x{:x} addr=0x{:x} membase=0x{:x} vec={}",
                    op, rn, base, addr, self.mem.as_ref().map(|m| m.base).unwrap_or(0), is_vector);
            }
            if is_vector {
                // SIMD&FP unsigned offset load/store; size+opc<<... determine width
                let width_log = size | (((opc >> 1) & 1) << 2);
                let n = 1usize << width_log; // 1,2,4,8,16
                let is_load = (opc & 1) == 1;
                if is_load {
                    let val = match n {
                        16 => self.mem.as_mut().unwrap().read128(addr)?,
                        _ => self.mem.as_mut().unwrap().read(addr, n)? as u128,
                    };
                    self.v[rt as usize] = val;
                } else {
                    let val = self.v[rt as usize];
                    match n {
                        16 => self.mem.as_mut().unwrap().write128(addr, val)?,
                        _ => self.mem.as_mut().unwrap().write(addr, n, val as u64)?,
                    }
                }
                return Ok(());
            }
            let n = 1usize << size;
            // Precise: opc 00=STR, 01=LDR, 10=LDRS(64-dest), 11=LDRS(32-dest).
            // Read any source register BEFORE borrowing `self.mem` mutably.
            match opc {
                0b00 => { // STR
                    let val = if size == 3 { self.xr(rt) } else { self.wr(rt) };
                    self.mem.as_mut().unwrap().write(addr, n, val)?;
                }
                0b01 => { // LDR (zero-extend)
                    let v = self.mem.as_mut().unwrap().read(addr, n)?;
                    self.setx(rt, v, size != 3);
                }
                0b10 => { // LDRS -> sign-extend to 64
                    let v = self.mem.as_mut().unwrap().read(addr, n)?;
                    let sv = sign_extend(v, 8 * n);
                    self.setx(rt, sv, false);
                }
                0b11 => { // LDRS -> sign-extend to 32
                    let v = self.mem.as_mut().unwrap().read(addr, n)?;
                    let sv = sign_extend(v, 8 * n) & 0xFFFF_FFFF;
                    self.setx(rt, sv, true);
                }
                _ => return Err(StepErr::Unsupported(op)),
            }
            return Ok(());
        }

        Err(StepErr::Unsupported(op))
    }

    // ── NEON / SIMD / scalar FP ──────────────────────────────────────────────
    // Returns Some(result) when handled, None to fall through to other groups.
    fn try_simd_fp(&mut self, op: u32) -> Result<Option<Result<(), StepErr>>, StepErr> {
        // Scalar FP data-processing (2 source): 0001 1110 ftype 1 Rm opcode 10 Rn Rd
        // FMUL/FDIV/FADD/FSUB/FMAX/FMIN/FMAXNM/FMINNM/FNMUL — delegate to the
        // shared `fp_scalar_2src` (spec-literal, IEEE-754 host arithmetic).
        if (op & 0xFF20_0C00) == 0x1E20_0800 {
            let ftype = (op >> 22) & 0x3; // 00=S,01=D
            let rm = (op >> 16) & 0x1F;
            let opcode = (op >> 12) & 0xF;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            match fp_scalar_2src(ftype, opcode, self.v[rn as usize], self.v[rm as usize]) {
                Some(bits) => {
                    self.v[rd as usize] = bits; // scalar write zeros upper bits
                    return Ok(Some(Ok(())));
                }
                None => return Ok(Some(Err(StepErr::Unsupported(op)))),
            }
        }

        // Advanced SIMD three same (vector): 0Q00_1110_size_1_Rm_opc_1_Rn_Rd
        // ARM ARM C4.1.6 "Advanced SIMD three same". opcode = bits[15:11].
        // Covers ADD/SUB, MUL/MLA/MLS, {S,U}{MAX,MIN}, {S,U}ABD, {S,U}HADD/HSUB,
        // ADDP, {S,U}SHL, integer compares, bitwise (AND/BIC/ORR/ORN/EOR/BSL/BIT/
        // BIF), CMTST, and the FP three-same subgroup (opcodes 0x18..0x1F).
        if (op & 0x9F20_0400) == 0x0E20_0400 {
            let q = (op >> 30) & 1;
            let u = (op >> 29) & 1;
            let size = (op >> 22) & 0x3;
            let rm = (op >> 16) & 0x1F;
            let opcode = (op >> 11) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let a = self.v[rn as usize];
            let b = self.v[rm as usize];
            let lanes = if q == 1 { 16 >> size } else { 8 >> size };
            let esize = 8usize << size; // bits per element
            let dbl = q == 1; // 128-bit (true) vs 64-bit (false)

            // ── FP three-same (opcodes 0x18..0x1F). bit23(size>>1) = add/sub |
            //    max/min | maxnm/minnm | mla/mls selector; bit22(size&1) = sz
            //    (0=single .2s/.4s, 1=double .2d). ─────────────────────────────
            if opcode >= 0x18 {
                let is_double = (size & 1) == 1;
                let hi23 = size >> 1;
                let felem = if is_double { 64 } else { 32 };
                let flanes = if q == 1 { 128 / felem } else { 64 / felem };
                let mut res: u128 = 0;
                for lane in 0..flanes {
                    let ea = lane_get(a, lane, felem);
                    let eb = lane_get(b, lane, felem);
                    // FMLA/FMLS (opcode 0b11001) accumulate into Vd; sub = bit23.
                    let bits = if opcode == 0b11001 {
                        let ed = lane_get(self.v[rd as usize], lane, felem);
                        fp_mla_lane(ed, ea, eb, is_double, hi23 == 1)
                    } else {
                        match fp_three_same(opcode, u, hi23, is_double, ea, eb) {
                            Some(x) => x,
                            None => return Ok(Some(Err(StepErr::Unsupported(op)))),
                        }
                    };
                    res |= (bits & lane_mask(felem)) << (lane * felem);
                }
                self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                return Ok(Some(Ok(())));
            }

            // ── whole-register bitwise (opcode 0x03) incl. BSL/BIT/BIF ──────────
            // Vn = a(Rn), Vm = b(Rm), Vd = d (pre-existing dest, read for the
            // select ops). Truth-table forms (spec-literal, ARM ARM C7):
            //   AND  = a & b               BIC = a & ~b
            //   ORR  = a | b               ORN = a | ~b
            //   EOR  = a ^ b
            //   BSL  = bit? Vn : Vm  where sel=Vd  => (d & a) | (!d & b)
            //   BIT  = insert Vn where Vm=1        => (b & a) | (!b & d)
            //   BIF  = insert Vn where Vm=0        => (!b & a) | (b & d)
            if opcode == 0b00011 {
                let d = self.v[rd as usize];
                let r = match (u, size) {
                    (0, 0b00) => a & b,              // AND
                    (0, 0b01) => a & !b,             // BIC
                    (0, 0b10) => a | b,              // ORR
                    (0, 0b11) => a | !b,             // ORN
                    (1, 0b00) => a ^ b,              // EOR
                    (1, 0b01) => (d & a) | (!d & b), // BSL
                    (1, 0b10) => (b & a) | (!b & d), // BIT
                    (1, 0b11) => (!b & a) | (b & d), // BIF
                    _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
                };
                self.v[rd as usize] = mask_reg(r, dbl);
                return Ok(Some(Ok(())));
            }

            // ── pairwise ops that gather across the a:b concat: ADDP (0x17,U=0),
            //    SMAXP/UMAXP (0x14), SMINP/UMINP (0x15). Output lane `out` takes
            //    the reduce of adjacent pair (2*pair, 2*pair+1) — first half from
            //    Vn, second half from Vm. ────────────────────────────────────────
            if opcode == 0b10111 || opcode == 0b10100 || opcode == 0b10101 {
                let mut res: u128 = 0;
                let total = lanes; // output lanes == input lanes
                for out in 0..total {
                    let (src, pair) = if out < total / 2 {
                        (a, out)
                    } else {
                        (b, out - total / 2)
                    };
                    let lo = lane_get(src, 2 * pair, esize);
                    let hi = lane_get(src, 2 * pair + 1, esize);
                    let s = match (opcode, u) {
                        (0b10111, 0) => lo.wrapping_add(hi),                       // ADDP
                        (0b10100, 0) => if s_cmp(lo, hi, esize) == std::cmp::Ordering::Greater { lo } else { hi }, // SMAXP
                        (0b10100, 1) => if lo > hi { lo } else { hi },             // UMAXP
                        (0b10101, 0) => if s_cmp(lo, hi, esize) == std::cmp::Ordering::Less { lo } else { hi },    // SMINP
                        (0b10101, 1) => if lo < hi { lo } else { hi },             // UMINP
                        _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
                    };
                    res |= (s & lane_mask(esize)) << (out * esize);
                }
                self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                return Ok(Some(Ok(())));
            }

            let mut res: u128 = 0;
            for lane in 0..lanes {
                let ea = lane_get(a, lane, esize);
                let eb = lane_get(b, lane, esize);
                let ed = lane_get(self.v[rd as usize], lane, esize);
                let r = match (opcode, u) {
                    // ADD (u=0) / SUB (u=1). opcode 0b10000.
                    (0b10000, 0) => ea.wrapping_add(eb),
                    (0b10000, 1) => ea.wrapping_sub(eb),
                    // MUL (0b10011,u=0); PMUL (u=1) not modelled here.
                    (0b10011, 0) => ea.wrapping_mul(eb),
                    // MLA (0b10010,u=0): Vd += Vn*Vm.  MLS (u=1): Vd -= Vn*Vm.
                    (0b10010, 0) => ed.wrapping_add(ea.wrapping_mul(eb)),
                    (0b10010, 1) => ed.wrapping_sub(ea.wrapping_mul(eb)),
                    // SMAX/UMAX (0b01100), SMIN/UMIN (0b01101).
                    (0b01100, 0) => if s_cmp(ea, eb, esize) == std::cmp::Ordering::Greater { ea } else { eb }, // SMAX
                    (0b01100, 1) => if ea > eb { ea } else { eb }, // UMAX
                    (0b01101, 0) => if s_cmp(ea, eb, esize) == std::cmp::Ordering::Less { ea } else { eb }, // SMIN
                    (0b01101, 1) => if ea < eb { ea } else { eb }, // UMIN
                    // SMAXP/UMAXP (0b10100), SMINP/UMINP (0b10101) — pairwise; but
                    // those need the pairwise gather, handled below via unreachable.
                    // {S,U}ABD (0b01110): absolute difference.
                    (0b01110, 0) => { // SABD (signed)
                        let x = s_ext_i128(ea, esize);
                        let y = s_ext_i128(eb, esize);
                        (x - y).unsigned_abs() as u128
                    }
                    (0b01110, 1) => { // UABD (unsigned)
                        if ea >= eb { ea - eb } else { eb - ea }
                    }
                    // {S,U}HADD (0b00000): halving add = (a+b)>>1 (arith/logical).
                    (0b00000, 0) => { // SHADD
                        let x = s_ext_i128(ea, esize);
                        let y = s_ext_i128(eb, esize);
                        ((x + y) >> 1) as u128
                    }
                    (0b00000, 1) => { // UHADD
                        (ea + eb) >> 1
                    }
                    // {S,U}HSUB (0b00100): halving subtract = (a-b)>>1.
                    (0b00100, 0) => { // SHSUB
                        let x = s_ext_i128(ea, esize);
                        let y = s_ext_i128(eb, esize);
                        ((x - y) >> 1) as u128
                    }
                    (0b00100, 1) => { // UHSUB
                        // (a - b) as signed >> 1, but values are unsigned; use i128.
                        (((ea as i128) - (eb as i128)) >> 1) as u128
                    }
                    // {S,U}SHL (0b01000): register (variable) shift, low byte of Vm
                    //   is a signed shift count per lane. Positive => left; negative
                    //   => right (arith for S, logical for U).
                    (0b01000, 0) => simd_sshl(ea, eb, esize), // SSHL
                    (0b01000, 1) => simd_ushl(ea, eb, esize), // USHL
                    // Integer compares (result = all-ones or all-zeros per lane):
                    (0b00110, 0) => { // CMGT — signed a > b
                        if s_cmp(ea, eb, esize) == std::cmp::Ordering::Greater { lane_mask(esize) } else { 0 }
                    }
                    (0b00110, 1) => { // CMHI — UNSIGNED a > b (the historical bug)
                        let gt = if buggy_cmhi() {
                            // Reconstruct the defect: signed compare instead of unsigned.
                            s_cmp(ea, eb, esize) == std::cmp::Ordering::Greater
                        } else {
                            ea > eb // architecturally-correct unsigned compare
                        };
                        if gt { lane_mask(esize) } else { 0 }
                    }
                    (0b00111, 0) => { // CMGE — signed a >= b
                        if s_cmp(ea, eb, esize) != std::cmp::Ordering::Less { lane_mask(esize) } else { 0 }
                    }
                    (0b00111, 1) => { // CMHS — unsigned a >= b
                        if ea >= eb { lane_mask(esize) } else { 0 }
                    }
                    (0b10001, 0) => { // CMTST — (a & b) != 0
                        if (ea & eb) != 0 { lane_mask(esize) } else { 0 }
                    }
                    (0b10001, 1) => { // CMEQ — a == b (u=1)
                        if ea == eb { lane_mask(esize) } else { 0 }
                    }
                    _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
                };
                res |= (r & lane_mask(esize)) << (lane * esize);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // DUP (element/general): 0Q00_1110_000_imm5_0_0001_1_Rn_Rd (DUP general)
        // DUP Vd.T, Rn  (general reg) : op[31:21]... imm5 selects size.
        if (op & 0x9FE0_FC00) == 0x0E00_0C00 {
            let q = (op >> 30) & 1;
            let imm5 = (op >> 16) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let (esize, _idx) = dup_size(imm5).ok_or(StepErr::Unsupported(op))?;
            let src = self.xr(rn) as u128 & lane_mask(esize);
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };
            let mut res: u128 = 0;
            for lane in 0..lanes {
                res |= src << (lane * esize);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── SIMD two-register misc (unified int + FP subgroup) ──────────────────
        // Encoding: 0 Q U 01110 size 10000 opcode 10 Rn Rd  (bits[16:12]=10000).
        // Int opcodes: ABS/NEG(0x0B), CMGT/CMGE#0(0x08), CMEQ/CMLE#0(0x09),
        //   CMLT#0(0x0A), {S,U}ADDLP(0x02), XTN(0x12).
        // FP opcodes: FCMGT0(0x0C), FCMEQ0(0x0D), FCMLT0/FCMLE0(0x0E),
        //   FABS/FNEG(0x0F), FRINTN/FRINTM(0x18), FRINTP/FRINTZ(0x19),
        //   FCVTNS.. / FCVTMS.. (0x1A), FCVTZS/FCVTZU(0x1B), SCVTF/UCVTF(0x1D),
        //   FRINTA... , FSQRT(0x1F). We disambiguate int vs FP purely by opcode
        //   (the two opcode sets are disjoint) so ABS.2d (size=11) is unambiguous.
        if (op & 0x9F3E_0C00) == 0x0E20_0800 {
            let q = (op >> 30) & 1;
            let u = (op >> 29) & 1;
            let size = (op >> 22) & 0x3;
            let opcode = (op >> 12) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let a = self.v[rn as usize];

            // FP subgroup: opcodes >= 0x0C route to FP handling (sz = size bit0).
            let is_fp_opcode = matches!(opcode,
                0b01100 | 0b01101 | 0b01110 | 0b01111 |          // FCMxx0 / FABS / FNEG
                0b11000 | 0b11001 | 0b11010 | 0b11011 |          // FRINT / FCVT
                0b11100 | 0b11101 | 0b11110 | 0b11111);          // FCVTxU / SCVTF / FRINTx / FSQRT
            if is_fp_opcode {
                let sz = (size & 1) as u32; // 0=single,1=double
                let felem = if sz == 1 { 64 } else { 32 };
                let lanes = if q == 1 { 128 / felem } else { 64 / felem };
                let mut res = 0u128;
                for lane in 0..lanes {
                    let bits = lane_get(a, lane, felem);
                    // FP compare vs #0 opcodes (0x0C..0x0E) produce a lane mask.
                    let out = if opcode == 0b01100 || opcode == 0b01101 || opcode == 0b01110 {
                        match fp_cmp_zero(opcode, u, sz == 1, bits) {
                            Some(true) => Some(lane_mask(felem)),
                            Some(false) => Some(0),
                            None => None,
                        }
                    } else {
                        fp_misc_unary(opcode, u, sz == 1, bits).map(|x| x & lane_mask(felem))
                    };
                    match out {
                        Some(x) => res |= x << (lane * felem),
                        None => return Ok(Some(Err(StepErr::Unsupported(op)))),
                    }
                }
                self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                return Ok(Some(Ok(())));
            }

            let esize = 8usize << size;
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };

            // {S,U}ADDLP (opcode 0b00010): pairwise add long (widens ×2).
            //   SADDLP (U=0) sign-extends, UADDLP (U=1) zero-extends the pair.
            if opcode == 0b00010 {
                let out_esize = esize * 2;
                let out_lanes = lanes / 2;
                let mut res: u128 = 0;
                for out in 0..out_lanes {
                    let lo = lane_get(a, 2 * out, esize);
                    let hi = lane_get(a, 2 * out + 1, esize);
                    let s = if u == 0 {
                        (s_ext_i128(lo, esize) + s_ext_i128(hi, esize)) as u128
                    } else {
                        lo + hi
                    };
                    res |= (s & lane_mask(out_esize)) << (out * out_esize);
                }
                self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                return Ok(Some(Ok(())));
            }

            // XTN / XTN2 (opcode 0b10010, U=0): narrow — truncate each wide lane
            //   to half width. `size` selects the *source* (wide) element: 00->16,
            //   01->32, 10->64.  Q=0 -> lower half; Q=1 (XTN2) -> upper half.
            if opcode == 0b10010 && u == 0 {
                let src_esz = 16usize << size; // 16/32/64
                let dst_esz = src_esz / 2;
                let n_out = 64 / dst_esz;
                let mut narrow = 0u128;
                for lane in 0..n_out {
                    let ea = lane_get(a, lane, src_esz);
                    narrow |= (ea & lane_mask(dst_esz)) << (lane * dst_esz);
                }
                if q == 0 {
                    self.v[rd as usize] = narrow & u128_lo64_mask();
                } else {
                    let lo = self.v[rd as usize] & u128_lo64_mask();
                    self.v[rd as usize] = lo | (narrow << 64);
                }
                return Ok(Some(Ok(())));
            }

            let mut res: u128 = 0;
            for lane in 0..lanes {
                let ea = lane_get(a, lane, esize);
                let r = match (opcode, u) {
                    // ABS (0b01011,U=0): absolute value (signed).
                    (0b01011, 0) => {
                        let x = s_ext_i128(ea, esize);
                        x.unsigned_abs() as u128
                    }
                    // NEG (0b01011,U=1): negate (two's complement).
                    (0b01011, 1) => (ea as i128).wrapping_neg() as u128,
                    // CMxx against #0. CMGT 0b01000(U=0), CMEQ 0b01001(U=0),
                    //   CMLT 0b01010(U=0), CMGE 0b01000(U=1), CMLE 0b01001(U=1).
                    (0b01000, 0) => if s_ext_i128(ea, esize) > 0 { lane_mask(esize) } else { 0 }, // CMGT #0
                    (0b01001, 0) => if ea == 0 { lane_mask(esize) } else { 0 },                    // CMEQ #0
                    (0b01010, 0) => if s_ext_i128(ea, esize) < 0 { lane_mask(esize) } else { 0 },   // CMLT #0
                    (0b01000, 1) => if s_ext_i128(ea, esize) >= 0 { lane_mask(esize) } else { 0 },  // CMGE #0
                    (0b01001, 1) => if s_ext_i128(ea, esize) <= 0 { lane_mask(esize) } else { 0 },  // CMLE #0
                    _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
                };
                res |= (r & lane_mask(esize)) << (lane * esize);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── SIMD shift by immediate: SHL/SSHR/USHR/SSRA/USRA/SLI/SRI/SHRN/
        //    {S,U}SHLL. Encoding: 0 Q U 011110 immh immb opcode 1 Rn Rd. ─────────
        if (op & 0x9F80_0400) == 0x0F00_0400 {
            let q = (op >> 30) & 1;
            let u = (op >> 29) & 1;
            let immh = (op >> 19) & 0xF;
            let immb = (op >> 16) & 0x7;
            let opcode = (op >> 11) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            if immh == 0 {
                return Ok(Some(Err(StepErr::Unsupported(op)))); // that's MODI, not shift
            }
            let a = self.v[rn as usize];

            // esize from immh: highest set bit picks 8/16/32/64.
            let (esize, shift_amt_left, shift_amt_right) = shift_imm_params(immh, immb);

            match opcode {
                // SHL (0b01010, U=0): left shift by imm.  SLI (0b01010, U=1):
                //   shift-left-insert (keeps the low `sh` bits of Rd).
                0b01010 => {
                    let esz = esize;
                    let lanes = if q == 1 { 128 / esz } else { 64 / esz };
                    let sh = shift_amt_left;
                    let is_sli = u == 1;
                    let d = self.v[rd as usize];
                    let mut res = 0u128;
                    for lane in 0..lanes {
                        let ea = lane_get(a, lane, esz);
                        let shifted = (ea << sh) & lane_mask(esz);
                        let r = if is_sli {
                            let ed = lane_get(d, lane, esz);
                            let keep = if sh == 0 { 0 } else { (1u128 << sh) - 1 };
                            shifted | (ed & keep)
                        } else {
                            shifted
                        };
                        res |= (r & lane_mask(esz)) << (lane * esz);
                    }
                    self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                    return Ok(Some(Ok(())));
                }
                // SSHR (0b00000,U=0) / USHR (0b00000,U=1): right shift.
                // SSRA (0b00010,U=0) / USRA (0b00010,U=1): shift-right-accumulate.
                0b00000 | 0b00010 => {
                    let esz = esize;
                    let lanes = if q == 1 { 128 / esz } else { 64 / esz };
                    let sh = shift_amt_right;
                    let accumulate = opcode == 0b00010;
                    let d = self.v[rd as usize];
                    let mut res = 0u128;
                    for lane in 0..lanes {
                        let ea = lane_get(a, lane, esz);
                        // Right-shift amount `sh` is in 1..=esize (esize ≤ 64, so
                        // no i128/u128 UB). SSHR fills with the sign bit, USHR 0.
                        let shifted = if u == 0 {
                            let x = s_ext_i128(ea, esz); // arithmetic (sign) shift
                            (x >> sh) as u128 & lane_mask(esz)
                        } else {
                            (ea >> sh) & lane_mask(esz)
                        };
                        let r = if accumulate {
                            (lane_get(d, lane, esz).wrapping_add(shifted)) & lane_mask(esz)
                        } else {
                            shifted
                        };
                        res |= r << (lane * esz);
                    }
                    self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                    return Ok(Some(Ok(())));
                }
                // SRI (0b01000,U=1): shift-right-insert (keeps top `sh` bits of Rd).
                0b01000 if u == 1 => { // SRI
                    let esz = esize;
                    let lanes = if q == 1 { 128 / esz } else { 64 / esz };
                    let sh = shift_amt_right;
                    let d = self.v[rd as usize];
                    let mut res = 0u128;
                    for lane in 0..lanes {
                        let ea = lane_get(a, lane, esz);
                        let ed = lane_get(d, lane, esz);
                        // keep top `sh` bits of destination, insert shifted source.
                        let keepmask = if sh == 0 {
                            0
                        } else if sh >= esz as u32 {
                            lane_mask(esz)
                        } else {
                            (lane_mask(esz) << (esz as u32 - sh)) & lane_mask(esz)
                        };
                        let r = ((ea >> sh) & lane_mask(esz)) | (ed & keepmask);
                        res |= (r & lane_mask(esz)) << (lane * esz);
                    }
                    self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
                    return Ok(Some(Ok(())));
                }
                // Narrowing shift-right family (opcode 0b10000..=0b10011). For
                //   narrowing, immh encodes the *destination* (narrow) element;
                //   the source is twice as wide. `shift_amt_right` = 2*dst - immhb.
                //   Writes the LOWER half (Q=0) or UPPER half (Q=1 -> the `2`
                //   variant, e.g. SHRN2/SQSHRUN2). The (opcode,U) pair selects
                //   rounding + signedness — spec-literal from the ARM ARM
                //   C7.2.x (matches the DBT decoder dp_simd_fp::decode_simd_shrn_sat):
                //
                //     opcode\U   U=0                    U=1
                //     10000      SHRN   (modular)       SQSHRUN  (S src → U dst, sat)
                //     10001      RSHRN  (modular,round)  SQRSHRUN (S src → U dst, sat, round)
                //     10010      SQSHRN (S → S, sat)     UQSHRN   (U → U, sat)
                //     10011      SQRSHRN(S → S, sat,rnd) UQRSHRN  (U → U, sat, round)
                //
                //   Plain SHRN/RSHRN are MODULAR (no saturation) — the shifted
                //   value is simply truncated to the narrow width. The saturating
                //   variants clamp: SQSHRN/SQRSHRN to the signed dst range,
                //   UQSHRN/UQRSHRN to [0, UINT_MAX], and SQSHRUN/SQRSHRUN take a
                //   SIGNED source value and clamp it into the UNSIGNED dst range —
                //   so NEGATIVE source lanes saturate to 0 (not wrap).
                0b10000 | 0b10001 | 0b10010 | 0b10011 => {
                    let dst_esz = esize;      // 8/16/32 (narrow) — immh picks this
                    let src_esz = esize * 2;  // 16/32/64 (wide)
                    let sh = shift_amt_right; // 1..=src_esz
                    // (round, saturate, src_signed, dst_signed) per (opcode, U).
                    let (round, saturate, src_signed, dst_signed) = match (opcode, u) {
                        (0b10000, 0) => (false, false, false, false), // SHRN    (modular)
                        (0b10000, 1) => (false, true, true, false),   // SQSHRUN  (S→U)
                        (0b10001, 0) => (true, false, false, false),  // RSHRN   (modular, round)
                        (0b10001, 1) => (true, true, true, false),    // SQRSHRUN (S→U, round)
                        (0b10010, 0) => (false, true, true, true),    // SQSHRN   (S→S)
                        (0b10010, 1) => (false, true, false, false),  // UQSHRN   (U→U)
                        (0b10011, 0) => (true, true, true, true),     // SQRSHRN  (S→S, round)
                        (0b10011, 1) => (true, true, false, false),   // UQRSHRN  (U→U, round)
                        _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
                    };
                    // Destination clamp bounds (as i128) for the narrow width.
                    let (dst_min, dst_max): (i128, i128) = if dst_signed {
                        let half = 1i128 << (dst_esz - 1);
                        (-half, half - 1)
                    } else {
                        (0, (1i128 << dst_esz) - 1)
                    };
                    let n_out = 64 / dst_esz;      // narrow output fills 64 bits
                    let mut narrow = 0u128;
                    for lane in 0..n_out {
                        let ea = lane_get(a, lane, src_esz);
                        // Read the source element with the correct signedness, add
                        // the rounding bias, then shift right. Use i128 so the
                        // (widened) intermediate never overflows before clamping.
                        let src_val: i128 = if src_signed {
                            s_ext_i128(ea, src_esz)
                        } else {
                            ea as i128
                        };
                        let biased = if round && sh > 0 {
                            src_val + (1i128 << (sh - 1))
                        } else {
                            src_val
                        };
                        // Arithmetic shift for a signed source, logical for
                        // unsigned (biased ≥ 0 in the unsigned case, so `>>` on
                        // i128 is exact).
                        let shifted = biased >> sh;
                        let r: u128 = if saturate {
                            let clamped = shifted.clamp(dst_min, dst_max);
                            (clamped as u128) & lane_mask(dst_esz)
                        } else {
                            // Modular (SHRN/RSHRN): truncate to the narrow width.
                            (shifted as u128) & lane_mask(dst_esz)
                        };
                        narrow |= r << (lane * dst_esz);
                    }
                    // Q=0 writes lower 64 bits (upper cleared); Q=1 (the `2` form)
                    // writes the UPPER 64 bits, preserving the lower half of Rd.
                    if q == 0 {
                        self.v[rd as usize] = narrow & u128_lo64_mask();
                    } else {
                        let lo = self.v[rd as usize] & u128_lo64_mask();
                        self.v[rd as usize] = lo | (narrow << 64);
                    }
                    return Ok(Some(Ok(())));
                }
                // {S,U}SHLL (0b10100): shift left long (widens ×2). USHLL/SSHLL;
                //   with shift 0 it's the {U,S}XTL zero/sign-extend alias.
                0b10100 => {
                    let src_esz = esize;        // per immh this is the *narrow* size
                    // For SSHLL/USHLL immh encodes the source (narrow) esize.
                    let dst_esz = src_esz * 2;
                    let sh = shift_amt_left;
                    // Q selects which 64-bit half of the source to read: the base
                    // form (Q=0) widens the LOW 64 bits, the `2` form (Q=1) widens
                    // the HIGH 64 bits.
                    let base_lane = if q == 1 { 64 / src_esz } else { 0 };
                    // A widening long always writes a FULL 128-bit destination:
                    // `n` narrow source lanes (from one 64-bit half) become `n`
                    // wide lanes spanning all 128 bits. So out_lanes = 128/dst_esz
                    // (== 64/src_esz), NOT 64/dst_esz (which filled only the low
                    // half and left the top 64 bits zero — the R1 reference bug).
                    let out_lanes = 128 / dst_esz;
                    let mut res = 0u128;
                    for out in 0..out_lanes {
                        let ea = lane_get(a, base_lane + out, src_esz);
                        let widened = if u == 0 {
                            (s_ext_i128(ea, src_esz) as u128) & lane_mask(dst_esz)
                        } else {
                            ea & lane_mask(dst_esz)
                        };
                        let r = (widened << sh) & lane_mask(dst_esz);
                        res |= r << (out * dst_esz);
                    }
                    self.v[rd as usize] = res; // long result is always 128-bit
                    return Ok(Some(Ok(())));
                }
                _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
            }
        }

        // ── EXT: 0 Q 101110 00 0 Rm 0 imm4 0 Rn Rd (byte extract from a:b) ──────
        if (op & 0xBFE0_8400) == 0x2E00_0000 {
            let q = (op >> 30) & 1;
            let rm = (op >> 16) & 0x1F;
            let imm4 = (op >> 11) & 0xF;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let a = self.v[rn as usize];
            let b = self.v[rm as usize];
            let nbytes = if q == 1 { 16usize } else { 8 };
            let idx = imm4 as usize;
            if idx >= nbytes {
                return Ok(Some(Err(StepErr::Unsupported(op)))); // reserved for this Q
            }
            // Concatenate Vn:Vm (Vn low), take `nbytes` bytes starting at byte idx.
            let mut res = 0u128;
            for out in 0..nbytes {
                let src_byte = idx + out;
                let byte = if q == 1 {
                    if src_byte < 16 { (a >> (src_byte * 8)) & 0xFF } else { (b >> ((src_byte - 16) * 8)) & 0xFF }
                } else {
                    // 64-bit: concat low 8 bytes of a then low 8 of b.
                    if src_byte < 8 { (a >> (src_byte * 8)) & 0xFF } else { (b >> ((src_byte - 8) * 8)) & 0xFF }
                };
                res |= byte << (out * 8);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── ZIP/UZP/TRN: 0 Q 0 01110 size 0 Rm 0 opcode 10 Rn Rd ───────────────
        // opcode (bits[14:12]): 001=UZP1, 010=TRN1, 011=ZIP1, 101=UZP2, 110=TRN2,
        //   111=ZIP2.
        if (op & 0xBF20_8C00) == 0x0E00_0800 {
            let q = (op >> 30) & 1;
            let size = (op >> 22) & 0x3;
            let rm = (op >> 16) & 0x1F;
            let opcode = (op >> 12) & 0x7;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let a = self.v[rn as usize];
            let b = self.v[rm as usize];
            let esize = 8usize << size;
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };
            let mut res = 0u128;
            match opcode {
                0b011 | 0b111 => { // ZIP1 / ZIP2 — interleave
                    let part = if opcode == 0b111 { lanes / 2 } else { 0 };
                    for i in 0..(lanes / 2) {
                        let ea = lane_get(a, part + i, esize);
                        let eb = lane_get(b, part + i, esize);
                        res |= (ea & lane_mask(esize)) << ((2 * i) * esize);
                        res |= (eb & lane_mask(esize)) << ((2 * i + 1) * esize);
                    }
                }
                0b001 | 0b101 => { // UZP1 / UZP2 — deinterleave (even/odd)
                    let start = if opcode == 0b101 { 1 } else { 0 };
                    for i in 0..lanes {
                        let src_idx = start + 2 * i;
                        let e = if src_idx < lanes {
                            lane_get(a, src_idx, esize)
                        } else {
                            lane_get(b, src_idx - lanes, esize)
                        };
                        res |= (e & lane_mask(esize)) << (i * esize);
                    }
                }
                0b010 | 0b110 => { // TRN1 / TRN2 — transpose
                    let off = if opcode == 0b110 { 1 } else { 0 };
                    for i in 0..(lanes / 2) {
                        let ea = lane_get(a, 2 * i + off, esize);
                        let eb = lane_get(b, 2 * i + off, esize);
                        res |= (ea & lane_mask(esize)) << ((2 * i) * esize);
                        res |= (eb & lane_mask(esize)) << ((2 * i + 1) * esize);
                    }
                }
                _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── TBL/TBX: 0 Q 001110 000 Rm 0 len op 00 Rn Rd ───────────────────────
        // len (bits[14:13]) => 1..4 tables (consecutive Vn..). op(bit12): 0=TBL,
        //   1=TBX. Index byte >= 16*len -> TBL writes 0, TBX keeps dst byte.
        if (op & 0xBFE0_8C00) == 0x0E00_0000 {
            let q = (op >> 30) & 1;
            let rm = (op >> 16) & 0x1F;
            let len = ((op >> 13) & 0x3) as usize + 1; // 1..4
            let is_tbx = ((op >> 12) & 1) == 1;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let idxv = self.v[rm as usize];
            let dst = self.v[rd as usize];
            let table_bytes = 16 * len;
            let nbytes = if q == 1 { 16usize } else { 8 };
            // Gather table registers Vn, Vn+1, ... (wrap mod 32).
            let mut table = [0u8; 64];
            for t in 0..len {
                let reg = self.v[((rn as usize) + t) % 32];
                for byte in 0..16 {
                    table[t * 16 + byte] = ((reg >> (byte * 8)) & 0xFF) as u8;
                }
            }
            let mut res = 0u128;
            for out in 0..nbytes {
                let index = ((idxv >> (out * 8)) & 0xFF) as usize;
                let byte = if index < table_bytes {
                    table[index] as u128
                } else if is_tbx {
                    (dst >> (out * 8)) & 0xFF
                } else {
                    0
                };
                res |= byte << (out * 8);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── DUP (element): 0 Q 0 01110000 imm5 0 0000 1 Rn Rd ──────────────────
        if (op & 0xBFE0_FC00) == 0x0E00_0400 {
            let q = (op >> 30) & 1;
            let imm5 = (op >> 16) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let (esize, index) = dup_size(imm5).ok_or(StepErr::Unsupported(op))?;
            let elem = lane_get(self.v[rn as usize], index, esize);
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };
            let mut res = 0u128;
            for lane in 0..lanes {
                res |= (elem & lane_mask(esize)) << (lane * esize);
            }
            self.v[rd as usize] = if q == 1 { res } else { res & u128_lo64_mask() };
            return Ok(Some(Ok(())));
        }

        // ── INS (element): 0 1 101110 000 imm5 0 imm4 1 Rn Rd (Vd[i]<-Vn[j]) ────
        if (op & 0xFFE0_8400) == 0x6E00_0400 {
            let imm5 = (op >> 16) & 0x1F;
            let imm4 = (op >> 11) & 0xF;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let (esize, dst_idx) = dup_size(imm5).ok_or(StepErr::Unsupported(op))?;
            // src index from imm4 within the same esize.
            let src_idx = (imm4 >> (esize.trailing_zeros() - 3)) as usize;
            let elem = lane_get(self.v[rn as usize], src_idx, esize);
            let mut d = self.v[rd as usize];
            let shift = dst_idx * esize;
            d &= !(lane_mask(esize) << shift);
            d |= (elem & lane_mask(esize)) << shift;
            self.v[rd as usize] = d;
            return Ok(Some(Ok(())));
        }

        // ── INS (general): 0 1 001110 000 imm5 0 0011 1 Rn Rd (Vd[i]<-Xn) ───────
        if (op & 0xFFE0_FC00) == 0x4E00_1C00 {
            let imm5 = (op >> 16) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let (esize, dst_idx) = dup_size(imm5).ok_or(StepErr::Unsupported(op))?;
            let elem = (self.xr(rn) as u128) & lane_mask(esize);
            let mut d = self.v[rd as usize];
            let shift = dst_idx * esize;
            d &= !(lane_mask(esize) << shift);
            d |= elem << shift;
            self.v[rd as usize] = d;
            return Ok(Some(Ok(())));
        }

        // ── UMOV/SMOV: 0 Q 0 01110000 imm5 0 opc 1 Rn Rd (opc=0111 UMOV,0101 SMOV)
        if (op & 0xBFE0_FC00) == 0x0E00_3C00 || (op & 0xBFE0_FC00) == 0x0E00_2C00 {
            let q = (op >> 30) & 1;
            let imm5 = (op >> 16) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let is_smov = (op & 0xBFE0_FC00) == 0x0E00_2C00;
            let (esize, index) = dup_size(imm5).ok_or(StepErr::Unsupported(op))?;
            let elem = lane_get(self.v[rn as usize], index, esize);
            let is32 = q == 0;
            if is_smov {
                let sv = s_ext_i128(elem, esize) as u64;
                self.setx(rd, if is32 { sv & 0xFFFF_FFFF } else { sv }, is32);
            } else {
                // UMOV: with q==1 and esize==64 it's a 64-bit move; else 32-bit.
                self.setx(rd, elem as u64, is32);
            }
            return Ok(Some(Ok(())));
        }

        // ── Across-lane: ADDV / {S,U}ADDLV / {S,U}{MAX,MIN}V. ───────────────────
        // 0 Q U 01110 size 11000 opcode 10 Rn Rd. opcode 0b11011=ADDV;
        //   0b00011={S,U}ADDLV (widen×2); 0b01010=SMAXV(U=0)/UMAXV(U=1);
        //   0b11010=SMINV(U=0)/UMINV(U=1).
        if (op & 0x9F3E_0C00) == 0x0E30_0800 {
            let q = (op >> 30) & 1;
            let u = (op >> 29) & 1;
            let size = (op >> 22) & 0x3;
            let opcode = (op >> 12) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let esize = 8usize << size;
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };
            let a = self.v[rn as usize];
            let first = lane_get(a, 0, esize);
            match opcode {
                0b11011 => { // ADDV — sum all lanes (modular)
                    let mut s: u128 = 0;
                    for lane in 0..lanes {
                        s = s.wrapping_add(lane_get(a, lane, esize));
                    }
                    self.v[rd as usize] = s & lane_mask(esize);
                }
                0b00011 => { // {S,U}ADDLV — long add across lanes (result widened ×2)
                    let out_esize = esize * 2;
                    let mut s: i128 = 0;
                    for lane in 0..lanes {
                        let e = lane_get(a, lane, esize);
                        s = s.wrapping_add(if u == 0 { s_ext_i128(e, esize) } else { e as i128 });
                    }
                    self.v[rd as usize] = (s as u128) & lane_mask(out_esize);
                }
                0b01010 => { // SMAXV / UMAXV
                    if u == 0 {
                        let mut acc = s_ext_i128(first, esize);
                        for lane in 1..lanes {
                            let x = s_ext_i128(lane_get(a, lane, esize), esize);
                            if x > acc { acc = x; }
                        }
                        self.v[rd as usize] = (acc as u128) & lane_mask(esize);
                    } else {
                        let mut m = first;
                        for lane in 1..lanes {
                            let x = lane_get(a, lane, esize);
                            if x > m { m = x; }
                        }
                        self.v[rd as usize] = m & lane_mask(esize);
                    }
                }
                0b11010 => { // SMINV / UMINV
                    if u == 0 {
                        let mut acc = s_ext_i128(first, esize);
                        for lane in 1..lanes {
                            let x = s_ext_i128(lane_get(a, lane, esize), esize);
                            if x < acc { acc = x; }
                        }
                        self.v[rd as usize] = (acc as u128) & lane_mask(esize);
                    } else {
                        let mut m = first;
                        for lane in 1..lanes {
                            let x = lane_get(a, lane, esize);
                            if x < m { m = x; }
                        }
                        self.v[rd as usize] = m & lane_mask(esize);
                    }
                }
                _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
            }
            return Ok(Some(Ok(())));
        }

        // ── FP scalar 1-source: FABS/FNEG/FSQRT/FRINTx/FCVT(precision) ─────────
        // 0 0 0 11110 ftype 1 opcode(6) 10000 Rn Rd.  opcode(bits[20:15]):
        //   000000 FMOV, 000001 FABS, 000010 FNEG, 000011 FSQRT,
        //   0001xx FCVT (to other precision), 001000 FRINTN, 001001 FRINTP,
        //   001010 FRINTM, 001011 FRINTZ, 001100 FRINTA.
        if (op & 0xFF20_7C00) == 0x1E20_4000 {
            let ftype = (op >> 22) & 0x3; // 00=S,01=D
            let opcode6 = (op >> 15) & 0x3F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            if let Some(bits) = fp_scalar_1src(ftype, opcode6, self.v[rn as usize]) {
                self.v[rd as usize] = bits; // scalar write zeros upper bits
                return Ok(Some(Ok(())));
            }
            // else unsupported opcode — fall through to Unsupported.
        }

        // ── FP scalar 3-source: FMADD/FMSUB/FNMADD/FNMSUB ──────────────────────
        // 0001 1111 ftype o1 Rm o0 Ra Rn Rd.
        if (op & 0xFF00_0000) == 0x1F00_0000 {
            let ftype = (op >> 22) & 0x3;
            let o1 = (op >> 21) & 1;
            let rm = (op >> 16) & 0x1F;
            let o0 = (op >> 15) & 1;
            let ra = (op >> 10) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let out = fp_scalar_3src(ftype, o1, o0,
                self.v[rn as usize], self.v[rm as usize], self.v[ra as usize]);
            if let Some(bits) = out {
                self.v[rd as usize] = bits;
                return Ok(Some(Ok(())));
            }
            return Ok(Some(Err(StepErr::Unsupported(op))));
        }

        // ── FP scalar compare: FCMP/FCMPE (sets NZCV). 0001 1110 ftype 1 Rm 001000 Rn opc2 ─
        // 0001 1110 ftype 1 Rm op 1000 Rn opc  (opcode2 field bits[15:14]=00, [13:10]=1000)
        if (op & 0xFF20_FC07) == 0x1E20_2000 {
            let ftype = (op >> 22) & 0x3;
            let rm = (op >> 16) & 0x1F;
            let rn = (op >> 5) & 0x1F;
            let opc2 = (op >> 3) & 0x3; // bits[4:3]: 00=FCMP reg, 01=FCMP #0,
                                        // 10=FCMPE reg, 11=FCMPE #0
            let (a, b) = match ftype {
                0b00 => {
                    let a = f32::from_bits(self.v[rn as usize] as u32) as f64;
                    let b = if opc2 & 1 == 1 { 0.0 } else { f32::from_bits(self.v[rm as usize] as u32) as f64 };
                    (a, b)
                }
                0b01 => {
                    let a = f64::from_bits(self.v[rn as usize] as u64);
                    let b = if opc2 & 1 == 1 { 0.0 } else { f64::from_bits(self.v[rm as usize] as u64) };
                    (a, b)
                }
                _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
            };
            self.nzcv = fp_compare_nzcv(a, b);
            return Ok(Some(Ok(())));
        }

        // ── FCSEL: 0001 1110 ftype 1 Rm cond 11 Rn Rd ──────────────────────────
        if (op & 0xFF20_0C00) == 0x1E20_0C00 {
            let ftype = (op >> 22) & 0x3;
            let rm = (op >> 16) & 0x1F;
            let cond = (op >> 12) & 0xF;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            let taken = cond_holds(cond, self.nzcv);
            let src = if taken { self.v[rn as usize] } else { self.v[rm as usize] };
            let bits = match ftype {
                0b00 => src & 0xFFFF_FFFF,
                0b01 => src & u128_lo64_mask(),
                _ => return Ok(Some(Err(StepErr::Unsupported(op)))),
            };
            self.v[rd as usize] = bits;
            return Ok(Some(Ok(())));
        }

        // ── FP<->int convert (scalar): SCVTF/UCVTF/FCVTZS/FCVTZU ────────────────
        // 0 0 0 11110 ftype 1 rmode:2 opcode:3 000000 Rn Rd  (fixed 000000 in [15:10])
        if (op & 0x7F20_FC00) == 0x1E20_0000 {
            let sf = (op >> 31) & 1;
            let ftype = (op >> 22) & 0x3;
            let rmode = (op >> 19) & 0x3;
            let opcode3 = (op >> 16) & 0x7;
            let rn = (op >> 5) & 0x1F;
            let rd = op & 0x1F;
            if let Some(r) = self.fp_int_convert(sf, ftype, rmode, opcode3, rn, rd) {
                return Ok(Some(r));
            }
            // else fall through / unsupported
        }

        Ok(None)
    }

    /// FP<->int scalar convert. Returns Some(result) if the (rmode,opcode) pair is
    /// one we model (SCVTF/UCVTF/FCVTZS/FCVTZU); None otherwise (unsupported →
    /// caller falls through). `sf` selects 64/32-bit GPR width.
    fn fp_int_convert(&mut self, sf: u32, ftype: u32, rmode: u32, opcode3: u32, rn: u32, rd: u32)
        -> Option<Result<(), StepErr>>
    {
        // opcode3 (bits[18:16]) combined with rmode (bits[20:19]):
        //   FCVTZS: rmode=11 opcode=000 ; FCVTZU: rmode=11 opcode=001
        //   SCVTF : rmode=00 opcode=010 ; UCVTF : rmode=00 opcode=011
        // (Other rmode values are FCVTNS/AS/PS/MS etc — not modelled here.)
        let is64 = sf == 1;
        match (rmode, opcode3) {
            (0b00, 0b010) | (0b00, 0b011) => {
                // SCVTF (010) / UCVTF (011): GPR int -> FP.
                let signed = opcode3 == 0b010;
                let intval = if is64 { self.xr(rn) } else { self.wr(rn) };
                let bits = match ftype {
                    0b00 => {
                        let f = if signed {
                            if is64 { (intval as i64) as f32 } else { (intval as i32) as f32 }
                        } else if is64 { intval as f32 } else { (intval as u32) as f32 };
                        f.to_bits() as u128
                    }
                    0b01 => {
                        let f = if signed {
                            if is64 { (intval as i64) as f64 } else { (intval as i32) as f64 }
                        } else if is64 { intval as f64 } else { (intval as u32) as f64 };
                        f.to_bits() as u128
                    }
                    _ => return Some(Err(StepErr::Unsupported(0))),
                };
                self.v[rd as usize] = bits; // scalar write zeros upper bits
                Some(Ok(()))
            }
            (0b11, 0b000) | (0b11, 0b001) => {
                // FCVTZS (000) / FCVTZU (001): FP -> int, round toward zero.
                let signed = opcode3 == 0b000;
                let out = match ftype {
                    0b00 => {
                        let f = f32::from_bits(self.v[rn as usize] as u32);
                        fp_to_int(f as f64, signed, is64)
                    }
                    0b01 => {
                        let f = f64::from_bits(self.v[rn as usize] as u64);
                        fp_to_int(f, signed, is64)
                    }
                    _ => return Some(Err(StepErr::Unsupported(0))),
                };
                self.setx(rd, out, !is64);
                Some(Ok(()))
            }
            _ => None,
        }
    }
}

// ── shared arithmetic helpers ────────────────────────────────────────────────

fn mask_for(is32: bool) -> u64 {
    if is32 { 0xFFFF_FFFF } else { u64::MAX }
}
fn neg(v: u64, is32: bool) -> bool {
    if is32 { (v >> 31) & 1 == 1 } else { (v >> 63) & 1 == 1 }
}

/// a + b (or a - b) with NZCV. `sub` selects subtraction.
fn addsub(a: u64, b: u64, sub: bool, is32: bool) -> (u64, u64) {
    let cin = if sub { 1u64 } else { 0 };
    let bb = if sub { !b } else { b };
    addsub_carry(a, bb, cin, is32)
}

/// a + b + cin with NZCV (the true architectural adder).
fn addsub_carry(a: u64, b: u64, cin: u64, is32: bool) -> (u64, u64) {
    let m = mask_for(is32);
    let a = a & m;
    let b = b & m;
    if is32 {
        let sum = (a as u128) + (b as u128) + (cin as u128);
        let res = (sum as u64) & m;
        let c = ((sum >> 32) & 1) as u64;
        let n = neg(res, true);
        let z = res == 0;
        // Signed overflow: operands same sign, result differs.
        let sa = (a >> 31) & 1;
        let sb = (b >> 31) & 1;
        let sr = (res >> 31) & 1;
        let v = (sa == sb) && (sr != sa);
        (res, pack_nzcv(n, z, c == 1, v))
    } else {
        let sum = (a as u128) + (b as u128) + (cin as u128);
        let res = sum as u64;
        let c = ((sum >> 64) & 1) as u64;
        let n = neg(res, false);
        let z = res == 0;
        let sa = (a >> 63) & 1;
        let sb = (b >> 63) & 1;
        let sr = (res >> 63) & 1;
        let v = (sa == sb) && (sr != sa);
        (res, pack_nzcv(n, z, c == 1, v))
    }
}

fn pack_nzcv(n: bool, z: bool, c: bool, v: bool) -> u64 {
    ((n as u64) << 31) | ((z as u64) << 30) | ((c as u64) << 29) | ((v as u64) << 28)
}

/// Shift a register value. ty: 0=LSL,1=LSR,2=ASR,3=ROR. Returns None if invalid.
fn shift_reg(v: u64, ty: u32, amount: u32, is32: bool) -> Option<u64> {
    let width = if is32 { 32 } else { 64 };
    let amt = amount % width; // ROR uses mod; LSL/LSR shift by amount<width for reg
    let m = mask_for(is32);
    let v = v & m;
    let r = match ty {
        0 => (v << amount) & m,                        // LSL
        1 => (v & m) >> amount,                         // LSR
        2 => {
            if is32 {
                ((v as i32 as i64) >> amount.min(31)) as u64 & m
            } else {
                ((v as i64) >> amount.min(63)) as u64
            }
        }
        3 => {
            if is32 {
                let x = v as u32;
                x.rotate_right(amt) as u64
            } else {
                v.rotate_right(amt)
            }
        }
        _ => return None,
    };
    Some(r & m)
}

/// Extended-register form (for ADD/SUB extended). option selects extension.
fn extend_reg(v: u64, option: u32, shift: u32, _is32: bool) -> u64 {
    let ext = match option {
        0b000 => (v & 0xFF) as u64,                       // UXTB
        0b001 => (v & 0xFFFF) as u64,                     // UXTH
        0b010 => (v & 0xFFFF_FFFF) as u64,                // UXTW
        0b011 => v,                                       // UXTX
        0b100 => (v as i8 as i64) as u64,                 // SXTB
        0b101 => (v as i16 as i64) as u64,                // SXTH
        0b110 => (v as i32 as i64) as u64,                // SXTW
        0b111 => v,                                       // SXTX
        _ => v,
    };
    ext << shift
}

fn sign_extend(v: u64, bits: usize) -> u64 {
    if bits >= 64 { return v; }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

/// SBFM/BFM/UBFM. opc: 00=SBFM,01=BFM,10=UBFM. `dst` is current Rd (for BFM).
///
/// Spec-literal per ARM ARM `aarch64/instrs/integer/bitfield`:
///   (wmask, tmask) = DecodeBitMasks(imms, immr)
///   bot = ROR(src, immr) & wmask     (BFM ORs in dst outside wmask)
///   top = 0 (UBFM) | all-ones-if-src<imms> (SBFM) | dst (BFM)
///   result = (top & ~tmask) | (bot & tmask)
/// This correctly handles BOTH the imms>=immr (extract/LSR) and imms<immr
/// (insert-high/LSL) cases — the previous single-rotate form was wrong for the
/// LSL alias (imms<immr), silently producing garbage for e.g. `LSL Xd,Xn,#3`.
fn bitfield(opc: u32, src: u64, immr: u32, imms: u32, width: u32, dst: u64) -> Option<u64> {
    let m = if width == 32 { 0xFFFF_FFFFu64 } else { u64::MAX };
    let (wmask, tmask) = decode_bitfield_masks(imms, immr, width);
    let rotated = ror_within(src & m, immr, width) & m;
    let bot_bits = rotated & wmask;
    let top_bits = match opc {
        0b10 => 0u64,                                    // UBFM: zero fill
        0b00 => {                                        // SBFM: sign fill
            let sign = (src >> imms) & 1;
            if sign == 1 { m } else { 0 }
        }
        0b01 => dst & m,                                 // BFM: keep dst
        _ => return None,
    };
    let bot = match opc {
        0b01 => (dst & !wmask) | bot_bits,               // BFM merges dst outside wmask
        _ => bot_bits,
    };
    Some(((top_bits & !tmask) | (bot & tmask)) & m)
}

/// ARM ARM `DecodeBitMasks(imms, immr)` restricted to the bitfield (non-logical)
/// use: returns (wmask, tmask) for a given datasize `width` (32 or 64).
///   diff = imms - immr (mod width);  d = diff<width-1:0>
///   wmask = ROR(Ones(imms+1), immr) within width
///   tmask = Ones(diff+1) within width
/// (Element size is `width` here since bitfield ops don't replicate sub-elements.)
fn decode_bitfield_masks(imms: u32, immr: u32, width: u32) -> (u64, u64) {
    let full = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    // welem = Ones(imms+1) (imms in 0..width-1, so imms+1 in 1..width)
    let welem = if imms + 1 >= 64 { u64::MAX } else { (1u64 << (imms + 1)) - 1 } & full;
    // wmask = ROR(welem, immr) within width
    let wmask = ror_within(welem, immr, width) & full;
    // tmask = Ones(diff+1) where diff = (imms - immr) mod width
    let diff = (imms.wrapping_sub(immr)) & (width - 1);
    let telem = if diff + 1 >= 64 { u64::MAX } else { (1u64 << (diff + 1)) - 1 } & full;
    (wmask, telem)
}

fn ror_within(v: u64, amount: u32, width: u32) -> u64 {
    if width == 32 {
        (v as u32).rotate_right(amount % 32) as u64
    } else {
        v.rotate_right(amount % 64)
    }
}

/// Decode a logical-immediate bitmask (N,imms,immr). Returns None if reserved.
/// Faithful to ARM ARM `DecodeBitMasks` (immediate variant).
fn decode_bitmask(n: u32, imms: u32, immr: u32, is32: bool) -> Option<u64> {
    let width = if is32 { 32u32 } else { 64u32 };
    // len = position of the highest set bit of (N : NOT(imms<5:0>)), 0-indexed
    // over a 7-bit value. A reserved encoding has len < 1.
    let field = ((n & 1) << 6) | ((!imms) & 0x3F);
    if field == 0 { return None; }
    let len = 31 - (field.leading_zeros()); // top set bit index in a u32 => 0..6
    if len < 1 { return None; }
    let size = 1u32 << len; // element size in bits: 2,4,8,16,32,64
    if size > width { return None; }
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels { return None; } // reserved (all-ones would be invalid)
    // welem = (s+1) ones, ror by r WITHIN the element size, then replicate to
    // `width`. NOTE: the rotate is within `size` bits (2/4/8/16/32/64), which
    // `ror_within` only supports for 32/64 — so rotate the small element by hand.
    let welem: u64 = if s + 1 >= 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let elem = ror_in_size(welem & mask_of_bits(size), r, size);
    let mut result = 0u64;
    let mut i = 0u32;
    while i < width {
        result |= elem << i;
        i += size;
    }
    Some(result & mask_for(is32))
}

fn mask_of_bits(bits: u32) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// Rotate `v` right by `amount` WITHIN a `size`-bit element (size in 2..=64).
/// Needed by `decode_bitmask` for sub-word replicated masks (0xAAAA.., 0x3333..,
/// etc.) — `ror_within` only handles 32/64 and would rotate within 64 bits,
/// wiping the tiny element to zero.
fn ror_in_size(v: u64, amount: u32, size: u32) -> u64 {
    if size >= 64 { return v.rotate_right(amount % 64); }
    let sz = size;
    let a = amount % sz;
    let m = (1u64 << sz) - 1;
    let v = v & m;
    ((v >> a) | (v << (sz - a))) & m
}

/// AArch64 condition-code evaluation from NZCV bits [31:28].
fn cond_holds(cond: u32, nzcv: u64) -> bool {
    let n = (nzcv >> 31) & 1 == 1;
    let z = (nzcv >> 30) & 1 == 1;
    let c = (nzcv >> 29) & 1 == 1;
    let v = (nzcv >> 28) & 1 == 1;
    let base = match cond >> 1 {
        0b000 => z,               // EQ/NE
        0b001 => c,               // CS/CC
        0b010 => n,               // MI/PL
        0b011 => v,               // VS/VC
        0b100 => c && !z,         // HI/LS
        0b101 => n == v,          // GE/LT
        0b110 => (n == v) && !z,  // GT/LE
        0b111 => true,            // AL
        _ => true,
    };
    if (cond & 1) == 1 && cond != 0b1111 { !base } else { base }
}

// ── SIMD lane helpers ────────────────────────────────────────────────────────

fn lane_mask(esize: usize) -> u128 {
    if esize >= 128 { u128::MAX } else { (1u128 << esize) - 1 }
}
fn u128_lo64_mask() -> u128 {
    (1u128 << 64) - 1
}
fn lane_get(v: u128, lane: usize, esize: usize) -> u128 {
    (v >> (lane * esize)) & lane_mask(esize)
}
/// Signed compare of two esize-bit lanes (sign-extend then compare).
fn s_cmp(a: u128, b: u128, esize: usize) -> std::cmp::Ordering {
    let sa = s_ext_i128(a, esize);
    let sb = s_ext_i128(b, esize);
    sa.cmp(&sb)
}
fn s_ext_i128(v: u128, esize: usize) -> i128 {
    if esize >= 128 { return v as i128; }
    let shift = 128 - esize;
    ((v << shift) as i128) >> shift
}
/// DUP-general element size from imm5. Returns (esize_bits, index).
fn dup_size(imm5: u32) -> Option<(usize, usize)> {
    if imm5 & 1 == 1 { Some((8, (imm5 >> 1) as usize)) }
    else if imm5 & 2 == 2 { Some((16, (imm5 >> 2) as usize)) }
    else if imm5 & 4 == 4 { Some((32, (imm5 >> 3) as usize)) }
    else if imm5 & 8 == 8 { Some((64, (imm5 >> 4) as usize)) }
    else { None }
}

// ── SIMD extra helpers (added: shifts, FP, convert) ──────────────────────────

/// Mask a 128-bit vector result to the register width (Q selects 128 vs 64).
fn mask_reg(v: u128, dbl: bool) -> u128 {
    if dbl { v } else { v & u128_lo64_mask() }
}

/// SSHL — signed variable shift of an esize-bit lane. The shift count is the
/// signed 8-bit value in the LOW byte of the corresponding `shift` lane
/// (bits[7:0]). Positive => left; negative => arithmetic right. Out-of-range
/// shifts saturate to all-sign / zero per the architecture's rounding-free rule.
fn simd_sshl(val: u128, shift_lane: u128, esize: usize) -> u128 {
    let cnt = (shift_lane & 0xFF) as u8 as i8 as i32; // sign-extend low byte
    let x = s_ext_i128(val, esize);
    let r = if cnt >= 0 {
        if cnt as usize >= esize { 0 } else { x << cnt }
    } else {
        let sh = (-cnt) as usize;
        if sh >= esize { if x < 0 { -1 } else { 0 } } else { x >> sh }
    };
    (r as u128) & lane_mask(esize)
}

/// USHL — unsigned variable shift. Same count semantics; right shift is logical.
fn simd_ushl(val: u128, shift_lane: u128, esize: usize) -> u128 {
    let cnt = (shift_lane & 0xFF) as u8 as i8 as i32;
    let x = val & lane_mask(esize);
    let r = if cnt >= 0 {
        if cnt as usize >= esize { 0 } else { x << cnt }
    } else {
        let sh = (-cnt) as usize;
        if sh >= esize { 0 } else { x >> sh }
    };
    r & lane_mask(esize)
}

/// Decode (esize, left_amount, right_amount) for a SIMD shift-by-immediate from
/// (immh, immb). `immh` picks the element size; the 7-bit `immh:immb` field then
/// encodes the amount differently for left vs right shifts:
///   left  amount = (immh:immb) - esize
///   right amount = 2*esize - (immh:immb)
/// (ARM ARM C7 shift-by-immediate.)
fn shift_imm_params(immh: u32, immb: u32) -> (usize, u32, u32) {
    let hb = (immh << 3) | immb; // 7-bit immh:immb
    let esize = if immh & 0b1000 != 0 { 64 }
        else if immh & 0b0100 != 0 { 32 }
        else if immh & 0b0010 != 0 { 16 }
        else { 8 };
    let left = hb - esize as u32;                 // SHL/SLI/SSHLL amount
    let right = (2 * esize as u32).wrapping_sub(hb); // SSHR/USHR/SRI amount
    (esize, left, right)
}

/// ARM canonical (quiet, positive) default NaNs — what FMAX/FMIN emit when an
/// input is NaN. Matches FPCR.DN=1 (DefaultNaN) and the quieted form ARM uses
/// even with DN=0 (top mantissa bit set, all other payload bits cleared).
const ARM_DEFAULT_QNAN_F32: u32 = 0x7FC0_0000;
const ARM_DEFAULT_QNAN_F64: u64 = 0x7FF8_0000_0000_0000;

/// ARM FMAX / FMIN (register form) — these **propagate NaN**: if either operand
/// is a NaN the result is a quiet NaN (unlike FMAXNM/FMINNM which return the
/// numeric operand, i.e. Rust's `f32::max`/`min` maxNum/minNum semantics). For
/// all non-NaN inputs FMAX == maxNum and FMIN == minNum, so we defer to the host
/// `max`/`min` there (which also gets the +0/-0 ordering right).
fn arm_fmax_f32(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() { f32::from_bits(ARM_DEFAULT_QNAN_F32) } else { x.max(y) }
}
fn arm_fmin_f32(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() { f32::from_bits(ARM_DEFAULT_QNAN_F32) } else { x.min(y) }
}
fn arm_fmax_f64(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() { f64::from_bits(ARM_DEFAULT_QNAN_F64) } else { x.max(y) }
}
fn arm_fmin_f64(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() { f64::from_bits(ARM_DEFAULT_QNAN_F64) } else { x.min(y) }
}

/// FP three-same vector op. `opcode` bits[15:11], `u`, `hi23` = size bit23 (the
/// add/sub or max/min or maxnm/minnm or mla/mls selector), `is_double`, and the
/// two operand lanes as raw FP bits. Returns the result bits, or None if not
/// modelled. Uses host IEEE-754 (matches ARM for +/-/*//). FMLA/FMLS use fused
/// mul-add. NaN/inf edge cases are left to host semantics (adequate as a diff
/// reference for the values the corpus exercises).
fn fp_three_same(opcode: u32, u: u32, hi23: u32, is_double: bool, a: u128, b: u128) -> Option<u128> {
    if is_double {
        let x = f64::from_bits(a as u64);
        let y = f64::from_bits(b as u64);
        let r: f64 = match (opcode, u, hi23) {
            (0b11010, 0, 0) => x + y,                 // FADD
            (0b11010, 0, 1) => x - y,                 // FSUB
            (0b11010, 1, 1) => (x - y).abs(),         // FABD
            (0b11011, 1, _) => x * y,                 // FMUL (U=1)
            (0b11111, 1, _) => x / y,                 // FDIV (U=1)
            (0b11110, 0, 0) => arm_fmax_f64(x, y),    // FMAX (propagates NaN)
            (0b11110, 0, 1) => arm_fmin_f64(x, y),    // FMIN (propagates NaN)
            (0b11000, 0, 0) => x.max(y),              // FMAXNM (maxNum — ignores NaN)
            (0b11000, 0, 1) => x.min(y),              // FMINNM (minNum — ignores NaN)
            // FP compares all share opcode 0b11100: FCMEQ(U=0), FCMGE(U=1,bit23=0),
            //   FCMGT(U=1,bit23=1).
            (0b11100, 0, _) => return fcmp_lane_d(x, y, FpCmp::Eq), // FCMEQ
            (0b11100, 1, 0) => return fcmp_lane_d(x, y, FpCmp::Ge), // FCMGE
            (0b11100, 1, 1) => return fcmp_lane_d(x, y, FpCmp::Gt), // FCMGT
            // FMLA/FMLS (opcode 0b11001) read the destination lane — handled in
            // the three-same branch, not here.
            _ => return None,
        };
        Some(r.to_bits() as u128)
    } else {
        let x = f32::from_bits(a as u32);
        let y = f32::from_bits(b as u32);
        let r: f32 = match (opcode, u, hi23) {
            (0b11010, 0, 0) => x + y,                 // FADD
            (0b11010, 0, 1) => x - y,                 // FSUB
            (0b11010, 1, 1) => (x - y).abs(),         // FABD
            (0b11011, 1, _) => x * y,                 // FMUL
            (0b11111, 1, _) => x / y,                 // FDIV
            (0b11110, 0, 0) => arm_fmax_f32(x, y),    // FMAX (propagates NaN)
            (0b11110, 0, 1) => arm_fmin_f32(x, y),    // FMIN (propagates NaN)
            (0b11000, 0, 0) => x.max(y),              // FMAXNM (maxNum — ignores NaN)
            (0b11000, 0, 1) => x.min(y),              // FMINNM (minNum — ignores NaN)
            (0b11100, 0, _) => return fcmp_lane_s(x, y, FpCmp::Eq), // FCMEQ
            (0b11100, 1, 0) => return fcmp_lane_s(x, y, FpCmp::Ge), // FCMGE
            (0b11100, 1, 1) => return fcmp_lane_s(x, y, FpCmp::Gt), // FCMGT
            _ => return None,
        };
        Some(r.to_bits() as u128)
    }
}

/// Vector FP three-same FMLA/FMLS accumulate: they read the destination lane.
/// Called from the three-same branch when opcode==0b11001. `sub` = FMLS.
///   FMLA: Vd += Vn*Vm     FMLS: Vd -= Vn*Vm   (fused single-rounding).
fn fp_mla_lane(dst: u128, a: u128, b: u128, is_double: bool, sub: bool) -> u128 {
    if is_double {
        let d = f64::from_bits(dst as u64);
        let x = f64::from_bits(a as u64);
        let y = f64::from_bits(b as u64);
        let r = if sub { (-x).mul_add(y, d) } else { x.mul_add(y, d) };
        r.to_bits() as u128
    } else {
        let d = f32::from_bits(dst as u32);
        let x = f32::from_bits(a as u32);
        let y = f32::from_bits(b as u32);
        let r = if sub { (-x).mul_add(y, d) } else { x.mul_add(y, d) };
        r.to_bits() as u128
    }
}

enum FpCmp { Eq, Ge, Gt }
fn fcmp_lane_s(x: f32, y: f32, k: FpCmp) -> Option<u128> {
    let t = match k { FpCmp::Eq => x == y, FpCmp::Ge => x >= y, FpCmp::Gt => x > y };
    Some(if t { (u32::MAX) as u128 } else { 0 })
}
fn fcmp_lane_d(x: f64, y: f64, k: FpCmp) -> Option<u128> {
    let t = match k { FpCmp::Eq => x == y, FpCmp::Ge => x >= y, FpCmp::Gt => x > y };
    Some(if t { (u64::MAX) as u128 } else { 0 })
}

/// FP compare-vs-#0 (vector two-reg-misc). opcode 0b01100 FCMGT, 0b01101 FCMEQ
/// (U=0) / FCMLE (U=1), 0b01110 FCMLT (U=0) / — . Returns Some(bool) or None.
/// The comparison is against +0.0.
fn fp_cmp_zero(opcode: u32, u: u32, is_double: bool, bits: u128) -> Option<bool> {
    let v = if is_double { f64::from_bits(bits as u64) } else { f32::from_bits(bits as u32) as f64 };
    let r = match (opcode, u) {
        (0b01100, 0) => v > 0.0,  // FCMGT #0
        (0b01100, 1) => v >= 0.0, // FCMGE #0
        (0b01101, 0) => v == 0.0, // FCMEQ #0
        (0b01101, 1) => v <= 0.0, // FCMLE #0
        (0b01110, 0) => v < 0.0,  // FCMLT #0
        _ => return None,
    };
    Some(r)
}

/// FP vector two-reg-misc unary: FABS/FNEG/FSQRT + FRINTx. Returns result bits.
/// (FCVT widen/narrow across precisions are NOT modelled here — return None so
/// the block SKIPs rather than risk a wrong lane-width answer.)
fn fp_misc_unary(opcode: u32, u: u32, is_double: bool, bits: u128) -> Option<u128> {
    macro_rules! do_op { ($f:ty, $from:expr) => {{
        let v: $f = $from;
        let r: $f = match (opcode, u) {
            (0b01111, 0) => v.abs(),                        // FABS
            (0b01111, 1) => -v,                             // FNEG
            (0b11111, 1) => v.sqrt(),                       // FSQRT
            (0b11000, 0) => round_ties_even(v as f64) as $f, // FRINTN (to-nearest-even)
            (0b11000, 1) => (v as f64).floor() as $f,        // FRINTM (toward -inf)
            (0b11001, 0) => (v as f64).ceil() as $f,         // FRINTP (toward +inf)
            (0b11001, 1) => (v as f64).trunc() as $f,        // FRINTZ (toward zero)
            (0b11100, 0) => (v as f64).round() as $f,        // FRINTA (to-nearest, ties-away)
            _ => return None,
        };
        Some(r.to_bits() as u128)
    }}}
    if is_double { do_op!(f64, f64::from_bits(bits as u64)) }
    else {
        // for singles, compute in f32 but route the f64-rounding ops through f64.
        let v = f32::from_bits(bits as u32);
        let r: f32 = match (opcode, u) {
            (0b01111, 0) => v.abs(),
            (0b01111, 1) => -v,
            (0b11111, 1) => v.sqrt(),
            (0b11000, 0) => round_ties_even(v as f64) as f32,
            (0b11000, 1) => v.floor(),
            (0b11001, 0) => v.ceil(),
            (0b11001, 1) => v.trunc(),
            (0b11100, 0) => v.round(),
            _ => return None,
        };
        Some(r.to_bits() as u128)
    }
}

/// Round to nearest, ties to even (ARM default rounding, FRINTN / SCVTF etc).
/// Rust's `f64::round` is ties-away, so implement RNE explicitly.
fn round_ties_even(x: f64) -> f64 {
    let r = x.round(); // ties away from zero
    if (x - x.trunc()).abs() == 0.5 {
        // exactly halfway: pick the even neighbour
        let lo = x.floor();
        let hi = x.ceil();
        if (lo as i64) % 2 == 0 { lo } else { hi }
    } else {
        r
    }
}

/// FP scalar 2-source (FMUL/FDIV/FADD/FSUB/FMAX/FMIN/FMAXNM/FMINNM/FNMUL).
/// opcode = bits[15:12]. Returns result bits (upper zeroed by caller), or None.
fn fp_scalar_2src(ftype: u32, opcode: u32, an: u128, am: u128) -> Option<u128> {
    match ftype {
        0b00 => {
            let a = f32::from_bits(an as u32);
            let b = f32::from_bits(am as u32);
            let r = match opcode {
                0b0000 => a * b,          // FMUL
                0b0001 => a / b,          // FDIV
                0b0010 => a + b,          // FADD
                0b0011 => a - b,          // FSUB
                0b0100 => arm_fmax_f32(a, b), // FMAX (propagates NaN)
                0b0101 => arm_fmin_f32(a, b), // FMIN (propagates NaN)
                0b0110 => a.max(b),       // FMAXNM (maxNum — ignores NaN)
                0b0111 => a.min(b),       // FMINNM (minNum — ignores NaN)
                0b1000 => -(a * b),       // FNMUL
                _ => return None,
            };
            Some(r.to_bits() as u128)
        }
        0b01 => {
            let a = f64::from_bits(an as u64);
            let b = f64::from_bits(am as u64);
            let r = match opcode {
                0b0000 => a * b,
                0b0001 => a / b,
                0b0010 => a + b,
                0b0011 => a - b,
                0b0100 => arm_fmax_f64(a, b), // FMAX (propagates NaN)
                0b0101 => arm_fmin_f64(a, b), // FMIN (propagates NaN)
                0b0110 => a.max(b),           // FMAXNM (maxNum — ignores NaN)
                0b0111 => a.min(b),           // FMINNM (minNum — ignores NaN)
                0b1000 => -(a * b),
                _ => return None,
            };
            Some(r.to_bits() as u128)
        }
        _ => None,
    }
}

/// FP scalar 1-source (FMOV/FABS/FNEG/FSQRT/FRINTx/FCVT precision). opcode6 =
/// bits[20:15]. Returns result bits, or None if not modelled. FCVT converts the
/// single scalar between S and D (opcode6 0b0001_xx where the low 2 bits pick the
/// destination type: 00=S,01=D,11=H). We model S<->D only.
fn fp_scalar_1src(ftype: u32, opcode6: u32, an: u128) -> Option<u128> {
    // FCVT (precision change): opcode6 = 0b0001_dd where dd = dest ftype.
    if opcode6 & 0b111100 == 0b000100 {
        let dst = opcode6 & 0b11;
        // source value per ftype:
        let src_val: f64 = match ftype {
            0b00 => f32::from_bits(an as u32) as f64,
            0b01 => f64::from_bits(an as u64),
            _ => return None, // half not modelled
        };
        return match dst {
            0b00 => Some((src_val as f32).to_bits() as u128), // -> single
            0b01 => Some(src_val.to_bits() as u128),          // -> double
            _ => None,                                        // -> half not modelled
        };
    }
    macro_rules! one { ($f:ty, $from:expr) => {{
        let v: $f = $from;
        let r: $f = match opcode6 {
            0b000000 => v,                                    // FMOV
            0b000001 => v.abs(),                              // FABS
            0b000010 => -v,                                   // FNEG
            0b000011 => v.sqrt(),                             // FSQRT
            0b001000 => round_ties_even(v as f64) as $f,      // FRINTN
            0b001001 => (v as f64).ceil() as $f,              // FRINTP
            0b001010 => (v as f64).floor() as $f,             // FRINTM
            0b001011 => (v as f64).trunc() as $f,             // FRINTZ
            0b001100 => (v as f64).round() as $f,             // FRINTA
            _ => return None,
        };
        Some(r.to_bits() as u128)
    }}}
    match ftype {
        0b00 => one!(f32, f32::from_bits(an as u32)),
        0b01 => one!(f64, f64::from_bits(an as u64)),
        _ => None,
    }
}

/// FP scalar 3-source (FMADD/FMSUB/FNMADD/FNMSUB). o1=bit21, o0=bit15.
///   o1=0,o0=0 FMADD : Rd =  Ra + Rn*Rm
///   o1=0,o0=1 FMSUB : Rd =  Ra - Rn*Rm
///   o1=1,o0=0 FNMADD: Rd = -Ra - Rn*Rm
///   o1=1,o0=1 FNMSUB: Rd = -Ra + Rn*Rm
/// Uses fused mul-add (matches ARM's single-rounding FMA).
fn fp_scalar_3src(ftype: u32, o1: u32, o0: u32, an: u128, am: u128, aa: u128) -> Option<u128> {
    match ftype {
        0b00 => {
            let n = f32::from_bits(an as u32);
            let m = f32::from_bits(am as u32);
            let a = f32::from_bits(aa as u32);
            let r = match (o1, o0) {
                (0, 0) => n.mul_add(m, a),        // FMADD
                (0, 1) => (-n).mul_add(m, a),     // FMSUB:  a + (-n)*m = a - n*m
                (1, 0) => (-n).mul_add(m, -a),    // FNMADD: -a - n*m
                (1, 1) => n.mul_add(m, -a),       // FNMSUB: -a + n*m
                _ => return None,
            };
            Some(r.to_bits() as u128)
        }
        0b01 => {
            let n = f64::from_bits(an as u64);
            let m = f64::from_bits(am as u64);
            let a = f64::from_bits(aa as u64);
            let r = match (o1, o0) {
                (0, 0) => n.mul_add(m, a),
                (0, 1) => (-n).mul_add(m, a),
                (1, 0) => (-n).mul_add(m, -a),
                (1, 1) => n.mul_add(m, -a),
                _ => return None,
            };
            Some(r.to_bits() as u128)
        }
        _ => None,
    }
}

/// FCMP/FCMPE NZCV per ARM ARM `FPCompare`. Ordered compare of `a` vs `b`:
///   a==b -> 0110 (Z,C)   a<b -> 1000 (N)   a>b -> 0010 (C)
///   unordered (NaN) -> 0011 (C,V).  Returns NZCV packed in bits[31:28].
fn fp_compare_nzcv(a: f64, b: f64) -> u64 {
    let (n, z, c, v) = if a.is_nan() || b.is_nan() {
        (false, false, true, true)   // unordered
    } else if a == b {
        (false, true, true, false)
    } else if a < b {
        (true, false, false, false)
    } else {
        (false, false, true, false)  // a > b
    };
    pack_nzcv(n, z, c, v)
}

/// FP -> integer, round toward zero (FCVTZS/FCVTZU). Saturates to the int range
/// per ARM (NaN -> 0; out-of-range -> min/max). `signed` selects S vs U; `is64`
/// selects 64-bit vs 32-bit result width.
fn fp_to_int(x: f64, signed: bool, is64: bool) -> u64 {
    if x.is_nan() {
        return 0;
    }
    let t = x.trunc(); // round toward zero
    if signed {
        if is64 {
            let lo = i64::MIN as f64;
            let hi = i64::MAX as f64;
            let r = if t <= lo { i64::MIN } else if t >= hi { i64::MAX } else { t as i64 };
            r as u64
        } else {
            let lo = i32::MIN as f64;
            let hi = i32::MAX as f64;
            let r = if t <= lo { i32::MIN } else if t >= hi { i32::MAX } else { t as i32 };
            (r as u32) as u64 // zero-extended into the 32-bit GPR view
        }
    } else if is64 {
        let hi = u64::MAX as f64;
        if t <= 0.0 { 0 } else if t >= hi { u64::MAX } else { t as u64 }
    } else {
        let hi = u32::MAX as f64;
        let r = if t <= 0.0 { 0 } else if t >= hi { u32::MAX } else { t as u32 };
        r as u64
    }
}
