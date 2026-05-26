//! IR serialization for the AT-2 gate and the future AOT cache (AT-22).
//!
//! Format: little-endian, length-implicit. 1-byte variant tag + variant
//! payload. Decoder uses the tag to dispatch to a per-variant payload parser.
//!
//! Phase A fill: encode/decode bodies for the ~25 IR variants needed by the
//! AT-1 integer/branch/load-store lift. Remaining variants return
//! `NotYetImplemented` and are exercised by the at2_every_variant_roundtrips
//! test only when the corresponding fill commit lands.

use alloc::vec::Vec;

use super::flags::{IrFlagsId, NzcvBit};
use super::memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
use super::value::IrValueId;
use super::{BlockId, IrOp};

use crate::decoder::Cond;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerErr {
    NotYetImplemented,
    Truncated,
    BadTag(u8),
    BadEnum(u8),
}

// ---------- writer helpers ----------

#[inline]
fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}
#[inline]
fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_vid(out: &mut Vec<u8>, v: IrValueId) {
    put_u32(out, v.0);
}
#[inline]
fn put_fid(out: &mut Vec<u8>, v: IrFlagsId) {
    put_u32(out, v.0);
}
#[inline]
fn put_bid(out: &mut Vec<u8>, v: BlockId) {
    put_u32(out, v.0);
}
#[inline]
fn put_cond(out: &mut Vec<u8>, c: Cond) {
    put_u8(out, c as u8);
}
#[inline]
fn put_memord(out: &mut Vec<u8>, m: MemOrder) {
    let v = match m {
        MemOrder::Relaxed => 0,
        MemOrder::Acquire => 1,
        MemOrder::Release => 2,
        MemOrder::AcqRel => 3,
        MemOrder::SeqCst => 4,
    };
    put_u8(out, v);
}
#[inline]
fn put_loadty(out: &mut Vec<u8>, t: LoadTy) {
    let v = match t {
        LoadTy::U8 => 0,
        LoadTy::I8 => 1,
        LoadTy::U16 => 2,
        LoadTy::I16 => 3,
        LoadTy::U32 => 4,
        LoadTy::I32 => 5,
        LoadTy::U64 => 6,
        LoadTy::F32 => 7,
        LoadTy::F64 => 8,
        LoadTy::Vec128 => 9,
    };
    put_u8(out, v);
}
#[inline]
fn put_storety(out: &mut Vec<u8>, t: StoreTy) {
    let v = match t {
        StoreTy::U8 => 0,
        StoreTy::U16 => 1,
        StoreTy::U32 => 2,
        StoreTy::U64 => 3,
        StoreTy::F32 => 4,
        StoreTy::F64 => 5,
        StoreTy::Vec128 => 6,
    };
    put_u8(out, v);
}
#[inline]
fn put_atomicop(out: &mut Vec<u8>, op: AtomicOp) {
    let v = match op {
        AtomicOp::Add => 0,
        AtomicOp::Clr => 1,
        AtomicOp::Eor => 2,
        AtomicOp::Set => 3,
        AtomicOp::Smax => 4,
        AtomicOp::Smin => 5,
        AtomicOp::Umax => 6,
        AtomicOp::Umin => 7,
        AtomicOp::Swp => 8,
    };
    put_u8(out, v);
}
#[inline]
fn put_barrier(out: &mut Vec<u8>, b: BarrierDomain) {
    let v = match b {
        BarrierDomain::Ish => 0,
        BarrierDomain::Ishst => 1,
        BarrierDomain::Ishld => 2,
        BarrierDomain::Nsh => 3,
        BarrierDomain::NshSt => 4,
        BarrierDomain::NshLd => 5,
        BarrierDomain::Osh => 6,
        BarrierDomain::OshSt => 7,
        BarrierDomain::OshLd => 8,
        BarrierDomain::Sy => 9,
        BarrierDomain::SyStore => 10,
        BarrierDomain::SyLoad => 11,
    };
    put_u8(out, v);
}
#[inline]
fn put_nzcv(out: &mut Vec<u8>, n: NzcvBit) {
    let v = match n {
        NzcvBit::N => 0,
        NzcvBit::Z => 1,
        NzcvBit::C => 2,
        NzcvBit::V => 3,
    };
    put_u8(out, v);
}

// ---------- reader helpers ----------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SerErr> {
        if self.pos + n > self.buf.len() {
            return Err(SerErr::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, SerErr> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SerErr> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, SerErr> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, SerErr> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    fn i32(&mut self) -> Result<i32, SerErr> {
        Ok(self.u32()? as i32)
    }
    fn i64(&mut self) -> Result<i64, SerErr> {
        Ok(self.u64()? as i64)
    }
    fn vid(&mut self) -> Result<IrValueId, SerErr> {
        Ok(IrValueId(self.u32()?))
    }
    fn fid(&mut self) -> Result<IrFlagsId, SerErr> {
        Ok(IrFlagsId(self.u32()?))
    }
    fn bid(&mut self) -> Result<BlockId, SerErr> {
        Ok(BlockId(self.u32()?))
    }
    fn cond(&mut self) -> Result<Cond, SerErr> {
        Ok(Cond::from_bits(self.u8()? & 0xF))
    }
    fn memord(&mut self) -> Result<MemOrder, SerErr> {
        Ok(match self.u8()? {
            0 => MemOrder::Relaxed,
            1 => MemOrder::Acquire,
            2 => MemOrder::Release,
            3 => MemOrder::AcqRel,
            4 => MemOrder::SeqCst,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn loadty(&mut self) -> Result<LoadTy, SerErr> {
        Ok(match self.u8()? {
            0 => LoadTy::U8,
            1 => LoadTy::I8,
            2 => LoadTy::U16,
            3 => LoadTy::I16,
            4 => LoadTy::U32,
            5 => LoadTy::I32,
            6 => LoadTy::U64,
            7 => LoadTy::F32,
            8 => LoadTy::F64,
            9 => LoadTy::Vec128,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn storety(&mut self) -> Result<StoreTy, SerErr> {
        Ok(match self.u8()? {
            0 => StoreTy::U8,
            1 => StoreTy::U16,
            2 => StoreTy::U32,
            3 => StoreTy::U64,
            4 => StoreTy::F32,
            5 => StoreTy::F64,
            6 => StoreTy::Vec128,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn atomicop(&mut self) -> Result<AtomicOp, SerErr> {
        Ok(match self.u8()? {
            0 => AtomicOp::Add,
            1 => AtomicOp::Clr,
            2 => AtomicOp::Eor,
            3 => AtomicOp::Set,
            4 => AtomicOp::Smax,
            5 => AtomicOp::Smin,
            6 => AtomicOp::Umax,
            7 => AtomicOp::Umin,
            8 => AtomicOp::Swp,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn barrier(&mut self) -> Result<BarrierDomain, SerErr> {
        Ok(match self.u8()? {
            0 => BarrierDomain::Ish,
            1 => BarrierDomain::Ishst,
            2 => BarrierDomain::Ishld,
            3 => BarrierDomain::Nsh,
            4 => BarrierDomain::NshSt,
            5 => BarrierDomain::NshLd,
            6 => BarrierDomain::Osh,
            7 => BarrierDomain::OshSt,
            8 => BarrierDomain::OshLd,
            9 => BarrierDomain::Sy,
            10 => BarrierDomain::SyStore,
            11 => BarrierDomain::SyLoad,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn nzcv(&mut self) -> Result<NzcvBit, SerErr> {
        Ok(match self.u8()? {
            0 => NzcvBit::N,
            1 => NzcvBit::Z,
            2 => NzcvBit::C,
            3 => NzcvBit::V,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
}

// ---------- public API ----------

pub fn encode(op: &IrOp, out: &mut Vec<u8>) -> Result<(), SerErr> {
    let tag = variant_tag(op);
    out.push(tag);
    match op {
        IrOp::ConstI32 { dst, val } => {
            put_vid(out, *dst);
            put_i32(out, *val);
        }
        IrOp::ConstI64 { dst, val } => {
            put_vid(out, *dst);
            put_i64(out, *val);
        }
        IrOp::Add { dst, a, b }
        | IrOp::Sub { dst, a, b }
        | IrOp::And { dst, a, b }
        | IrOp::Or { dst, a, b }
        | IrOp::Xor { dst, a, b }
        | IrOp::Shl { dst, a, b }
        | IrOp::LShr { dst, a, b }
        | IrOp::AShr { dst, a, b }
        | IrOp::Ror { dst, a, b }
        | IrOp::Mul { dst, a, b }
        | IrOp::MulHU { dst, a, b }
        | IrOp::MulHS { dst, a, b }
        | IrOp::SDiv { dst, a, b }
        | IrOp::UDiv { dst, a, b } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_vid(out, *b);
        }
        IrOp::Neg { dst, a } | IrOp::Not { dst, a } | IrOp::Clz { dst, a } | IrOp::Cls { dst, a }
        | IrOp::Rbit { dst, a } | IrOp::Bswap16 { dst, a } | IrOp::Bswap32 { dst, a }
        | IrOp::Bswap64 { dst, a } => {
            put_vid(out, *dst);
            put_vid(out, *a);
        }
        IrOp::Madd { dst, a, b, c } | IrOp::Msub { dst, a, b, c } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_vid(out, *b);
            put_vid(out, *c);
        }
        IrOp::AddS { dst, flags, a, b } | IrOp::SubS { dst, flags, a, b }
        | IrOp::AndS { dst, flags, a, b } => {
            put_vid(out, *dst);
            put_fid(out, *flags);
            put_vid(out, *a);
            put_vid(out, *b);
        }
        IrOp::Cmp { flags, a, b } | IrOp::Cmn { flags, a, b } | IrOp::Tst { flags, a, b } => {
            put_fid(out, *flags);
            put_vid(out, *a);
            put_vid(out, *b);
        }
        IrOp::Load { dst, addr, ty, order } => {
            put_vid(out, *dst);
            put_vid(out, *addr);
            put_loadty(out, *ty);
            put_memord(out, *order);
        }
        IrOp::Store { val, addr, ty, order } => {
            put_vid(out, *val);
            put_vid(out, *addr);
            put_storety(out, *ty);
            put_memord(out, *order);
        }
        IrOp::LoadExclusive { dst, addr, ty } => {
            put_vid(out, *dst);
            put_vid(out, *addr);
            put_loadty(out, *ty);
        }
        IrOp::StoreExclusive { status, val, addr, ty } => {
            put_vid(out, *status);
            put_vid(out, *val);
            put_vid(out, *addr);
            put_storety(out, *ty);
        }
        IrOp::AtomicRmw { dst, op, addr, val, order } => {
            put_vid(out, *dst);
            put_atomicop(out, *op);
            put_vid(out, *addr);
            put_vid(out, *val);
            put_memord(out, *order);
        }
        IrOp::AtomicCas { dst, addr, expected, new, order } => {
            put_vid(out, *dst);
            put_vid(out, *addr);
            put_vid(out, *expected);
            put_vid(out, *new);
            put_memord(out, *order);
        }
        IrOp::Branch { target } => put_bid(out, *target),
        IrOp::CondBranch { cond, flags, taken, fallthru } => {
            put_cond(out, *cond);
            put_fid(out, *flags);
            put_bid(out, *taken);
            put_bid(out, *fallthru);
        }
        IrOp::IndirectBranch { target } => put_vid(out, *target),
        IrOp::Call { target, link_pc } => {
            put_vid(out, *target);
            put_u64(out, *link_pc);
        }
        IrOp::Return { target } => put_vid(out, *target),
        IrOp::Cbz { a, taken, fallthru } | IrOp::Cbnz { a, taken, fallthru } => {
            put_vid(out, *a);
            put_bid(out, *taken);
            put_bid(out, *fallthru);
        }
        IrOp::Tbz { a, bit, taken, fallthru } | IrOp::Tbnz { a, bit, taken, fallthru } => {
            put_vid(out, *a);
            put_u8(out, *bit);
            put_bid(out, *taken);
            put_bid(out, *fallthru);
        }
        IrOp::Sext { dst, a, from_bits, to_bits } | IrOp::Zext { dst, a, from_bits, to_bits } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_u8(out, *from_bits);
            put_u8(out, *to_bits);
        }
        IrOp::Trunc { dst, a, to_bits } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_u8(out, *to_bits);
        }
        IrOp::Hvc { imm16 } | IrOp::Svc { imm16 } | IrOp::Smc { imm16 } | IrOp::Brk { imm16 }
        | IrOp::Hlt { imm16 } => put_u16(out, *imm16),
        IrOp::Dmb { domain } | IrOp::Dsb { domain } => put_barrier(out, *domain),
        IrOp::Isb | IrOp::Sb => {}
        IrOp::Hint { imm } => put_u8(out, *imm),
        IrOp::NzcvBitOp { dst, flags, bit } => {
            put_vid(out, *dst);
            put_fid(out, *flags);
            put_nzcv(out, *bit);
        }
        IrOp::Unimplemented(w) => put_u32(out, *w),

        // Guest CPU state access
        IrOp::ReadGpr { dst, reg, sf } => {
            put_vid(out, *dst);
            put_u8(out, *reg);
            put_u8(out, if *sf { 1 } else { 0 });
        }
        IrOp::WriteGpr { reg, src, sf } => {
            put_u8(out, *reg);
            put_vid(out, *src);
            put_u8(out, if *sf { 1 } else { 0 });
        }
        IrOp::ReadSp { dst, sf } => {
            put_vid(out, *dst);
            put_u8(out, if *sf { 1 } else { 0 });
        }
        IrOp::WriteSp { src, sf } => {
            put_vid(out, *src);
            put_u8(out, if *sf { 1 } else { 0 });
        }
        IrOp::ReadFpr { dst, reg } => {
            put_vid(out, *dst);
            put_u8(out, *reg);
        }
        IrOp::WriteFpr { reg, src } => {
            put_u8(out, *reg);
            put_vid(out, *src);
        }
        IrOp::ReadFlags { dst } => put_fid(out, *dst),
        IrOp::WriteFlags { src } => put_fid(out, *src),
        IrOp::ReadPc { dst } => put_vid(out, *dst),
        IrOp::WritePc { src } => put_vid(out, *src),

        // Variants whose payload codec lands in a follow-up prompt:
        _ => return Err(SerErr::NotYetImplemented),
    }
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<(IrOp, usize), SerErr> {
    let mut r = Reader::new(bytes);
    let tag = r.u8()?;
    let op = match tag {
        0x02 => IrOp::ConstI64 {
            dst: r.vid()?,
            val: r.i64()?,
        },
        0x01 => IrOp::ConstI32 {
            dst: r.vid()?,
            val: r.i32()?,
        },
        0x10 => IrOp::Add {
            dst: r.vid()?, a: r.vid()?, b: r.vid()?,
        },
        0x11 => IrOp::Sub {
            dst: r.vid()?, a: r.vid()?, b: r.vid()?,
        },
        0x13 => IrOp::And { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x14 => IrOp::Or  { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x15 => IrOp::Xor { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x17 => IrOp::Shl { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x18 => IrOp::LShr { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x19 => IrOp::AShr { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1A => IrOp::Ror { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1B => IrOp::Mul { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1C => IrOp::MulHU { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1D => IrOp::MulHS { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1E => IrOp::SDiv { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x1F => IrOp::UDiv { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x20 => IrOp::Madd { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0x21 => IrOp::Msub { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0x12 => IrOp::Neg { dst: r.vid()?, a: r.vid()? },
        0x16 => IrOp::Not { dst: r.vid()?, a: r.vid()? },
        0x22 => IrOp::Rbit { dst: r.vid()?, a: r.vid()? },
        0x24 => IrOp::Clz { dst: r.vid()?, a: r.vid()? },
        0x25 => IrOp::Cls { dst: r.vid()?, a: r.vid()? },
        0x26 => IrOp::Bswap16 { dst: r.vid()?, a: r.vid()? },
        0x27 => IrOp::Bswap32 { dst: r.vid()?, a: r.vid()? },
        0x28 => IrOp::Bswap64 { dst: r.vid()?, a: r.vid()? },
        0x30 => IrOp::AddS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x31 => IrOp::SubS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x32 => IrOp::AndS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x35 => IrOp::Cmp { flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x36 => IrOp::Cmn { flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x37 => IrOp::Tst { flags: r.fid()?, a: r.vid()?, b: r.vid()? },
        0x40 => IrOp::Sext { dst: r.vid()?, a: r.vid()?, from_bits: r.u8()?, to_bits: r.u8()? },
        0x41 => IrOp::Zext { dst: r.vid()?, a: r.vid()?, from_bits: r.u8()?, to_bits: r.u8()? },
        0x42 => IrOp::Trunc { dst: r.vid()?, a: r.vid()?, to_bits: r.u8()? },
        0x50 => IrOp::Load { dst: r.vid()?, addr: r.vid()?, ty: r.loadty()?, order: r.memord()? },
        0x51 => IrOp::Store { val: r.vid()?, addr: r.vid()?, ty: r.storety()?, order: r.memord()? },
        0x52 => IrOp::LoadExclusive { dst: r.vid()?, addr: r.vid()?, ty: r.loadty()? },
        0x53 => IrOp::StoreExclusive {
            status: r.vid()?, val: r.vid()?, addr: r.vid()?, ty: r.storety()?,
        },
        0x56 => IrOp::AtomicRmw {
            dst: r.vid()?, op: r.atomicop()?, addr: r.vid()?, val: r.vid()?, order: r.memord()?,
        },
        0x57 => IrOp::AtomicCas {
            dst: r.vid()?, addr: r.vid()?, expected: r.vid()?, new: r.vid()?, order: r.memord()?,
        },
        0x60 => IrOp::Branch { target: r.bid()? },
        0x61 => IrOp::CondBranch {
            cond: r.cond()?, flags: r.fid()?, taken: r.bid()?, fallthru: r.bid()?,
        },
        0x62 => IrOp::IndirectBranch { target: r.vid()? },
        0x63 => IrOp::Call { target: r.vid()?, link_pc: r.u64()? },
        0x64 => IrOp::Return { target: r.vid()? },
        0x65 => IrOp::Cbz { a: r.vid()?, taken: r.bid()?, fallthru: r.bid()? },
        0x66 => IrOp::Cbnz { a: r.vid()?, taken: r.bid()?, fallthru: r.bid()? },
        0x67 => IrOp::Tbz {
            a: r.vid()?, bit: r.u8()?, taken: r.bid()?, fallthru: r.bid()?,
        },
        0x68 => IrOp::Tbnz {
            a: r.vid()?, bit: r.u8()?, taken: r.bid()?, fallthru: r.bid()?,
        },
        0xC0 => IrOp::Hvc { imm16: r.u16()? },
        0xC1 => IrOp::Svc { imm16: r.u16()? },
        0xC2 => IrOp::Smc { imm16: r.u16()? },
        0xC3 => IrOp::Brk { imm16: r.u16()? },
        0xC4 => IrOp::Hlt { imm16: r.u16()? },
        0xC7 => IrOp::Dmb { domain: r.barrier()? },
        0xC8 => IrOp::Dsb { domain: r.barrier()? },
        0xC9 => IrOp::Isb,
        0xCA => IrOp::Sb,
        0xCB => IrOp::Hint { imm: r.u8()? },
        0x3A => IrOp::NzcvBitOp { dst: r.vid()?, flags: r.fid()?, bit: r.nzcv()? },
        0xE0 => IrOp::ReadGpr { dst: r.vid()?, reg: r.u8()?, sf: r.u8()? != 0 },
        0xE1 => IrOp::WriteGpr { reg: r.u8()?, src: r.vid()?, sf: r.u8()? != 0 },
        0xE2 => IrOp::ReadSp { dst: r.vid()?, sf: r.u8()? != 0 },
        0xE3 => IrOp::WriteSp { src: r.vid()?, sf: r.u8()? != 0 },
        0xE4 => IrOp::ReadFpr { dst: r.vid()?, reg: r.u8()? },
        0xE5 => IrOp::WriteFpr { reg: r.u8()?, src: r.vid()? },
        0xE6 => IrOp::ReadFlags { dst: r.fid()? },
        0xE7 => IrOp::WriteFlags { src: r.fid()? },
        0xE8 => IrOp::ReadPc { dst: r.vid()? },
        0xE9 => IrOp::WritePc { src: r.vid()? },
        0xF0 => IrOp::X86Mfence,
        0xF1 => IrOp::X86Cpuid,
        0xFF => IrOp::Unimplemented(r.u32()?),
        other => return Err(SerErr::BadTag(other)),
    };
    Ok((op, r.pos))
}

/// Stable 1-byte tag per [`IrOp`] variant. Stability matters for the AOT cache
/// across releases; once AT-22 ships, changing a tag is a breaking format
/// version bump.
pub fn variant_tag(op: &IrOp) -> u8 {
    match op {
        IrOp::ConstI32 { .. } => 0x01,
        IrOp::ConstI64 { .. } => 0x02,
        IrOp::ConstF32 { .. } => 0x03,
        IrOp::ConstF64 { .. } => 0x04,
        IrOp::ConstVec128 { .. } => 0x05,

        IrOp::Add { .. } => 0x10,
        IrOp::Sub { .. } => 0x11,
        IrOp::Neg { .. } => 0x12,
        IrOp::And { .. } => 0x13,
        IrOp::Or { .. } => 0x14,
        IrOp::Xor { .. } => 0x15,
        IrOp::Not { .. } => 0x16,
        IrOp::Shl { .. } => 0x17,
        IrOp::LShr { .. } => 0x18,
        IrOp::AShr { .. } => 0x19,
        IrOp::Ror { .. } => 0x1A,
        IrOp::Mul { .. } => 0x1B,
        IrOp::MulHU { .. } => 0x1C,
        IrOp::MulHS { .. } => 0x1D,
        IrOp::SDiv { .. } => 0x1E,
        IrOp::UDiv { .. } => 0x1F,
        IrOp::Madd { .. } => 0x20,
        IrOp::Msub { .. } => 0x21,
        IrOp::Rbit { .. } => 0x22,
        IrOp::Rev { .. } => 0x23,
        IrOp::Clz { .. } => 0x24,
        IrOp::Cls { .. } => 0x25,
        IrOp::Bswap16 { .. } => 0x26,
        IrOp::Bswap32 { .. } => 0x27,
        IrOp::Bswap64 { .. } => 0x28,

        IrOp::AddS { .. } => 0x30,
        IrOp::SubS { .. } => 0x31,
        IrOp::AndS { .. } => 0x32,
        IrOp::Adcs { .. } => 0x33,
        IrOp::Sbcs { .. } => 0x34,
        IrOp::Cmp { .. } => 0x35,
        IrOp::Cmn { .. } => 0x36,
        IrOp::Tst { .. } => 0x37,
        IrOp::CCmp { .. } => 0x38,
        IrOp::Csel { .. } => 0x39,
        IrOp::NzcvBitOp { .. } => 0x3A,

        IrOp::Sext { .. } => 0x40,
        IrOp::Zext { .. } => 0x41,
        IrOp::Trunc { .. } => 0x42,

        IrOp::Load { .. } => 0x50,
        IrOp::Store { .. } => 0x51,
        IrOp::LoadExclusive { .. } => 0x52,
        IrOp::StoreExclusive { .. } => 0x53,
        IrOp::LoadPair { .. } => 0x54,
        IrOp::StorePair { .. } => 0x55,
        IrOp::AtomicRmw { .. } => 0x56,
        IrOp::AtomicCas { .. } => 0x57,

        IrOp::Branch { .. } => 0x60,
        IrOp::CondBranch { .. } => 0x61,
        IrOp::IndirectBranch { .. } => 0x62,
        IrOp::Call { .. } => 0x63,
        IrOp::Return { .. } => 0x64,
        IrOp::Cbz { .. } => 0x65,
        IrOp::Cbnz { .. } => 0x66,
        IrOp::Tbz { .. } => 0x67,
        IrOp::Tbnz { .. } => 0x68,

        IrOp::VAdd { .. } => 0x80,
        IrOp::VSub { .. } => 0x81,
        IrOp::VMul { .. } => 0x82,
        IrOp::VAnd { .. } => 0x83,
        IrOp::VOr { .. } => 0x84,
        IrOp::VXor { .. } => 0x85,
        IrOp::VShl { .. } => 0x86,
        IrOp::VLShr { .. } => 0x87,
        IrOp::VAShr { .. } => 0x88,
        IrOp::VNeg { .. } => 0x89,
        IrOp::VAbs { .. } => 0x8A,
        IrOp::VMin { .. } => 0x8B,
        IrOp::VMax { .. } => 0x8C,
        IrOp::VCmp { .. } => 0x8D,
        IrOp::VDup { .. } => 0x8E,
        IrOp::VInsLane { .. } => 0x8F,
        IrOp::VExtractLane { .. } => 0x90,
        IrOp::VPermute { .. } => 0x91,
        IrOp::VTbl { .. } => 0x92,
        IrOp::VTbx { .. } => 0x93,
        IrOp::VModImm { .. } => 0x94,
        IrOp::VConvert { .. } => 0x95,
        IrOp::VFAdd { .. } => 0x96,
        IrOp::VFSub { .. } => 0x97,
        IrOp::VFMul { .. } => 0x98,
        IrOp::VFDiv { .. } => 0x99,
        IrOp::VFMa { .. } => 0x9A,

        IrOp::FAdd { .. } => 0xA0,
        IrOp::FSub { .. } => 0xA1,
        IrOp::FMul { .. } => 0xA2,
        IrOp::FDiv { .. } => 0xA3,
        IrOp::FNeg { .. } => 0xA4,
        IrOp::FAbs { .. } => 0xA5,
        IrOp::FSqrt { .. } => 0xA6,
        IrOp::FCvt { .. } => 0xA7,
        IrOp::FToInt { .. } => 0xA8,
        IrOp::IntToF { .. } => 0xA9,
        IrOp::FCmp { .. } => 0xAA,

        IrOp::AesE { .. } => 0xB0,
        IrOp::AesD { .. } => 0xB1,
        IrOp::AesMc { .. } => 0xB2,
        IrOp::AesImc { .. } => 0xB3,
        IrOp::Sha1c { .. } => 0xB4,
        IrOp::Sha1m { .. } => 0xB5,
        IrOp::Sha1p { .. } => 0xB6,
        IrOp::Sha256h { .. } => 0xB7,
        IrOp::Sha256h2 { .. } => 0xB8,
        IrOp::Sha256su0 { .. } => 0xB9,
        IrOp::Sha256su1 { .. } => 0xBA,
        IrOp::Pmull { .. } => 0xBB,
        IrOp::Crc32 { .. } => 0xBC,

        IrOp::Hvc { .. } => 0xC0,
        IrOp::Svc { .. } => 0xC1,
        IrOp::Smc { .. } => 0xC2,
        IrOp::Brk { .. } => 0xC3,
        IrOp::Hlt { .. } => 0xC4,
        IrOp::Mrs { .. } => 0xC5,
        IrOp::Msr { .. } => 0xC6,
        IrOp::Dmb { .. } => 0xC7,
        IrOp::Dsb { .. } => 0xC8,
        IrOp::Isb => 0xC9,
        IrOp::Sb => 0xCA,
        IrOp::Hint { .. } => 0xCB,

        // Guest CPU state access
        IrOp::ReadGpr { .. } => 0xE0,
        IrOp::WriteGpr { .. } => 0xE1,
        IrOp::ReadSp { .. } => 0xE2,
        IrOp::WriteSp { .. } => 0xE3,
        IrOp::ReadFpr { .. } => 0xE4,
        IrOp::WriteFpr { .. } => 0xE5,
        IrOp::ReadFlags { .. } => 0xE6,
        IrOp::WriteFlags { .. } => 0xE7,
        IrOp::ReadPc { .. } => 0xE8,
        IrOp::WritePc { .. } => 0xE9,

        IrOp::X86Mfence => 0xF0,
        IrOp::X86Cpuid => 0xF1,
        IrOp::Unimplemented(_) => 0xFF,
    }
}

/// Variants that have a payload codec implemented in this Phase A fill.
/// Used by `at2_ir_roundtrip` to scope its assertions.
pub fn is_codec_implemented(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::ConstI32 { .. }
            | IrOp::ConstI64 { .. }
            | IrOp::Add { .. }
            | IrOp::Sub { .. }
            | IrOp::And { .. }
            | IrOp::Or { .. }
            | IrOp::Xor { .. }
            | IrOp::Shl { .. }
            | IrOp::LShr { .. }
            | IrOp::AShr { .. }
            | IrOp::Ror { .. }
            | IrOp::Mul { .. }
            | IrOp::MulHU { .. }
            | IrOp::MulHS { .. }
            | IrOp::SDiv { .. }
            | IrOp::UDiv { .. }
            | IrOp::Madd { .. }
            | IrOp::Msub { .. }
            | IrOp::Neg { .. }
            | IrOp::Not { .. }
            | IrOp::Rbit { .. }
            | IrOp::Clz { .. }
            | IrOp::Cls { .. }
            | IrOp::Bswap16 { .. }
            | IrOp::Bswap32 { .. }
            | IrOp::Bswap64 { .. }
            | IrOp::AddS { .. }
            | IrOp::SubS { .. }
            | IrOp::AndS { .. }
            | IrOp::Cmp { .. }
            | IrOp::Cmn { .. }
            | IrOp::Tst { .. }
            | IrOp::Sext { .. }
            | IrOp::Zext { .. }
            | IrOp::Trunc { .. }
            | IrOp::Load { .. }
            | IrOp::Store { .. }
            | IrOp::LoadExclusive { .. }
            | IrOp::StoreExclusive { .. }
            | IrOp::AtomicRmw { .. }
            | IrOp::AtomicCas { .. }
            | IrOp::Branch { .. }
            | IrOp::CondBranch { .. }
            | IrOp::IndirectBranch { .. }
            | IrOp::Call { .. }
            | IrOp::Return { .. }
            | IrOp::Cbz { .. }
            | IrOp::Cbnz { .. }
            | IrOp::Tbz { .. }
            | IrOp::Tbnz { .. }
            | IrOp::Hvc { .. }
            | IrOp::Svc { .. }
            | IrOp::Smc { .. }
            | IrOp::Brk { .. }
            | IrOp::Hlt { .. }
            | IrOp::Dmb { .. }
            | IrOp::Dsb { .. }
            | IrOp::Isb
            | IrOp::Sb
            | IrOp::Hint { .. }
            | IrOp::NzcvBitOp { .. }
            | IrOp::ReadGpr { .. }
            | IrOp::WriteGpr { .. }
            | IrOp::ReadSp { .. }
            | IrOp::WriteSp { .. }
            | IrOp::ReadFpr { .. }
            | IrOp::WriteFpr { .. }
            | IrOp::ReadFlags { .. }
            | IrOp::WriteFlags { .. }
            | IrOp::ReadPc { .. }
            | IrOp::WritePc { .. }
            | IrOp::Unimplemented(_)
    )
}
