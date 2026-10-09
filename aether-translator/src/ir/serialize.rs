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
use super::ops::{
    FpBinOp, FpFmaOp, FpUnOp, RoundMode, VecBinOp, VecCmpOp, VecFpCmpOp, VecFpOp, VecFpUnOp,
    VecPairOp, VecReduceOp, VecShiftOp, VecUnOp,
};
use super::value::{IrValueId, LaneType};
use super::{BlockId, IrOp};

use crate::decoder::sysreg::{self, SysReg, SysRegId};
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

// ---------- M4b-6 SIMD/FP op-kind enum codecs ----------
// Each fieldless enum has declaration-order discriminants (no repr/explicit
// values), so `v as u8` is the stable byte tag. Readers map back explicitly.
fn put_vecbinop(out: &mut Vec<u8>, v: VecBinOp) { put_u8(out, v as u8); }
fn put_vecunop(out: &mut Vec<u8>, v: VecUnOp) { put_u8(out, v as u8); }
fn put_vecshiftop(out: &mut Vec<u8>, v: VecShiftOp) { put_u8(out, v as u8); }
fn put_veccmpop(out: &mut Vec<u8>, v: VecCmpOp) { put_u8(out, v as u8); }
fn put_vecpairop(out: &mut Vec<u8>, v: VecPairOp) { put_u8(out, v as u8); }
fn put_vecreduceop(out: &mut Vec<u8>, v: VecReduceOp) { put_u8(out, v as u8); }
fn put_vecfpop(out: &mut Vec<u8>, v: VecFpOp) { put_u8(out, v as u8); }
fn put_vecfpcmpop(out: &mut Vec<u8>, v: VecFpCmpOp) { put_u8(out, v as u8); }
fn put_vecfpunop(out: &mut Vec<u8>, v: VecFpUnOp) { put_u8(out, v as u8); }
fn put_fpbinop(out: &mut Vec<u8>, v: FpBinOp) { put_u8(out, v as u8); }
fn put_fpfmaop(out: &mut Vec<u8>, v: FpFmaOp) { put_u8(out, v as u8); }
fn put_fpunop(out: &mut Vec<u8>, v: FpUnOp) { put_u8(out, v as u8); }
fn put_round(out: &mut Vec<u8>, v: RoundMode) { put_u8(out, v as u8); }

#[inline]
fn put_lane(out: &mut Vec<u8>, l: LaneType) {
    let v = match l {
        LaneType::I8 => 0,
        LaneType::I16 => 1,
        LaneType::I32 => 2,
        LaneType::I64 => 3,
        LaneType::F16 => 4,
        LaneType::F32 => 5,
        LaneType::F64 => 6,
    };
    put_u8(out, v);
}
#[inline]
fn put_bytes16(out: &mut Vec<u8>, b: &[u8; 16]) {
    out.extend_from_slice(b);
}
#[inline]
fn put_sysreg(out: &mut Vec<u8>, r: SysReg) {
    // Named variants and the OtherKnown escape all collapse to a 16-bit packed
    // encoding via SysReg::to_id; decode resolves it back through sysreg::lookup.
    put_u16(out, r.to_id().0);
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

    // ---------- M4b-6 SIMD/FP op-kind readers ----------
    fn vecbinop(&mut self) -> Result<VecBinOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecBinOp::Add, 1 => VecBinOp::Sub, 2 => VecBinOp::Mul,
            3 => VecBinOp::Mla, 4 => VecBinOp::Mls, 5 => VecBinOp::SqAdd,
            6 => VecBinOp::UqAdd, 7 => VecBinOp::SqSub, 8 => VecBinOp::UqSub,
            9 => VecBinOp::SHadd, 10 => VecBinOp::UHadd, 11 => VecBinOp::SrHadd,
            12 => VecBinOp::UrHadd, 13 => VecBinOp::SAbd, 14 => VecBinOp::UAbd,
            15 => VecBinOp::SAba, 16 => VecBinOp::UAba, 17 => VecBinOp::SMax,
            18 => VecBinOp::SMin, 19 => VecBinOp::UMax, 20 => VecBinOp::UMin,
            21 => VecBinOp::And, 22 => VecBinOp::Or, 23 => VecBinOp::Eor,
            24 => VecBinOp::Bic, 25 => VecBinOp::Orn,
            26 => VecBinOp::Bsl, 27 => VecBinOp::Bit, 28 => VecBinOp::Bif,
            29 => VecBinOp::SHsub, 30 => VecBinOp::UHsub,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecunop(&mut self) -> Result<VecUnOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecUnOp::Abs, 1 => VecUnOp::Neg,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecshiftop(&mut self) -> Result<VecShiftOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecShiftOp::Shl, 1 => VecShiftOp::SShr, 2 => VecShiftOp::UShr,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn veccmpop(&mut self) -> Result<VecCmpOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecCmpOp::Eq, 1 => VecCmpOp::SGt, 2 => VecCmpOp::SGe,
            3 => VecCmpOp::UGt, 4 => VecCmpOp::UGe, 5 => VecCmpOp::Tst,
            6 => VecCmpOp::SLt, 7 => VecCmpOp::SLe,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecpairop(&mut self) -> Result<VecPairOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecPairOp::Add, 1 => VecPairOp::SMax, 2 => VecPairOp::SMin,
            3 => VecPairOp::UMax, 4 => VecPairOp::UMin,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecreduceop(&mut self) -> Result<VecReduceOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecReduceOp::Add, 1 => VecReduceOp::SMax, 2 => VecReduceOp::SMin,
            3 => VecReduceOp::UMax, 4 => VecReduceOp::UMin,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecfpop(&mut self) -> Result<VecFpOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecFpOp::Add, 1 => VecFpOp::Sub, 2 => VecFpOp::Mul,
            3 => VecFpOp::Div, 4 => VecFpOp::Min, 5 => VecFpOp::Max,
            6 => VecFpOp::MaxNm, 7 => VecFpOp::MinNm, 8 => VecFpOp::Mla,
            9 => VecFpOp::Mls, 10 => VecFpOp::Abd,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecfpcmpop(&mut self) -> Result<VecFpCmpOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecFpCmpOp::Eq, 1 => VecFpCmpOp::Gt, 2 => VecFpCmpOp::Ge,
            3 => VecFpCmpOp::Lt, 4 => VecFpCmpOp::Le,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn vecfpunop(&mut self) -> Result<VecFpUnOp, SerErr> {
        Ok(match self.u8()? {
            0 => VecFpUnOp::Abs, 1 => VecFpUnOp::Neg, 2 => VecFpUnOp::Sqrt,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn fpbinop(&mut self) -> Result<FpBinOp, SerErr> {
        Ok(match self.u8()? {
            0 => FpBinOp::Add, 1 => FpBinOp::Sub, 2 => FpBinOp::Mul,
            3 => FpBinOp::Div, 4 => FpBinOp::Min, 5 => FpBinOp::Max, 6 => FpBinOp::NMul,
            7 => FpBinOp::MaxNm, 8 => FpBinOp::MinNm,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn fpunop(&mut self) -> Result<FpUnOp, SerErr> {
        Ok(match self.u8()? {
            0 => FpUnOp::Abs, 1 => FpUnOp::Neg, 2 => FpUnOp::Sqrt, 3 => FpUnOp::Mov,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn fpfmaop(&mut self) -> Result<FpFmaOp, SerErr> {
        Ok(match self.u8()? {
            0 => FpFmaOp::Madd, 1 => FpFmaOp::Msub, 2 => FpFmaOp::NMadd, 3 => FpFmaOp::NMsub,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn round(&mut self) -> Result<RoundMode, SerErr> {
        Ok(match self.u8()? {
            0 => RoundMode::Nearest, 1 => RoundMode::NegInf, 2 => RoundMode::PosInf,
            3 => RoundMode::Zero, 4 => RoundMode::NearestTiesAway, 5 => RoundMode::Current,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn lane(&mut self) -> Result<LaneType, SerErr> {
        Ok(match self.u8()? {
            0 => LaneType::I8, 1 => LaneType::I16, 2 => LaneType::I32, 3 => LaneType::I64,
            4 => LaneType::F16, 5 => LaneType::F32, 6 => LaneType::F64,
            v => return Err(SerErr::BadEnum(v)),
        })
    }
    fn bytes16(&mut self) -> Result<[u8; 16], SerErr> {
        let s = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn sysreg(&mut self) -> Result<SysReg, SerErr> {
        // Inverse of put_sysreg: the 16-bit packed id resolves via the catalog.
        Ok(sysreg::lookup(SysRegId(self.u16()?)))
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
        IrOp::Neg { dst, a } | IrOp::Not { dst, a }
        | IrOp::Bswap16 { dst, a } | IrOp::Bswap32 { dst, a }
        | IrOp::Bswap64 { dst, a } => {
            put_vid(out, *dst);
            put_vid(out, *a);
        }
        IrOp::Rbit { dst, a, sf } | IrOp::Clz { dst, a, sf } | IrOp::Cls { dst, a, sf } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            out.push(if *sf { 1 } else { 0 });
        }
        IrOp::Madd { dst, a, b, c } | IrOp::Msub { dst, a, b, c } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_vid(out, *b);
            put_vid(out, *c);
        }
        IrOp::AddS { dst, flags, a, b, sf } | IrOp::SubS { dst, flags, a, b, sf }
        | IrOp::AndS { dst, flags, a, b, sf } => {
            put_vid(out, *dst);
            put_fid(out, *flags);
            put_vid(out, *a);
            put_vid(out, *b);
            put_u8(out, *sf as u8);
        }
        IrOp::Cmp { flags, a, b, sf } | IrOp::Cmn { flags, a, b, sf } | IrOp::Tst { flags, a, b, sf } => {
            put_fid(out, *flags);
            put_vid(out, *a);
            put_vid(out, *b);
            put_u8(out, *sf as u8);
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
        IrOp::AtomicRmw { dst, op, addr, val, order, size } => {
            put_vid(out, *dst);
            put_atomicop(out, *op);
            put_vid(out, *addr);
            put_vid(out, *val);
            put_memord(out, *order);
            put_u8(out, *size);
        }
        IrOp::AtomicCas { dst, addr, expected, new, order, size } => {
            put_vid(out, *dst);
            put_vid(out, *addr);
            put_vid(out, *expected);
            put_vid(out, *new);
            put_memord(out, *order);
            put_u8(out, *size);
        }
        IrOp::AtomicCasPair { dst_a, dst_b, addr, expected_a, expected_b, new_a, new_b, order, size } => {
            put_vid(out, *dst_a);
            put_vid(out, *dst_b);
            put_vid(out, *addr);
            put_vid(out, *expected_a);
            put_vid(out, *expected_b);
            put_vid(out, *new_a);
            put_vid(out, *new_b);
            put_memord(out, *order);
            put_u8(out, *size);
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
        IrOp::EretRt => {} // no payload
        IrOp::VecMoviImm { d, lo, hi } => {
            put_u8(out, *d);
            put_u64(out, *lo);
            put_u64(out, *hi);
        }
        IrOp::VecDupGpr { d, src, size, q } => {
            put_u8(out, *d);
            put_vid(out, *src);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
        }
        IrOp::FpCvtIntScalar { d, src, to_dbl, signed, src_64, fbits } => {
            put_u8(out, *d);
            put_vid(out, *src);
            put_u8(out, u8::from(*to_dbl));
            put_u8(out, u8::from(*signed));
            put_u8(out, u8::from(*src_64));
            put_u8(out, *fbits);
        }
        IrOp::FpCvtToIntScalar { dst, n, from_dbl, to_64, round, signed } => {
            put_vid(out, *dst);
            put_u8(out, *n);
            put_u8(out, u8::from(*from_dbl));
            put_u8(out, u8::from(*to_64));
            put_round(out, *round);
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecExtractLane { dst, n, lane, size, signed } => {
            put_vid(out, *dst);
            put_u8(out, *n);
            put_u8(out, *lane);
            put_u8(out, *size);
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecInsGpr { d, lane, src, size } => {
            put_u8(out, *d);
            put_u8(out, *lane);
            put_vid(out, *src);
            put_u8(out, *size);
        }
        IrOp::VecCnt { d, n, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, u8::from(*q));
        }
        IrOp::VecAddvLong { d, n, esize, q, signed } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *esize);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecCmpZero { op, size, q, d, n } => {
            put_veccmpop(out, *op);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
            put_u8(out, *d);
            put_u8(out, *n);
        }
        IrOp::VecShiftNarrow { d, n, shift, esize_out, high } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *shift);
            put_u8(out, *esize_out);
            put_u8(out, u8::from(*high));
        }
        IrOp::VecShiftLong { d, n, shift, esize_in, high, signed } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *shift);
            put_u8(out, *esize_in);
            put_u8(out, u8::from(*high));
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecShiftReg { d, n, m, size, q, signed } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecShiftIns { d, n, shift, size, q, left } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *shift);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*left));
        }
        IrOp::VecShiftNarrowSat { d, n, shift, esize_out, high, round, src_signed, dst_signed, modular } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *shift);
            put_u8(out, *esize_out);
            put_u8(out, u8::from(*high));
            put_u8(out, u8::from(*round));
            put_u8(out, u8::from(*src_signed));
            put_u8(out, u8::from(*dst_signed));
            put_u8(out, u8::from(*modular));
        }
        IrOp::VecExt { d, n, m, imm, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, *imm);
            put_u8(out, u8::from(*q));
        }
        IrOp::VecTbl1 { d, n, m, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, u8::from(*q));
        }
        IrOp::VecTblN { d, n, m, len, op, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, *len);
            put_u8(out, *op);
            put_u8(out, u8::from(*q));
        }
        IrOp::VecDupElem { d, n, size, lane, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *size);
            put_u8(out, *lane);
            put_u8(out, u8::from(*q));
        }
        IrOp::VecPmull { d, n, m, high } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, u8::from(*high));
        }
        IrOp::VecMulLong { d, n, m, size, q, signed, accum, sub } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*signed));
            put_u8(out, u8::from(*accum));
            put_u8(out, u8::from(*sub));
        }
        IrOp::VecRev64 { d, n, size, q, container } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *size);
            put_u8(out, u8::from(*q));
            put_u8(out, *container);
        }
        IrOp::CryptoSha256 { kind, d, n, m } => {
            put_u8(out, *kind);
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
        }
        IrOp::VecBicOrrImm { d, imm, is_bic, q } => {
            put_u8(out, *d);
            put_u64(out, *imm);
            put_u8(out, u8::from(*is_bic));
            put_u8(out, u8::from(*q));
        }
        IrOp::VecAddLongPair { d, n, esize_in, q, signed } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *esize_in);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*signed));
        }
        IrOp::VecUnzip { d, n, m, esize, q, odd } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *m);
            put_u8(out, *esize);
            put_u8(out, u8::from(*q));
            put_u8(out, u8::from(*odd));
        }
        IrOp::VecReduceAdd { d, n, esize, q } => {
            put_u8(out, *d);
            put_u8(out, *n);
            put_u8(out, *esize);
            put_u8(out, u8::from(*q));
        }
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

        // ───── M4b-6 SIMD/FP/crypto ctx-template ops ─────
        IrOp::VecBin { op, size, q, d, n, m } => {
            put_vecbinop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::VecUn { op, size, q, d, n } => {
            put_vecunop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::VecShift { op, size, q, d, n, amount } => {
            put_vecshiftop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *amount);
        }
        IrOp::VecShiftAcc { signed, size, q, d, n, amount } => {
            put_u8(out, *signed as u8); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *amount);
        }
        IrOp::VecCmp { op, size, q, d, n, m } => {
            put_veccmpop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::VecPair { op, size, q, d, n, m } => {
            put_vecpairop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::VecReduce { op, size, q, d, n } => {
            put_vecreduceop(out, *op); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::VecAddLong { across, signed, size, q, d, n } => {
            put_u8(out, *across as u8); put_u8(out, *signed as u8); put_u8(out, *size);
            put_u8(out, *q as u8); put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::VecFp { op, dbl, q, d, n, m } => {
            put_vecfpop(out, *op); put_u8(out, *dbl as u8); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::VecFpCmp { op, dbl, q, d, n, m, zero } => {
            put_vecfpcmpop(out, *op); put_u8(out, *dbl as u8); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m); put_u8(out, *zero as u8);
        }
        IrOp::VecFpUn { op, dbl, q, d, n } => {
            put_vecfpunop(out, *op); put_u8(out, *dbl as u8); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::VecByElem { op, is_fp, dbl, size, q, d, n, m, idx } => {
            put_vecfpop(out, *op); put_u8(out, *is_fp as u8); put_u8(out, *dbl as u8);
            put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m); put_u8(out, *idx);
        }
        IrOp::VecCvtFp { to_fp, signed, dbl, q, d, n } => {
            put_u8(out, *to_fp as u8); put_u8(out, *signed as u8); put_u8(out, *dbl as u8);
            put_u8(out, *q as u8); put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::VecZipTrn { kind, size, q, d, n, m } => {
            put_u8(out, *kind); put_u8(out, *size); put_u8(out, *q as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::VecScalarPair { is_fp, dbl, d, n } => {
            put_u8(out, *is_fp as u8); put_u8(out, *dbl as u8); put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::FpFromInt { d, n_gpr, from_bits, to_bits, signed } => {
            put_u8(out, *d); put_u8(out, *n_gpr); put_u8(out, *from_bits);
            put_u8(out, *to_bits); put_u8(out, *signed as u8);
        }
        IrOp::FpToIntR { d_gpr, n, from_bits, to_bits, signed, round } => {
            put_u8(out, *d_gpr); put_u8(out, *n); put_u8(out, *from_bits);
            put_u8(out, *to_bits); put_u8(out, *signed as u8); put_round(out, *round);
        }
        IrOp::FpRound { d, n, dbl, round, raise_inexact } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *dbl as u8);
            put_round(out, *round); put_u8(out, *raise_inexact as u8);
        }
        IrOp::VecFpRound { d, n, dbl, q, round } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *dbl as u8);
            put_u8(out, *q as u8); put_round(out, *round);
        }
        IrOp::VecFpCvtWidth { d, n, widen, half, upper } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *widen as u8);
            put_u8(out, *half as u8); put_u8(out, *upper as u8);
        }
        IrOp::FpCvt2 { d, n, from_bits, to_bits } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *from_bits); put_u8(out, *to_bits);
        }
        IrOp::FpCsel { d, n, m, cond, dbl } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m); put_cond(out, *cond); put_u8(out, *dbl as u8);
        }
        IrOp::FpMov { d, n, width_bits } => {
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *width_bits);
        }
        IrOp::FpBin { op, dbl, d, n, m } => {
            put_fpbinop(out, *op); put_u8(out, *dbl as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::FpFma { op, dbl, d, n, m, a } => {
            put_fpfmaop(out, *op); put_u8(out, *dbl as u8);
            put_u8(out, *d); put_u8(out, *n); put_u8(out, *m); put_u8(out, *a);
        }
        IrOp::FpUn { op, dbl, d, n } => {
            put_fpunop(out, *op); put_u8(out, *dbl as u8); put_u8(out, *d); put_u8(out, *n);
        }
        IrOp::FpCmpN { n, m, dbl, zero } => {
            put_u8(out, *n); put_u8(out, *m); put_u8(out, *dbl as u8); put_u8(out, *zero as u8);
        }
        IrOp::FpToGpr { d_gpr, n, bits, high_half } => {
            put_u8(out, *d_gpr); put_u8(out, *n); put_u8(out, *bits); put_u8(out, *high_half as u8);
        }
        IrOp::FpFromGpr { d, n_gpr, bits, high_half } => {
            put_u8(out, *d); put_u8(out, *n_gpr); put_u8(out, *bits); put_u8(out, *high_half as u8);
        }
        IrOp::CryptoAesR { kind, d, n, m } => {
            put_u8(out, *kind); put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }
        IrOp::CryptoShaR { kind, d, n, m } => {
            put_u8(out, *kind); put_u8(out, *d); put_u8(out, *n); put_u8(out, *m);
        }

        // ───── Defensive-hardening fill: remaining variants ─────
        // Every variant that has a `variant_tag` now has an encode + decode arm
        // so the AOT-cache round-trip is total (no silent NotYetImplemented holes
        // if the Dispatcher / AOT path is ever enabled). Tags are kept stable.
        IrOp::ConstF32 { dst, bits } => {
            put_vid(out, *dst);
            put_u32(out, *bits);
        }
        IrOp::ConstF64 { dst, bits } => {
            put_vid(out, *dst);
            put_u64(out, *bits);
        }
        IrOp::ConstVec128 { dst, bytes } => {
            put_vid(out, *dst);
            put_bytes16(out, bytes);
        }
        IrOp::Rev { dst, a, bytes } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_u8(out, *bytes);
        }
        IrOp::Adcs { dst, flags, a, b, c_in, sf }
        | IrOp::Sbcs { dst, flags, a, b, c_in, sf } => {
            put_vid(out, *dst);
            put_fid(out, *flags);
            put_vid(out, *a);
            put_vid(out, *b);
            put_fid(out, *c_in);
            put_u8(out, *sf as u8);
        }
        IrOp::CCmp { flags_out, a, b, cond, nzcv_if_false, flags_in, is_neg, sf } => {
            put_fid(out, *flags_out);
            put_vid(out, *a);
            put_vid(out, *b);
            put_cond(out, *cond);
            put_u8(out, *nzcv_if_false);
            put_fid(out, *flags_in);
            put_u8(out, *is_neg as u8);
            put_u8(out, *sf as u8);
        }
        IrOp::Csel { dst, a, b, cond, flags, variant } => {
            put_vid(out, *dst);
            put_vid(out, *a);
            put_vid(out, *b);
            put_cond(out, *cond);
            put_fid(out, *flags);
            put_u8(out, *variant);
        }
        IrOp::LoadPair { dst_a, dst_b, addr, ty } => {
            put_vid(out, *dst_a);
            put_vid(out, *dst_b);
            put_vid(out, *addr);
            put_loadty(out, *ty);
        }
        IrOp::StorePair { val_a, val_b, addr, ty } => {
            put_vid(out, *val_a);
            put_vid(out, *val_b);
            put_vid(out, *addr);
            put_storety(out, *ty);
        }
        IrOp::ZeroBlock { addr } => put_vid(out, *addr),
        IrOp::StampFaultPc(pc) => put_u64(out, *pc),
        IrOp::X86Mfence | IrOp::X86Cpuid => {} // no payload
        // System register access — SysReg collapses to its 16-bit packed id.
        IrOp::Mrs { dst, reg } => {
            put_vid(out, *dst);
            put_sysreg(out, *reg);
        }
        IrOp::Msr { reg, val } => {
            put_sysreg(out, *reg);
            put_vid(out, *val);
        }
        // TLBI: 1-byte presence flag + optional VA operand.
        IrOp::TlbInval { va } => match va {
            Some(v) => { put_u8(out, 1); put_vid(out, *v); }
            None => put_u8(out, 0),
        },
        IrOp::AtS1E1 { va, is_write, at_el0 } => {
            put_vid(out, *va);
            put_u8(out, *is_write as u8);
            put_u8(out, *at_el0 as u8);
        }

        // ----- IrValueId-keyed NEON (XMM-allocator) ops -----
        IrOp::VAdd { dst, a, b, lane }
        | IrOp::VSub { dst, a, b, lane }
        | IrOp::VMul { dst, a, b, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_lane(out, *lane);
        }
        IrOp::VAnd { dst, a, b }
        | IrOp::VOr { dst, a, b }
        | IrOp::VXor { dst, a, b } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
        }
        IrOp::VShl { dst, a, amount, lane }
        | IrOp::VLShr { dst, a, amount, lane }
        | IrOp::VAShr { dst, a, amount, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_u8(out, *amount); put_lane(out, *lane);
        }
        IrOp::VNeg { dst, a, lane } | IrOp::VAbs { dst, a, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_lane(out, *lane);
        }
        IrOp::VMin { dst, a, b, lane, signed }
        | IrOp::VMax { dst, a, b, lane, signed } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
            put_lane(out, *lane); put_u8(out, *signed as u8);
        }
        IrOp::VCmp { dst, a, b, lane, eq, signed } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
            put_lane(out, *lane); put_u8(out, *eq as u8); put_u8(out, *signed as u8);
        }
        IrOp::VDup { dst, a, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_lane(out, *lane);
        }
        IrOp::VInsLane { dst, src, scalar, lane_idx, lane } => {
            put_vid(out, *dst); put_vid(out, *src); put_vid(out, *scalar);
            put_u8(out, *lane_idx); put_lane(out, *lane);
        }
        IrOp::VExtractLane { dst, a, lane_idx, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_u8(out, *lane_idx); put_lane(out, *lane);
        }
        IrOp::VPermute { dst, a, b, index } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_bytes16(out, index);
        }
        IrOp::VTbl { dst, table_lo, table_hi, index } => {
            put_vid(out, *dst); put_vid(out, *table_lo); put_vid(out, *table_hi); put_vid(out, *index);
        }
        IrOp::VTbx { dst, prev, table_lo, table_hi, index } => {
            put_vid(out, *dst); put_vid(out, *prev); put_vid(out, *table_lo);
            put_vid(out, *table_hi); put_vid(out, *index);
        }
        IrOp::VModImm { dst, imm, lane } => {
            put_vid(out, *dst); put_u64(out, *imm); put_lane(out, *lane);
        }
        IrOp::VConvert { dst, a, from, to } => {
            put_vid(out, *dst); put_vid(out, *a); put_lane(out, *from); put_lane(out, *to);
        }
        IrOp::VFAdd { dst, a, b, lane }
        | IrOp::VFSub { dst, a, b, lane }
        | IrOp::VFMul { dst, a, b, lane }
        | IrOp::VFDiv { dst, a, b, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_lane(out, *lane);
        }
        IrOp::VFMa { dst, a, b, c, lane } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_vid(out, *c); put_lane(out, *lane);
        }

        // ----- IrValueId-keyed scalar FP ops -----
        IrOp::FAdd { dst, a, b }
        | IrOp::FSub { dst, a, b }
        | IrOp::FMul { dst, a, b }
        | IrOp::FDiv { dst, a, b } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
        }
        IrOp::FNeg { dst, a } | IrOp::FAbs { dst, a } | IrOp::FSqrt { dst, a } => {
            put_vid(out, *dst); put_vid(out, *a);
        }
        IrOp::FCvt { dst, a, from_bits, to_bits } => {
            put_vid(out, *dst); put_vid(out, *a); put_u8(out, *from_bits); put_u8(out, *to_bits);
        }
        IrOp::FToInt { dst, a, to_bits, signed } => {
            put_vid(out, *dst); put_vid(out, *a); put_u8(out, *to_bits); put_u8(out, *signed as u8);
        }
        IrOp::IntToF { dst, a, from_bits, signed } => {
            put_vid(out, *dst); put_vid(out, *a); put_u8(out, *from_bits); put_u8(out, *signed as u8);
        }
        IrOp::FCmp { flags, a, b } => {
            put_fid(out, *flags); put_vid(out, *a); put_vid(out, *b);
        }

        // ----- IrValueId-keyed crypto ops -----
        IrOp::AesE { dst, a, key } | IrOp::AesD { dst, a, key } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *key);
        }
        IrOp::AesMc { dst, a } | IrOp::AesImc { dst, a } => {
            put_vid(out, *dst); put_vid(out, *a);
        }
        IrOp::Sha1c { dst, a, b, c }
        | IrOp::Sha1m { dst, a, b, c }
        | IrOp::Sha1p { dst, a, b, c }
        | IrOp::Sha256h { dst, a, b, c }
        | IrOp::Sha256h2 { dst, a, b, c }
        | IrOp::Sha256su1 { dst, a, b, c } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_vid(out, *c);
        }
        IrOp::Sha256su0 { dst, a, b } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
        }
        IrOp::Pmull { dst, a, b, wide } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b); put_u8(out, *wide as u8);
        }
        IrOp::Crc32 { dst, a, b, size, castagnoli } => {
            put_vid(out, *dst); put_vid(out, *a); put_vid(out, *b);
            put_u8(out, *size); put_u8(out, *castagnoli as u8);
        }
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
        0x22 => IrOp::Rbit { dst: r.vid()?, a: r.vid()?, sf: r.u8()? != 0 },
        0x24 => IrOp::Clz { dst: r.vid()?, a: r.vid()?, sf: r.u8()? != 0 },
        0x25 => IrOp::Cls { dst: r.vid()?, a: r.vid()?, sf: r.u8()? != 0 },
        0x26 => IrOp::Bswap16 { dst: r.vid()?, a: r.vid()? },
        0x27 => IrOp::Bswap32 { dst: r.vid()?, a: r.vid()? },
        0x28 => IrOp::Bswap64 { dst: r.vid()?, a: r.vid()? },
        0x30 => IrOp::AddS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
        0x31 => IrOp::SubS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
        0x32 => IrOp::AndS { dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
        0x35 => IrOp::Cmp { flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
        0x36 => IrOp::Cmn { flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
        0x37 => IrOp::Tst { flags: r.fid()?, a: r.vid()?, b: r.vid()?, sf: r.u8()? != 0 },
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
            size: r.u8()?,
        },
        0x57 => IrOp::AtomicCas {
            dst: r.vid()?, addr: r.vid()?, expected: r.vid()?, new: r.vid()?, order: r.memord()?,
            size: r.u8()?,
        },
        0x79 => IrOp::AtomicCasPair {
            dst_a: r.vid()?, dst_b: r.vid()?, addr: r.vid()?, expected_a: r.vid()?,
            expected_b: r.vid()?, new_a: r.vid()?, new_b: r.vid()?, order: r.memord()?,
            size: r.u8()?,
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
        0x59 => IrOp::EretRt,
        0x5A => IrOp::VecMoviImm { d: r.u8()?, lo: r.u64()?, hi: r.u64()? },
        0x5B => IrOp::VecDupGpr { d: r.u8()?, src: r.vid()?, size: r.u8()?, q: r.u8()? != 0 },
        0x73 => IrOp::FpCvtIntScalar { d: r.u8()?, src: r.vid()?, to_dbl: r.u8()? != 0, signed: r.u8()? != 0, src_64: r.u8()? != 0, fbits: r.u8()? },
        0x74 => IrOp::FpCvtToIntScalar { dst: r.vid()?, n: r.u8()?, from_dbl: r.u8()? != 0, to_64: r.u8()? != 0, round: r.round()?, signed: r.u8()? != 0 },
        0x5C => IrOp::VecExtractLane {
            dst: r.vid()?, n: r.u8()?, lane: r.u8()?, size: r.u8()?, signed: r.u8()? != 0,
        },
        0x5D => IrOp::VecInsGpr { d: r.u8()?, lane: r.u8()?, src: r.vid()?, size: r.u8()? },
        0x5E => IrOp::VecCnt { d: r.u8()?, n: r.u8()?, q: r.u8()? != 0 },
        0x5F => IrOp::VecAddvLong {
            d: r.u8()?, n: r.u8()?, esize: r.u8()?, q: r.u8()? != 0, signed: r.u8()? != 0,
        },
        0x69 => IrOp::VecCmpZero {
            op: r.veccmpop()?, size: r.u8()?, q: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0x6A => IrOp::VecShiftNarrow {
            d: r.u8()?, n: r.u8()?, shift: r.u8()?, esize_out: r.u8()?, high: r.u8()? != 0,
        },
        0x6B => IrOp::VecBicOrrImm {
            d: r.u8()?, imm: r.u64()?, is_bic: r.u8()? != 0, q: r.u8()? != 0,
        },
        0x6C => IrOp::VecAddLongPair {
            d: r.u8()?, n: r.u8()?, esize_in: r.u8()?, q: r.u8()? != 0, signed: r.u8()? != 0,
        },
        0x6D => IrOp::VecUnzip {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, esize: r.u8()?, q: r.u8()? != 0, odd: r.u8()? != 0,
        },
        0x6F => IrOp::VecShiftLong {
            d: r.u8()?, n: r.u8()?, shift: r.u8()?, esize_in: r.u8()?,
            high: r.u8()? != 0, signed: r.u8()? != 0,
        },
        0x44 => IrOp::VecShiftReg {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, size: r.u8()?,
            q: r.u8()? != 0, signed: r.u8()? != 0,
        },
        0x45 => IrOp::VecShiftIns {
            d: r.u8()?, n: r.u8()?, shift: r.u8()?, size: r.u8()?,
            q: r.u8()? != 0, left: r.u8()? != 0,
        },
        0x46 => IrOp::VecShiftNarrowSat {
            d: r.u8()?, n: r.u8()?, shift: r.u8()?, esize_out: r.u8()?,
            high: r.u8()? != 0, round: r.u8()? != 0,
            src_signed: r.u8()? != 0, dst_signed: r.u8()? != 0,
            modular: r.u8()? != 0,
        },
        0x47 => IrOp::VecFpRound {
            d: r.u8()?, n: r.u8()?, dbl: r.u8()? != 0, q: r.u8()? != 0, round: r.round()?,
        },
        0x7D => IrOp::VecFpCvtWidth {
            d: r.u8()?, n: r.u8()?, widen: r.u8()? != 0, half: r.u8()? != 0, upper: r.u8()? != 0,
        },
        0x70 => IrOp::VecExt {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, imm: r.u8()?, q: r.u8()? != 0,
        },
        0x76 => IrOp::VecTbl1 {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, q: r.u8()? != 0,
        },
        0x7C => IrOp::VecTblN {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, len: r.u8()?, op: r.u8()?, q: r.u8()? != 0,
        },
        0x77 => IrOp::VecDupElem {
            d: r.u8()?, n: r.u8()?, size: r.u8()?, lane: r.u8()?, q: r.u8()? != 0,
        },
        0x78 => IrOp::VecPmull {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, high: r.u8()? != 0,
        },
        0x7B => IrOp::VecShiftAcc {
            signed: r.u8()? != 0, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, amount: r.u8()?,
        },
        0x71 => IrOp::VecMulLong {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, size: r.u8()?, q: r.u8()? != 0,
            signed: r.u8()? != 0, accum: r.u8()? != 0, sub: r.u8()? != 0,
        },
        0x72 => IrOp::VecRev64 {
            d: r.u8()?, n: r.u8()?, size: r.u8()?, q: r.u8()? != 0, container: r.u8()?,
        },
        0x75 => IrOp::CryptoSha256 {
            kind: r.u8()?, d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0x6E => IrOp::VecReduceAdd {
            d: r.u8()?, n: r.u8()?, esize: r.u8()?, q: r.u8()? != 0,
        },
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

        // ───── M4b-6 SIMD/FP/crypto ctx-template ops ─────
        0xCD => IrOp::VecBin {
            op: r.vecbinop()?, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xCE => IrOp::VecUn {
            op: r.vecunop()?, size: r.u8()?, q: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0xCF => IrOp::VecShift {
            op: r.vecshiftop()?, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, amount: r.u8()?,
        },
        0xD0 => IrOp::VecCmp {
            op: r.veccmpop()?, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xD1 => IrOp::VecPair {
            op: r.vecpairop()?, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xD2 => IrOp::VecReduce {
            op: r.vecreduceop()?, size: r.u8()?, q: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0xD3 => IrOp::VecAddLong {
            across: r.u8()? != 0, signed: r.u8()? != 0, size: r.u8()?,
            q: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0xD4 => IrOp::VecFp {
            op: r.vecfpop()?, dbl: r.u8()? != 0, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xEB => IrOp::VecFpCmp {
            op: r.vecfpcmpop()?, dbl: r.u8()? != 0, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?, zero: r.u8()? != 0,
        },
        0xEC => IrOp::VecFpUn {
            op: r.vecfpunop()?, dbl: r.u8()? != 0, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?,
        },
        0xED => IrOp::VecByElem {
            op: r.vecfpop()?, is_fp: r.u8()? != 0, dbl: r.u8()? != 0,
            size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?, idx: r.u8()?,
        },
        0xEE => IrOp::VecCvtFp {
            to_fp: r.u8()? != 0, signed: r.u8()? != 0, dbl: r.u8()? != 0,
            q: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0xEF => IrOp::VecZipTrn {
            kind: r.u8()?, size: r.u8()?, q: r.u8()? != 0,
            d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xF2 => IrOp::VecScalarPair {
            is_fp: r.u8()? != 0, dbl: r.u8()? != 0, d: r.u8()?, n: r.u8()?,
        },
        0xD5 => IrOp::FpFromInt {
            d: r.u8()?, n_gpr: r.u8()?, from_bits: r.u8()?, to_bits: r.u8()?, signed: r.u8()? != 0,
        },
        0xD6 => IrOp::FpToIntR {
            d_gpr: r.u8()?, n: r.u8()?, from_bits: r.u8()?, to_bits: r.u8()?,
            signed: r.u8()? != 0, round: r.round()?,
        },
        0xD7 => IrOp::FpRound {
            d: r.u8()?, n: r.u8()?, dbl: r.u8()? != 0, round: r.round()?, raise_inexact: r.u8()? != 0,
        },
        0xD8 => IrOp::FpCvt2 {
            d: r.u8()?, n: r.u8()?, from_bits: r.u8()?, to_bits: r.u8()?,
        },
        0x7A => IrOp::FpCsel {
            d: r.u8()?, n: r.u8()?, m: r.u8()?, cond: r.cond()?, dbl: r.u8()? != 0,
        },
        0xD9 => IrOp::FpMov { d: r.u8()?, n: r.u8()?, width_bits: r.u8()? },
        0xDA => IrOp::FpBin {
            op: r.fpbinop()?, dbl: r.u8()? != 0, d: r.u8()?, n: r.u8()?, m: r.u8()?,
        },
        0xF3 => IrOp::FpFma {
            op: r.fpfmaop()?, dbl: r.u8()? != 0, d: r.u8()?, n: r.u8()?, m: r.u8()?, a: r.u8()?,
        },
        0xDB => IrOp::FpUn { op: r.fpunop()?, dbl: r.u8()? != 0, d: r.u8()?, n: r.u8()? },
        0xDC => IrOp::FpCmpN { n: r.u8()?, m: r.u8()?, dbl: r.u8()? != 0, zero: r.u8()? != 0 },
        0xDD => IrOp::FpToGpr { d_gpr: r.u8()?, n: r.u8()?, bits: r.u8()?, high_half: r.u8()? != 0 },
        0xDE => IrOp::FpFromGpr { d: r.u8()?, n_gpr: r.u8()?, bits: r.u8()?, high_half: r.u8()? != 0 },
        0xDF => IrOp::CryptoAesR { kind: r.u8()?, d: r.u8()?, n: r.u8()?, m: r.u8()? },
        0xEA => IrOp::CryptoShaR { kind: r.u8()?, d: r.u8()?, n: r.u8()?, m: r.u8()? },

        // ───── Defensive-hardening fill: remaining variants ─────
        0x03 => IrOp::ConstF32 { dst: r.vid()?, bits: r.u32()? },
        0x04 => IrOp::ConstF64 { dst: r.vid()?, bits: r.u64()? },
        0x05 => IrOp::ConstVec128 { dst: r.vid()?, bytes: r.bytes16()? },
        0x23 => IrOp::Rev { dst: r.vid()?, a: r.vid()?, bytes: r.u8()? },
        0x33 => IrOp::Adcs {
            dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()?, c_in: r.fid()?, sf: r.u8()? != 0,
        },
        0x34 => IrOp::Sbcs {
            dst: r.vid()?, flags: r.fid()?, a: r.vid()?, b: r.vid()?, c_in: r.fid()?, sf: r.u8()? != 0,
        },
        0x38 => IrOp::CCmp {
            flags_out: r.fid()?, a: r.vid()?, b: r.vid()?, cond: r.cond()?,
            nzcv_if_false: r.u8()?, flags_in: r.fid()?, is_neg: r.u8()? != 0, sf: r.u8()? != 0,
        },
        0x39 => IrOp::Csel {
            dst: r.vid()?, a: r.vid()?, b: r.vid()?, cond: r.cond()?, flags: r.fid()?, variant: r.u8()?,
        },
        0x54 => IrOp::LoadPair { dst_a: r.vid()?, dst_b: r.vid()?, addr: r.vid()?, ty: r.loadty()? },
        0x55 => IrOp::StorePair { val_a: r.vid()?, val_b: r.vid()?, addr: r.vid()?, ty: r.storety()? },
        0x58 => IrOp::ZeroBlock { addr: r.vid()? },
        0xFE => IrOp::StampFaultPc(r.u64()?),
        0xC5 => IrOp::Mrs { dst: r.vid()?, reg: r.sysreg()? },
        0xC6 => IrOp::Msr { reg: r.sysreg()?, val: r.vid()? },
        0xCC => IrOp::TlbInval {
            va: if r.u8()? != 0 { Some(r.vid()?) } else { None },
        },
        // AtS1E1: relocated 0xCD -> 0x43 to break the collision with VecBin.
        0x43 => IrOp::AtS1E1 { va: r.vid()?, is_write: r.u8()? != 0, at_el0: r.u8()? != 0 },

        // ----- IrValueId-keyed NEON (XMM-allocator) ops -----
        0x80 => IrOp::VAdd { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x81 => IrOp::VSub { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x82 => IrOp::VMul { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x83 => IrOp::VAnd { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x84 => IrOp::VOr  { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x85 => IrOp::VXor { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0x86 => IrOp::VShl  { dst: r.vid()?, a: r.vid()?, amount: r.u8()?, lane: r.lane()? },
        0x87 => IrOp::VLShr { dst: r.vid()?, a: r.vid()?, amount: r.u8()?, lane: r.lane()? },
        0x88 => IrOp::VAShr { dst: r.vid()?, a: r.vid()?, amount: r.u8()?, lane: r.lane()? },
        0x89 => IrOp::VNeg { dst: r.vid()?, a: r.vid()?, lane: r.lane()? },
        0x8A => IrOp::VAbs { dst: r.vid()?, a: r.vid()?, lane: r.lane()? },
        0x8B => IrOp::VMin { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()?, signed: r.u8()? != 0 },
        0x8C => IrOp::VMax { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()?, signed: r.u8()? != 0 },
        0x8D => IrOp::VCmp {
            dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()?,
            eq: r.u8()? != 0, signed: r.u8()? != 0,
        },
        0x8E => IrOp::VDup { dst: r.vid()?, a: r.vid()?, lane: r.lane()? },
        0x8F => IrOp::VInsLane {
            dst: r.vid()?, src: r.vid()?, scalar: r.vid()?, lane_idx: r.u8()?, lane: r.lane()?,
        },
        0x90 => IrOp::VExtractLane { dst: r.vid()?, a: r.vid()?, lane_idx: r.u8()?, lane: r.lane()? },
        0x91 => IrOp::VPermute { dst: r.vid()?, a: r.vid()?, b: r.vid()?, index: r.bytes16()? },
        0x92 => IrOp::VTbl { dst: r.vid()?, table_lo: r.vid()?, table_hi: r.vid()?, index: r.vid()? },
        0x93 => IrOp::VTbx {
            dst: r.vid()?, prev: r.vid()?, table_lo: r.vid()?, table_hi: r.vid()?, index: r.vid()?,
        },
        0x94 => IrOp::VModImm { dst: r.vid()?, imm: r.u64()?, lane: r.lane()? },
        0x95 => IrOp::VConvert { dst: r.vid()?, a: r.vid()?, from: r.lane()?, to: r.lane()? },
        0x96 => IrOp::VFAdd { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x97 => IrOp::VFSub { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x98 => IrOp::VFMul { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x99 => IrOp::VFDiv { dst: r.vid()?, a: r.vid()?, b: r.vid()?, lane: r.lane()? },
        0x9A => IrOp::VFMa { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()?, lane: r.lane()? },

        // ----- IrValueId-keyed scalar FP ops -----
        0xA0 => IrOp::FAdd { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0xA1 => IrOp::FSub { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0xA2 => IrOp::FMul { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0xA3 => IrOp::FDiv { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0xA4 => IrOp::FNeg { dst: r.vid()?, a: r.vid()? },
        0xA5 => IrOp::FAbs { dst: r.vid()?, a: r.vid()? },
        0xA6 => IrOp::FSqrt { dst: r.vid()?, a: r.vid()? },
        0xA7 => IrOp::FCvt { dst: r.vid()?, a: r.vid()?, from_bits: r.u8()?, to_bits: r.u8()? },
        0xA8 => IrOp::FToInt { dst: r.vid()?, a: r.vid()?, to_bits: r.u8()?, signed: r.u8()? != 0 },
        0xA9 => IrOp::IntToF { dst: r.vid()?, a: r.vid()?, from_bits: r.u8()?, signed: r.u8()? != 0 },
        0xAA => IrOp::FCmp { flags: r.fid()?, a: r.vid()?, b: r.vid()? },

        // ----- IrValueId-keyed crypto ops -----
        0xB0 => IrOp::AesE { dst: r.vid()?, a: r.vid()?, key: r.vid()? },
        0xB1 => IrOp::AesD { dst: r.vid()?, a: r.vid()?, key: r.vid()? },
        0xB2 => IrOp::AesMc { dst: r.vid()?, a: r.vid()? },
        0xB3 => IrOp::AesImc { dst: r.vid()?, a: r.vid()? },
        0xB4 => IrOp::Sha1c { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xB5 => IrOp::Sha1m { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xB6 => IrOp::Sha1p { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xB7 => IrOp::Sha256h { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xB8 => IrOp::Sha256h2 { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xB9 => IrOp::Sha256su0 { dst: r.vid()?, a: r.vid()?, b: r.vid()? },
        0xBA => IrOp::Sha256su1 { dst: r.vid()?, a: r.vid()?, b: r.vid()?, c: r.vid()? },
        0xBB => IrOp::Pmull { dst: r.vid()?, a: r.vid()?, b: r.vid()?, wide: r.u8()? != 0 },
        0xBC => IrOp::Crc32 {
            dst: r.vid()?, a: r.vid()?, b: r.vid()?, size: r.u8()?, castagnoli: r.u8()? != 0,
        },

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
        IrOp::StampFaultPc(_) => 0xFE, // diagnostic — never serialized in prod
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
        IrOp::ZeroBlock { .. } => 0x58,
        IrOp::AtomicRmw { .. } => 0x56,
        IrOp::AtomicCas { .. } => 0x57,
        IrOp::AtomicCasPair { .. } => 0x79,

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
        IrOp::EretRt => 0x59,
        IrOp::VecMoviImm { .. } => 0x5A,
        IrOp::VecDupGpr { .. } => 0x5B,
        IrOp::FpCvtIntScalar { .. } => 0x73,
        IrOp::FpCvtToIntScalar { .. } => 0x74,
        IrOp::VecExtractLane { .. } => 0x5C,
        IrOp::VecInsGpr { .. } => 0x5D,
        IrOp::VecCnt { .. } => 0x5E,
        IrOp::VecAddvLong { .. } => 0x5F,
        IrOp::VecCmpZero { .. } => 0x69,
        IrOp::VecShiftNarrow { .. } => 0x6A,
        IrOp::VecBicOrrImm { .. } => 0x6B,
        IrOp::VecAddLongPair { .. } => 0x6C,
        IrOp::VecUnzip { .. } => 0x6D,
        IrOp::VecReduceAdd { .. } => 0x6E,
        IrOp::VecShiftLong { .. } => 0x6F,
        IrOp::VecShiftReg { .. } => 0x44,
        IrOp::VecShiftIns { .. } => 0x45,
        IrOp::VecShiftNarrowSat { .. } => 0x46,
        IrOp::VecFpRound { .. } => 0x47,
        IrOp::VecFpCvtWidth { .. } => 0x7D,
        IrOp::VecExt { .. } => 0x70,
        IrOp::VecTbl1 { .. } => 0x76,
        IrOp::VecTblN { .. } => 0x7C,
        IrOp::VecDupElem { .. } => 0x77,
        IrOp::VecPmull { .. } => 0x78,
        IrOp::VecShiftAcc { .. } => 0x7B,
        IrOp::VecMulLong { .. } => 0x71,
        IrOp::VecRev64 { .. } => 0x72,
        IrOp::CryptoSha256 { .. } => 0x75,
        IrOp::Mrs { .. } => 0xC5,
        IrOp::Msr { .. } => 0xC6,
        IrOp::Dmb { .. } => 0xC7,
        IrOp::Dsb { .. } => 0xC8,
        IrOp::Isb => 0xC9,
        IrOp::Sb => 0xCA,
        IrOp::Hint { .. } => 0xCB,
        IrOp::TlbInval { .. } => 0xCC,
        // AtS1E1 relocated 0xCD -> 0x43 to break a tag collision with the M4b-6
        // SIMD group (VecBin == 0xCD). 0x43 was a free byte in the extension
        // band (0x40..0x4F); the barrier/system group keeps its 0xC7..0xCC tags.
        IrOp::AtS1E1 { .. } => 0x43,

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

        // M4b-6 SIMD/FP/crypto ctx-template ops (0xCD..0xDF + 0xEA).
        IrOp::VecBin { .. } => 0xCD,
        IrOp::VecUn { .. } => 0xCE,
        IrOp::VecShift { .. } => 0xCF,
        IrOp::VecCmp { .. } => 0xD0,
        IrOp::VecPair { .. } => 0xD1,
        IrOp::VecReduce { .. } => 0xD2,
        IrOp::VecAddLong { .. } => 0xD3,
        IrOp::VecFp { .. } => 0xD4,
        IrOp::VecFpCmp { .. } => 0xEB,
        IrOp::VecFpUn { .. } => 0xEC,
        IrOp::VecByElem { .. } => 0xED,
        IrOp::VecCvtFp { .. } => 0xEE,
        IrOp::VecZipTrn { .. } => 0xEF,
        IrOp::VecScalarPair { .. } => 0xF2,
        IrOp::FpFromInt { .. } => 0xD5,
        IrOp::FpToIntR { .. } => 0xD6,
        IrOp::FpRound { .. } => 0xD7,
        IrOp::FpCvt2 { .. } => 0xD8,
        IrOp::FpCsel { .. } => 0x7A,
        IrOp::FpMov { .. } => 0xD9,
        IrOp::FpBin { .. } => 0xDA,
        IrOp::FpFma { .. } => 0xF3,
        IrOp::FpUn { .. } => 0xDB,
        IrOp::FpCmpN { .. } => 0xDC,
        IrOp::FpToGpr { .. } => 0xDD,
        IrOp::FpFromGpr { .. } => 0xDE,
        IrOp::CryptoAesR { .. } => 0xDF,
        IrOp::CryptoShaR { .. } => 0xEA,

        IrOp::Unimplemented(_) => 0xFF,
    }
}

/// Whether `op` has a payload codec (encode + decode arm).
///
/// As of the defensive-hardening fill EVERY `IrOp` variant round-trips —
/// `encode` is an exhaustive match (no `NotYetImplemented` fallback) and
/// `decode` has an arm for every tag. The function is retained for API
/// compatibility (the AT-2 gate calls it) and now answers `true` for all ops;
/// `variant_tag_is_injective` is the test that keeps the tag space coherent.
pub fn is_codec_implemented(_op: &IrOp) -> bool {
    true
}
