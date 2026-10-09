//! Dead-code elimination pass (AT-7).
//!
//! Marks ops live if their result is used by another live op or if the op has
//! a side effect (memory write, branch, call, system op, barrier).  Removes
//! all unmarked ops.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ir::{IrFunction, IrOp, IrValueId};

pub struct DcePass;

impl DcePass {
    pub fn run(mut func: IrFunction) -> IrFunction {
        for blk in &mut func.blocks {
            // Collect the set of live values by propagating from root uses.
            let mut live: BTreeSet<u32> = BTreeSet::new();

            // Seed: values used by side-effecting ops are live; their uses
            // are transitively live.  We do two passes: first forward to
            // collect defs, then backward to propagate liveness.

            // Build def map: value_id → op_index.
            let mut def_at: alloc::collections::BTreeMap<u32, usize> =
                alloc::collections::BTreeMap::new();
            for (i, op) in blk.ops.iter().enumerate() {
                op.visit_def_values(|v: IrValueId| {
                    def_at.insert(v.0, i);
                });
            }

            // Seed side-effecting ops and phi uses as live.
            let n = blk.ops.len();
            let mut op_live = vec![false; n];
            for (i, op) in blk.ops.iter().enumerate() {
                if is_side_effecting(op) {
                    op_live[i] = true;
                    op.visit_use_values(|v: IrValueId| {
                        live.insert(v.0);
                    });
                }
            }

            // Phi uses are always live.
            for phi in &blk.phis {
                for &(_, v) in &phi.incoming {
                    live.insert(v.0);
                }
            }

            // Propagate liveness backward.
            let mut changed = true;
            while changed {
                changed = false;
                for (i, op) in blk.ops.iter().enumerate() {
                    if op_live[i] {
                        continue;
                    }
                    let mut is_live = false;
                    op.visit_def_values(|v: IrValueId| {
                        if live.contains(&v.0) {
                            is_live = true;
                        }
                    });
                    if is_live {
                        op_live[i] = true;
                        op.visit_use_values(|v: IrValueId| {
                            if live.insert(v.0) {
                                changed = true;
                            }
                        });
                        changed = true;
                    }
                }
            }

            // Retain only live ops.
            let mut new_ops = Vec::with_capacity(n);
            for (i, op) in blk.ops.drain(..).enumerate() {
                if op_live[i] {
                    new_ops.push(op);
                }
            }
            blk.ops = new_ops;
        }
        func
    }
}

/// True if `op` has a side effect that DCE must preserve **even when the op
/// defines no live `IrValueId`**. This is the DCE-liveness seed set for every
/// op that mutates guest-visible state — the q-register file, guest memory, the
/// NZCV bank, the PC, a sysreg, or the host fault-PC slot — through a path the
/// SSA def/use graph does NOT model.
///
/// Membership rule: an op belongs here iff it writes observable state with **no
/// `IrValueId` def**. Ops that DO define an `IrValueId` (e.g. `VecExtractLane`,
/// `FpCvtToIntScalar`, `Mrs`, `Load`) are kept alive transitively by the normal
/// liveness walk and must NOT be listed — listing them would only pessimise DCE.
/// (`Crc32`/`CryptoAesR`/`CryptoShaR` are listed defensively per the M4b review;
/// they never run through live DCE on the ctx path, and an extra "always keep"
/// marker is correctness-safe — it can only retain, never drop, an op.)
fn is_side_effecting(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::Store { .. }
        | IrOp::StoreExclusive { .. }
        | IrOp::StorePair { .. }
        | IrOp::AtomicRmw { .. }
        | IrOp::AtomicCas { .. }
        | IrOp::AtomicCasPair { .. }
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
        | IrOp::EretRt
        // DC ZVA — zeroes a 64-byte guest-memory block; no IrValueId def.
        | IrOp::ZeroBlock { .. }
        // Diagnostic fault-PC stamp — stores to the FAULT_OP_PC ctx slot.
        | IrOp::StampFaultPc(_)
        // AT S1E1 — writes PAR_EL1 via the runtime walker; no SSA def.
        | IrOp::AtS1E1 { .. }
        // x86 fence / serialising CPUID lowered from ARM barriers — pure side
        // effects with no def; dropping them would reorder TSO-visible memory.
        | IrOp::X86Mfence
        | IrOp::X86Cpuid
        | IrOp::VecMoviImm { .. }
        | IrOp::VecDupGpr { .. }
        | IrOp::FpCvtIntScalar { .. }
        | IrOp::VecInsGpr { .. }
        | IrOp::VecCnt { .. }
        | IrOp::VecAddvLong { .. }
        | IrOp::VecCmpZero { .. }
        | IrOp::VecShiftNarrow { .. }
        | IrOp::VecShiftLong { .. }
        // SSRA/USRA — accumulates into the q-register file (no IrValueId def), so
        // DCE must seed it live the same way the other ctx-template writers are.
        | IrOp::VecShiftAcc { .. }
        | IrOp::VecExt { .. }
        | IrOp::VecTbl1 { .. }
        | IrOp::VecTblN { .. }
        | IrOp::VecDupElem { .. }
        | IrOp::VecPmull { .. }
        | IrOp::VecMulLong { .. }
        | IrOp::VecRev64 { .. }
        | IrOp::CryptoSha256 { .. }
        | IrOp::SimdInterp { .. }
        | IrOp::VecBicOrrImm { .. }
        | IrOp::VecAddLongPair { .. }
        | IrOp::VecUnzip { .. }
        | IrOp::VecReduceAdd { .. }
        // M4b-6 V-register-numbered ctx-template writers — write the q-register
        // file ([R15 + vec_disp(reg)]) with no SSA def, so DCE must seed them
        // live like the other ctx-template ops above.
        | IrOp::VecBin { .. }
        | IrOp::VecUn { .. }
        | IrOp::VecShift { .. }
        | IrOp::VecCmp { .. }
        | IrOp::VecPair { .. }
        | IrOp::VecReduce { .. }
        | IrOp::VecAddLong { .. }
        // Vector FP ctx-template writers — write the q-register file with no SSA
        // def, so DCE must seed them live like the other ctx-template ops above.
        | IrOp::VecFp { .. }
        | IrOp::VecFpCmp { .. }
        | IrOp::VecFpUn { .. }
        // SIMD by-element / int↔FP convert / zip-trn — ctx-template writers with
        // no SSA def, so DCE must seed them live like the other ctx-template ops.
        | IrOp::VecByElem { .. }
        | IrOp::VecCvtFp { .. }
        | IrOp::VecZipTrn { .. }
        | IrOp::VecScalarPair { .. }
        // Scalar FP / int↔FP ctx-template writers — write the scalar V slot in
        // the q-register file with no SSA def.
        | IrOp::FpFromInt { .. }
        | IrOp::FpToIntR { .. }
        | IrOp::FpRound { .. }
        | IrOp::FpCvt2 { .. }
        | IrOp::FpCsel { .. }
        | IrOp::FpMov { .. }
        | IrOp::FpBin { .. }
        | IrOp::FpFma { .. }
        | IrOp::FpUn { .. }
        | IrOp::FpCmpN { .. }
        | IrOp::FpToGpr { .. }
        | IrOp::FpFromGpr { .. }
        // Crypto ctx-template writers (no SSA def) + the IrValueId-keyed crypto
        // forms (listed defensively per the M4b review; see fn doc).
        | IrOp::CryptoAesR { .. }
        | IrOp::CryptoShaR { .. }
        | IrOp::Crc32 { .. }
        | IrOp::Msr { .. }
        | IrOp::Dmb { .. }
        | IrOp::Dsb { .. }
        | IrOp::Isb
        | IrOp::Sb
        | IrOp::TlbInval { .. }
        | IrOp::WriteGpr { .. }
        | IrOp::WriteSp { .. }
        | IrOp::WriteFpr { .. }
        | IrOp::WriteFlags { .. }
        | IrOp::WritePc { .. }
    )
}
