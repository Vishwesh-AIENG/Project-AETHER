//! AETHER translator IR.
//!
//! Phase A IR is intentionally pre-SSA: each [`IrBlock`] is a linear vector
//! of [`IrOp`]; values are referenced by [`IrValueId`] indices that are unique
//! within their owning block. SSA construction with phi nodes is AT-6 in
//! Phase B.

pub mod flags;
pub mod memory;
pub mod ops;
pub mod serialize;
pub mod value;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

pub use flags::{IrFlagsId, NzcvBit};
pub use memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
pub use ops::IrOp;
pub use value::{IrValueId, IrValueKind, LaneType};

/// Sequential identifier for a block within an [`IrFunction`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct BlockId(pub u32);

/// AT-6 SSA phi node at a block entry.
///
/// `incoming[i] = (pred_block_id, value_from_pred)`.  Every predecessor must
/// appear exactly once in `incoming`.
#[derive(Debug, Clone, PartialEq)]
pub struct IrPhi {
    pub dst: IrValueId,
    pub incoming: Vec<(BlockId, IrValueId)>,
}

/// A linear basic block.
#[derive(Debug, Clone, Default)]
pub struct IrBlock {
    pub id: BlockId,
    /// AT-6: phi nodes at block entry (empty in Phase A pre-SSA IR).
    pub phis: Vec<IrPhi>,
    pub ops: Vec<IrOp>,
    /// Block-local value type table; index = `IrValueId`.
    pub values: Vec<IrValueKind>,
    /// Block-local flag table; index = `IrFlagsId`.
    pub flags: Vec<()>,
    /// AT-8: flag IDs whose production can be suppressed on x86 (never read).
    pub elided_flags: BTreeSet<u32>,
}

impl IrBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            phis: Vec::new(),
            ops: Vec::new(),
            values: Vec::new(),
            flags: Vec::new(),
            elided_flags: BTreeSet::new(),
        }
    }

    pub fn push_op(&mut self, op: IrOp) {
        self.ops.push(op);
    }

    pub fn new_value(&mut self, kind: IrValueKind) -> IrValueId {
        let id = self.values.len() as u32;
        self.values.push(kind);
        IrValueId(id)
    }

    pub fn new_flags(&mut self) -> IrFlagsId {
        let id = self.flags.len() as u32;
        self.flags.push(());
        IrFlagsId(id)
    }
}

/// A function = vector of blocks. Phase A has no CFG analysis; the vector
/// order is implementation-defined.
#[derive(Debug, Clone, Default)]
pub struct IrFunction {
    pub blocks: Vec<IrBlock>,
    /// Source guest VA at function entry (informational; preserved into AOT cache).
    pub entry_pc: u64,
}

impl IrFunction {
    pub fn new(entry_pc: u64) -> Self {
        Self {
            blocks: Vec::new(),
            entry_pc,
        }
    }

    pub fn add_block(&mut self) -> &mut IrBlock {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(IrBlock::new(id));
        self.blocks.last_mut().expect("just pushed")
    }

    /// AT-2 gate: structural verification (block-local).
    pub fn verify(&self) -> Result<(), VerifyErr> {
        for blk in &self.blocks {
            for op in &blk.ops {
                op.verify_within(blk)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErr {
    UndefinedValue(IrValueId),
    UndefinedBlock(BlockId),
    BadMemOrder,
}
