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

use alloc::vec::Vec;

pub use flags::{IrFlagsId, NzcvBit};
pub use memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
pub use ops::IrOp;
pub use value::{IrValueId, IrValueKind, LaneType};

/// Sequential identifier for a block within an [`IrFunction`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct BlockId(pub u32);

/// A linear basic block.
#[derive(Debug, Clone, Default)]
pub struct IrBlock {
    pub id: BlockId,
    pub ops: Vec<IrOp>,
    /// Block-local value type table; index = `IrValueId`.
    pub values: Vec<IrValueKind>,
    /// Block-local flag table; index = `IrFlagsId`.
    pub flags: Vec<()>, // placeholder; flags are positional in Phase A
}

impl IrBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            ops: Vec::new(),
            values: Vec::new(),
            flags: Vec::new(),
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
