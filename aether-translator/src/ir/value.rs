//! IR value model.

/// Block-local SSA-style value identifier (will become true SSA in AT-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct IrValueId(pub u32);

/// Lane element type for fixed-128-bit vector values (NEON).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneType {
    I8,
    I16,
    I32,
    I64,
    F16,
    F32,
    F64,
}

/// What an [`IrValueId`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrValueKind {
    I8,
    I16,
    I32,
    I64,
    F16,
    F32,
    F64,
    Vec128 { lane: LaneType },
    /// Pointer-sized (always 64-bit on AArch64); kept distinct so that AT-6
    /// SSA phi insertion can preserve pointer-ness for the x86 backend's
    /// pointer-tracking peephole.
    Ptr,
    /// 4-bit NZCV bundle produced by `*S` ops and `CMP`/`CMN`. Modeled as a
    /// distinct kind so flag elision in AT-8 can find producers cheaply.
    Flags,
}

impl IrValueKind {
    pub const fn byte_width(self) -> usize {
        match self {
            IrValueKind::I8 => 1,
            IrValueKind::I16 | IrValueKind::F16 => 2,
            IrValueKind::I32 | IrValueKind::F32 => 4,
            IrValueKind::I64 | IrValueKind::F64 | IrValueKind::Ptr => 8,
            IrValueKind::Vec128 { .. } => 16,
            IrValueKind::Flags => 1, // 4 bits, byte-rounded
        }
    }
}
