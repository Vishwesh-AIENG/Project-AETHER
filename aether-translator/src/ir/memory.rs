//! Memory ordering and access shapes used by load/store IR ops.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemOrder {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoadTy {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    F32,
    F64,
    Vec128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreTy {
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Vec128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    Add,
    Clr,
    Eor,
    Set,
    Smax,
    Smin,
    Umax,
    Umin,
    Swp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierDomain {
    /// Inner Shareable
    Ish,
    /// Inner Shareable, Stores only
    Ishst,
    /// Inner Shareable, Loads only
    Ishld,
    /// Non-Shareable
    Nsh,
    NshSt,
    NshLd,
    /// Outer Shareable
    Osh,
    OshSt,
    OshLd,
    /// Full System
    Sy,
    SyStore,
    SyLoad,
}
