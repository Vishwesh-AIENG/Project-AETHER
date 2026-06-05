//! x86_64 register definitions for the AT-9 linear-scan allocator.

/// 64-bit general-purpose registers.  `Rsp` is reserved (stack pointer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum X86Gpr {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    // Rsp = 4  -- reserved; not in allocatable set
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8  = 8,
    R9  = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

/// 128-bit XMM registers (also used as YMM when AVX is available).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum X86Xmm {
    Xmm0  = 0,  Xmm1  = 1,  Xmm2  = 2,  Xmm3  = 3,
    Xmm4  = 4,  Xmm5  = 5,  Xmm6  = 6,  Xmm7  = 7,
    Xmm8  = 8,  Xmm9  = 9,  Xmm10 = 10, Xmm11 = 11,
    Xmm12 = 12, Xmm13 = 13, Xmm14 = 14, Xmm15 = 15,
}

/// 14-entry GPR table (RSP and R15 already excluded). **The linear-scan
/// allocator reserves indices 0 (RAX) and 1 (RCX) as M4a spill / NZCV scratch
/// — see `GPR_ALLOC_FIRST_INDEX` and `LinearScanAlloc::allocate`.** Real values
/// are only ever assigned indices 2.. (RDX onward); RAX/RCX stay free so
/// `build_nzcv`, the spill-materialization helpers, and shift/mul/div lowerings
/// can use them as scratch without clobbering a live value. The table order is
/// kept stable (RAX@0, RCX@1, RDX@2, …) so byte-exact lowering tests that pin a
/// register by index remain valid.
pub const ALLOCATABLE_GPRS: [X86Gpr; 14] = [
    X86Gpr::Rax, X86Gpr::Rcx, X86Gpr::Rdx, X86Gpr::Rbx,
    X86Gpr::Rbp, X86Gpr::Rsi, X86Gpr::Rdi,
    X86Gpr::R8,  X86Gpr::R9,  X86Gpr::R10, X86Gpr::R11,
    X86Gpr::R12, X86Gpr::R13, X86Gpr::R14,
];

/// First allocatable index the linear-scan allocator may hand to a live value.
/// Indices 0 (RAX) and 1 (RCX) are reserved as scratch (M4a).
pub const GPR_ALLOC_FIRST_INDEX: usize = 2;

pub const ALLOCATABLE_XMMS: [X86Xmm; 16] = [
    X86Xmm::Xmm0,  X86Xmm::Xmm1,  X86Xmm::Xmm2,  X86Xmm::Xmm3,
    X86Xmm::Xmm4,  X86Xmm::Xmm5,  X86Xmm::Xmm6,  X86Xmm::Xmm7,
    X86Xmm::Xmm8,  X86Xmm::Xmm9,  X86Xmm::Xmm10, X86Xmm::Xmm11,
    X86Xmm::Xmm12, X86Xmm::Xmm13, X86Xmm::Xmm14, X86Xmm::Xmm15,
];

// ── M4b-6: fixed scratch XMMs for the ctx-template SIMD/FP lowering ───────────
//
// The vector lowering (`backend::lower_simd_ctx`) is a template JIT: every op
// loads its q-register operands from ctx ([R15+vec_disp]), computes in these
// fixed scratch XMMs, and stores the result back to ctx. They are never handed
// to the linear-scan allocator, so they can be clobbered freely inside a single
// op without disturbing any allocator-resident value (mirrors how RAX/RCX are
// reserved GPR scratch — see `GPR_ALLOC_FIRST_INDEX`).
/// Primary operand / result accumulator.
pub const VS0: u8 = 0;
/// Second operand.
pub const VS1: u8 = 1;
/// Third operand / accumulator-read (Mla/Mls/SAba) / mask build.
pub const VS2: u8 = 2;
/// Min-max trees, sign masks, constant materialization.
pub const VS3: u8 = 3;
/// First XMM index the linear-scan allocator may assign to an IR value.
/// 0..=3 are reserved as SIMD scratch (mirrors `GPR_ALLOC_FIRST_INDEX = 2`).
pub const XMM_ALLOC_FIRST_INDEX: usize = 4;
/// Non-volatile (Win64 callee-saved) XMM used to ferry a 128-bit guest q-register
/// value across the `aether_mmu_xlate` call in LDR/STR Q lowering. VS0..3
/// (XMM0..3) are volatile and would be clobbered by the call; XMM6..15 survive
/// it. Reserved out of allocation by `XMM_ALLOC_LAST_RESERVED` below.
pub const VFP: u8 = 15;
/// The top XMM index is reserved as the FPR-transfer register (`VFP`); the
/// linear-scan allocator hands out 4..=14 only.
pub const XMM_ALLOC_COUNT: usize = 15; // indices 4..15 minus the reserved top

/// Which x86 register class holds an ARM64 IR value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegClass {
    Gpr,
    Xmm,
}

impl RegClass {
    pub fn n_regs(self) -> usize {
        match self {
            RegClass::Gpr => ALLOCATABLE_GPRS.len(),
            RegClass::Xmm => ALLOCATABLE_XMMS.len(),
        }
    }
}
