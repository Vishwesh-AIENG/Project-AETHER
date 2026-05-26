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

/// 15 allocatable GPRs (RSP reserved).
pub const ALLOCATABLE_GPRS: [X86Gpr; 15] = [
    X86Gpr::Rax, X86Gpr::Rcx, X86Gpr::Rdx, X86Gpr::Rbx,
    X86Gpr::Rbp, X86Gpr::Rsi, X86Gpr::Rdi,
    X86Gpr::R8,  X86Gpr::R9,  X86Gpr::R10, X86Gpr::R11,
    X86Gpr::R12, X86Gpr::R13, X86Gpr::R14, X86Gpr::R15,
];

pub const ALLOCATABLE_XMMS: [X86Xmm; 16] = [
    X86Xmm::Xmm0,  X86Xmm::Xmm1,  X86Xmm::Xmm2,  X86Xmm::Xmm3,
    X86Xmm::Xmm4,  X86Xmm::Xmm5,  X86Xmm::Xmm6,  X86Xmm::Xmm7,
    X86Xmm::Xmm8,  X86Xmm::Xmm9,  X86Xmm::Xmm10, X86Xmm::Xmm11,
    X86Xmm::Xmm12, X86Xmm::Xmm13, X86Xmm::Xmm14, X86Xmm::Xmm15,
];

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
