//! Phase C — x86_64 backend for the AETHER translator.
//!
//! | Chapter | Module          | Description                              |
//! |---------|-----------------|------------------------------------------|
//! | AT-11   | [`encode`]      | REX/ModRM/SIB x86_64 machine-code encoder|
//! | AT-12   | [`lower_int`]   | Integer IR → x86_64 instruction sequences|
//! | AT-13   | [`lower_simd`]  | NEON → SSE2/SSE4 SIMD lowering           |
//! | AT-14   | [`lower_atomic`]| LL/SC → LOCK CMPXCHG retry loops         |
//! | AT-15   | [`code_buf`]    | JIT code buffer + ICache coherency       |

pub mod code_buf;
pub mod encode;
pub mod lower_atomic;
pub mod lower_int;
pub mod lower_simd;

pub use code_buf::{CodeBlock, CodeBuf, CodeBufError, Protection};
pub use encode::X86Encoder;
pub use lower_int::IntLower;
pub use lower_simd::SimdLower;
pub use lower_atomic::AtomicLower;

/// Phase C version pin.
pub const PHASE_C_VERSION: u32 = 0x0000_0003;
