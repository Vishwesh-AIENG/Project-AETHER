//! Phase C — x86_64 backend for the AETHER translator.
//!
//! | Chapter | Module             | Description                                   |
//! |---------|--------------------|-----------------------------------------------|
//! | AT-11   | [`encode`]         | REX/ModRM/SIB x86_64 machine-code encoder     |
//! | AT-12   | [`lower_int`]      | Integer IR → x86_64 (incl. LSE + LL/SC atomics)|
//! | AT-13   | [`lower_simd_ctx`] | NEON/FP → SSE via the guest q-register file   |
//! | AT-15   | [`code_buf`]       | JIT code buffer + ICache coherency            |
//!
//! The original SSA-register `lower_simd` / `lower_atomic` passes were never on
//! the live path (`lower_simd_ctx` and `lower_int`'s atomic arms superseded
//! them) and were removed.

pub mod code_buf;
pub mod encode;
pub mod lower_int;
pub mod lower_simd_ctx;

pub use code_buf::{CodeBuf, CodeBufError, Protection};
// `CodeBlock` is part of the `cfg(test)`-gated per-block registry (test-only;
// the production path uses `BlockCache`). See `code_buf::CodeBuf::blocks`.
#[cfg(test)]
pub use code_buf::CodeBlock;
pub use encode::X86Encoder;
pub use lower_int::IntLower;

/// Phase C version pin.
pub const PHASE_C_VERSION: u32 = 0x0000_0003;
