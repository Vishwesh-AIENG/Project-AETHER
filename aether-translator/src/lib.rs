//! AETHER ARM64 -> x86_64 dynamic binary translator.
//!
//! Phase B scope: SSA construction (AT-6), optimizer passes (AT-7/8/10), and
//! linear-scan register allocator (AT-9).  Built on the Phase A decoder + IR.
//!
//! Production builds are `no_std`. Host test builds enable `std` via the
//! `cfg(test)` switch + `--features std`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(dead_code)]

#[macro_use]
extern crate alloc;

pub mod backend;
pub mod dbt;
pub mod decoder;
pub mod forbidden_symbols;
pub mod ir;
pub mod lift;
pub mod opt;
pub mod regalloc;
pub mod runtime;
pub mod ssa;

#[cfg(feature = "std")]
pub mod corpus;

/// Phase A version pin.
pub const PHASE_A_VERSION: u32 = 0x0000_0001;
/// Phase B version pin. Bumped on SSA/optimizer ABI changes.
pub const PHASE_B_VERSION: u32 = 0x0000_0002;
/// Phase C version pin. Bumped on backend ABI changes.
pub const PHASE_C_VERSION: u32 = 0x0000_0003;
/// Phase D version pin. Bumped on runtime/dispatcher ABI changes.
pub const PHASE_D_VERSION: u32 = 0x0000_0004;
/// Phase E version pin. Bumped on productization ABI changes.
pub const PHASE_E_VERSION: u32 = 0x0000_0005;
/// Phase F version pin. Bumped on validation-layer ABI changes.
pub const PHASE_F_VERSION: u32 = 0x0000_0006;
