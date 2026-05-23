//! AETHER ARM64 -> x86_64 dynamic binary translator.
//!
//! Phase A scope: decoder + IR foundation. No optimization, no codegen, no
//! dispatcher. See plan file at
//! `~/.claude/plans/identify-your-weaknesses-in-wondrous-pond.md`.
//!
//! Production builds are `no_std`. Host test builds enable `std` via the
//! `cfg(test)` switch + `--features std`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(dead_code)] // Phase A skeleton — wired-up usage lands in follow-ups.

extern crate alloc;

pub mod decoder;
pub mod ir;
pub mod lift;

#[cfg(feature = "std")]
pub mod corpus;

/// Phase A version pin. Bumped when the IR or decoder ABI changes.
pub const PHASE_A_VERSION: u32 = 0x0000_0001;
