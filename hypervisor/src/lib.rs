#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// AETHER hypervisor — core library
// All code here runs at EL2 on bare-metal ARM64.
// There is no host OS; std is unavailable by design.
//
// Module layout mirrors the chapter structure of the specification.
// Each module corresponds to one or more chapters in README.md.
//
// Part I — The Vision (Chapters 1–3)
pub mod fingerprint; // ch02: fingerprint sources and elimination strategies
pub mod partition;   // ch03: non-negotiables encoded as types

// Part II — The Silicon (Chapters 4–6)
pub mod arm64; // ch04: ARM64 substrate — regs, barriers, paging constants
