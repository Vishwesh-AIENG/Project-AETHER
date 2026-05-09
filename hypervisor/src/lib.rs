// Production: no_std (bare-metal EL2). Tests: std available (native host).
#![cfg_attr(not(test), no_std)]
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

// Part III — The Hypervisor (Chapters 7–11)
pub mod boot;        // ch07: UEFI handoff, ExitBootServices, ACPI discovery, guest ERET
pub mod memory;      // ch08: Stage 2 page tables, bump allocator, SMMU v3 stream table
pub mod cpu;         // ch09: static CPU partitioning, PSCI dispatch, GIC SPI routing
pub mod gic;         // ch10: GICv3 init, virtual interrupt injection, maintenance IRQ

// Part IV — Devices (Chapters 11–16)
pub mod passthrough; // ch11: PCIe device assignment — IOMMU groups, FLR, BAR mapping, SMMU STE
pub mod paravirt;    // ch12: paravirtualization — virtual modem (AT/3GPP), MEMS sensor suite (BMI160
                     //       Gaussian noise models), Phone Bridge Mode toggle
pub mod gpu;         // ch13: GPU partitioning via SR-IOV — VF enumeration, assignment, isolation
pub mod storage;     // ch14: storage partitioning — NVMe namespace isolation, SR-IOV, exclusive attachment
pub mod network;     // ch15: network partitioning — SR-IOV VFs, dedicated adapters, paravirt bridge fallback
pub mod usb;         // ch16: USB controller partitioning, xHCI passthrough, cross-partition input switching

// Support
pub mod uart;        // PL011 UART driver — polled TX for boot diagnostics
