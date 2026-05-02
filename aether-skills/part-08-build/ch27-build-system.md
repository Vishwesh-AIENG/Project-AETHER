# SKILL.md — Chapter 27: The Build System

## Confidence Disclosure

**HIGH for Rust/Cargo, HIGH for Make, MEDIUM for AOSP Soong, LOW for cross-compilation toolchain configuration specifics.** Claude knows build systems well conceptually. The failure zone is in the integration of three separate build systems (Cargo, Make, Soong) and in the specific cross-compilation flags required for bare-metal ARM64 targets.

## Required Primary Sources

**Cargo documentation** at doc.rust-lang.org/cargo — Particularly:
- Chapter on Build Scripts (`build.rs`) — AETHER hypervisor uses these for assembly integration
- Chapter on Configuration (`.cargo/config.toml`) — for cross-compilation target configuration
- Chapter on Workspaces — AETHER's hypervisor is a Cargo workspace

**Rust Embedded Book** at docs.rust-embedded.org/book — Particularly:
- Chapter on Bare Metal — `no_std` configuration for the hypervisor
- Chapter on Using a Linker Script — AETHER needs a custom linker script to place the hypervisor at EL2's expected address

**AOSP build documentation** at source.android.com/docs/setup/build — Particularly:
- Soong build system
- Android.bp file syntax
- Building Android

**GNU ld linker documentation** — For the custom linker script that places AETHER at the correct physical address.

## Secondary Sources

**The `cortex-m` crate ecosystem** at crates.io — While targeting ARM Cortex-M rather than Cortex-A, these crates establish patterns for bare-metal Rust (startup code, panic handler, `no_std` structure) that AETHER adapts.

**The `aarch64-unknown-none` Rust target specification** — In the Rust repository at `compiler/rustc_target/src/spec/aarch64_unknown_none.rs`. Defines what the bare-metal ARM64 Rust target provides and what it doesn't.

## Critical Concepts

**Three Build Systems In One Project.** AETHER's build consists of three independent subsystems that must produce compatible outputs. First, the hypervisor: a Rust/Cargo workspace producing a bare-metal EFI binary. Second, the Android image: an AOSP Make/Soong build producing a flashable Android system. Third, the Windows configuration: a set of scripts that prepare the Windows partition on the NVMe namespace. The top-level build orchestration uses a Makefile that invokes each subsystem in the correct order and packages the outputs.

**The Hypervisor Binary Format.** The hypervisor must be a UEFI-compatible binary — specifically an EFI application in PE/COFF format — so that the platform firmware can load it as the OS bootloader. Rust produces ELF binaries by default, not PE/COFF. Converting ELF to PE/COFF requires either using the `r-efi` crate (which provides UEFI-compatible Rust code with PE/COFF output) or post-processing the ELF with `objcopy`. The `aarch64-unknown-uefi` Rust target produces PE/COFF directly and is the recommended target for the hypervisor binary.

**The Linker Script.** A bare-metal ARM64 program requires a custom linker script that specifies:
- Where in physical memory the binary is loaded (AETHER is loaded by UEFI so this is UEFI's responsibility, but the script must account for it)
- The order and alignment of sections (.text, .data, .bss, .rodata)
- The entry point symbol
- The stack layout

For a UEFI application, the `aarch64-unknown-uefi` target handles most of this automatically. For any non-UEFI portions (such as the EL2 initialization stubs that must run before Rust's runtime), a separate minimal assembly file with its own section placement is required.

**`no_std` And `no_main` In The Hypervisor.** The hypervisor cannot use the Rust standard library (`std`) because `std` depends on an operating system (for file I/O, heap allocation, threading, etc.) and the hypervisor runs before any OS. Instead, the hypervisor uses `#![no_std]` and provides its own implementations of the few standard services it needs: a heap allocator (using a simple bump allocator initially), a panic handler (that prints to the serial console and halts), and a minimal runtime startup that initializes the BSS section and calls the Rust entry point.

**The Assembly Integration.** Some parts of AETHER must be written in ARM64 assembly — specifically the exception vector table (which has strict 128-byte alignment requirements that are easier to guarantee in assembly) and the context-switching code (which must save and restore specific registers in a specific order that a compiler might reorder). These assembly files are compiled by the GNU ARM64 assembler (`aarch64-linux-gnu-as`) and linked into the Cargo build through a `build.rs` build script.

**AOSP Build Variables For AETHER's Device.** The AOSP build requires many variables set in `BoardConfig.mk` that control the kernel, partition layout, and hardware configuration. These variables must be consistent with the actual NVMe namespace sizes and the kernel binary produced by the Android Common Kernel build. Any inconsistency produces either build errors or boot failures. The build system should derive these values from a single source of truth (a configuration file) rather than having them hardcoded in multiple places.

## Common AI Mistakes In This Domain

Claude generates Rust code for the hypervisor using `std` types like `Vec`, `String`, and `HashMap`. These require the standard library and cannot be used in `no_std`. The `alloc` crate provides `Vec` and `String` for `no_std` environments with a custom allocator, but must be explicitly enabled.

Claude generates `build.rs` scripts that invoke the assembler with x86-64 flags rather than ARM64 flags. Cross-compilation errors here produce silent failures where the wrong architecture binary is linked in.

Claude generates AOSP `BoardConfig.mk` files with partition sizes in bytes rather than in the units AOSP expects. Some partition size variables are in bytes, others are in kilobytes — mixing them produces wrong-sized partitions.

Claude suggests using `cargo build` directly for the hypervisor without specifying the target (`--target aarch64-unknown-uefi`), producing an x86-64 binary on an x86 development machine.

## Verification Protocol

For the hypervisor binary:
1. Run `file aether.efi` and verify it reports ARM64 PE32+ executable
2. Run in QEMU with OVMF before testing on real hardware: `qemu-system-aarch64 -machine virt -bios OVMF.fd -drive file=fat:rw:efi_partition/`
3. Verify the EFI application loads and reaches its entry point by checking serial console output

For the AOSP build:
1. Run `m checkbuild` to verify the build configuration is internally consistent
2. Flash the produced image to a test device and verify boot to Android home screen

## Pre-Flight Checklist

- [ ] Read Cargo book chapters on workspaces and build scripts
- [ ] Read Rust Embedded Book chapter on bare metal
- [ ] Install ARM64 cross-compilation toolchain: `sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu`
- [ ] Add the `aarch64-unknown-uefi` Rust target: `rustup target add aarch64-unknown-uefi`
- [ ] Download OVMF for ARM64 and test a minimal UEFI application in QEMU before building AETHER
- [ ] Set up AOSP build environment following source.android.com setup instructions — this takes 4–8 hours on first setup
