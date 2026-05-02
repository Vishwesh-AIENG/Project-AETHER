# SKILL.md — Chapter 28: Development Workflow

## Confidence Disclosure

**HIGH for general software engineering workflow, MEDIUM for QEMU ARM64 system emulation specifics, MEDIUM for hardware-in-the-loop testing strategies.** The workflow itself is engineering judgment. The QEMU configuration details for a faithful ARM64 virtualization environment require verification against QEMU documentation.

## Required Primary Sources

**QEMU documentation** at qemu.org/docs — Particularly:

| Document | Topic | Priority |
|---|---|---|
| System Emulation Guide | ARM64 system emulation | MANDATORY |
| `qemu-system-aarch64` man page | All command-line options | Reference |
| QEMU GIC documentation | GICv3 emulation options | Essential |

**LLDB documentation** at lldb.llvm.org — LLDB is the Rust-friendly debugger. For bare-metal debugging:
- Remote debugging via GDB server protocol
- ARM64 register display commands

**GDB documentation** — GDB's remote protocol is used even when the front-end is LLDB. The `target remote` command and hardware breakpoint support.

## Secondary Sources

**QEMU's ARM GIC emulation source** at `hw/intc/arm_gicv3.c` in QEMU source — Understanding QEMU's GIC limitations is important; QEMU's GICv3 emulation does not support all features of real hardware.

**Rust GDB/LLDB integration** — The `rust-lldb` and `rust-gdb` wrapper scripts distributed with the Rust toolchain.

**cargo-binutils** at github.com/rust-embedded/cargo-binutils — Cargo subcommands for common binary inspection tasks (`cargo-nm`, `cargo-objdump`, `cargo-size`, `cargo-strip`).

## Critical Concepts

**The QEMU Development Loop.** The development loop for AETHER has three tiers:

Tier 1 (fastest, minutes per cycle): QEMU with a minimal test guest. No Android, no Windows. A simple ARM64 bare-metal test program that exercises one specific hypervisor feature. Boot time is under 5 seconds. Used for all new feature development and bug fixing.

Tier 2 (slower, 10–30 minutes per cycle): QEMU with a real Linux kernel as the guest. Verifies that real guest software works with the hypervisor. Used for integration testing after Tier 1 passes. Android Common Kernel in QEMU is acceptable here.

Tier 3 (slowest, hours per cycle): Real Snapdragon X Elite hardware. Used for hardware-specific validation, SR-IOV testing, and performance measurement. Never used for initial development.

**QEMU ARM64 Configuration For AETHER Development.** The QEMU invocation for AETHER development is:
```
qemu-system-aarch64 \
  -machine virt,gic-version=3,virtualization=on \
  -cpu cortex-a76 \
  -m 8G \
  -bios OVMF.fd \
  -drive file=fat:rw:efi_partition/ \
  -nographic \
  -serial stdio \
  -monitor telnet::4444,server,nowait \
  -S -gdb tcp::1234
```

Key flags:
- `gic-version=3` — use GICv3, matching the target hardware
- `virtualization=on` — enable EL2, required for hypervisor development
- `-S` — freeze CPU at startup, wait for GDB connection
- `-gdb tcp::1234` — GDB remote stub on port 1234

**Debugging A Bare-Metal Hypervisor.** Standard printf-style debugging does not work in early boot (no OS, no terminal). The primary early debug mechanism is a UART serial output. AETHER maps the platform UART (or QEMU's pl011 UART at 0x09000000 in the `virt` machine) early in initialization and writes diagnostic messages there. Every major initialization step should log to serial.

After serial output is established, the secondary debug mechanism is QEMU's GDB stub (the `-gdb` flag). Connect with:
```
rust-lldb
target remote :1234
```
This gives register inspection, memory examination, and hardware breakpoints. LLDB can load the AETHER ELF file (not the EFI binary) to get symbol names:
```
add-symbol-file aether.elf
```

**Hardware Breakpoints vs Software Breakpoints.** In EL2 before the MMU is on, software breakpoints (which overwrite an instruction with a BRK instruction) don't work correctly because the memory might not be writable in the way the debugger expects. Use hardware breakpoints instead (`hbreak` in GDB rather than `break`). There are typically 6 hardware breakpoints available on ARM64.

**Continuous Integration For A Multi-Subsystem Project.** AETHER's CI pipeline has three stages. First, build verification: `cargo check` on the hypervisor Rust code (fast, no codegen), `m checkbuild` on AOSP (slow, skip on every commit — run nightly). Second, unit tests: Rust unit tests for pure logic in the hypervisor (fast), Python tests for the build tooling. Third, integration tests: QEMU-based boot tests that boot the hypervisor with a minimal guest and verify it reaches expected milestones (takes minutes — run on every pull request).

**Bisection Strategy.** When a regression occurs between two working states, git bisect with the QEMU Tier 1 test suite is the fastest way to find the commit. AETHER's test suite should be designed to make `git bisect run make test-tier1` work automatically — each test must exit 0 for pass and non-zero for fail, with no human interaction required.

**Snapshot-Based Testing.** QEMU supports savestate snapshots. After a slow initialization sequence (e.g., Android boot), save a QEMU snapshot. Future test runs can restore from the snapshot and test post-boot behavior without waiting for boot. This accelerates the Tier 2 development loop significantly.

## Common AI Mistakes In This Domain

Claude suggests using `println!` for hypervisor debug output. `println!` requires the standard library which is unavailable. The correct approach is a `write!` to a serial port writer that implements `core::fmt::Write`.

Claude generates QEMU invocations without `virtualization=on`, producing a QEMU environment where EL2 is inaccessible and hypervisor code fails silently.

Claude suggests software breakpoints in early boot code. As explained above, use hardware breakpoints before the MMU is configured.

Claude generates CI configurations that run the full AOSP build on every commit. A full AOSP build takes 4+ hours and requires 200+ GB of disk — it cannot be a per-commit gate. Use `m checkbuild` for quick verification and run the full build only nightly or on release branches.

## Verification Protocol

For the QEMU development environment:
1. Verify `cat /proc/cpuinfo` in a test guest shows ARM64 cores — confirms virtualization=on is working
2. Verify GDB can set a hardware breakpoint at the hypervisor entry point and halt there
3. Verify serial output appears for every major initialization step

For CI:
1. Verify the Tier 1 test suite completes in under 5 minutes — if it takes longer, it won't be run consistently
2. Verify all tests are reproducible — no flaky tests in the CI suite

## Pre-Flight Checklist

- [ ] Install QEMU with ARM64 support: `apt install qemu-system-arm` or build from source for latest version
- [ ] Download OVMF for ARM64 (available in the `ovmf` package or from tianocore.org)
- [ ] Set up the LLDB/GDB remote debugging workflow with a minimal bare-metal ARM64 program in QEMU before building AETHER
- [ ] Establish the UART debug output infrastructure on day 1 of coding — it is the most important debugging tool
- [ ] Set up a GitHub Actions or similar CI workflow with the Tier 1 test suite before writing significant code
- [ ] Create a QEMU snapshot of a working system state at every major milestone for fast regression testing
