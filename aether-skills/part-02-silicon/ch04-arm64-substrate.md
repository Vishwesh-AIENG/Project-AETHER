# SKILL.md — Chapter 4: ARM64 As The Substrate

## Confidence Disclosure

**MEDIUM overall.** Claude understands ARM64 at the conceptual level well. The failure zone is specific encoding details — instruction binary formats, system register bit fields, exact mnemonics for edge-case instructions. Claude will produce plausible-looking register names and instruction sequences that are subtly wrong. Always verify against the ARM ARM before trusting any specific register name, bit field, or instruction encoding Claude produces.

## Required Primary Sources

**ARM Architecture Reference Manual for Armv8-A** (`DDI0487`, available free at developer.arm.com)

Specific sections to read before implementing anything in this domain:

| Section | Topic | Priority |
|---|---|---|
| Chapter A1 | Introduction to the ARM architecture | READ FIRST |
| Chapter B1 | The AArch64 application level architecture | Essential |
| Chapter C1–C7 | AArch64 instruction descriptions | Reference as needed |
| Chapter D1 | AArch64 System level architecture | Essential |
| Section D1.2 | AArch64 registers in EL1 and EL0 | Read completely |
| Section D5 | The AArch64 Virtual Memory System Architecture | Critical |
| Appendix G | Registers listed by encoding | Use as lookup table |

## Secondary Sources

**Linux kernel `arch/arm64/include/asm/`** — The Linux kernel's ARM64 headers are the most authoritative practical reference for register names and bit field definitions as they appear in real production code. Specifically:
- `sysreg.h` — system register definitions
- `pgtable-hwdef.h` — page table hardware definitions
- `page.h` — page size and alignment constants

**AOSP `kernel/msm-*` device-specific headers** — Qualcomm-specific extensions to ARM64 that appear in Snapdragon platforms.

## Critical Concepts

**The Register File.** ARM64 has 31 general-purpose 64-bit registers (X0–X30). X29 is conventionally the frame pointer. X30 is the link register (return address). SP is the stack pointer, separate from the general registers. PC is the program counter, not directly accessible as a general register. XZR (alias for X31) always reads as zero; writes to it are discarded. W0–W30 are the 32-bit aliases of the lower halves of X0–X30. This distinction matters: writing W0 zero-extends into X0, not sign-extends.

**System Registers.** Hundreds of system registers control the processor's behavior. They are accessed only through MRS (read) and MSR (write) instructions. Their names follow the pattern `<register>_EL<n>` where n is the exception level at which they are accessible. Examples: `SCTLR_EL1` (system control register for EL1), `TTBR0_EL1` (translation table base register 0 for EL1), `VTTBR_EL2` (virtualization translation table base register, EL2 only). Claude frequently confuses which registers exist at which exception levels and which bits within them do what — always verify against Appendix G of the ARM ARM.

**The Memory Model.** ARM64 has a weakly ordered memory model. Loads and stores can be reordered by the processor relative to their program order. This is critical for hypervisor code that manipulates shared data structures. The DSB (Data Synchronization Barrier) and ISB (Instruction Synchronization Barrier) instructions enforce ordering. Incorrect use of barriers is one of the hardest bugs to diagnose in systems software. Claude understands the concept but may suggest insufficient barriers in specific situations.

**Page Sizes.** ARM64 supports 4KB, 16KB, and 64KB translation granules. Most Android devices and Linux systems use 4KB. The choice of granule affects the page table layout (number of levels, address bits per level) and must be consistent throughout the system.

## Common AI Mistakes In This Domain

Claude frequently produces register names with incorrect EL suffixes — for example, writing `TTBR0_EL2` when the correct register for a specific operation is `VTTBR_EL2`. These mistakes compile and run but do completely wrong things.

Claude sometimes omits required ISB instructions after writes to system registers that affect instruction fetch behavior. The ARM ARM specifies exactly when ISB is required after MSR instructions; Claude does not always follow this correctly.

Claude may use deprecated or renamed mnemonics from earlier ARM architecture versions. Always check that the instruction Claude produces is valid in ARMv8-A or ARMv9-A as appropriate.

## Verification Protocol

For any ARM64 assembly or system register code Claude produces:
1. Look up every system register name in ARM ARM Appendix G — verify it exists at the claimed EL
2. Look up every barrier instruction (DSB, DMB, ISB) and verify the operand (SY, ISH, ISHST, etc.) matches the ARM ARM's specification for that specific use case
3. Check the Linux kernel's `arch/arm64/include/asm/sysreg.h` to see how Linux defines the same registers — if Linux uses a different name or bit field, Linux is right

## Pre-Flight Checklist

- [ ] Download ARM ARM `DDI0487` from developer.arm.com
- [ ] Read ARM ARM Chapter A1 completely (approximately 30 pages)
- [ ] Read ARM ARM Section D1.2 (register descriptions)
- [ ] Clone the Linux kernel source: `git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git`
- [ ] Browse `arch/arm64/include/asm/sysreg.h` to understand naming conventions
- [ ] Write a simple EL1 bare-metal "Hello World" in ARM64 assembly targeting QEMU before touching hypervisor code
