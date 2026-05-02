# SKILL.md — Chapter 5: Exception Levels

## Confidence Disclosure

**MEDIUM.** Claude understands the conceptual hierarchy well but makes specific mistakes in exception entry/exit sequences, saved register state layout, and the exact conditions that trigger transitions between levels. The exception model is one of the areas where a subtle mistake is catastrophic — incorrect exception handling means the hypervisor either crashes or is compromised.

## Required Primary Sources

**ARM ARM `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Chapter D1.1 | Exception levels | Read completely |
| Section D1.10 | Exception vectors | Critical |
| Section D1.11 | Exception entry | Critical |
| Section D1.12 | Exception return | Critical |
| Section D1.13 | Synchronous exceptions | Critical |
| Section D1.14 | Asynchronous exceptions (IRQ, FIQ, SError) | Critical |
| Section D1.15 | Exception linking registers (ELR, SPSR) | Critical |

## Secondary Sources

**Linux kernel `arch/arm64/kernel/entry.S`** — The Linux ARM64 exception entry code is the most studied, most correct implementation of ARM64 exception handling in the world. Read every line and every comment. It handles the exact same vector table, SPSR manipulation, and register saving that AETHER's EL2 handler needs to do.

**ARM Trusted Firmware `bl31/aarch64/runtime_exceptions.S`** — TF-A's EL3 exception handler, structurally similar to what AETHER needs at EL2.

**Xen on ARM `xen/arch/arm/arm64/entry.S`** — Xen's EL2 exception entry, the closest existing reference to what AETHER implements.

## Critical Concepts

**The Four Exception Types.** ARM64 exceptions fall into four categories. Synchronous exceptions are caused directly by the currently executing instruction — a page fault, an undefined instruction, a system call (SVC), or a hypervisor call (HVC). IRQ (Interrupt Request) is a normal hardware interrupt. FIQ (Fast Interrupt Request) is a high-priority interrupt, typically used by secure firmware. SError (System Error) is an asynchronous data abort from the memory system, typically from a bus error. Each type has different vector table entries and different handling requirements.

**The Vector Table.** Each exception level has a vector table at a configurable base address stored in a system register (VBAR_EL1, VBAR_EL2, VBAR_EL3). The table has sixteen entries, each 128 bytes (32 instructions), organized into four groups of four: exceptions taken from the same EL with SP_EL0, exceptions taken from the same EL with SP_ELx, exceptions taken from lower EL in AArch64, exceptions taken from lower EL in AArch32. For AETHER's EL2 handler, the "exceptions taken from lower EL in AArch64" group is the critical one — this is where guest VM exits land. Claude sometimes generates incorrect vector table layouts with wrong entry offsets.

**ESR_EL2 — The Exception Syndrome Register.** When an exception is taken to EL2, ESR_EL2 contains the reason. The top 6 bits (EC field, Exception Class) identify the category of exception. The remaining bits contain exception-class-specific information. EC value 0x16 means HVC instruction executed. EC value 0x24 means Data Abort from lower EL. EC value 0x20 means Instruction Abort from lower EL. Every EL2 exception handler begins by reading ESR_EL2 and branching based on the EC field. Claude knows the concept but frequently gets specific EC values wrong — always look them up in ARM ARM Table D1-6.

**SPSR — Saved Program Status Register.** When an exception is taken, the processor saves the current PSTATE (processor state flags, exception level, stack pointer selection) into SPSR_ELx. On exception return (ERET instruction), PSTATE is restored from SPSR. Manipulating SPSR incorrectly when constructing a new guest context is one of the most common hypervisor initialization bugs. AETHER must carefully construct SPSR_EL2 values that represent a valid EL1 state for each new guest.

**ELR — Exception Link Register.** ELR_EL2 holds the address that ERET will return to. When taking an exception, the processor sets ELR_EL2 to the address of the faulting or next instruction (depending on exception type). When AETHER synthesizes a guest entry using ERET, it sets ELR_EL2 to the guest's intended entry point.

**Context Switching Between Guests.** When AETHER switches execution from one guest to another (which in static partitioning it essentially never does on the same core, but must do during initialization), it must save all general-purpose registers, all relevant system registers, and all floating-point/SIMD registers for the outgoing guest, then restore the same set for the incoming guest. Missing a single register corrupts the guest's state invisibly.

## Common AI Mistakes In This Domain

Claude generates vector table entry code with incorrect offsets. The ARM64 vector table must be aligned to 2KB and entries are exactly 128 bytes apart. Off-by-one errors in the alignment or the entry size produce a table that looks correct but handles exceptions with wrong handlers.

Claude sometimes confuses ELR_EL2 and ELR_EL1 in context-switching code. These are separate registers. ELR_EL2 is the hypervisor's own exception link register. EL1 has its own ELR_EL1 that is part of the guest's state and must be saved/restored.

Claude may suggest using SP_EL0 when SP_ELx is required (or vice versa) in exception handler entry code. The stack pointer selection at exception entry depends on the SPSR.M field and is a source of subtle bugs.

## Verification Protocol

For exception handling code Claude produces:
1. Verify the vector table base alignment is exactly 2048 bytes (0x800)
2. Verify each vector entry is exactly 128 bytes (32 instructions maximum)
3. Verify every EC value read from ESR_EL2 against ARM ARM Table D1-6
4. Verify SPSR construction against ARM ARM Section D1.12
5. Confirm that all callee-saved registers (X19–X30) are saved before any function call in exception handlers
6. Compare the generated vector table structure against `arch/arm64/kernel/entry.S` in the Linux kernel

## Pre-Flight Checklist

- [ ] Read ARM ARM Chapter D1.10 through D1.15 completely
- [ ] Study Linux `arch/arm64/kernel/entry.S` line by line — add comments explaining each macro
- [ ] Study Xen `xen/arch/arm/arm64/entry.S` as the EL2-specific reference
- [ ] Write a minimal EL2 bare-metal program in QEMU that installs a vector table and handles a single synchronous exception — print the EC value and return — before touching any AETHER code
- [ ] Create a reference table of all EC values you expect AETHER to handle and what each one means
