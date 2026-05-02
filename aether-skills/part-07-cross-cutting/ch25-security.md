# SKILL.md — Chapter 25: Security

## Confidence Disclosure

**HIGH for security architecture concepts, MEDIUM for Rust memory safety specifics in no_std environments, LOW for formal verification tooling for hypervisors.** The security model is well-reasoned at the architectural level. Implementation-level security requires careful attention to Rust's unsafe blocks and to the specific ARM64 security features that enforce the model.

## Required Primary Sources

**ARM Architecture Reference Manual `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Section D1.9 | Security Extensions | Read |
| Section D5.9 | Memory access control | Read for permission enforcement |

**Rust Reference Manual** at doc.rust-lang.org/reference — Particularly:
- Chapter on Unsafe Code — every `unsafe` block in AETHER must be justified
- Chapter on Memory Model — for reasoning about concurrency correctness

**Rust Embedded Book** at docs.rust-embedded.org/book — Covers `no_std` Rust patterns that AETHER uses throughout the hypervisor.

**ARM Security Advisories** at developer.arm.com/support/security-update — Historical CPU vulnerabilities (Spectre, Meltdown variants) and their mitigations for ARM64. Critical for understanding what the hypervisor must do to protect itself.

## Secondary Sources

**seL4 microkernel security proofs** at sel4.systems — The world's most formally verified OS kernel. While AETHER will not undergo formal verification at launch, seL4's design principles for minimal trusted computing base are directly applicable.

**Xen Security Advisories** at xenbits.xen.org/xsa — Historical vulnerabilities in the Xen hypervisor. Each advisory is a lesson in what hypervisor code must not do. Read the ARM-specific ones carefully.

**Linux Kernel Self Protection Project (KSPP)** at kernsec.org/wiki/index.php/Kernel_Self_Protection_Project — Security hardening techniques applicable to hypervisors.

## Critical Concepts

**The Trusted Computing Base.** AETHER's Trusted Computing Base (TCB) is the set of code that, if compromised, would break the security of the entire system. For AETHER, the TCB is: the hypervisor itself, the EL3 firmware, and the hardware. Everything else — both guest operating systems, all apps — is outside the TCB. This means a compromised Android guest cannot affect the hypervisor or the Windows guest. This isolation guarantee is AETHER's core security property. The TCB must be kept as small as possible. Every line of code added to the hypervisor is a potential vulnerability; code that can run in guests should run in guests, not in the hypervisor.

**SMMU As A Security Boundary.** Without the SMMU, a compromised Android device driver could program a DMA-capable device to read or write Windows's memory — a complete isolation bypass that requires no privilege escalation in the CPU world. The SMMU is therefore a mandatory security component, not an optional performance feature. AETHER must configure the SMMU before enabling any guest's device drivers, and must verify the SMMU configuration is active before considering the system secure.

**Spectre And Meltdown On ARM64.** The Spectre and Meltdown vulnerabilities (and their variants) affect ARM64 processors including those in modern laptops. The relevant variants for hypervisors are Spectre v2 (branch target injection, which allows a guest to influence the hypervisor's speculative execution) and Meltdown (which allows reading kernel memory from userspace — patched in hardware on newer ARM cores but relevant for software on older ones). AETHER must implement ARM64 Spectre v2 mitigations: invalidating branch predictors on VM entry and exit (using `CLRBHB` or `BPIALL` depending on CPU generation), and using return stack buffer flushing where required. The Linux kernel's Spectre mitigation code at `arch/arm64/kernel/entry.S` is the reference.

**Rust Safety In The Hypervisor.** AETHER is written in Rust to gain memory safety guarantees. The rule is: every `unsafe` block must have a documented proof that it is actually safe — a comment explaining exactly why the invariants hold. Unsafe blocks that exist for "convenience" or "performance without evidence" are vulnerabilities waiting to be found. Common legitimate unsafe patterns in hypervisors: reading/writing hardware registers through raw pointers (safe because the pointer is derived from a hardware-documented address), managing page table memory pools (safe when the allocator is designed with correct alignment and lifecycle management). Common illegitimate unsafe patterns: raw pointer arithmetic without bounds checking, transmuting between types without verifying the invariants of the target type.

**Hypervisor Attack Surface.** AETHER's attack surface — the interfaces a guest can use to send data to AETHER and potentially exploit a bug — consists of: HVC calls (hypercall interface), trapped system register accesses, SMMU faults, and timer interrupts. Each of these is a point where malicious guest data reaches AETHER code. Every handler for these events must validate all inputs before acting on them. A guest should not be able to cause AETHER to dereference an arbitrary pointer, write to an arbitrary address, or execute arbitrary code by crafting specific HVC arguments or fault addresses.

## Common AI Mistakes In This Domain

Claude generates HVC handlers that use guest-supplied addresses directly as pointers without validating that the address falls within the calling guest's assigned memory. A guest supplying a hypervisor memory address as an HVC argument could read or corrupt hypervisor state.

Claude generates SMMU fault handlers that retry the faulting DMA transaction after logging the fault. This is wrong — a fault means a guest device tried to access memory outside its allowed range, which is a security event that should terminate the guest, not be silently retried.

Claude suggests using `unsafe { *(addr as *const u32) }` for MMIO access without explaining why `addr` is guaranteed to be a valid MMIO address. This pattern is correct but requires the justification.

Claude generates context-switching code that does not flush branch predictors between guests, leaving AETHER vulnerable to Spectre v2 cross-guest attacks.

## Verification Protocol

For every `unsafe` block:
1. Write a comment explaining the invariant that makes this safe
2. Have a second person read the comment and the code and agree the invariant holds
3. Add a test that exercises the boundary condition most likely to violate the invariant

For SMMU configuration:
1. Attempt a DMA from each guest to the other guest's memory and verify the SMMU faults rather than allows the access
2. Verify the fault handler terminates the offending guest rather than ignoring the fault

For Spectre mitigations:
1. Verify branch predictor invalidation instructions are present in every EL1→EL2 and EL2→EL1 transition path
2. Run a Spectre v2 PoC (available in public security research repositories) against AETHER and verify it cannot extract cross-guest data

## Pre-Flight Checklist

- [ ] Read all ARM Security Advisories from the past five years, especially ARM-specific Spectre variants
- [ ] Read every XSA (Xen Security Advisory) tagged as ARM-relevant at xenbits.xen.org/xsa
- [ ] Study seL4's design principles at sel4.systems — adopt its philosophy on TCB minimization
- [ ] Read the Rust Reference chapter on Unsafe Code fully before writing the first line of unsafe AETHER code
- [ ] Establish a code review policy: every `unsafe` block requires sign-off from a second engineer
