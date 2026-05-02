# SKILL.md — Part I: The Vision (Chapters 1–3)

## Confidence Disclosure

Claude has HIGH confidence in this part. Chapters 1–3 are architectural philosophy and design constraints — no bit-level hardware knowledge required. The risk here is not technical incorrectness but conceptual drift: over time, implementation pressure tempts teams to violate the non-negotiables established here. Claude can help enforce the principles but cannot prevent humans from choosing to abandon them.

## Required Primary Sources

None for these chapters specifically. The vision is self-contained in the README.

## Critical Concepts

**The No-Boundary Principle** is the founding constraint. Every future engineering decision is evaluated against it. When a proposed implementation would create a dependency between the Windows partition and the Android partition — any dependency whatsoever, beyond the ARM64 instruction set — the implementation violates the principle and must be rejected or redesigned.

**The Distinction Between Type-1 and Type-2** must be internalized before any other work begins. AETHER is Type-1: no host OS, hypervisor on bare metal, guests as equals. Any architecture that has Windows "underneath" Android is Type-2 and violates the design. This mistake is easy to drift into because most existing Android-on-PC solutions are Type-2.

**Fingerprint Purity** is the commercial reason the principle exists. Every compromised boundary becomes a detectable fingerprint. The principle and the business case are the same argument.

## Common AI Mistakes In This Domain

Claude may suggest "pragmatic shortcuts" that violate the non-negotiables — for example, suggesting a shared file system between Windows and Android for developer convenience, or suggesting that the hypervisor could run as a Windows driver to simplify boot. These are Type-2 architectures and must be rejected even when Claude frames them as reasonable trade-offs.

## Verification Protocol

When reviewing any architectural decision:
1. Does it create any dependency between the Windows and Android partitions?
2. If yes, is that dependency mediated entirely by the hypervisor with no direct guest-to-guest communication?
3. If no to question 2, the decision violates Part I.

## Pre-Flight Checklist

- [ ] Read Chapters 1–3 of the README in full
- [ ] Write down, in your own words, the three non-negotiables from Chapter 3
- [ ] Keep those non-negotiables visible at your workstation during all development
