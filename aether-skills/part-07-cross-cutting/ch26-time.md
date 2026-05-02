# SKILL.md — Chapter 26: Time

## Confidence Disclosure

**MEDIUM for ARM architectural timer concepts, LOW for cross-VM timer coherence implementation details.** Time is one of the most underestimated sources of virtualization fingerprints. Claude understands the general problem but specific ARM timer register behavior under virtualization needs primary source verification.

## Required Primary Sources

**ARM ARM `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Section D11 | Generic Timer | MANDATORY — read entirely |
| Section D11.1 | About the Generic Timer | Read first |
| Section D11.2 | Timer registers | Critical |
| Section D11.3 | Timers and virtualization | MANDATORY |
| Section G5 (CNTHCTL_EL2) | Hypervisor timer control register | Critical |
| Section G5 (CNTPOFF_EL2) | Counter physical offset | Critical for time virtualization |

**Google Project Zero research on timing side channels** — projectzero.blogspot.com. Relevant posts on timer-based fingerprinting and detection methods.

## Secondary Sources

**KVM ARM timer implementation** at `arch/arm64/kvm/arch_timer.c` — The most complete reference for ARM timer virtualization. Study how KVM virtualizes the physical and virtual timers for ARM64 guests.

**Xen timer implementation** at `xen/arch/arm/time.c` — Alternative reference.

**Linux ARM64 timer driver** at `drivers/clocksource/arm_arch_timer.c` — Shows what the guest kernel does with the timer, which informs what AETHER must provide.

## Critical Concepts

**The ARM Generic Timer Architecture.** ARM64 has multiple timer sources, each accessible via system registers:
- `CNTPCT_EL0` — Physical counter, always counts at the same rate, readable from EL0 in normal operation
- `CNTVCT_EL0` — Virtual counter, normally equal to physical minus the virtual offset (`CNTVOFF_EL2`)
- `CNTFRQ_EL0` — Counter frequency, typically 19.2 MHz or 25 MHz depending on platform
- `CNTP_CTL_EL0` / `CNTP_CVAL_EL0` — Physical timer control and compare value
- `CNTV_CTL_EL0` / `CNTV_CVAL_EL0` — Virtual timer control and compare value

The physical counter is the ground truth — it counts at a fixed rate synchronized to the platform clock. The virtual counter is what most software should use; it can be offset from the physical by the hypervisor to provide time isolation between guests.

**Why Timer Virtualization Matters For Fingerprinting.** Anti-cheat and integrity systems use timers in two ways. First, they measure the wall-clock time of specific operations and compare against expected values — if an operation that should take 1µs takes 100µs, virtualization overhead is suspected. Second, they check for discontinuities in the time stream — if the timer appears to jump forward unexpectedly, this indicates a VM exit occurred and the guest was descheduled. AETHER's static CPU partitioning eliminates the second problem entirely (no descheduling of Android cores means no time discontinuities). The first problem is addressed by AETHER's native-speed execution — operations take the same time they would on real hardware because they run on the same hardware.

**CNTPOFF_EL2 — The Counter Offset Register.** When HCR_EL2.E2H=0 (nVHE mode, which AETHER uses), the hypervisor can set `CNTPOFF_EL2` to make the virtual counter appear offset from the physical counter. This is how AETHER could, if desired, make each guest appear to have started at time zero by offsetting their virtual counter. For fingerprinting purposes this is not necessary (the absolute timer value is not the fingerprint — the timing of operations is). But it is available if needed.

**CNTHCTL_EL2 — Timer Access Control.** This register controls whether EL0 and EL1 in the guest can access physical and virtual timer registers without trapping to EL2. The key bits are:
- `EL1PCEN` (bit 1): allows EL1 to access physical counter/timer without trap — set to 1 for performance
- `EL1PCTEN` (bit 0): allows EL1 to read physical counter without trap — set to 1
- `EVNTEN` (bit 2): enables event stream generation — usually 0

If these bits are not set correctly, every timer register access by the guest traps to EL2, producing enormous performance overhead and creating exactly the timing anomalies that fingerprinting looks for.

**Timer Interrupt Delivery.** The virtual timer generates interrupts to the guest via the GIC. The interrupt is a PPI (Private Peripheral Interrupt) with a specific INTID (typically 27 for the virtual timer). AETHER must configure the GIC's redistributor for each Android core to route this interrupt to the Android partition's virtual GIC interface. When the Android kernel sets the virtual timer compare value and the counter reaches that value, the hardware delivers the interrupt through the virtual GIC to the Android kernel without AETHER's involvement.

**NTP And Real-Time Clock.** Beyond the architectural timer (which is a monotonic counter, not a real-time clock), Android needs to know the actual calendar time. This comes from the RTC (Real-Time Clock) and/or NTP. AETHER provides a virtual RTC that is initialized from the platform's real RTC at boot and runs autonomously. Android also syncs with NTP through its assigned network interface. Neither of these requires special AETHER involvement beyond the basic hardware simulation.

## Common AI Mistakes In This Domain

Claude generates EL2 timer setup that leaves `CNTHCTL_EL2.EL1PCEN=0`, causing every physical timer access from the guest to trap to EL2. This produces correct timer behavior but with enormous performance overhead and visible timing anomalies.

Claude confuses the virtual timer interrupt INTID (PPI 11, which maps to INTID 27 = 16+11) with other timer interrupt IDs. The non-secure physical timer is PPI 14 (INTID 30), the virtual timer is PPI 11 (INTID 27), the hypervisor physical timer is PPI 10 (INTID 26). Using wrong INTIDs produces timers that never fire interrupts.

Claude generates timer code that reads `CNTPCT_EL0` directly in the hypervisor for timekeeping. In nVHE mode, the hypervisor should use `CNTPCT_EL0` or its EL2-accessible equivalent, but must be careful about register access rules at EL2.

## Verification Protocol

For timer configuration:
1. Verify `CNTHCTL_EL2` bit settings against ARM ARM Section G5 — confirm EL1PCEN and EL1PCTEN are set correctly for the nVHE mode
2. Boot the Android kernel and verify `cat /proc/timer_list` shows the expected timer sources active
3. Measure timer access latency from Android userspace — should be <10ns for direct counter reads (indicating no trap to EL2)

For timer interrupt delivery:
1. Verify the virtual timer PPI (INTID 27) is correctly configured in the GIC redistributor
2. Use `sleep 1` in Android and verify it takes approximately 1 second — timer accuracy test

## Pre-Flight Checklist

- [ ] Read ARM ARM Section D11 (Generic Timer) completely — all subsections
- [ ] Study `arch/arm64/kvm/arch_timer.c` fully — every function's relationship to the ARM spec
- [ ] Study `drivers/clocksource/arm_arch_timer.c` — understand what the guest kernel does with the timer
- [ ] On QEMU, measure the overhead of timer register access with and without EL1PCEN set — understand the performance difference before choosing timer trap settings
- [ ] Document the exact timer PPI INTIDs for the target platform's GIC configuration before writing interrupt routing code
