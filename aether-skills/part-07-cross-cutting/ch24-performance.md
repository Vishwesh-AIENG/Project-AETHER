# SKILL.md — Chapter 24: Performance

## Confidence Disclosure

**HIGH for performance analysis methodology, MEDIUM for ARM64-specific performance characteristics, LOW for Snapdragon X Elite-specific microarchitecture details.** Claude understands performance profiling and optimization at a conceptual level well. Specific cycle counts, cache sizes, and pipeline characteristics of the Snapdragon X Elite require Qualcomm's documentation or empirical measurement.

## Required Primary Sources

**ARM Cortex-X4 Software Optimization Guide** — available at developer.arm.com. The Snapdragon X Elite uses Cortex-X4 performance cores. This guide documents cycle counts, pipeline stages, and optimization guidance.

**ARM Neoverse Reference Perf Model** — for background on ARM microarchitecture performance modeling.

**Linux `perf` documentation** at `tools/perf/Documentation/` in the kernel source — The primary tool for performance measurement on Linux/Android.

**Brendan Gregg's performance documentation** at brendangregg.com — The best freely available systems performance reference. Particularly relevant: Linux Performance, Flame Graphs, and BPF performance tools.

## Secondary Sources

**Google's Android performance documentation** at developer.android.com/games/optimize — Game-specific performance guidance for Android, relevant for AETHER's primary use case.

**Perfetto tracing tool** at perfetto.dev — Android's system tracing tool. Essential for measuring end-to-end latency in the Android graphics pipeline.

**ARM Streamline** — ARM's performance analysis tool for Cortex processors, available through DS-5. Free license for Arm developer account holders.

## Critical Concepts

**The AETHER Performance Model.** AETHER's performance advantage over Type-2 emulators comes from eliminating every software layer between the guest and the hardware. In a Type-2 emulator like BlueStacks, an Android graphics call travels through: Android app → GLES driver → host graphics API translation (ANGLE or similar) → Windows graphics driver → GPU. In AETHER, the path is: Android app → GLES driver → Adreno driver talking directly to the GPU VF. Every removed layer eliminates latency and reduces CPU overhead.

**VM Exit Frequency Is The Key Metric.** A VM exit occurs whenever a guest performs an operation that requires AETHER's intervention — a trapped system register access, an HVC call, a memory fault. Each exit takes roughly 1,000–5,000 cycles on ARM64 depending on the operation. In a well-designed hypervisor, VM exits during normal operation (after boot) should be rare — primarily timer-related exits and device interrupt acknowledgements. If AETHER is exiting thousands of times per second during gameplay, something is wrong with the trap configuration. Measuring VM exit frequency is the first performance diagnostic step.

**TLB Pressure From Stage 2 Translation.** Stage 2 translation adds a second TLB level to every memory access that misses Stage 1. Modern ARM processors have dedicated Stage 2 TLBs that can hold thousands of entries. If Android's working set fits in the Stage 2 TLB, the performance impact of Stage 2 translation is effectively zero. If Android's working set causes Stage 2 TLB thrashing — common if the Stage 2 mapping uses too many small pages instead of large pages (2MB blocks instead of 4KB pages) — performance degrades measurably. AETHER should map as much of Android's address space as possible with 2MB block mappings to maximize TLB coverage.

**Cache Coherence Between Guests.** The L3 cache is physically shared between all cores on the Snapdragon X Elite regardless of partition assignment. Android's working set and Windows's working set compete for L3 space. This is unavoidable with a shared last-level cache and is the one place where the two guests genuinely interact at the hardware level. The performance implication is that an intensive Windows workload can evict Android's cache entries and vice versa. This is the same behavior as running two processes on a native machine — it is not a hypervisor artifact, just physics.

**Graphics Latency Pipeline.** For gaming in Android, the critical latency path is: input event → Android input processing → game logic → GPU command submission → GPU rendering → display. AETHER's SR-IOV GPU passthrough eliminates the host-GPU translation layer, but the Android graphics stack still adds latency through its own buffering (typically triple-buffered). Measuring and minimizing this pipeline latency, using tools like Perfetto and the GPU profiler in Android Studio, is the primary graphics optimization task.

## Common AI Mistakes In This Domain

Claude suggests using `time` or similar wall-clock measurement for hypervisor performance analysis. VM exit frequency and duration require hardware performance counters (`perf stat` with KVM-specific events) not wall-clock measurement.

Claude suggests optimizing Stage 2 page tables by using smaller pages for finer granularity. The opposite is almost always correct — larger pages (2MB) reduce TLB pressure at the cost of finer-grained protection, and the TLB pressure reduction almost always wins for large continuous workloads like game rendering.

Claude suggests disabling Stage 2 translation for performance. This would eliminate memory isolation entirely. Stage 2 translation with large pages has near-zero performance impact on modern ARM processors.

## Verification Protocol

For VM exit frequency measurement:
1. Use `perf kvm stat` (on Linux KVM as reference) to measure exits per second during idle and under gaming load
2. Target: fewer than 1,000 VM exits per second during sustained gaming
3. Identify the top exit reasons and address any that are unexpectedly frequent

For graphics pipeline latency:
1. Use Perfetto to capture a system trace during gameplay
2. Measure frame time from input event to display flip
3. Target: less than 16.7ms per frame for 60fps, less than 8.3ms for 120fps

## Pre-Flight Checklist

- [ ] Download ARM Cortex-X4 Software Optimization Guide
- [ ] Read Brendan Gregg's Linux Performance page at brendangregg.com
- [ ] Set up Perfetto on a test Android device to understand the tool before needing it on AETHER
- [ ] Establish performance baselines on native hardware before virtualizing — know what "native" looks like before optimizing toward it
- [ ] Write a VM exit counter into AETHER from the beginning — this should be a built-in diagnostic, not an afterthought
