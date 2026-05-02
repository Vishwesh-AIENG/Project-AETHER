# SKILL.md — Part IX: The Roadmap (Chapters 29–33)

## Confidence Disclosure

**HIGH.** The roadmap chapters deal with project management, phase planning, and milestone definition — not hardware-specific technical details. Claude's knowledge of software project planning is reliable. The risk here is not technical incorrectness but estimation overconfidence. All time estimates in the README should be treated as optimistic best cases; multiply by 2–3 for realistic planning.

## Required Primary Sources

None specific to Part IX. The roadmap is derived from the technical decisions made in Parts I–VIII. The relevant primary source is the README itself, read as a whole.

## Recommended Background Reading

**"The Mythical Man-Month"** by Fred Brooks — The foundational text on software project estimation. Its core lesson (software takes longer than you think, adding people to a late project makes it later) applies directly to AETHER.

**"A Philosophy of Software Design"** by John Ousterhout — On managing complexity in large software systems. AETHER is a large software system with many interacting subsystems.

**Linus Torvalds on kernel development** — The Linux kernel mailing list (lkml.org) archives are a real-time record of how a large open-source systems project manages decisions, reverts, and long-term planning.

## Critical Concepts

**Phase Gate Discipline.** Each phase of the roadmap has an exit criterion — a specific, measurable, binary result that must be achieved before the next phase begins. Phase 1 exits when two isolated Linux guests boot simultaneously and cannot access each other's memory. Phase 2 exits when Windows-on-ARM boots to desktop in its partition. Phase 3 exits when Android boots to home screen in its partition. Phase 4 exits when Free Fire runs in Android at 60fps for 30 minutes without crash or detection. Phase 5 exits when the installer works on a clean target machine without developer intervention. None of these gates should be negotiated down — they represent the minimum viable product for each phase. Passing a gate with known workarounds is not passing the gate.

**The Research Phase Is Not Optional.** Before writing the first line of hypervisor code, there is a required research phase of 2–4 months. During this phase: read all primary sources listed in these SKILL.md files, build familiarity with QEMU ARM64 system emulation, write throw-away experimental code to verify understanding, and establish the development environment. Skipping this phase produces code that must be rewritten — which takes longer than the research phase would have.

**Parallelism And Its Limits.** Some AETHER subsystems can be developed in parallel: the Android userspace build (Chapters 19–23) does not depend on the hypervisor (Chapters 7–10) being complete. The Windows ACPI tables (Chapter 18) can be designed in parallel with the memory architecture implementation (Chapter 8). But the hypervisor's core (Chapters 5–10) must be completed before any guest can run, and therefore before any guest-specific work can be tested. The critical path is: ARM64 substrate → exception handling → memory isolation → boot → Windows boots → Android boots. Everything else hangs off this critical path.

**Version Control Strategy For A Multi-Repository Project.** AETHER spans at least three repositories: the hypervisor (Rust, GitHub), the Android device configuration (in the AOSP tree, managed by `repo`), and possibly a documentation repository. The hypervisor repository is the primary development repository and uses standard Git workflow: feature branches, pull requests, code review, linear history (rebase not merge). The AOSP fork uses Google's `repo` tool but should keep AETHER-specific changes in named overlay directories rather than in-place patches to AOSP files, to make rebasing onto new Android releases tractable.

**Open Source Release Strategy.** The roadmap's Phase 5 includes public release. The release strategy is: the hypervisor core (the security-critical code) is released under GPL v2 or MIT license. The AOSP changes are already covered by the Apache 2.0 license AOSP uses. The documentation (the README and these SKILL.md files) is released under Creative Commons. The installers and tooling are released under MIT. This allows commercial use while keeping the core open for security audit.

**Sustaining Development After Initial Release.** The project's long-term sustainability depends on community adoption generating either commercial revenue (enterprise licensing, OEM deals) or contributor volume sufficient to maintain the codebase. The Phase 5 release should include: a clear contributor guide, a documented architecture that matches the code, a test suite with documented coverage targets, and a public roadmap for Phase 6 features (multi-monitor support, audio passthrough, suspend/resume). Without this infrastructure, the project stalls after initial release.

## Common AI Mistakes In This Domain

Claude produces project timelines that assume full-time dedicated engineering from the start. AETHER is being built in parallel with a 4-year CS degree. Realistic planning accounts for exam periods, coursework deadlines, and the fact that deep systems work requires mental bandwidth that is not available after a full day of lectures. A realistic timeline might show 2–4 hours of effective AETHER work per weekday and 6–8 hours on weekends during term, more during holidays.

Claude produces phase plans that treat all subsystems as independent. They are not — the memory isolation implementation must be correct before any guest can safely run, and therefore before any integration testing of guest-specific features can begin.

Claude suggests skipping the QEMU-based development tier and developing directly on hardware. This extends the iteration cycle from minutes to hours and makes debugging exponentially harder.

## Verification Protocol

At the end of each phase:
1. Run the phase gate criterion test — it must pass cleanly, not with workarounds
2. Write a phase retrospective: what took longer than expected, what was easier, what would you do differently
3. Update the time estimates for remaining phases based on the retrospective
4. Update the relevant SKILL.md files with failure modes discovered during the phase

## Pre-Flight Checklist

- [ ] Read "The Mythical Man-Month" before committing to any timeline
- [ ] Write down your realistic weekly hour budget for AETHER work during term vs. vacation
- [ ] Define the exit criteria for Phase 1 in a single sentence that cannot be argued with — write it in the project README
- [ ] Set up a project journal (even just a dated text file) to record progress, blockers, and decisions from day one — it becomes invaluable after month 6 when you can no longer remember why certain decisions were made
- [ ] Identify at least one other person (a classmate, an online collaborator, a professor) who will review code — solo projects with no external review produce worse code and are harder to sustain
