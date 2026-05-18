<div align="center">

# ⬡ AETHER

**A Type-1 hypervisor that delivers production Android on any ARM64 or x86 PC — native, sovereign,Safe and undetectable.**

[![Rust nightly](https://img.shields.io/badge/rust-nightly-orange?logo=rust)](https://rust-lang.org)
[![Target](https://img.shields.io/badge/target-aarch64--unknown--uefi-blue)](https://doc.rust-lang.org/nightly/rustc/platform-support.html)
[![Tests](https://img.shields.io/badge/tests-1076%20passing-brightgreen)](#build)
[![Chapters](https://img.shields.io/badge/chapters-47%20%2F%2070-yellow)](#chapter-progress)
[![License](https://img.shields.io/badge/license-GPLv2-red)](LICENSE)

*Boots at EL2 before any OS. Gives Android exclusive hardware. Leaves no fingerprint.*

</div>

---

## What AETHER Is

AETHER is a bare-metal Rust hypervisor that boots from UEFI firmware, takes EL2 on ARM64 (or VMX root on x86), and delivers a complete production Android partition with direct hardware ownership — no host OS, no emulation seams, no detectable virtualization artifacts.

**Two tiers, one installer:**

| | ARM Tier | x86 Tier |
|---|---|---|
| **Hardware** | Snapdragon X Elite / X Plus | Intel VT-x · AMD-V |
| **Hypervisor level** | EL2 (nVHE) | VMX / SVM root |
| **Android execution** | Native ARM64 — zero translation | FEX-Emu DBT inside the hypervisor |
| **GPU** | Adreno SR-IOV VF passthrough | SR-IOV (Phase 4 target) |
| **Memory isolation** | Stage 2 IPA→PA + SMMU | EPT / NPT |
| **Frame time p99** | ≤ 17 ms | ≤ 33 ms |

**Phone Bridge Mode** — connect any Android phone via USB. Toggle real sensor data (gyro, accel, mag, baro, GPS, camera, IMEI, IMSI, carrier) vs. physics-accurate Gaussian software models. Works on both tiers.

---

## The Four Non-Negotiables

> **Resource Isolation** — Android never calls into any host system for resources.

> **Host Opaqueness** — nothing outside the Android partition has visibility into its memory, devices, or state.

> **Hypervisor Invisibility** — Android detects virtualization only via deliberate ARM64 instructions; every signal matches real hardware.

> **No Host** — AETHER is referee only. Android is the sole guest.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Android Applications (EL0)              │
├─────────────────────────────────────────────────────┤
│           Android Linux Kernel / ART (EL1)           │
│   NVMe ── GIC ── Timer ── Adreno VF ── xHCI ── WiFi  │
├─────────────────────────────────────────────────────┤  ← Stage 2 + SMMU boundary
│         AETHER Hypervisor  (EL2 / VMX root)          │
│  boot.rs  memory.rs  gic.rs  cpu.rs  exception.rs    │
│  passthrough.rs  gpu.rs  storage.rs  paravirt.rs     │
│  usb.rs  network.rs  acpi.rs  kernel.rs  aosp.rs     │
├─────────────────────────────────────────────────────┤
│            EL3 Firmware (ARM Trusted Firmware)        │
├─────────────────────────────────────────────────────┤
│       Snapdragon X Elite  /  Intel  /  AMD           │
└─────────────────────────────────────────────────────┘
```

---

## Chapter Progress

**33 / 70 chapters complete · 47% · v1.0 ships at Chapter 70**

<details>
<summary><strong>Part I — The Hypervisor Core  (Chapters 1–16) · ✅ Complete</strong></summary>

| # | Title | Status | One-Line Summary |
|---|-------|--------|-----------------|
| 1 | What AETHER Is | ✅ | Type-1 EL2 hypervisor; native ARM64 and x86 DBT; full Android at hardware speed |
| 2 | Why AETHER Exists | ✅ | Every Android-on-PC product leaks fingerprints; AETHER takes none of those shortcuts |
| 3 | The Non-Negotiables | ✅ | Four inviolable constraints encoded as Rust types; any violation is a compile error |
| 4 | ARM64 As The Substrate | ✅ | ARM ARM DDI0487 is the only spec; `read_sysreg!`/`write_sysreg!` macros; 4KB granule |
| 5 | Exception Levels | ✅ | EL0 apps · EL1 kernel · EL2 AETHER · EL3 firmware; `GuestContext` 272-byte save frame |
| 6 | The Virtualization Extensions | ✅ | nVHE; HCR_EL2 GUEST_FLAGS; VTCR_EL2=0x8005_3558; Stage 2 descriptor encoding |
| 7 | Boot | ✅ | UEFI ExitBootServices retry loop; ACPI RSDP capture; `GuestLaunch::eret_to_el1()` |
| 8 | Memory Architecture | ✅ | `BumpAllocator`; `Stage2Tables` (IPA→PA); SMMU STE write ordering; TLB flush |
| 9 | CPU Partitioning | ✅ | Static core assignment; PSCI CPU_ON security; MPIDR affinity; `CorePartition` |
| 10 | Interrupt Routing | ✅ | GICv3 init order; ICH_LR injection; `handle_physical_irq` forwarding path; LR bitmap |
| 11 | The Passthrough Principle | ✅ | IOMMU groups; BAR scan; FLR; SMMU STE; five-step `assign_device_group()` pipeline |
| 12 | The Necessity Of Paravirtualization | ✅ | BMI160 Gaussian noise; Luhn IMEI; AT commands; `VirtualSensorSuite`; bridge toggle |
| 13 | GPU Partitioning Through SR-IOV | ✅ | PCIe Extended Capability; `GpuPartitionRegistry`; VF assignment conflict detection |
| 14 | Storage Partitioning | ✅ | NVMe namespace management (opcode 0x0D/0x15); `NamespaceRegistry` exclusive attach |
| 15 | Network Partitioning | ✅ | SR-IOV VF · dedicated adapter · paravirt bridge; `MacRegistry` uniqueness enforcer |
| 16 | USB And Input Routing | ✅ | xHCI controller assignment; HID boot-protocol input switch; `reject_software_switch()` |

</details>

<details>
<summary><strong>Part II — The Android Stack Design  (Chapters 17–33) · ✅ Complete</strong></summary>

| # | Title | Status | One-Line Summary |
|---|-------|--------|-----------------|
| 17 | ARM Tier — Hardware And Partition Configuration | ✅ | Windows CPUID leaf; Hyper-V enlightenments; `SecureBootConfig`; inbox-only drivers |
| 18 | The Windows ACPI Description | ✅ | MADT ARM GIC entries; GTDT 96 bytes; FADT HW_REDUCED; RSDP dual checksum |
| 19 | The Bootloader | ✅ | AVB2 `VbmetaHeader`; rollback index; A/B slot BCB; `BootloaderState` phase machine |
| 20 | The Linux Kernel | ✅ | ARM64 Image header magic; `DtbBuilder` FDT big-endian; GICv3 3-cell interrupts |
| 21 | AOSP And The Android Userspace | ✅ | 21 HALs; 35 device properties; `ro.build.type=user`; `PartitionLayout` validation |
| 22 | The microG Substitution | ✅ | 13 GMS service coverage table; `PlayIntegrityMaxVerdict::BasicOnly`; F-Droid + Aurora |
| 23 | The Play Store Question | ✅ | `GenuinePlayStore` rejected as automatic path; manual disclaimer gate; Aurora anonymous |
| 24 | Performance | ✅ | `ExitCounter` per-core; `LargePagePolicy::PreferBlock`; gaming threshold <1000 exits/s |
| 25 | Security | ✅ | TCB layers; SMMU fault → terminate guest; Spectre v2 CLRBHB; `HvcInputValidator` |
| 26 | Time | ✅ | 19.2 MHz counter; `CNTHCTL_EL2` EL1PCTEN+EL1PCEN; `CNTPOFF_EL2=0`; passthrough |
| 27 | The Build System | ✅ | `aarch64-unknown-uefi`; `-Z build-std` CLI flag; LTO + opt-level=s; `BuildSummary` |
| 28 | The Development Workflow | ✅ | QEMU Tier 1 CI; GICv3 mandatory; `SnapshotConfig` for Tier 2 loop; bisection contract |
| 29 | Phase One — Foundation (ARM Tier) | ✅ | 11-milestone critical path; `ResearchPhaseStatus` gate; 24-month realistic estimate |
| 30 | Phase Two — Android Bring-Up | ✅ | 14-milestone path; `claims_device_integrity=false`; app category coverage |
| 31 | Phase Three — x86 Tier Foundation | ✅ | VT-x AND AMD-V both required; `FexEmuIntegrationMode::InHypervisor`; EPT/NPT |
| 32 | Phase Four — Performance And Compatibility | ✅ | `PerformanceTarget` arm≤x86; sensor fidelity milli-units; 95% app compat |
| 33 | Phase Five — Polish And Release | ✅ | License stack; `InstallerCapabilities`; 7 doc deliverables; `Phase5GateCriterion` |

</details>

<details>
<summary><strong>Part III — ARM Tier Implementation  (Chapters 34–49) · 🔲 Pending</strong></summary>

| # | Title | Status | Deliverable |
|---|-------|--------|-------------|
| 34 | Linux Kernel Boot in QEMU | 🔲 | ARM64 GKI boots to `/bin/sh` shell through AETHER in QEMU |
| 35 | Multi-Core SMP | 🔲 | Secondary CPUs via PSCI `cpu_on`; `nproc` shows all cores in guest |
| 36 | Physical IRQ Forwarding — Validated | 🔲 | `/proc/interrupts` ticks on timer and UART lines in live guest |
| 37 | NVMe Namespace — Functional | 🔲 | `nvme list` shows namespace; `dd` to `/dev/nvme0n1` succeeds |
| 38 | PCIe Device Assignment and SMMU Wiring | 🔲 | Any PCIe device passes five-step assignment; `lspci` in guest confirms |
| 39 | GPU SR-IOV — Functional Enable | 🔲 | Adreno VF visible; GPU driver loads; `vulkaninfo` shows GPU in Android |
| 40 | Network Passthrough — Functional | 🔲 | `ping 8.8.8.8` works from inside Android guest |
| 41 | USB Controller and Input Switch — Functional | 🔲 | USB keyboard in Android; Ctrl+Alt+Tab switches input without reboot |
| 42 | AOSP Device Configuration and Build | 🔲 | `lunch aether_arm64-user && m` produces bootable partition images |
| 43 | Android Bootloader — Functional AVB | 🔲 | Hypervisor reads `boot.img`, verifies AVB2 chain, ERETs to Android |
| 44 | Android Kernel and Device Tree | 🔲 | GKI + AETHER DTB boots Android `init` successfully |
| 45 | Android Userspace Boot | 🔲 | Home screen renders; SELinux enforcing; `ro.build.type=user` |
| 46 | Adreno GPU — Rendering | 🔲 | Vulkan 1.1 validated; `glmark2-es2` runs; YouTube plays 1080p |
| 47 | Virtual Sensors and Modem — Live | 🔲 | `dumpsys sensorservice` shows accel/gyro/mag; "No SIM" shown correctly |
| 48 | Phone Bridge Mode — End to End | 🔲 | Toggle ON/OFF; real sensor timestamps replace virtual with no gap |
| 49 | App Compatibility Validation | 🔲 | ≥950 / 1000 top apps pass (attestation-only failures excluded) |

</details>

<details>
<summary><strong>Part IV — x86 Tier  (Chapters 50–54) · 🔲 Pending</strong></summary>

| # | Title | Status | Deliverable |
|---|-------|--------|-------------|
| 50 | Intel VT-x Foundation | 🔲 | VMCS initialized; EPT active; first VM exit (HLT) handled on Intel |
| 51 | AMD-V Foundation | 🔲 | VMCB + NPT; first VM exit on AMD; runtime CPU detection |
| 52 | FEX-Emu Integration in Hypervisor | 🔲 | `no_std` FEX linked in EFI binary; ARM64 ELF runs on x86 hardware |
| 53 | Android on x86 — Userspace | 🔲 | Android home screen on Intel/AMD through FEX DBT layer |
| 54 | x86 Tier Hardware Validation | 🔲 | Both Intel AND AMD boot Android on real hardware; no workarounds |

</details>

<details>
<summary><strong>Part V — Installer & Management  (Chapters 55–64) · 🔲 Pending</strong></summary>

| # | Title | Status | Deliverable |
|---|-------|--------|-------------|
| 55 | Hardware Compatibility Checker | 🔲 | Standalone binary: structured JSON report; no admin required |
| 56 | AETHER Installer CLI | 🔲 | `aether-install install` — partition NVMe, flash EFI, write UEFI entry |
| 57 | Secure Boot Integration | 🔲 | `hypervisor.efi` boots with Secure Boot ON via shim + MOK enrollment |
| 58 | UEFI Boot Selector | 🔲 | 5-second timeout menu at startup; `[A]ndroid [W]indows [S]ettings` |
| 59 | Setup Wizard — GUI Frontend | 🔲 | Tauri 2 app; 7 screens; double-click-and-install; no terminal needed |
| 60 | Configuration App | 🔲 | Host Tauri app + Android AETHER Manager system app; USB rerouting |
| 61 | OTA Update System | 🔲 | A/B EFI slots; Android OTA via `update_engine`; auto-rollback on panic |
| 62 | Recovery Mode | 🔲 | `recovery.efi`; re-flash from USB; factory reset; never touches Windows |
| 63 | AETHER Manager Android App | 🔲 | Pre-installed system app; Phone Bridge toggle; diagnostics log export |
| 64 | HVC Paravirt ABI | 🔲 | SMCCC `0x8600_0001–0x8600_0006`; `/dev/aether` kernel module; SensorHAL |

</details>

<details>
<summary><strong>Part VI — Production Hardening & Release  (Chapters 65–70) · 🔲 Pending</strong></summary>

| # | Title | Status | Deliverable |
|---|-------|--------|-------------|
| 65 | Security Hardening and Unsafe Audit | 🔲 | Every `unsafe` block has SAFETY comment; HVC fuzzer runs 10M iterations clean |
| 66 | Performance Optimization | 🔲 | All Phase 4 perf targets met on real hardware (ARM ≤17ms, x86 ≤33ms p99) |
| 67 | Fingerprint Elimination Audit | 🔲 | Zero detections from DMA-Guard / GameGuard / Play Integrity test suite |
| 68 | CI/CD Pipeline and Release Engineering | 🔲 | Per-commit <60s; per-PR QEMU Tier 1; nightly AOSP; signed release artifacts |
| 69 | Documentation | 🔲 | User manual, architecture doc, contributor guide, troubleshooting, security policy |
| 70 | Public Release | 🔲 | `git tag v1.0.0`; installers on GitHub Releases; update server live |

</details>

---

## Build

```bash
# Check (fastest — no binary produced)
cd ~/AETHER && cargo +nightly check \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --target aarch64-unknown-uefi -p hypervisor

# Build release EFI binary
cd ~/AETHER && cargo +nightly build \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --release --target aarch64-unknown-uefi -p hypervisor

# Run unit tests (host target — hardware modules are gated)
cd ~/AETHER && cargo +nightly test --lib -p hypervisor

# Run QEMU Tier 1 gate (3 tests: EL2 boot, Stage 2 guest, fault isolation)
qemu-system-aarch64 \
  -machine virt,virtualization=on,gic-version=3 \
  -cpu cortex-a76 -m 2G -nographic \
  -drive if=pflash,format=raw,file=OVMF_CODE.fd \
  -kernel target/aarch64-unknown-uefi/release/hypervisor.efi
```

**Output:** `target/aarch64-unknown-uefi/release/hypervisor.efi`  
**Verify:** `file hypervisor.efi` → `PE32+ executable (EFI application) Aarch64`

---

## Source Layout

```
hypervisor/src/
├── lib.rs / main.rs          ← UEFI efi_main entry point
│
│  — Part I: The Hypervisor Core —
├── arm64/
│   ├── regs.rs               ← MRS/MSR macros; HCR_EL2 / VTCR_EL2 / VBAR_EL2
│   ├── barriers.rs           ← DSB/ISB/DMB with correct domain operands
│   ├── paging.rs             ← 4KB granule; IPA sizing; page table shifts
│   ├── context.rs            ← GuestContext — 272-byte CPU state save frame
│   ├── exception.rs          ← ExceptionClass; aether_handle_* C handlers
│   ├── vectors.rs            ← EL2 vector table; install_vectors()
│   └── virt.rs               ← configure_el2_virt(); HCR/VTCR/VTTBR/Stage2/GIC
├── boot.rs                   ← ExitBootServices retry; ACPI discovery; GuestLaunch
├── memory.rs                 ← BumpAllocator; Stage2Tables; SmmuSte; TLB flush
├── cpu.rs                    ← CorePartition; handle_psci_call(); MPIDR routing
├── gic.rs                    ← GICv3 init; VGicState ICH_LR; handle_physical_irq
├── passthrough.rs            ← PcieEcam; IommuGroup; assign_device_group()
├── paravirt.rs               ← VirtualSensorSuite; VirtualModem; BridgeMode
├── gpu.rs                    ← SrIovCapability; GpuPartitionRegistry
├── storage.rs                ← NsId; StoragePartitionState; NvmeSrIovState
├── network.rs                ← NetworkMode; MacRegistry; NetworkPartitionState
├── usb.rs                    ← UsbController; InputSwitchState; reject_software_switch
│
│  — Part II: The Android Stack Design —
├── windows.rs                ← CPUID hypervisor leaf; EnlightenmentSet; SecureBootConfig
├── acpi.rs                   ← MADT / GTDT / FADT / IORT / XSDT / RSDP builders
├── bootloader.rs             ← AVB2; BootloaderState phase machine; A/B slots
├── kernel.rs                 ← Arm64ImageHeader; DtbBuilder; GkiConfig; KernelState
├── aosp.rs                   ← TrebleManifest; DeviceProperties; PartitionLayout
├── microg.rs                 ← GmsServiceEntry; MicrogConfig; PlayIntegrityMaxVerdict
├── play_store.rs             ← PlayStoreConfig; ManualInstallPath; disclaimer gate
├── performance.rs            ← ExitCounter; LargePagePolicy; PerformanceSummary
├── security.rs               ← SmmuFaultPolicy; SpectreV2Mitigation; UnsafeAuditRecord
├── time.rs                   ← CounterFrequency; CnthctlConfig; TimerConfiguration
├── build_system.rs           ← HypervisorBuildConfig; BuildSummary; EfiOutputFormat
├── development_workflow.rs   ← QemuMachineConfig; CiPipeline; SnapshotConfig
├── roadmap_phase1.rs … roadmap_phase5.rs
│
│  — Parts III–VI (Pending Ch 34–70) —
├── x86/ (Ch 50–54)           ← vmx.rs · svm.rs · ept.rs · npt.rs · fex.rs
├── aosp/ (Ch 42–49)          ← device/aether/aether_arm64/ · packages/apps/AetherManager/
├── installer/ (Ch 59)        ← Tauri 2 setup wizard
├── selector/ (Ch 58)         ← UEFI boot selector EFI app
├── tools/ (Ch 55–56·61·62)   ← compat-check · aether-install · aether-update · recovery.efi
└── config-app/ (Ch 60)       ← Host Tauri configuration app
```

## Critical Path

```
Ch 34 (Linux in QEMU)
  → Ch 35 (SMP) → Ch 36 (IRQ validated)
  → Ch 37 (NVMe MMIO) → Ch 38 (PCIe/SMMU backbone)
      → Ch 39 (GPU SR-IOV) → Ch 40 (Network) → Ch 41 (USB + input switch)
  → Ch 42 (AOSP build) → Ch 43 (bootloader) → Ch 44 (kernel+DTB)
      → Ch 45 (Android boots) → Ch 46 (GPU rendering)
      → Ch 47 (sensors/modem) → Ch 48 (Phone Bridge)
      → Ch 49 (app compat)
  ∥ Ch 50 (Intel VT-x) → Ch 51 (AMD-V) → Ch 52 (FEX-Emu)
      → Ch 53 (Android on x86) → Ch 54 (x86 hardware validation)
  → Ch 55–58 (compat check · installer CLI · Secure Boot · UEFI selector)
  → Ch 59 (setup wizard) → Ch 60 (config app) → Ch 61 (OTA) → Ch 62 (recovery)
  ∥ Ch 63 (AETHER Manager app) ← depends on Ch 64 (HVC ABI)
  → Ch 65 (security) → Ch 66 (perf) → Ch 67 (fingerprint)
  → Ch 68 (CI/CD) → Ch 69 (docs) → Ch 70 (v1.0 release)
```

---

## Current QEMU Status

Three Tier 1 gate tests pass on every commit:

| Test | Expected Output | Status |
|------|-----------------|--------|
| EL2 boot | `Hypervisor ready.` on PL011 serial | ✅ |
| Stage 2 guest | `Guest EL1 OK` after ERET | ✅ |
| Stage 2 fault isolation | Unmapped IPA fault caught at EL2 | ✅ |

---

## Design Principles Encoded In Types

| Type | Invariant Enforced |
|------|--------------------|
| `Exclusive<T, G>` | No `Clone`/`Copy` — compile-time ownership per guest |
| `HypervisorRole::Referee` | Only variant — no `Host` |
| `Strategy::Passthrough \| PhysicsAccurateSimulation` | No proxy-through-host variant |
| `SmmuFaultPolicy::TerminateGuest` | DMA fault kills the guest, never ignored |
| `reject_software_switch()` | Always returns `Forbidden` — hardware trigger only |
| `BuildType::User` | Only production-safe build type in `DeviceProperties::validate()` |
| `PlayIntegrityMaxVerdict::BasicOnly` | DeviceIntegrity unattainable — compile-time honesty |

---

## Timeline

| Phase | Chapters | Realistic Estimate | Milestone |
|-------|----------|--------------------|-----------|
| Phase 1 — Foundation | 1–10 | 24 months | ✅ EL2 boots on QEMU; Stage 2 active |
| Phase 2 — Android Bring-Up | 34–49 | 12–24 months | Android home screen on Snapdragon X |
| Phase 3 — x86 Tier | 50–54 | 24–36 months | Android boots on Intel AND AMD |
| Phase 4 — Perf & Compat | 66 | 24–36 months | ≥95% app compat; frame time targets met |
| Phase 5 — Polish & Release | 55–70 | 12–24 months | v1.0 public; installer; docs; CI |

*Realistic multiplier = 2×, pessimistic = 3× against optimistic estimates (see `roadmap_phase1.rs`).*

---

## License

| Component | License |
|-----------|---------|
| Hypervisor (`hypervisor/`) | GPLv2 |
| AOSP overlays (`aosp/`) | Apache 2.0 |
| Installer (`tools/`, `installer/`) | MIT |
| Documentation (`docs/`, `README.md`) | CC-BY-SA |

---

<div align="center">

*The journey is long. The destination is clear.*  
*Work begins at the silicon and proceeds upward, layer by layer, exactly as this document describes.*

</div>
