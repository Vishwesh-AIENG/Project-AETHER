# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project Context

**AETHER** is a Type-1 hypervisor written in Rust that delivers a complete, production Android environment on any ARM64 or x86 PC hardware — with no host OS, no detectable fingerprint, and full app compatibility.

**Two hardware tiers, auto-detected at install time:**
- **ARM Tier** — Snapdragon X Elite / X Plus. Rust hypervisor at EL2. Android runs natively at full hardware speed. Zero translation layers.
- **x86 Tier** — Intel / AMD with VT-x or AMD-V. Rust hypervisor at VMX/SVM root. FEX-Emu DBT engine (ARM64→x86) integrated inside the hypervisor. No host OS.

**Both tiers support Phone Bridge Mode:** connect Android phone via USB → toggle real sensor/identity data (gyro, accel, magnetometer, barometer, GPS, camera, IMEI, IMSI, carrier) vs. physics-accurate software models.

**Key Design Principle:** No shortcuts between AETHER's Android partition and the host machine. Every design decision is evaluated against the No-Boundary Principle — any dependency on host OS resources violates the architecture and is rejected.

**Always read TXT.rtf before any implementation work.** It is the authoritative specification. Located at `README/TXT.rtf`. The `README.md` in the repo root is the user-facing rendered version.

---

## Chapter Progress

| Chapter | Title | Status |
|---|---|---|
| 1 | What AETHER Is | ✅ Complete |
| 2 | Why AETHER Exists | ✅ Complete |
| 3 | The Non-Negotiables | ✅ Complete |
| 4 | ARM64 As The Substrate | ✅ Complete |
| 5 | Exception Levels | ✅ Complete |
| 6 | The Virtualization Extensions | ✅ Complete |
| 7 | Boot | ✅ Complete |
| 8 | Memory Architecture | ✅ Complete |
| 9 | CPU Partitioning | ✅ Complete |
| 10 | Interrupt Routing | ✅ Complete |
| 11 | The Passthrough Principle | ✅ Complete |
| 12 | The Necessity Of Paravirtualization | ✅ Complete |
| 13 | GPU Partitioning Through SR-IOV | ✅ Complete |
| 14 | Storage Partitioning | ✅ Complete |
| 15 | Network Partitioning | ✅ Complete |
| 16 | USB And Input Routing | ✅ Complete |
| 17 | ARM Tier — Hardware And Partition Configuration | ✅ Complete |
| 18 | x86 Tier — DBT And VMCS Configuration | ✅ Complete |
| 19 | The Bootloader | ✅ Complete |
| 20 | The Linux Kernel | ✅ Complete |
| 21 | AOSP And The Android Userspace | ✅ Complete |
| 22 | The microG Substitution | ✅ Complete |
| 23 | The Play Store Question | ✅ Complete |
| 24 | Performance | ✅ Complete |
| 25 | Security | ✅ Complete |
| 26 | Time | ✅ Complete |
| 27 | The Build System | ✅ Complete |
| 28 | The Development Workflow | ✅ Complete |
| 29 | Phase One — Foundation | ✅ Complete |
| 30 | Phase Two — Windows | ✅ Complete |
| 31 | Phase Three — Android Bring-Up | ✅ Complete |
| 32 | Phase Four — Performance And Compatibility | ✅ Complete |
| 33 | Phase Five — Polish And Release | ✅ Complete |
| 34 | Linux Kernel Boot in QEMU | ✅ Complete |
| 35 | Multi-Core SMP | ⬜ Not started |
| 36 | Physical IRQ Forwarding — Validated | ⬜ Not started |
| 37 | NVMe Namespace — Functional | ⬜ Not started |
| 38 | PCIe Device Assignment and SMMU Wiring | ⬜ Not started |
| 39 | GPU SR-IOV — Functional Enable | ⬜ Not started |
| 40 | Network Passthrough — Functional | ⬜ Not started |
| 41 | USB Controller and Input Switch — Functional | ⬜ Not started |
| 42 | AOSP Device Configuration and Build | ⬜ Not started |
| 43 | Android Bootloader — Functional AVB | ⬜ Not started |
| 44 | Android Kernel and Device Tree | ⬜ Not started |
| 45 | Android Userspace Boot | ⬜ Not started |
| 46 | Adreno GPU — Rendering | ⬜ Not started |
| 47 | Virtual Sensors and Modem — Live | ⬜ Not started |
| 48 | Phone Bridge Mode — End to End | ⬜ Not started |
| 49 | App Compatibility Validation | ⬜ Not started |
| 50 | Intel VT-x Foundation | ⬜ Not started |
| 51 | AMD-V Foundation | ⬜ Not started |
| 52 | FEX-Emu Integration in Hypervisor | ⬜ Not started |
| 53 | Android on x86 — Userspace | ⬜ Not started |
| 54 | x86 Tier Hardware Validation | ⬜ Not started |
| 55 | Hardware Compatibility Checker | ⬜ Not started |
| 56 | AETHER Installer CLI | ⬜ Not started |
| 57 | Secure Boot Integration | ⬜ Not started |
| 58 | UEFI Boot Selector | ⬜ Not started |
| 59 | Setup Wizard — GUI Frontend | ⬜ Not started |
| 60 | Configuration App | ⬜ Not started |
| 61 | OTA Update System | ⬜ Not started |
| 62 | Recovery Mode | ⬜ Not started |
| 63 | AETHER Manager Android App | ⬜ Not started |
| 64 | HVC Paravirt ABI | ⬜ Not started |
| 65 | Security Hardening and Unsafe Audit | ⬜ Not started |
| 66 | Performance Optimization | ⬜ Not started |
| 67 | Fingerprint Elimination Audit | ⬜ Not started |
| 68 | CI/CD Pipeline and Release Engineering | ⬜ Not started |
| 69 | Documentation | ⬜ Not started |
| 70 | Public Release | ⬜ Not started |

**Progress: 34 / 70 chapters complete (49%)**

---

## Build Commands

```bash
# Build hypervisor EFI binary (release)
cd ~/AETHER && cargo +nightly build -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem --release --target aarch64-unknown-uefi -p hypervisor

# Build hypervisor (debug)
cd ~/AETHER && cargo +nightly build -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem --target aarch64-unknown-uefi -p hypervisor

# Check code without producing binary (faster iteration)
cd ~/AETHER && cargo +nightly check -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem --target aarch64-unknown-uefi -p hypervisor

# Run unit tests (native host, lib only)
cd ~/AETHER && cargo +nightly test --lib -p hypervisor

# Clean build artifacts
cd ~/AETHER && cargo +nightly clean
```

**Output:** `target/aarch64-unknown-uefi/release/hypervisor.efi`
**Verify:** `file hypervisor.efi` → "PE32+ executable (EFI application) Aarch64"

**QEMU boot scripts:**
- `qemu/run.sh` — smoke test (boots hypervisor to "Hypervisor ready." banner)
- `qemu/run-ch34.sh` — ch34 gate test (loads ARM64 GKI Image + initrd, boots to `/bin/sh`)

**Why `-Z build-std` is on the CLI (not in `.cargo/config.toml`):**
A global `[unstable] build-std` in config.toml causes a duplicate-lang-item error when `cargo test` runs because it rebuilds `core` for the native host target which already has it in its sysroot. Moving build-std to an explicit CLI flag lets `cargo test --lib` compile cleanly on the host while keeping the UEFI build correct.

---

## Source Layout

```
hypervisor/src/
├── lib.rs              ← module declarations (mirrors chapter structure)
├── main.rs             ← UEFI efi_main entry point (#![no_main])
│
│   — Part I: The Vision (Ch. 1–3) —
├── fingerprint.rs      ← ch02: FingerprintSource + Strategy enum table
├── partition.rs        ← ch03: GuestId, Exclusive<T,G>, HypervisorRole,
│                              PartitionConfig, compile-time assertions
│
│   — Part II: The Silicon (Ch. 4–6) —
├── arm64/
│   ├── mod.rs          ← ch04/05: module root, ARM64 primitives
│   ├── regs.rs         ← ch04: MRS/MSR macros; SCTLR/HCR/VBAR/ESR/ELR/SPSR
│   ├── barriers.rs     ← ch04: DSB/ISB/DMB with correct domain operands
│   ├── paging.rs       ← ch04: 4KB granule, page table shifts, IPA sizing
│   ├── context.rs      ← ch05: GuestContext — 272-byte CPU state save frame
│   ├── exception.rs    ← ch05: ExceptionClass/ExitReason; aether_handle_* C handlers
│   ├── vectors.rs      ← ch05: EL2 vector table (global_asm!); install_vectors()
│   └── virt.rs         ← ch06: configure_el2_virt(); VTCR_EL2/VTTBR_EL2/HCR_EL2/CPTR_EL2
│
│   — Part III: The Hypervisor (Ch. 7–11) —
├── boot.rs             ← ch07: BootContext, ExitBootServices retry loop,
│                              MemoryMap, ACPI discovery, GuestLaunch::eret_to_el1()
├── memory.rs           ← ch08: BumpAllocator, Stage2Tables (IPA→PA page tables),
│                              SmmuSte, SmmuStreamTable, tlb_flush_s1s2_vmid()
├── cpu.rs              ← ch09: Mpidr, CorePartition, CoreState, handle_psci_call(),
│                              build_irouter_specific(), init_gic_routing()
├── gic.rs              ← ch10: GicAddrs, discover_gic_from_madt(), init_physical_gic(),
│                              VGicState (ICH_LRn management), handle_physical_irq(),
│                              handle_maintenance_irq()
│
│   — Part IV: Devices (Ch. 11–16) —
├── passthrough.rs      ← ch11: PcieEcam, IommuGroup, PassthroughRegistry;
│                              assign_device_group() — IOMMU check → FLR → BAR map
│                              → SMMU STE → registry
├── paravirt.rs         ← ch12: Xorshift64 PRNG, validate_imei() (Luhn),
│                              VirtualSensorSuite (BMI160/BMM150 Gaussian noise,
│                              gyro bias drift), BridgeMode, VirtualModem (AT cmds)
├── gpu.rs              ← ch13: SrIovCapability, GpuVirtualFunction,
│                              GpuPartitionRegistry, GpuPartitionState
├── storage.rs          ← ch14: NsId (1-based), LbaShift, NvmeControllerCaps,
│                              NvmeVirtualFunction, NamespaceRegistry,
│                              NvmeSrIovState, StoragePartitionState
├── network.rs          ← ch15: NetworkMode (SrIov|DedicatedAdapter|ParavirtBridge),
│                              MacAddr, MacRegistry, NicVirtualFunction,
│                              NetworkPartitionRegistry, NetworkPartitionState
├── usb.rs              ← ch16: UsbControllerKind, InputSwitchTrigger (HID boot-protocol,
│                              hardware-only Ctrl+Alt+Tab), XhciResetState,
│                              UsbPartitionRegistry, UsbPartitionState
│
│   — Part V: The Windows Partition (Ch. 17–18) —
├── windows.rs          ← ch17: HypervisorVendorString, CpuidHypervisorLeaf,
│                              EnlightenmentSet, SecureBootConfig, CrashDumpConfig,
│                              inbox_devices, WindowsPartitionConfig/State
├── acpi.rs             ← ch18: ACPI table builders — RSDP, XSDT, MADT (ARM GICv3
│                              entries types 0x0B/0x0C/0x0E/0x0F), GTDT, IORT, FADT
│
│   — Part VI: The Android Partition (Ch. 19–34) —
├── bootloader.rs       ← ch19: BootImageHeader (v3/v4), VbmetaHeader (AVB2),
│                              BootControlBlock (BCB A/B slot), RollbackIndexStore,
│                              BootloaderState phase machine, KernelLaunchParams
├── kernel.rs           ← ch20: Arm64ImageHeader (64-byte, 0x644D5241 magic),
│                              DtbBuilder (FDT binary, big-endian tokens, string
│                              interning), AndroidDtbConfig + build_android_dtb()
│                              (root/memory/cpus/psci/intc/timer/serial/chosen nodes),
│                              GkiConfig + GKI_REQUIRED_OPTIONS (32 options),
│                              KernelState phase machine (Init→ReadyToLaunch)
├── aosp.rs             ← ch21: PartitionLayout, TrebleManifest (21 HALs),
│                              DeviceProperties, ArtConfig, AospDeviceConfig
├── microg.rs           ← ch22: GmsServiceEntry + MICROG_SERVICE_COVERAGE,
│                              MicrogConfig, PlayIntegrityMaxVerdict (BasicOnly)
├── play_store.rs       ← ch23: PlayCatalogAccess, StorePolicy, PlayStoreConfig
├── performance.rs      ← ch24: SubsystemOverhead, PerformanceProfile
├── security.rs         ← ch25: TcbLayer, SecurityProperty, SecurityConfig
├── time.rs             ← ch26: CounterFrequency, VirtualClock, TimeConfig
├── build_system.rs     ← ch27: ArtifactKind, BuildTarget, BuildConfig
├── development_workflow.rs ← ch28: TestTier, WorkflowStep, DevelopmentConfig
├── roadmap_phase1.rs   ← ch29: Phase One — Foundation. ResearchPhaseStatus,
│                              Phase1Milestone, Phase1GateCriterion, Phase1Config
├── roadmap_phase2.rs   ← ch30: Phase Two — Windows. Phase2Milestone,
│                              Phase2GateCriterion, Phase2Config
├── roadmap_phase3.rs   ← ch31: Phase Three — Android Bring-Up.
│                              X86VirtualizationFlavor, Phase3Tracker, Phase3Config
├── roadmap_phase4.rs   ← ch32: Phase Four — Performance And Compatibility.
│                              PerformanceTarget, SensorFidelityCheck, Phase4Config
├── roadmap_phase5.rs   ← ch33: Phase Five — Polish And Release. LicenseChoice,
│                              InstallerCapabilities, Phase5Milestone, Phase5Config
├── linux_boot.rs       ← ch34: Linux Kernel Boot in QEMU. prepare_linux_boot() —
│                              build_android_dtb() → FDT emit into 8KiB static staging
│                              buffer → memcpy to guest DRAM at DTB1_PA → D-cache clean
│                              → Arm64ImageHeader::parse() → KernelState phase machine
│                              → KernelLoadConfig for ERET. LinuxBootError enum.
│                              Gate: ARM64 GKI boots to /bin/sh on QEMU serial.
│
│   — Support —
├── uart.rs             ← PL011 UART driver — polled TX for boot diagnostics
└── guest_stub.rs       ← Test 2: minimal bare-metal ARM64 stub guest

qemu/
├── run.sh              ← smoke test (boots to "Hypervisor ready." banner)
└── run-ch34.sh         ← ch34 gate test — loads GKI Image at KERNEL1_PA,
                           boots to /bin/sh on QEMU serial console
```

---

## Architecture Overview

**ARM Tier — Exception Level Hierarchy:**
- EL0 — Android application code
- EL1 — Android Linux kernel
- **EL2 — AETHER hypervisor** (Rust code runs here)
- EL3 — platform firmware (ARM Trusted Firmware; AETHER does not replace it)

**x86 Tier — VMX Hierarchy:**
- VMX non-root ring 0 — Android Linux kernel (with DBT translating ARM64 → x86)
- **VMX root ring 0 — AETHER hypervisor** (Rust code runs here)

**Memory Isolation — three layers (ARM Tier):**
1. Guest page tables: VA → IPA (managed by Android kernel)
2. **Stage 2 tables: IPA → PA** (owned by AETHER, inaccessible to Android)
3. SMMU: same Stage 2 translation applied to device DMA

**QEMU Physical Memory Map (virt machine):**
| Address | Size | Purpose |
|---------|------|---------|
| 0x0000_0000 | 64 MiB | Flash (OVMF) |
| 0x0800_0000 | 64 KiB | GICv3 GICD |
| 0x080A_0000 | 128 KiB × n | GICv3 GICR |
| 0x0900_0000 | 4 KiB | PL011 UART |
| 0x4000_0000 | up to 255 GiB | DRAM |
| **0x4080_0000** | — | **KERNEL1_PA** — GKI Image pre-loaded here |
| **0x4400_0000** | — | **DTB1_PA** — AETHER writes FDT blob here |

---

## Critical Design Constants

```rust
VTCR_EL2     = 0x8005_3558  // 40-bit IPA, 4KB granule, 48-bit PA, L1 start
KERNEL1_PA   = 0x4080_0000  // ARM64 GKI Image load address (2MiB-aligned)
DTB1_PA      = 0x4400_0000  // DTB blob destination in guest DRAM
ANDROID_RAM  = 2 GiB        // IPA range given to Android partition
UART_PA      = 0x0900_0000  // PL011 UART (QEMU virt)
GICD_PA      = 0x0800_0000  // GICv3 Distributor (QEMU virt)
GICR_PA      = 0x080A_0000  // GICv3 Redistributor (QEMU virt)
```

---

## Stage 2 Attribute Encoding (CRITICAL — different from Stage 1)

**Never use Stage 1 `AP` or `AttrIndx` bits for Stage 2 page table entries.**

| Attribute | Bits | Value | Notes |
|-----------|------|-------|-------|
| S2AP_R (read) | [6] | 0x40 | |
| S2AP_W (write) | [7] | 0x80 | |
| MemAttr Normal | [5:2] | 0x3C | `0xF << 2` — Inner WB/WA |
| MemAttr Device nGnRE | [5:2] | 0x04 | `0x1 << 2` |
| SH Inner Shareable | [9:8] | 0x300 | `0b11 << 8` |
| AF (access flag) | [10] | 0x400 | **Must always be set** — guest faults without it |

---

## Boot Patterns (Chapter 7)

### ExitBootServices — mandatory retry loop

```
loop {
    GetMemoryMap(buf, &map_key, …)
    if ExitBootServices(handle, map_key) == SUCCESS → done
    if EFI_INVALID_PARAMETER → loop back
    else → halt()
}
```

Capture ACPI RSDP **before** ExitBootServices. Memory descriptor stride = `desc_size` from GetMemoryMap, never `sizeof(EfiMemoryDescriptor)`.

### Guest Launch via ERET

```rust
GuestLaunch {
    entry_pa: kernel_entry_ipa,   // ELR_EL2
    dtb_pa:   dtb_ipa,            // x0 at kernel entry (ARM64 boot protocol)
}.eret_to_el1();
```

Preconditions: HCR_EL2.VM=1, Stage 2 maps entry_pa and dtb_pa, VBAR_EL2 set.

---

## Linux Kernel Boot (Chapter 34)

### prepare_linux_boot() — Boot Wiring Sequence

```rust
// SAFETY: GKI Image pre-loaded at kernel_load_ipa by QEMU loader device;
//         dtb_target_ipa mapped NormalRw in Stage 2 with ≥ 8 KiB available.
let load_cfg = unsafe {
    prepare_linux_boot(KERNEL1_PA, DTB1_PA, &dtb_cfg)
}?;
GuestLaunch { entry_pa: load_cfg.kernel_load_ipa, dtb_pa: DTB1_PA }.eret_to_el1();
```

**Steps inside `prepare_linux_boot()`:**
1. Validate `kernel_load_ipa` is 2 MiB-aligned
2. `build_android_dtb(&dtb_cfg, &mut DTB_STAGING)` — emit FDT into static 8 KiB buffer
3. `memcpy(DTB_STAGING → dtb_target_ipa)` + `dc civac` / `dsb ish` D-cache clean to PoC
4. `Arm64ImageHeader::parse()` — verify Image magic `0x644D5241` and header fields
5. Pre-check all 32 GKI mandatory config options satisfied
6. `KernelState` phase machine: Init → ImageValidated → DtbPlaced → ConfigVerified → ReadyToLaunch
7. Return `KernelLoadConfig`

**ARM64 boot protocol registers at kernel entry:**
- `x0` = FDT blob IPA (`dtb_target_ipa`)
- `x1 = x2 = x3 = 0` (Linux checks for zero; must not be set)
- `ELR_EL2` = kernel entry IPA (`kernel_load_ipa` for text_offset=0 GKI kernels)

### QEMU ch34 Gate Test

```bash
KERNEL_IMAGE=./qemu/Image INITRD_IMAGE=./qemu/initrd.img ./qemu/run-ch34.sh
# Expected: ARM64 GKI boots to /bin/sh shell prompt on serial console
```

The QEMU `-device loader` places the kernel at KERNEL1_PA before OVMF starts:
```
-device loader,file=Image,addr=0x40800000,force-raw=on
```

---

## GICv3 Critical Rules

### Physical Init Order (Mandatory — IHI0069 §12.1)

1. `wake_gicr(rd_base)` per core — clear `GICR_WAKER.ProcessorSleep`, poll `ChildrenAsleep=0`
2. `init_icc()` — enable `ICC_SRE_EL2`, set `ICC_PMR_EL1=0xFF`, `ICC_IGRPEN1_EL1=1`
3. `init_gicd(gicd_base)` — set `ARE_NS=1`, `EnableGrp1A=1`

Writing GICD_CTLR before waking Redistributors = undefined behavior on real silicon.

### GICD_IROUTER Formula

`0x6000 + intid × 8` where intid ≥ 32 is the **absolute** INTID. Not `(intid − 32) × 8`.

### ICH_LR Bit Layout (bits [63:62] = State — most common AI mistake)

| Bits | Field | Values |
|------|-------|--------|
| [63:62] | State | 00=Invalid, 01=Pending, 10=Active, 11=Active+Pending |
| [61] | HW | 1 = hardware-backed (auto-deactivate on guest EOI) |
| [55:48] | Priority | 8-bit, lower = higher priority |
| [41:32] | pINTID | Physical INTID (valid only when HW=1) |
| [31:0] | vINTID | Virtual INTID seen by guest |

---

## Linux Kernel Patterns (Chapter 20)

### ARM64 Image Header (64 bytes at offset 0)

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| PE/COFF magic | 0 | 2 | "MZ" |
| text_offset | 8 | 8 | LE u64; 0 for modern GKI kernels |
| image_size | 16 | 8 | LE u64 |
| flags | 24 | 8 | bit 0 = BE; bits [2:1] = page size |
| ARM64 magic | 56 | 4 | 0x644D5241 LE — validates ARM64 kernel |

Always call `Arm64ImageHeader::parse()` — never assume text_offset=0 without reading it.

### FDT Binary Format — All Integers Big-Endian

DTB layout:
```
[0..40]  FDT header (magic 0xD00DFEED, version 17)
[40..56] Memory reservation block (16-byte terminator)
[56..]   Structure block (4-byte aligned big-endian u32 tokens)
[end]    Strings block (null-terminated, deduplicated)
```

### GICv3 Interrupt Specifiers — 3-Cell Format (NOT 2-cell)

`<type intid flags>`:
- Cell 0: type — 0=SPI, 1=PPI
- Cell 1: intid — 0-based in type range (SPI: INTID−32; PPI: INTID−16)
- Cell 2: flags — 4=level-high

### KernelState Phase Machine

```
Init → validate_image(load_ipa, bytes) → ImageValidated
     → place_dtb(dtb_ipa, dtb_size)   → DtbPlaced
     → verify_config(&gki)            → ConfigVerified
     → ready()                        → ReadyToLaunch → KernelLoadConfig
```

---

## SMMU v3 STE Write Order (Mandatory)

Write words 1–7 first → `DSB ISH` → write word 0 (Valid + Config bits last).
Word 0 first = partially-written STE seen as valid by SMMU = DMA isolation broken.

---

## No-Boundary Principle (Inviolable — Chapter 3)

All four must hold simultaneously. Any violation is a rejected design:

1. **Resource Isolation** — Android never calls into any host system for resources
2. **Host Opaqueness** — nothing outside the Android partition has visibility into its memory, devices, or state
3. **Hypervisor Invisibility** — Android detects virtualization only via deliberate ARM64/x86 virtualization instructions; signals must match real hardware
4. **No Host** — hypervisor is referee only; Android is the sole guest

Encoded in types: `HypervisorRole::Referee` is the only variant; `Exclusive<T,G>` prevents sharing; `Strategy` has no proxy-through-host variant.

---

## Hardware Authenticity (Cross-Cutting)

Production Android requirements that apply to every chapter involving Android configuration:

- `ro.build.type = user` always — never `userdebug`
- Sensor noise: **Gaussian** distribution (Irwin-Hall CLT, n=12) — never uniform random
- IMEI: must pass **Luhn checksum** (ISO/IEC 7812-1) — never all-zeros
- RAM: round numbers only (4 GB, 6 GB, 8 GB, 12 GB)
- SELinux: always **enforcing** in production; ADB disabled (`ro.adb.secure=1`)
- MIDR_EL1: **never trap or modify** — Android must read the real CPU identity

---

## Rust Toolchain

**Nightly required** for `-Z build-std=core,compiler_builtins`.

```toml
# hypervisor/rust-toolchain.toml
[toolchain]
channel = "nightly"
targets = ["aarch64-unknown-uefi"]
components = ["rust-src"]
```

**Linker:** `rust-lld` with `lld-link` flavor (`.cargo/config.toml`). Required on macOS — Apple's linker cannot produce PE32+ binaries.

**Profiles (workspace Cargo.toml):** `panic = "abort"` in both dev and release; `opt-level = "s"` + `lto = true` in release.

---

## Skills Workflow

`aether-skills/` (gitignored) contains a knowledge guide for every chapter. Before implementing any chapter:

1. Read the chapter in `README/TXT.rtf` — authoritative specification
2. Open `aether-skills/p1-hypervisor-core/p1-SKILLS.md` for Part I chapters
3. Read the listed primary sources (ARM ARM, GIC spec, SMMU spec, Linux KVM source)
4. Review the Common AI Mistakes and Verification Protocol sections

**Next chapters to implement:** 35 (Multi-Core SMP), 36 (Physical IRQ Forwarding), 37 (NVMe Namespace).

---

## Reference Material (Local, Gitignored)

- `linux-ref/arch/arm64/kvm/` — KVM reference (mmu.c, vgic-v3.c, psci.c)
- `linux-ref/arch/arm64/include/asm/` — sysreg.h, esr.h, kvm_arm.h
- `linux-ref/drivers/irqchip/irq-gic-v3.c` — GICD_IROUTER formula reference
- `aether-skills/` — chapter skill guides with primary sources and pitfall lists

---

## Patterns & Constraints

**All hypervisor code:**
- `#![no_std]` — no standard library
- `#![no_main]` in binary — no automatic main
- `#![deny(unsafe_op_in_unsafe_fn)]` — unsafe blocks inside unsafe fns must be explicit
- Static mutable data: use `addr_of_mut!` / `addr_of!` — never create references to `static mut`

**Commit naming convention:** `ch{N}: <description>` — e.g. `ch34: Linux kernel boot in QEMU`
