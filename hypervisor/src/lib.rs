// Production: no_std (bare-metal EL2). Tests: std available (native host).
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

// AETHER hypervisor — core library
// All code here runs at EL2 on bare-metal ARM64.
// There is no host OS; std is unavailable by design.
//
// Module layout mirrors the chapter structure of the specification.
// Each module corresponds to one or more chapters in README.md.
//
// Part I — The Vision (Chapters 1–3)
pub mod fingerprint; // ch02: fingerprint sources and elimination strategies
pub mod partition;   // ch03: non-negotiables encoded as types

// Part II — The Silicon (Chapters 4–6)
pub mod arm64; // ch04: ARM64 substrate — regs, barriers, paging constants

// Part III — The Hypervisor (Chapters 7–11)
pub mod boot;        // ch07: UEFI handoff, ExitBootServices, ACPI discovery, guest ERET
pub mod memory;      // ch08: Stage 2 page tables, bump allocator, SMMU v3 stream table
pub mod cpu;         // ch09: static CPU partitioning, PSCI dispatch, GIC SPI routing
pub mod gic;         // ch10: GICv3 init, virtual interrupt injection, maintenance IRQ

// Part IV — Devices (Chapters 11–16)
pub mod passthrough; // ch11: PCIe device assignment — IOMMU groups, FLR, BAR mapping, SMMU STE
pub mod paravirt;    // ch12: paravirtualization — virtual modem (AT/3GPP), MEMS sensor suite (BMI160
                     //       Gaussian noise models), Phone Bridge Mode toggle
pub mod gpu;         // ch13: GPU partitioning via SR-IOV — VF enumeration, assignment, isolation
pub mod storage;     // ch14: storage partitioning — NVMe namespace isolation, SR-IOV, exclusive attachment
pub mod network;     // ch15: network partitioning — SR-IOV VFs, dedicated adapters, paravirt bridge fallback
pub mod usb;         // ch16: USB controller partitioning, xHCI passthrough, cross-partition input switching

// Part V — The Windows Partition (Chapters 17–18)
pub mod windows;     // ch17: ARM Tier Windows partition config — CPUID hypervisor leaves, Hyper-V
                     //       enlightenments, Secure Boot chain, crash dump sizing, inbox-driver policy
pub mod acpi;        // ch18: Windows ACPI tables — RSDP, XSDT, MADT (ARM GIC entries), GTDT, IORT,
                     //       FADT (hardware-reduced); checksums, byte-precise table builders

// Part VI — The Android Partition (Chapters 19–23)
pub mod bootloader;  // ch19: Android bootloader — AVB2 VBMeta verification, boot image header v3/v4,
                     //       A/B slot selection (BCB), rollback protection, kernel command line builder,
                     //       BootloaderLockState (Locked/Unlocked/Orange), KernelLaunchParams
pub mod kernel;      // ch20: Linux kernel — ARM64 Image header parser (64-byte header, 0x644D5241 magic),
                     //       FDT/DTB builder (DtbBuilder: structure+strings blocks, big-endian tokens),
                     //       GKI mandatory config tracker (GkiConfig), KernelState phase machine
                     //       (Init→ImageValidated→DtbPlaced→ConfigVerified→ReadyToLaunch),
                     //       AndroidDtbConfig + build_android_dtb() for the full partition device tree
pub mod aosp;        // ch21: AOSP And The Android Userspace — PartitionLayout (A/B Android partitions,
                     //       size validation against NVMe namespace), TrebleManifest (HalInterface:
                     //       HIDL/AIDL HAL declarations, REQUIRED_HALS check), DeviceProperties
                     //       (AndroidProperty key/value, ro.build.type=user invariant, ro.adb.secure/
                     //       ro.secure enforcement), ArtConfig (Dalvik heap sizing: start/limit/max,
                     //       GC utilization), AospDeviceConfig (full validated configuration aggregate)
pub mod microg;      // ch22: The microG Substitution — GmsService coverage map (Authentication/FCM/
                     //       FusedLocation Full; PlayIntegrity Stub; Pay/Cast/AndroidAuto/MlKit
                     //       NotImplemented), SignatureSpoofingPolicy (framework patch required),
                     //       PlayIntegrityMaxVerdict (BasicOnly enforced — MEETS_DEVICE_INTEGRITY
                     //       unachievable without Google certification), LocationBackend (MLS/Beacondb/
                     //       GpsOnly), FcmRelay (Direct/SelfHosted), AppStore (FDroid/AuroraStore/
                     //       Obtainium/ManualSideload), MicrogConfig (default_config: spoofing+FDroid+
                     //       Aurora validated aggregate)
pub mod play_store;  // ch23: The Play Store Question — PlayCatalogAccess (OpenSourceOnly/AnonymousProxy/
                     //       GenuinePlayStore), LegalTolerance (Clear/ToleranceZone/UserResponsibility),
                     //       AuroraAccountMode (Anonymous/PersonalAccount), InstallerSpoofMode
                     //       (Disabled/SpoofAsPlayStore), UserDisclaimer + ManualInstallPath (manual
                     //       Google Play installation path with disclaimer gate), PlayStoreConfig
                     //       (default: F-Droid + Aurora anonymous; genuine Play Store manual-only)

// Part VII — Cross-Cutting Concerns (Chapters 24–26)
pub mod performance; // ch24: Performance — SubsystemOverhead (Native/Negligible/Present) per subsystem
                     //       (CPU/Memory/GPU/Storage/Network/Paravirt), ExitCounter (VM exit
                     //       instrumentation by ExitReason: WfxTrap/Hvc/Smc/SystemRegister/
                     //       InstructionFault/DataFault/PhysicalIrq/VirtualTimer/Other; saturating u64
                     //       counts; gaming threshold check <1 000 exits/s), LargePagePolicy
                     //       (PreferBlock: 2 MiB block descriptors for TLB efficiency; ForceSmall:
                     //       4 KiB pages for MMIO slivers), PerformanceSummary (all_native() gate)
pub mod security;    // ch25: Security — TcbLayer (Hardware/El3Firmware/Hypervisor trusted; Guest/
                     //       Application untrusted), SmmuSecurityState (Active/Pending/Absent;
                     //       mandatory DMA isolation boundary), SmmuFaultPolicy (TerminateGuest
                     //       production-safe; LogAndContinue dev-only), SpectreV2Mitigation
                     //       (ClrBhb/BhbLoopFlush{iterations}/IcacheFlush/HardwareIsolated; branch
                     //       predictor flush on every EL1↔EL2 transition), BranchPredictorFlushConfig
                     //       (flush_on_entry + flush_on_exit), AttackSurfaceEntry (HvcCall/
                     //       TrappedSysregWrite/SmmuFault/TimerInterrupt; carries_guest_data()),
                     //       HvcInputValidator (validate_ipa_argument/validate_ipa_range: reject
                     //       out-of-guest-range addresses before dereference), UnsafeAuditRecord
                     //       (Reviewed/PendingReview/Unannotated; every unsafe block requires
                     //       SAFETY comment + engineer sign-off), SecurityConfiguration (aggregate
                     //       validate: SMMU active + TerminateGuest policy + Spectre config valid),
                     //       SecuritySummary (all_secure: stage2+smmu+gic+spectre all active)

// Support
pub mod uart;        // PL011 UART driver — polled TX for boot diagnostics
