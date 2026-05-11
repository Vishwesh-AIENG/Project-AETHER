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
pub mod time;        // ch26: Time — CounterFrequency (19.2/24/25 MHz; plausibility check),
                     //       CnthctlConfig (CNTHCTL_EL2: EL1PCTEN+EL1PCEN=1 mandatory; no timer
                     //       traps for performance + fingerprint purity), CntpoffConfig
                     //       (CNTPOFF_EL2=0; non-zero offset is detectable on non-multiplexed
                     //       cores), TimerPpi (HypervisorPhysical→INTID 26; VirtualEl1→INTID 27;
                     //       SecurePhysicalEl1→INTID 29; NonSecurePhysicalEl1→INTID 30),
                     //       CounterPassthroughPolicy (DirectPassthrough safe for static
                     //       partitioning; TrapAndEmulate rejected), WallClockSource
                     //       (PlatformRtcAndNtp — hypervisor provides no time services),
                     //       TimerConfiguration (aggregate validate: plausible frequency + no
                     //       traps + zero offset + static-partition policy),
                     //       TimerSummary (timer_ready: passthrough+zero-offset+PPI wired)

// Part VIII — Build System (Chapters 27–28)
pub mod build_system; // ch27: The Build System — three-artifact build (hypervisor EFI / Android
                      //       image / Windows config), HardwareTier (Arm/X86 + Cargo target
                      //       triple), CargoProfile (Release/Debug), HypervisorBuildConfig
                      //       (build-std + build-std-mem required), AndroidBuildVariant (User
                      //       only in production), AndroidBuildConfig (partition sizes in bytes,
                      //       4 KiB aligned), WindowsBuildConfig (namespace ≥ RAM + Secure Boot
                      //       chain), CrossCompileToolchain (nightly + UEFI target + aarch64
                      //       cross toolchain + rust-src + AOSP env), BuildStep (ordered sequence
                      //       with parallelism rules: Android ∥ Windows after hypervisor),
                      //       EfiOutputFormat (PE32+ EFI application, tier-matched arch),
                      //       BuildSystemConfig (aggregate validate), BuildSummary (build_ready gate)
pub mod development_workflow; // ch28: The Development Workflow — TestTier (QemuMinimal/
                      //       QemuLinuxGuest/RealHardware; per-commit gate + bisection contract),
                      //       QemuMachineConfig (GICv3 + virtualization=on mandatory; freeze_on_start
                      //       requires GDB port; TIER1_CI/TIER1_DEBUG presets), GicVersion (V3 only),
                      //       SerialDebugConfig (PL011 UART at 0x0900_0000 on QEMU virt; primary
                      //       early-boot debug channel), BreakpointKind (Hardware safe before MMU;
                      //       Software unsafe in early boot; hbreak vs break GDB prefix),
                      //       DebuggerConfig (hardware breakpoints for EL2, port 1234),
                      //       CiStage (CargoCheck per-commit; CargoTestLib+QemuTier1 per-PR;
                      //       AospCheckBuild nightly; FullReleaseBuild hardware-only),
                      //       CiPipeline (all three gates required; Tier1 ≤ per-commit budget;
                      //       AOSP checkbuild NOT per-commit), BisectionConfig (tier1 bisection
                      //       contract: exit-0/non-zero no human interaction; git bisect run),
                      //       SnapshotConfig (QEMU savevm/loadvm for Tier 2 acceleration;
                      //       android_post_boot checkpoint), WorkflowConfig (aggregate validate),
                      //       WorkflowSummary (workflow_ready gate)

// Part IX — Roadmap (Chapters 29–33)
pub mod roadmap_phase1; // ch29: Phase One — Foundation (ARM Tier).  ResearchPhaseStatus
                        //       (5-item gate: ARM ARM read + KVM/ARM64 studied + QEMU env +
                        //       experimental code + project journal — mandatory before any
                        //       Phase 1 work begins), Phase1Milestone (11-step linear critical
                        //       path: Arm64Substrate → ExceptionHandling → Stage2 → UefiBoot →
                        //       MemoryIsolation → CpuPartitioning → GicVirt → Passthrough →
                        //       NvmeNamespace → MinimalLinuxInQemu → MinimalLinuxOnHardware),
                        //       MilestoneState (NotStarted/InProgress/Validated/Regressed;
                        //       prerequisite enforcement on advance), Phase1Tracker
                        //       (fixed-size array, all_validated/first_unvalidated/any_regressed),
                        //       Phase1TimelineEstimate (optimistic ≤ realistic ≤ pessimistic;
                        //       REALISTIC_MULTIPLIER=2, PESSIMISTIC_MULTIPLIER=3 — README
                        //       12-month estimate becomes 24-month realistic), WeeklyHourBudget
                        //       (DEFAULT_TERM=2h weekday + 6h weekend = 22h/wk; realistic caps:
                        //       4/8/10 enforced), Phase1GateCriterion (4 functional checks +
                        //       workaround_accepted rejection — "works in QEMU but not on
                        //       hardware" is not a pass), Phase1Config (aggregate validate),
                        //       Phase1Summary (phase1_complete: 5-pillar gate)
pub mod roadmap_phase2; // ch30: Phase Two — Android Bring-Up (ARM Tier). Phase2Milestone
                        //       (14-step linear path from Phase1GateClosed →
                        //       AospSourceSynced → BootloaderVerified → KernelBootsWithDtb →
                        //       UserspaceReachesBootCompleted → AdrenoVfRendersUi →
                        //       ParavirtSensorsLive → PhoneBridgeToggleWorking →
                        //       VirtualModemAttached → MicroGServicesRunning →
                        //       AppStoreInstallsSucceed → SafetyNetBasicIntegrityPasses →
                        //       AppCategoryCoverageComplete → AndroidStableOnHardware),
                        //       Phase2MilestoneState + Phase2Tracker (prerequisite enforcement),
                        //       AppCategory (7 categories: Communication/MapsNav/WebBrowsing/
                        //       MediaPlayback/Productivity/BankingAttestation/LightGaming —
                        //       Banking is recorded but not a hard requirement), AppCategoryCoverage
                        //       (HARD_REQUIREMENTS_PASS preset; banking left false because
                        //       attestation failure is expected), Phase2TimelineEstimate
                        //       (README_LOWER: 6→12→18; README_UPPER: 9→18→27),
                        //       Phase2GateCriterion (build_type=User invariant +
                        //       adreno_vf_rendering + microg_basic_integrity +
                        //       hard_app_categories_pass + soak_passes_on_hardware +
                        //       claims_device_integrity=false — DeviceIntegrity is unattainable),
                        //       Phase2Config (aggregate validate: Phase1NotComplete /
                        //       Phase1GateNotRecorded enforced), Phase2Summary
pub mod roadmap_phase3; // ch31: Phase Three — x86 Tier Foundation. X86VirtualizationFlavor
                        //       (IntelVtx→VMCS+EPT+VMX-root / AmdSvm→VMCB+NPT+SVM-host),
                        //       SecondStageTableConfig (INTEL/AMD_PRODUCTION; four_level_paging
                        //       required, invalidate_on_mapping_change required — stale TLB
                        //       leaks across guest boundary), FexEmuIntegrationMode
                        //       (InHypervisor required; HostUserland rejected — would need a
                        //       host OS, violates No-Boundary), FexEmuConfig (PRODUCTION:
                        //       persistent JIT + AOT for system apps), Phase3Milestone
                        //       (10-step linear: Phase2GateClosed → VmxOrSvmAvailable →
                        //       HypervisorEntersRootMode → VmcsVmcbInitialized → EptOrNptActive
                        //       → FexEmuExecutesArm64Binary → LinuxKernelBootsThroughDbt →
                        //       AndroidUserspaceBootsThroughDbt → CoreAppsValidatedThroughDbt
                        //       → X86TierValidatedOnHardware), Phase3Tracker (prerequisite
                        //       enforcement), Phase3TimelineEstimate (12→24→36 months —
                        //       structurally Phase One again on a different ISA),
                        //       Phase3GateCriterion (Intel AND AMD must both boot;
                        //       fex_in_hypervisor + ept_npt_invalidation_enforced invariants;
                        //       no workarounds), Phase3Config (aggregate), Phase3Summary
pub mod roadmap_phase4; // ch32: Phase Four — Performance And Compatibility. PerformanceTarget
                        //       (arm_tier_bound ≤ x86_tier_bound invariant — DBT cannot be
                        //       faster than native), constants FRAME_TIME_P99_MS (17/33),
                        //       COLD_LAUNCH_P99_MS (800/1800), VM_EXITS_PER_SEC (1k/10k),
                        //       PerformanceMeasurement (within_target + per-tier validate),
                        //       SubsystemPerfState (ARM_TARGET: all Native+Negligible;
                        //       X86_TARGET: CPU=Present from DBT, rest match ARM; arm_native
                        //       gate), SensorFidelityCheck (ACCEL/GYRO/MAG_REFERENCE matching
                        //       ch12 BMI160/BMM150 σ values in milli-units; 10% default
                        //       tolerance), AppCompatibilityReport (README_TARGET_TEMPLATE:
                        //       1000 apps + 95% pass rate; attestation-only failures excluded
                        //       from denominator — design issue not bug), Phase4Milestone
                        //       (9-step: Phase3GateClosed → ArmTierFrameTimeWithinTarget →
                        //       X86TierFrameTimeWithinTarget → ColdLaunchWithinTarget →
                        //       VmExitRateWithinTarget → SensorFidelityWithinTolerance →
                        //       AppCompatibilityTargetMet → AllCompatBugsTriaged →
                        //       SoakPassesOnBothTiers; perf milestones validate on
                        //       RealHardware — QEMU perf numbers are meaningless),
                        //       Phase4TimelineEstimate (12→24→36 months),
                        //       Phase4GateCriterion (8 booleans including arm_native_subsystems
                        //       + sensors_within_tolerance + workaround_accepted=false),
                        //       Phase4Config (aggregate validate), Phase4Summary

// Support
pub mod uart;        // PL011 UART driver — polled TX for boot diagnostics
