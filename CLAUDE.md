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
| 35 | Multi-Core SMP | ✅ Complete |
| 36 | Physical IRQ Forwarding — Validated | ✅ Complete |
| 37 | NVMe Namespace — Functional | ✅ Complete |
| 38 | PCIe Device Assignment and SMMU Wiring | ✅ Complete |
| 39 | GPU SR-IOV — Functional Enable | ✅ Complete |
| 40 | Network Passthrough — Functional | ✅ Complete |
| 41 | USB Controller and Input Switch — Functional | ✅ Complete |
| 42 | AOSP Device Configuration and Build | ✅ Complete |
| 43 | Android Bootloader — Functional AVB | ✅ Complete |
| 44 | Android Kernel and Device Tree | ✅ Complete |
| 45 | Android Userspace Boot | ✅ Complete |
| 46 | Adreno GPU — Rendering | ✅ Complete |
| 47 | Virtual Sensors and Modem — Live | ✅ Complete |
| 48 | Phone Bridge Mode — End to End | ✅ Complete |
| 49 | App Compatibility Validation | ✅ Complete |
| 50 | Intel VT-x Foundation | ✅ Complete |
| 51 | AMD-V Foundation | ✅ Complete |
| 52 | FEX-Emu Integration in Hypervisor | ✅ Complete |
| 53 | Android on x86 — Userspace | ✅ Complete |
| 54 | x86 Tier Hardware Validation | ✅ Complete |
| 55 | Hardware Compatibility Checker | ✅ Complete |
| 56 | AETHER Installer CLI | ✅ Complete |
| 57 | Secure Boot Integration | ✅ Complete |
| 58 | UEFI Boot Selector | ✅ Complete |
| 59 | Setup Wizard — GUI Frontend | ✅ Complete |
| 60 | Configuration App | ✅ Complete |
| 61 | OTA Update System | ✅ Complete |
| 62 | Recovery Mode | ✅ Complete |
| 63 | AETHER Manager Android App | ✅ Complete |
| 64 | HVC Paravirt ABI | ✅ Complete |
| 65 | Security Hardening and Unsafe Audit | ⬜ Not started |
| 66 | Performance Optimization | ⬜ Not started |
| 67 | Fingerprint Elimination Audit | ⬜ Not started |
| 68 | CI/CD Pipeline and Release Engineering | ⬜ Not started |
| 69 | Documentation | ⬜ Not started |
| 70 | Public Release | ⬜ Not started |

**Progress: 64 / 70 chapters complete (91%)**

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
├── gpu_sriov.rs        ← ch39: GPU SR-IOV — Functional Enable. Reads SR-IOV Extended
│                              Capability (ID=0x0010) from Adreno GPU PF via ECAM
│                              (walk extended cap list from 0x100), validates MaxVFs ≥ 2,
│                              writes NumVFs=2 then VF_Enable|VF_MSE to SRIOV_CTRL (NumVFs
│                              BEFORE VF Enable per PCIe §9.3.3.3.2), DSB ISH. Computes
│                              VF BDFs (PF_BDF + FirstVFOffset + n × VFStride). Maps each
│                              VF's BARs into Stage 2 as DeviceRw (IPA == PA) via scan_bars.
│                              Configures SMMU STE per VF StreamID (stage2_only; write_ste
│                              enforces words 1–7 → DSB ISH → word 0 per IHI0070E §3.6).
│                              Maps ECAM window so Android DRM reads Vendor ID 0x17CB
│                              (Qualcomm). Registers VFs in GpuPartitionRegistry.
│                              GpuSrIovConfig (pf_addr/ecam_window/vmid/s2ttb_pa/stream_ids),
│                              GpuSrIovGate (vendor_id_visible + vf_bars_mapped; passes()),
│                              GpuSrIovError (SrIovCapNotFound/InsufficientVfs/NoVfBarsFound/
│                              MapFailed/RegistryError/StreamIdOutOfRange), compute_vf_addr(),
│                              assign_gpu_vfs() — 7-step pipeline. QUALCOMM_VENDOR_ID=0x17CB.
│                              Gate: cat /sys/class/drm/card0/device/vendor = 0x17cb in Android.
├── network_passthrough.rs ← ch40: Network Passthrough — Functional. Probes NIC PF for
│                              SR-IOV Extended Capability (ID=0x0010; walk from 0x100),
│                              validates MaxVFs ≥ 2, writes NumVFs=2 then VF_Enable|VF_MSE
│                              to SRIOV_CTRL (NumVFs BEFORE VF Enable per PCIe §9.3.3.3.2),
│                              DSB ISH. Computes Android VF BDF (PF+FirstVFOffset+0×VFStride).
│                              Maps VF 0 BARs as DeviceRw (IPA==PA) into Stage 2 via scan_bars.
│                              Configures SMMU STEs for both stream IDs (stage2_only; write_ste
│                              enforces words 1–7 → DSB ISH → word 0 per IHI0070E §3.6). Maps
│                              ECAM window as DeviceRw. Re-asserts Bus Master Enable (Command
│                              reg bit 2) on VF 0 after FLR. Registers Android VF in
│                              NetworkPartitionRegistry with locally-administered MAC.
│                              NetworkPassthroughConfig (pf_addr/ecam_window/vmid/s2ttb_pa/
│                              stream_ids/android_vf_mac), NetworkPassthroughGate
│                              (mac_visible + dhcp_ready; passes() gate),
│                              NetworkPassthroughError (SrIovCapNotFound/InsufficientVfs/
│                              NoVfBarsFound/MapFailed/SmmuStreamIdOutOfRange/MacError),
│                              assign_nic_vf() — 10-step pipeline. AETHER_NIC_NUM_VFS=2.
│                              Gate: ip addr shows interface with valid MAC; DHCP succeeds.
├── pcie_assignment.rs  ← ch38: PCIe Device Assignment and SMMU Wiring — Functional.
│                              EcamWindow (mcfg_base_pa/start_bus/end_bus; window_pa(),
│                              window_size(), bdf_config_pa()), ECAM_PER_BUS_SIZE=1MiB
│                              (32×8×4KiB), map_ecam_window() (DeviceRw identity map of
│                              config-space window into guest Stage 2), enable_bus_master()
│                              (re-asserts BME=bit2 of Command reg cleared by FLR),
│                              PcieAssignmentConfig (group/guest/addr/ecam_window/vmid/
│                              s2ttb_pa + validate()), PcieAssignmentGate
│                              (ecam_mapped + device_visible_in_lspci; passes() gate),
│                              AssignmentError (Passthrough/InvalidBusRange/Overflow),
│                              assign_device_with_ecam() — 8-step pipeline: validate →
│                              IOMMU check → FLR → BAR map → SMMU STE (Stage-2-only,
│                              words 1–7 then word 0 + DSB) → registry commit → ECAM
│                              window map → BME enable.
│                              Gate: lspci in Android guest lists assigned device by BDF.
├── paravirt.rs         ← ch12: Xorshift64 PRNG, validate_imei() (Luhn),
│                              VirtualSensorSuite (BMI160/BMM150 Gaussian noise,
│                              gyro bias drift), BridgeMode, VirtualModem (AT cmds,
│                              AT+CPIN?→SIM NOT INSERTED, AT+CIMI→ERROR, default
│                              reg_state=NotRegistered for "No SIM" gate)
├── virtual_sensors_modem.rs ← ch47: Virtual Sensors and Modem — Live.
├── app_compat.rs       ← ch49: App Compatibility Validation. Automated test harness installs
│                              top-1000 APKs, runs UI Automator smoke tests, records pass/fail,
│                              fixes compat bugs. AppTestCategory (13 categories), SmokeTestStep
│                              (6-step fixed sequence; SMOKE_TEST_WAIT_MS=5000), UiAutomatorOutcome
│                              (Passed/TimedOut/Crashed/CrashDialogShown/InstallFailed),
│                              CompatFailureKind (AttestationRequired/MissingGmsService/CameraHalAbsent/
│                              NfcRequired/WidevineLevelOneRequired/HypervisorDetected/
│                              FingerprintMismatch/NativeAbiMismatch/ArtJitAnomaly/
│                              AndroidIdInconsistency; is_attestation_only/requires_fix),
│                              CompatBugSeverity (Critical/Major/Minor/Cosmetic),
│                              CompatBugFix (SystemPropertyOverride/ManifestFeatureStub/CameraStubHal/
│                              WidevineL3Config/SelinuxCompatRule/ArtJitWorkaround/AndroidIdPersistence/
│                              MicrogGsfNoopDefer), CompatBugRecord (needs_resolution()),
│                              COMPAT_KNOWN_BUG_FIXES (8 entries; all resolved),
│                              COMPAT_SELINUX_RULES (4 TE rules; each with silent_failure doc),
│                              COMPAT_PRODUCT_PACKAGES (4: AetherCompatHarness/aether_camera_stub/
│                              aether_compat_props/AuroraStore), AppCompatConfig (AETHER_DEFAULTS +
│                              validate()), AppCompatGate (report_meets_target+no_unresolved_compat_bugs+
│                              build_type_user; passes()), AppCompatPhase (NotStarted→HarnessReady→
│                              ApksInstalled→SmokeTestsRunning→BugsTriaged→GatePassed),
│                              AppCompatState (process_line()/gate()/mark_harness_ready()/
│                              should_abort()/total_tested()), UART_SIG_COMPAT_* byte-pattern constants,
│                              init_app_compat_validation(). Gate: ≥950/1000 apps pass
│                              (attestation-only excluded from denominator); all Critical/Major bugs
│                              resolved; ro.build.type=user.
├── phone_bridge.rs     ← ch48: Phone Bridge Mode — End to End. AETHER Bridge Protocol
│                              (magic 0xAE_CA_FE_48; FRAME_TYPE_SENSOR/IDENTITY/HANDSHAKE)
│                              over ADB WRTE USB bulk. PhoneSensorFrame (accel/gyro/mag +
│                              timestamp_lo; is_valid() rejects NaN/Inf), PhoneIdentity
│                              (manufacturer/model/bootloader 64-byte fields). parse_bridge_frame()
│                              (magic check → payload decode; BridgeFrameResult enum).
│                              ToggleBuffer (dual-source cache; read_*() falls back to other
│                              source → gap-free toggle guarantee). PhoneBridgeReader (BRIDGE_RX_BUF_MAX
│                              accumulation; partial-frame carry-forward; re-sync on magic mismatch).
│                              Global EL2 state: AETHER_TOGGLE_BUF/AETHER_BRIDGE_READER/
│                              AETHER_PHONE_IDENTITY. on_bridge_usb_data() (xHCI event ring entry),
│                              bridge_read_accel/gyro/mag(mode), update_virtual_cache().
│                              PhoneBridgeConfig/Gate/Error/Phase/State types.
│                              BRIDGE_KERNEL_CONFIG (4), BRIDGE_SELINUX_RULES (3),
│                              BRIDGE_PRODUCT_PACKAGES (3). init_phone_bridge() pipeline.
│                              Gate: toggle ON/OFF changes data source with no gap in stream. AETHER HVC
│                              vendor range 0x8600_0001–0x8600_0006 (GET_VERSION/
│                              BRIDGE_MODE_GET/SET/SENSOR_READ/UPDATE_STAGE stub/
│                              DIAG_LOG_READ stub). SENSOR_READ: x1=HvcSensorId
│                              (0=Accel/1=Gyro/2=Mag/3=Prox) → x0=0, x1=x_bits,
│                              x2=y_bits, x3=z_bits (f32::to_bits() in u64). Paravirt
│                              modem shared page at AETHER_MODEM_IPA=0x0B00_0000
│                              (4 KiB; cmd_ready/cmd_len/cmd_buf at 0x000;
│                              resp_ready/resp_len/resp_buf at 0x200). Polled on WFI
│                              exit via poll_modem_on_wfi() → VirtualModem::
│                              process_command(). dispatch_aether_hvc() called from
│                              exception.rs handle_hvc() before PSCI dispatch.
│                              VirtualSensorsAndModemConfig (imei/prng_seed/modem_ipa/
│                              sensor_odr_hz=100 + validate()), VirtualSensorsAndModemGate
│                              (accel_visible+gyro_visible+mag_visible+no_sim_shown;
│                              passes()), VirtualSensorsAndModemPhase (NotStarted→
│                              HvcRegistered→SensorHalStarted→ModemAttached→GatePassed),
│                              SENSOR_KERNEL_CONFIG (4 entries), SENSOR_SELINUX_RULES
│                              (3 TE rules), SENSOR_PRODUCT_PACKAGES (3 packages).
│                              Gate: dumpsys sensorservice shows accel/gyro/mag;
│                              getprop gsm.sim.state=ABSENT (phone shows No SIM).
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
├── usb_passthrough.rs  ← ch41: USB Controller and Input Switch — Functional. 7-step
│                              xHCI assignment pipeline: BAR scan → Stage 2 DeviceRw
│                              (IPA==PA), SMMU STEs (stage2_only; words 1–7 → DSB → word 0),
│                              ECAM window map, BME enable, HCRST (halt → USBCMD.HCRST=1 →
│                              poll HCRST=0), registry commit (smmu_configured=true/Clean).
│                              Event ring interception: poll_event_ring() reads Transfer Event
│                              TRBs (type 32, code 1) from EL2-private ring (EL2_EVENT_RING_BUF,
│                              16 TRBs, init_el2_event_ring()); Normal TRB data buffer pointer
│                              carries 8-byte USB HID boot-protocol report; DC IVAC before read.
│                              Input switch: execute_xhci_input_switch() — halt → HCRST →
│                              rewrite SMMU STEs (new VMID/S2TTB) → execute_switch() →
│                              mark_reset_clean(). Hardware-only Ctrl+Alt+Tab trigger.
│                              UsbPassthroughConfig (ctrl_addr/ecam_window/bar0_pa/vmid/
│                              s2ttb_pa/stream_ids/kind + validate()), UsbPassthroughGate
│                              (keyboard_enumerated + input_switch_ready; passes()),
│                              UsbPassthroughError (BarNotFound/MapFailed/SmmuStreamIdOutOfRange/
│                              HcrstTimeout/HaltTimeout/RegistryError), XhciTrb (16B; cycle_bit/
│                              trb_type/completion_code), XhciInterrupterState (dequeue/cycle/
│                              segment), XhciErstEntry (64B). HidReport (8B).
│                              Gate: USB keyboard works in Android; Ctrl+Alt+Tab switches input.
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
├── aosp_build.rs       ← ch42: AOSP Device Configuration and Build. DeviceMk
│                              (PRODUCT_PACKAGES: GmsCore/FakeStore/GsfProxy/gralloc/
│                              HAL services; PRODUCT_COPY_FILES; PRODUCT_PROPERTY_OVERRIDES
│                              with ro.build.type=user invariant), BoardConfigMk
│                              (TARGET_ARCH=arm64, BoardPartitionSizes matching ch21
│                              default_layout, SelinuxPolicyType::Enforcing, avb_enabled,
│                              AvbKeySource), AndroidBp (SoongModule: sensors/radio/power/
│                              health HAL services + gralloc.aether + prebuilts),
│                              MicrogIntegration (GmsCore/FakeStore/GsfProxy/UnifiedNlp
│                              at source level; SignatureSpoofingPolicy::Enabled required;
│                              MicrogLocationBackend: MLS/Beacondb/GpsOnly),
│                              LunchTarget (AETHER_LUNCH_TARGET = aether_arm64-user),
│                              OutputImage (Boot/System/Vendor/Vbmeta/Userdata required),
│                              ImageGateState (produced/non_empty/within_size_limit),
│                              AospBuildGate (lunch_target_registered + avb_verified +
│                              all required images pass()), AospBuildConfig
│                              (default_aether() + validate() aggregate).
│                              Gate: lunch aether_arm64-user && m → bootable images.
├── avb_boot.rs         ← ch43: Android Bootloader — Functional AVB. NVMe I/O queue
│                              setup (Create I/O CQ opcode 0x05, Create I/O SQ opcode 0x01),
│                              I/O Read (opcode 0x02) for misc/vbmeta/boot partitions.
│                              AVB2 pipeline: BCB → A/B slot → key check → sig check →
│                              rollback enforce → BootImageHeader parse → cmdline → ERET.
│                              AvbAdminState (bar0/sq_tail/cq_head/cq_phase; from_ch37_defaults),
│                              AvbPartitionLayout (default LBAs), AvbBootConfig + validate(),
│                              AvbBootGate (header_parsed/rollback_accepted/cmdline_built/
│                              eret_ready; passes()), run_avb_boot_pipeline() — 10-step pipeline.
│                              Gate: AVB2 verified Android slot boots; rollback_index enforced.
├── kernel_defconfig.rs ← ch44: Android Kernel and Device Tree. AETHER_GKI_DEFCONFIG
│                              (48 CONFIG_ entries: tmpfs/devtmpfs/unix/binderfs/ext4-security/
│                              psi/seccomp/keys/dm-crypt/netfilter/namespaces/cgroups/pstore-ram).
│                              Documents 8 silent boot failure causes. DefconfigEntry
│                              (name/DefconfigValue), AetherGkiDefconfigValidator (apply/gate),
│                              AetherDefconfigGate (all_required_enabled+gki_satisfied; passes()).
│                              ProductionDtbExtras (initrd_start/end_ipa/uart_clock_hz/ramoops),
│                              ProductionDtbGate (dtb_built/fstab_present/initrd/ramoops; passes()),
│                              build_production_android_dtb() — all ch20 nodes + clock-frequency
│                              on PL011 + linux,initrd-{start,end} in /chosen +
│                              /firmware/android/fstab/{system,vendor} (first_stage_mount) +
│                              /reserved-memory/ramoops@ (no-map). ProdDtbBuilder (8KiB/1KiB).
│                              Gate: logcat shows Zygote launch.
├── adreno_render.rs    ← ch46: Adreno GPU — Rendering. Integrates Mesa freedreno (Turnip
│                              Vulkan + freedreno OpenGL ES) into AOSP vendor partition.
│                              GpuDriverSource (MesaFreedrenoOpen/QualcommProprietary),
│                              GrallocVersion (Hidl4/Aidl2), HwcImplementation
│                              (DrmHwcomposer/QualcommProprietary/SoftwareFallback),
│                              DisplayPipeline (KernelModeSetting/VirtioGpuQemu),
│                              VulkanIcdConfig (icd_json_path/library_path/api_version),
│                              GrallocHalConfig (render_node_path=/dev/dri/renderD128,
│                              dma_heap_path=/dev/dma_heap/system), AdrenoRenderConfig
│                              (aether_defaults: MesaFreedrenoOpen+DrmHwcomposer+Vulkan 1.3;
│                              validate: rejects proprietary/SoftwareFallback/old VkAPI/
│                              wrong paths), AdrenoRenderError (ProprietaryDriverNot
│                              Redistributable/HwcIncompatibleWithDriverSource/
│                              SoftwareFallbackForbiddenInProduction/VulkanApiVersionTooOld/
│                              GrallocRenderNodePathEmpty/GrallocDmaHeapPathEmpty/
│                              VulkanIcdPathNotInVendor/VulkanLibraryNotInVendor),
│                              AdrenoRenderPhase (NotStarted→DrmDriverBound→GrallocReady→
│                              HwcReady→VulkanReady→RenderingActive→GatePassed),
│                              AdrenoRenderGate (vulkan_shows_adreno+glmark2_es2_runs+
│                              youtube_1080p_plays; passes()/gpu_visible()),
│                              AdrenoRenderState (process_line()/gate()),
│                              ADRENO_RENDER_DEFCONFIG (12 entries: DRM/KMS_HELPER/MSM/
│                              SYNC_FILE/DMA_SHARED_BUFFER/DMABUF_HEAPS/DMABUF_HEAPS_SYSTEM/
│                              DISPLAY_CONNECTOR/MEDIA_SUPPORT/VIDEO_DEV/MEDIA_CONTROLLER
│                              required + CONFIG_FB disabled; each with silent_failure),
│                              ADRENO_SELINUX_RULES (7 TE rules: gralloc_default/
│                              hal_graphics_composer/system_server/untrusted_app/mediacodec),
│                              ADRENO_AOSP_BUILD_VARS (5 BoardConfig.mk vars),
│                              ADRENO_PRODUCT_PACKAGES (8 packages including vulkan.freedreno),
│                              init_adreno_render_pipeline(), contains_bytes().
│                              Gate: vulkaninfo shows 0x17CB; glmark2-es2 runs; YouTube 1080p.
├── userspace_boot.rs   ← ch45: Android Userspace Boot. UART-based boot failure diagnostics,
│                              SELinux policy violation detection, and HAL startup failure
│                              classification. UserspaceBootPhase (KernelHandoff→FirstStageInit→
│                              SecondStageInit→SystemDaemonsStarted→HalsRegistered→ZygoteReady→
│                              HomeScreenRendered), BootFailureKind (FirstStageMountFailed/
│                              InitBinaryNotFound/SelinuxPolicyLoadFailed/SelinuxAvcDenial/
│                              HalStartupFailed/ZygoteCrashLoop/SystemServerCrash/SmmuFault),
│                              SelinuxViolationKind (GrallocDmaBuf/SensorsIioDevice/
│                              AetherHwbinder/VoldNvmeDevice/UeventdDevNode/Other),
│                              SelinuxViolation + required_fix(), SelinuxPolicyFix + te_source(),
│                              HalName (GraphicsAllocator/GraphicsComposer/Sensors/Audio/Radio/
│                              Health/Power) + is_critical_path(), HalStartupFailure +
│                              HalFailureCause (DeviceNodeMissing/SmmuFault/SelinuxDenial/
│                              BinaryNotFound/RegistrationFailed), UART signature constants
│                              (UART_SIG_FIRST_STAGE_FAIL/INIT_NOT_FOUND/SELINUX_FAIL/
│                              AVC_DENIAL/ZYGOTE_READY/HOME_SCREEN/SETTINGS/BUILD_TYPE_USER/
│                              SMMU_FAULT), scan_uart_line() (byte-pattern, no heap),
│                              contains_bytes(), UserspaceBootConfig (aether_defaults()/
│                              validate()), UserspaceBootState (process_line()/gate()),
│                              UserspaceBootGate (home_screen_rendered + settings_opens +
│                              build_type_user; passes()), AETHER_SEPOLICY_FIXES (5-entry TE
│                              rule table), init_userspace_boot_diagnostics() — pipeline.
│                              Gate: home screen renders; Settings opens; ro.build.type=user.
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
├── nvme_namespace.rs   ← ch37: NVMe Namespace — Functional. PCIe ECAM NVMe controller
│                              enumeration (Class=01h/SubClass=08h/ProgIF=02h), BAR0 read,
│                              Admin SQ/CQ bring-up (AQA/ASQ/ACQ before CC.EN=1), AdminSqe
│                              (64 bytes, CDW0–15), AdminCqe (16 bytes, phase/status/result),
│                              polled completion (DC IVAC per CQE slot). Three admin commands:
│                              Identify Controller (opcode 0x06, CNS=0x01, OACS[3] check),
│                              Namespace Management Create (opcode 0x0D, sel=0x00, NSZE/NCAP/
│                              FLBAS in 4096-byte aligned NsCreateBuf), Namespace Attachment
│                              (opcode 0x15, sel=0x00, CNTLID=0 in CtrlrListBuf). D-cache
│                              maintenance (DC CIVAC/IVAC) around every DMA buffer.
│                              NvmeNamespaceConfig (bdf/bar0_pa/nsid/size_lbas), static 4096-
│                              aligned BSS queue buffers (ADMIN_Q_DEPTH=4). NvmeNamespaceGate:
│                              nvme_list_shows_namespace + dd_write_succeeds both true.
│                              Gate: nvme list shows NSID 1; dd to /dev/nvme0n1 exits 0.
├── irq_forward.rs      ← ch36: Physical IRQ Forwarding Validated. IrqForwardConfig
│                              (TIMER_VIRT_INTID=27, TIMER_PHYS_NS_INTID=30,
│                              UART_SPI_INTID=33), IrqForwardingStats (timer/uart/
│                              maintenance/dropped saturating counters), IrqCategory
│                              (Timer/Uart/Maintenance/Other), enable_ppi_in_gicr()
│                              (GICR_ISENABLER0 per-core), enable_spi_in_gicd()
│                              (GICD_ISENABLER global), setup_irq_forwarding()
│                              (enables INTID 27+30 per-core + INTID 33 globally),
│                              record_forwarded_irq() (stats update from EL2 handler).
│                              Gate: /proc/interrupts ticks on timer + UART lines.
├── linux_boot.rs       ← ch34: Linux Kernel Boot in QEMU. prepare_linux_boot() —
│                              build_android_dtb() → FDT emit into 8KiB static staging
│                              buffer → memcpy to guest DRAM at DTB1_PA → D-cache clean
│                              → Arm64ImageHeader::parse() → KernelState phase machine
│                              → KernelLoadConfig for ERET. LinuxBootError enum.
│                              Gate: ARM64 GKI boots to /bin/sh on QEMU serial.
│
│   — Part X: x86 Tier (Ch. 50–54) —
├── vtx.rs              ← ch50: Intel VT-x Foundation. VMX detection (CPUID.1.ECX[5]),
│                              IA32_FEATURE_CONTROL enable/lock (bits 0+2), CR4.VMXE=1,
│                              VMXON (enter VMX root mode), VMCLEAR+VMPTRLD (per-vCPU VMCS
│                              initialization). VMCS field constants (exact SDM §24.11.2
│                              encodings cross-checked against Linux KVM vmx.h).
│                              EPT 4-level setup (EptTable/Eptp/EptLeafEntry/EptTableEntry),
│                              WB leaf entries for RAM, UC leaf entries for MMIO.
│                              INVEPT single-context after every EPT mapping change.
│                              UNRESTRICTED_GUEST in secondary controls (pre-paging guest).
│                              VMCS host-state capture (CR0/CR3/CR4/RSP/RIP/EFER/PAT/segs).
│                              VMCS guest-state init (64-bit long mode or real-mode entry).
│                              VM-execution controls (pin/primary/secondary/exit/entry).
│                              VtxExitReason decoder (HLT=12/EPT_VIOLATION=48/CPUID=10).
│                              handle_vm_exit() dispatcher; VtxFoundationConfig/Gate/Error/
│                              Phase/State; init_vtx_foundation() 8-step pipeline.
│                              Gate: first VM exit EXIT_REASON=12 (HLT); VMRESUME succeeds.
├── svm.rs              ← ch51: AMD-V Foundation. SVM detection (CPUID.80000001h.ECX[2]),
│                              VM_CR.SVMDIS check (firmware lock guard), EFER.SVME enable.
│                              HSAVE_PA MSR (4 KiB host state save area for VMRUN/VMEXIT).
│                              VmcbRegion (4 KiB byte array, 4 KiB-aligned; offset constants
│                              from AMD APM Table B-2; control area 0x000–0x3FF + state save
│                              0x400–; read/write u8/u16/u32/u64 helpers; write_seg();
│                              request_npt_tlb_flush() → TLB_CTL=FLUSH_ALL + CLEAN=0).
│                              SvmHsaveRegion (4 KiB; processor-managed layout).
│                              NptTable (512×u64, 4 KiB-aligned), NptLeafEntry (normal_ram
│                              WB/device_mmio UC via PWT+PCD), NptTableEntry (pointing_to()).
│                              vmcb_write_guest_state() (64-bit long mode or real mode;
│                              16-byte AMD VMCB seg format: sel+attrib+limit+base).
│                              vmcb_write_intercepts() (HLT=misc1[24]+CPUID=misc1[18]+
│                              VMRUN=misc2[0]+VMMCALL=misc2[1]+SHUTDOWN=misc1[31]).
│                              vmcb_write_npt() (NP_ENABLE bit 0 of nested_ctl; N_CR3;
│                              ASID=1; TLB_CTL=FLUSH_ALL; VMCB_CLEAN=0).
│                              AMD has NO INVNPT instruction — TLB flush is ASID-based
│                              (TLB_CTL field in VMCB; cleared by processor after flush).
│                              SvmCpuFeatures (svm_supported/npt_supported/asid_count/
│                              decode_assists/is_amd_vendor; vendor string "AuthenticAMD"
│                              verified at runtime — branch on vendor, not flags alone).
│                              SvmVmCrMsr (svmdis), svm_enable_svme().
│                              handle_vm_exit() (HLT=0x58→nRIP-then-manual-fallback+gate;
│                              CPUID=0x52→advance RIP; NPF=0x400→Terminate; INVALID→Terminate).
│                              SvmFoundationConfig/Gate/Error/Phase/State;
│                              init_svm_foundation() — 8-step pipeline.
│                              Gate: first VMEXIT exit_code=0x58 (HLT); VMRUN returns
│                              to hypervisor. SVM exit code HLT = 0x58, NOT 0x78.
├── fex_integration.rs  ← ch52: FEX-Emu Integration in Hypervisor. Embeds FEX-Emu
│                              (ARM64 → x86_64 dynamic binary translator) as no_std
│                              static library; host OS deps (malloc/pthread/file I/O)
│                              replaced by FexHostBindings (bump arena + FexSpinLock)
│                              and JIT cache spill to NVMe (no fopen). ELF64 parser:
│                              Elf64Header / Elf64ProgramHeader / Elf64ArmBinary
│                              (validates ELF magic 7F 45 4C 46, ELFCLASS64,
│                              ELFDATA2LSB, EM_AARCH64=183 NOT 40, ET_EXEC|ET_DYN,
│                              e_phentsize=56, ≥1 PT_LOAD with PF_X). FexJitCache
│                              (FEX_JIT_CACHE_SIZE=16 MiB, 16-byte alignment,
│                              guest_invisible invariant — MUST NOT appear in EPT
│                              or NPT; leak = arbitrary x86_64 injection into VMX
│                              root / SVM host = instant hypervisor compromise).
│                              FexBlockHashTable (FEX_BLOCK_HASH_BUCKETS=8192,
│                              multiplicative hash 0x9E37_79B9_7F4A_7C15, 8-slot
│                              linear probe, ARM64 VA → x86_64 host PA + length).
│                              FexHostBindings (bump_base/size/used + FexSpinLock
│                              atomic test-and-set; alloc() with alignment).
│                              extern "C" libfex.a FFI: fex_init / fex_load_arm64_
│                              elf / fex_translate_block / fex_dispatch_block /
│                              fex_shutdown returning FexResult enum; stubbed when
│                              fex_linked Cargo feature is off so cargo check
│                              succeeds without upstream FEX in tree.
│                              AotPreTranslationQueue (FEX_AOT_QUEUE_CAPACITY=64,
│                              AOT_DEFAULT_LIBRARIES 21-entry list: libc / libm /
│                              libdl / libart / libartbase / libartpalette / libhwui
│                              / libgui / libsurfaceflinger / libui / libbinder /
│                              libbinder_ndk / libutils / libcutils / libandroid_
│                              runtime / libvulkan / libEGL / libGLESv2 / libsqlite /
│                              libssl / libcrypto) — pre-translated at first boot
│                              for ≤ 33 ms p99 frame target. LIBC_FORBIDDEN_SYMBOLS
│                              (malloc / calloc / realloc / free / pthread_* / fopen /
│                              fclose / fread / fwrite / printf / open / close / read /
│                              write / mmap / munmap / mprotect / exit / abort /
│                              __libc_start_main): link step rejects hypervisor.efi
│                              containing any entry. symbol_is_forbidden() helper.
│                              UART signatures: FEX_HELLO_WORLD_SIGNATURE
│                              ("Hello, AETHER") + FEX_BLOCK_TRANSLATED_SIGNATURE
│                              ("[fex] translated block at pc=") + FEX_DISPATCHER_
│                              STALL_SIGNATURE ("[fex] dispatcher stalled").
│                              FexIntegrationConfig (jit_cache_base_pa/size + bump_
│                              arena_base_pa/size + run_in_hypervisor + enable_aot;
│                              aether_defaults() puts JIT at 0x2_0000_0000, bump
│                              arena at 0x2_0100_0000; validate() rejects HostUserland
│                              Rejected/Unaligned*/JitCacheTooSmall/BumpArenaToo
│                              Small/JitBumpOverlap), FexIntegrationGate (fex_linked
│                              + allocator_bound + jit_cache_ready + arm64_elf_
│                              validated + hello_world_observed + no_libc_symbols;
│                              passes() / hypervisor_side_ready()), FexError
│                              (HostUserlandRejected enforces No-Boundary per Ch 3 /
│                              Unaligned* / NotX86_64Host / Elf* / FexLibNotLinked /
│                              FexInitFailed / TranslationFailed / DispatchFailed /
│                              GuestVisibleJitCache / LibcSymbolDetected / HelloWorld
│                              NotObserved), FexIntegrationPhase (NotStarted →
│                              FexLinked → AllocatorBound → JitCacheReady →
│                              ArmElfLoaded → BlockTranslated → HelloWorldExecuted →
│                              GatePassed; strictly ordered), FexIntegrationState
│                              (process_line() / record_block_translation() /
│                              record_block_cache_hit()), init_fex_integration() —
│                              8-step pipeline (cfg(target_arch="x86_64") variant;
│                              ARM build returns NotX86_64Host stub),
│                              process_elf_load() advances phase to ArmElfLoaded.
│                              Gate: ARM64 hello-world ELF executes via FEX on x86
│                              hardware; "Hello, AETHER" on PL011 UART; no libc /
│                              pthread symbols in hypervisor.efi; JIT cache region
│                              never present in guest EPT or NPT.
├── android_x86_userspace.rs ← ch53: Android on x86 — Userspace. Wires the AOSP x86
│                              vendor partition for three GPU paths — NVIDIA
│                              (nouveau + Mesa NVK), AMD (amdgpu + Mesa RADV), Intel
│                              Arc (xe + Mesa ANV). Android kernel believes it
│                              talks to real GPU silicon — no virtio, no paravirt.
│                              GpuVendor (Nvidia/Amd/IntelArc/Unsupported),
│                              GpuDetectionResult::classify() — runs against
│                              ECAM-read Vendor ID + Class Code + Sub-class.
│                              NVIDIA_VENDOR_ID=0x10DE, AMD_VENDOR_ID=0x1002,
│                              INTEL_VENDOR_ID=0x8086; PCI_CLASS_DISPLAY=0x03,
│                              PCI_SUBCLASS_VGA=0x00, PCI_SUBCLASS_3D=0x02 (Arc).
│                              Integrated Intel routes to IntegratedIntelNotSupported
│                              (ch53 covers discrete Arc only; not i915).
│                              DrmKernelDriver (Nouveau/Amdgpu/Xe) with module_name()
│                              + kconfig_symbol() (CONFIG_DRM_NOUVEAU/AMDGPU/XE all =m
│                              so ueventd loads exactly one). MesaIcd (vendor +
│                              library_path /vendor/lib64/hw/vulkan.*.so +
│                              icd_json_path /vendor/etc/vulkan/icd.d/*_icd.x86_64.json
│                              + api_version Vulkan 1.3.0 + aosp_package); MESA_ICD_NVK
│                              / MESA_ICD_RADV / MESA_ICD_ANV constants; MESA_ICDS_X86
│                              slice. IcdSelector::select()/select_or_fail() mirrors
│                              libvulkan loader walk. X86GpuPassthroughHook
│                              (bar_index/bar_pa/bar_size + TlbInvalidationKind
│                              {IntelInvept | AmdInvlpgaOrTlbCtl} + invalidation_ack;
│                              mark_invalidated()/is_safe()): every BAR mapping MUST
│                              acknowledge matching TLB invalidation (vtx::invept_
│                              single_context for Intel, svm::VmcbRegion::request_npt_
│                              tlb_flush for AMD — AMD has no INVNPT; AMD uses VMCB
│                              TLB_CTL FLUSH_ALL or INVLPGA per page). Forgetting
│                              invalidation = stale TLB = silent isolation break.
│                              X86_GKI_GPU_DEFCONFIG (14 entries: DRM=y +
│                              DRM_KMS_HELPER=y + DRM_NOUVEAU=m + DRM_AMDGPU=m +
│                              DRM_XE=m + DRM_FBDEV_EMULATION=y + FB=n + VT=n +
│                              SYNC_FILE=y + DMA_SHARED_BUFFER=y + DMABUF_HEAPS=y +
│                              MTRR=y + X86_PAT=y + AGP=n; each with silent_failure).
│                              X86_BOARD_CONFIG_VARS (6: BOARD_GPU_DRIVERS=nouveau
│                              amdgpu xe / TARGET_USES_GRALLOC4=true /
│                              TARGET_USES_HWC2=true / BOARD_USES_DRM_HWCOMPOSER=true
│                              / TARGET_ARCH=arm64 — image is ARM64, FEX translates).
│                              X86_PRODUCT_PACKAGES (14: vulkan.nouveau/radv/intel +
│                              graphics.allocator-V2/mapper/composer3 + libdrm{,_intel,
│                              _amdgpu,_nouveau} + drm_hwcomposer.aether + libEGL_mesa
│                              + libGLESv{1,2}_mesa). X86_SELINUX_RULES (8 TE rules:
│                              hal_graphics_composer / gralloc / untrusted_app /
│                              mediacodec / surfaceflinger / ueventd / init /
│                              dma_heap_device; each documents silent_failure).
│                              UART signatures: X86_UART_SIG_VULKAN_INIT / HWC_READY /
│                              HOME_SCREEN / GLMARK2_RUNNING / NPROC_ALL_CORES.
│                              AndroidX86Config (aether_defaults + validate: rejects
│                              MissingDrmDriver / MissingVulkanIcd / MissingIcdManifest
│                              / SelinuxAvcDenial / InvalidConfig), AndroidX86Gate
│                              (home_screen_visible + glmark2_es2_runs + vulkan_hw_
│                              active + nproc_all_cores + build_type_user +
│                              no_software_fallback; passes()/graphics_stack_live()),
│                              AndroidX86Error (NoDisplayController / UnknownGpuVendor
│                              / IntegratedIntelNotSupported / MissingDrmDriver /
│                              MissingVulkanIcd / BarMappingFailed /
│                              InvalidationNotAcknowledged — explicit error if
│                              INVEPT/INVLPGA forgotten / SoftwareRenderingForbidden —
│                              Swiftshader/Lavapipe rejected / SelinuxAvcDenial /
│                              Glmark2DidNotUseHardware / NprocDoesNotMatchHost),
│                              AndroidX86Phase (NotStarted → GpuVendorDetected →
│                              KernelModulesLoaded → DrmDeviceVisible → IcdSelected
│                              → VulkanInitialized → DrmHwcLaunched →
│                              HomeScreenRendered → GatePassed; strictly ordered),
│                              AndroidX86State (process_line() / record_bar_mapping()
│                              / mark_invalidation_acked() / all_invalidations_acked()
│                              / gate()), init_android_x86_userspace() — 9-step
│                              pipeline. pre_flight_summary() emits banner counts.
│                              Gate: home screen visible on Intel/AMD/NVIDIA hardware;
│                              glmark2-es2 with hardware Vulkan; nproc all cores;
│                              vkGetPhysicalDeviceProperties returns matching vendor's
│                              PCI ID; no software-rendering fallback;
│                              ro.build.type=user.
│
│   — Part XI: Installer & Management (Chapters 55–64) —
├── uefi_boot_selector.rs ← ch58: UEFI Boot Selector — 5-second countdown menu on GOP
│                              framebuffer. [A]ndroid / [W]indows / [S]ettings. Default
│                              stored in AetherDefaultTarget UEFI variable (NV+BS+RT).
│                              OTA rollback guard via AetherBootAttempt counter (u8;
│                              incremented pre-chainload; reset on "Hypervisor ready.").
│                              Fires rollback when count ≥ BOOT_ATTEMPT_ROLLBACK_THRESHOLD=3.
│                              Android chainloads \EFI\AETHER\hypervisor.efi; Windows
│                              chainloads \EFI\Microsoft\Boot\bootmgfw.efi; Settings is
│                              in-process (no chainload). BootTarget (Android/Windows/
│                              Settings; to/from_variable_byte; efi_path; display_name),
│                              BootAttemptCounter (from_raw/incremented/reset/
│                              is_rollback_needed), OtaRollbackGuard (boot_attempt_count/
│                              rollback_triggered/hypervisor_confirmed; on_hypervisor_ready/
│                              pre_chainload_count), SelectorConfig (timeout_secs=5/
│                              default_target=Android/selector_path/hypervisor_path/
│                              windows_bootmgr_path/rollback_threshold=3; aether_defaults
│                              +validate), SelectorGate (menu_displayed+android_chainloads
│                              +windows_chainloads+timeout_boots_default+
│                              default_target_persists; passes+android_path_ready),
│                              SelectorError (12 variants), SelectorPhase (9 phases,
│                              strictly ordered: NotStarted→SelectorStarted→VariablesRead
│                              →FramebufferReady→MenuDisplayed→TargetSelected→
│                              ChainloadInitiated→TargetRunning→GatePassed),
│                              SelectorState (process_line/gate/phase/rollback_guard/
│                              is_gate_passed), AETHER_VARIABLE_GUID, UEFI_VAR_ATTRS_NV_BS_RT,
│                              8 UART signature constants, contains_bytes(),
│                              init_uefi_boot_selector() 8-step pipeline.
│                              Gate: menu_displayed+android_chainloads+windows_chainloads
│                              +timeout_boots_default+default_target_persists.
├── secure_boot.rs      ← ch57: Secure Boot Integration — shim + MOK path. Installer
│                              generates RSA-2048 key pair, signs hypervisor.efi with PE
│                              Authenticode, writes MokNew (DER cert) + MokAuth (32 zero
│                              bytes) UEFI variables. Two-reboot enrollment: Reboot1 →
│                              MokManager → user approves key; Reboot2 → shim verifies
│                              signature → "Hypervisor ready." Users NEVER asked to disable
│                              Secure Boot (DisableSecureBootForbidden is a distinct error).
│                              AETHER_MOK_KEY_BITS=2048, MOK_AUTH_PASSWORDLESS=[0u8;32],
│                              MokKeyFormat::Der, MokEnrollmentRecord, SecureBootConfig,
│                              SecureBootGate, SecureBootError (10 variants), SecureBootPhase
│                              (8 phases), SecureBootState, 7 UART sig constants,
│                              init_secure_boot_integration() 8-step pipeline.
│                              Gate: shim_present + mok_enrolled + signature_verified +
│                              two_reboot_complete (hypervisor ran after enrollment reboot).
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

**Next chapters to implement:** 57 (Secure Boot Integration), 58 (UEFI Boot Selector), 59 (Setup Wizard GUI).

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
