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
pub mod smp;         // ch35: Multi-Core SMP — secondary core bring-up, spin table, PSCI CPU_ON
pub mod irq_forward;      // ch36: Physical IRQ Forwarding Validated — timer PPI + UART SPI enable,
                     //       IrqForwardConfig (INTID classification), IrqForwardingStats (per-
                     //       category delivery counters: timer/uart/maintenance/dropped),
                     //       setup_irq_forwarding() (enables INTID 27/30 per-core in GICR,
                     //       INTID 33 in GICD), record_forwarded_irq() (stats update from EL2
                     //       handler). Gate: /proc/interrupts ticks on timer + UART lines.

// Part IV — Devices (Chapters 11–16, 37)
pub mod passthrough; // ch11: PCIe device assignment — IOMMU groups, FLR, BAR mapping, SMMU STE
pub mod paravirt;    // ch12: paravirtualization — virtual modem (AT/3GPP), MEMS sensor suite (BMI160
                     //       Gaussian noise models), Phone Bridge Mode toggle
pub mod gpu;         // ch13: GPU partitioning via SR-IOV — VF enumeration, assignment, isolation
pub mod storage;     // ch14: storage partitioning — NVMe namespace isolation, SR-IOV, exclusive attachment
pub mod network;     // ch15: network partitioning — SR-IOV VFs, dedicated adapters, paravirt bridge fallback
pub mod usb;             // ch16: USB controller partitioning, xHCI passthrough, cross-partition input switching
pub mod usb_passthrough; // ch41: USB Controller and Input Switch — Functional. Implements the xHCI
                         //       hardware pipeline: BAR scan → Stage 2 DeviceRw mapping (IPA==PA),
                         //       SMMU STEs (stage2_only; write_ste enforces words 1–7 → DSB → word 0),
                         //       ECAM window mapping, BME enable, HCRST (halt → USBCMD.HCRST=1 →
                         //       poll HCRST=0), registry commit (smmu_configured=true/reset=Clean).
                         //       Event ring interception: poll_event_ring() reads Transfer Event TRBs
                         //       (type 32, completion code 1) from the EL2-private ring segment
                         //       (EL2_EVENT_RING_BUF, 16 TRBs); Normal TRB data buffer pointer carries
                         //       the 8-byte USB HID boot-protocol keyboard report; DC IVAC before read.
                         //       Input switch: execute_xhci_input_switch() — halt → HCRST → rewrite
                         //       SMMU STEs (new VMID/S2TTB) → execute_switch() ownership transfer →
                         //       mark_reset_clean(). Hardware-only trigger; SoftwareSwitchForbidden on
                         //       any hypercall path. UsbPassthroughConfig (ctrl_addr/ecam_window/
                         //       bar0_pa/vmid/s2ttb_pa/stream_ids/kind + validate()), UsbPassthroughGate
                         //       (keyboard_enumerated + input_switch_ready; passes() gate),
                         //       UsbPassthroughError (BarNotFound/MapFailed/SmmuStreamIdOutOfRange/
                         //       HcrstTimeout/HaltTimeout/RegistryError), XhciTrb (16B; cycle_bit/
                         //       trb_type/completion_code), XhciInterrupterState (dequeue_pa/cycle_bit/
                         //       segment), XhciErstEntry (64B; segment_base_pa/segment_size),
                         //       assign_xhci_controller() — 7-step pipeline, init_el2_event_ring(),
                         //       poll_event_ring(), execute_xhci_input_switch(). HidReport (8B).
                         //       Gate: USB keyboard works in Android; Ctrl+Alt+Tab switches input.
pub mod pcie_assignment;  // ch38: PCIe Device Assignment and SMMU Wiring — Functional.
                          //       EcamWindow (MCFG base + bus range; window_pa/window_size/bdf_config_pa),
                          //       ECAM_PER_BUS_SIZE (1MiB = 32×8×4KiB), map_ecam_window() (DeviceRw
                          //       identity map of config-space window into guest Stage 2), enable_bus_master()
                          //       (re-asserts BME=bit2 of Command reg cleared by FLR), PcieAssignmentConfig
                          //       (group/guest/addr/ecam_window/vmid/s2ttb_pa + validate()), PcieAssignmentGate
                          //       (ecam_mapped + device_visible_in_lspci; passes() gate), AssignmentError
                          //       (Passthrough(AssignError)/InvalidBusRange/EcamWindowOverflow),
                          //       assign_device_with_ecam() — full 7-step pipeline: IOMMU check → FLR →
                          //       core passthrough → ECAM window map → BAR map → SMMU STE (Stage-2-only) →
                          //       BME enable → registry commit. Gate: lspci in guest lists assigned device.
pub mod network_passthrough; // ch40: Network Passthrough — Functional. Probes NIC PF for SR-IOV
                         //       Extended Capability (ID=0x0010; walk from 0x100), validates
                         //       MaxVFs ≥ AETHER_NIC_NUM_VFS (2), writes NumVFs=2 then
                         //       VF_Enable|VF_MSE to SRIOV_CTRL (NumVFs BEFORE VF Enable per
                         //       PCIe §9.3.3.3.2), DSB ISH. Computes Android VF BDF
                         //       (PF+FirstVFOffset+0×VFStride). Maps VF 0 BARs as DeviceRw
                         //       (IPA==PA) into Stage 2. Configures SMMU STEs for both stream
                         //       IDs (stage2_only; write_ste enforces words 1–7 → DSB → word 0).
                         //       Maps ECAM window for VF config-space visibility. Asserts Bus
                         //       Master Enable (Command reg bit 2) on VF 0. Registers Android VF
                         //       in NetworkPartitionRegistry with locally-administered MAC.
                         //       NetworkPassthroughConfig (pf_addr/ecam_window/vmid/s2ttb_pa/
                         //       stream_ids/android_vf_mac), NetworkPassthroughGate
                         //       (mac_visible + dhcp_ready; passes() gate),
                         //       NetworkPassthroughError (SrIovCapNotFound/InsufficientVfs/
                         //       NoVfBarsFound/MapFailed/SmmuStreamIdOutOfRange/MacError),
                         //       assign_nic_vf() — 10-step pipeline. AETHER_NIC_NUM_VFS=2.
                         //       Gate: ip addr shows interface with valid MAC; DHCP succeeds.
pub mod gpu_sriov;       // ch39: GPU SR-IOV — Functional Enable. Reads SR-IOV Extended Capability
                         //       (ID=0x0010) from Adreno GPU PF via ECAM extended config space
                         //       (walk from 0x100), validates MaxVFs ≥ 2, writes NumVFs=2 then
                         //       VF_Enable|VF_MSE to SRIOV_CTRL (NumVFs BEFORE VF Enable per
                         //       PCIe §9.3.3.3.2), DSB ISH. Computes VF BDFs (PF+FirstVFOffset+
                         //       n×VFStride). Maps each VF's BARs into Stage 2 as DeviceRw
                         //       (IPA==PA, via scan_bars on VF BDF). Configures SMMU STE per VF
                         //       StreamID (stage2_only; write_ste enforces words 1–7 → DSB → word 0).
                         //       Maps ECAM config-space window so Android DRM reads Vendor ID
                         //       0x17CB (Qualcomm). Registers both VFs in GpuPartitionRegistry.
                         //       GpuSrIovConfig (pf_addr/ecam_window/vmid/s2ttb_pa/stream_ids),
                         //       GpuSrIovGate (vendor_id_visible + vf_bars_mapped; passes() gate),
                         //       GpuSrIovError (SrIovCapNotFound/InsufficientVfs/NoVfBarsFound/
                         //       MapFailed/RegistryError/StreamIdOutOfRange), compute_vf_addr(),
                         //       assign_gpu_vfs() — 7-step pipeline. QUALCOMM_VENDOR_ID=0x17CB.
                         //       Gate: cat /sys/class/drm/card0/device/vendor shows 0x17cb in Android.
pub mod nvme_namespace;  // ch37: NVMe Namespace — Functional. PCIe ECAM NVMe controller enumeration,
                         //       Admin SQ/CQ bring-up, Identify Controller (CNS=0x01, OACS[3] check),
                         //       Namespace Management Create (opcode 0x0D, sel=0x00, NSZE/NCAP/FLBAS),
                         //       Namespace Attachment (opcode 0x15, sel=0x00, CNTLID=0 controller list).
                         //       NvmeNamespaceConfig (bdf/bar0_pa/nsid/size_lbas), NvmeNamespaceGate
                         //       (nvme_list_shows_namespace + dd_write_succeeds). D-cache maintenance
                         //       (DC CIVAC/IVAC) around every DMA buffer. AdminSqe (64 bytes, CDW0–15),
                         //       AdminCqe (16 bytes, phase/status/result). Static 4096-aligned queue
                         //       buffers in BSS. Gate: nvme list shows namespace; dd to /dev/nvme0n1
                         //       exits 0.

// Part V — The Windows Partition (Chapters 17–18)
pub mod windows;     // ch17: ARM Tier Windows partition config — CPUID hypervisor leaves, Hyper-V
                     //       enlightenments, Secure Boot chain, crash dump sizing, inbox-driver policy
pub mod acpi;        // ch18: Windows ACPI tables — RSDP, XSDT, MADT (ARM GIC entries), GTDT, IORT,
                     //       FADT (hardware-reduced); checksums, byte-precise table builders

// Part VI — The Android Partition (Chapters 19–45)
pub mod bootloader;  // ch19: Android bootloader — AVB2 VBMeta verification, boot image header v3/v4,
                     //       A/B slot selection (BCB), rollback protection, kernel command line builder,
                     //       BootloaderLockState (Locked/Unlocked/Orange), KernelLaunchParams
pub mod kernel;      // ch20: Linux kernel — ARM64 Image header parser (64-byte header, 0x644D5241 magic),
                     //       FDT/DTB builder (DtbBuilder: structure+strings blocks, big-endian tokens),
                     //       GKI mandatory config tracker (GkiConfig), KernelState phase machine
                     //       (Init→ImageValidated→DtbPlaced→ConfigVerified→ReadyToLaunch),
                     //       AndroidDtbConfig + build_android_dtb() for the full partition device tree
pub mod avb_boot;    // ch43: Android Bootloader — Functional AVB. NVMe I/O queue setup (Create I/O CQ
                     //       opcode 0x05, Create I/O SQ opcode 0x01 via admin queue), I/O Read (opcode
                     //       0x02) for misc/vbmeta/boot partitions. AVB2 pipeline: BCB parse → A/B slot
                     //       select → VBMeta key check → signature structural check → rollback index
                     //       enforce → BootImageHeader v3/v4 parse → kernel cmdline build →
                     //       KernelLaunchParams for ERET. AvbAdminState (bar0/sq_tail/cq_head/cq_phase/
                     //       cid/dstrd; from_ch37_defaults), AvbPartitionLayout (misc/vbmeta_a/vbmeta_b/
                     //       boot_a/boot_b; aether_defaults), AvbBootConfig (nsid/layout/trust_anchor/
                     //       rollback_store/lock_state/kernel_load_ipa/dtb_ipa/initrd_ipa + validate()),
                     //       AvbBootGate (header_parsed/rollback_accepted/cmdline_built/eret_ready;
                     //       passes()), AvbBootResult (launch + gate), AvbBootError enum,
                     //       run_avb_boot_pipeline() — 10-step pipeline. NvmeIoSqe (64B), NvmeIoCqe (16B).
                     //       Static 4KiB-aligned BSS queue buffers. D-cache maintenance (DC CIVAC/IVAC)
                     //       around every SQE/CQE/data buffer access.
                     //       Gate: AVB2 verified Android slot boots; rollback_index enforced.
pub mod kernel_defconfig; // ch44: Android Kernel and Device Tree. AETHER_GKI_DEFCONFIG — complete aarch64
                     //       GKI defconfig (48 CONFIG_ entries: tmpfs/devtmpfs/unix/binderfs/ext4-security/
                     //       psi/seccomp/keys/dm-crypt/netfilter/namespaces/cgroups/pstore-ram + disabled:
                     //       VT/MAGIC_SYSRQ/CPU_BIG_ENDIAN/ANDROID_LOW_MEMORY_KILLER). Critical omissions
                     //       that cause 70% of Android boot failures documented per entry. DefconfigEntry
                     //       (name/DefconfigValue: Enabled/Module/Disabled), AetherGkiDefconfigValidator
                     //       (apply: records all entries to GkiConfig; gate: AetherDefconfigGate),
                     //       AetherDefconfigGate (all_required_enabled + gki_satisfied; passes()).
                     //       ProductionDtbExtras (initrd_start/end_ipa/uart_clock_hz/ramoops_base/size/
                     //       record_size; aether_defaults; validate()), ProductionDtbGate
                     //       (dtb_built/fstab_present/initrd_addresses_present/ramoops_present; passes()),
                     //       ProductionDtbError (RamoopsSizeNotPowerOfTwo/TooSmall/RecordSizeNotPowerOfTwo/
                     //       SizeTooSmallForRecords/InitrdRangeInvalid/Kernel(KernelError)),
                     //       build_production_android_dtb() — full production DTB: all ch20 nodes +
                     //       clock-frequency on PL011 + linux,initrd-{start,end} in /chosen +
                     //       /firmware/android/fstab/{system,vendor} (first_stage_mount/slotselect/avb) +
                     //       /reserved-memory/ramoops@ (compatible=ramoops/reg/record-size/console-size/
                     //       no-map). ProdDtbBuilder (8KiB struct / 1KiB strings capacity).
                     //       Gate: build_production_android_dtb() returns Ok; dtc -I dtb -O dts confirms
                     //       all four required node paths present; logcat shows Zygote launch.
pub mod adreno_render;  // ch46: Adreno GPU — Rendering. Integrates Mesa freedreno (Turnip Vulkan +
                        //       freedreno OpenGL ES) into the AOSP vendor partition. Wires Gralloc
                        //       and HWC (drm_hwcomposer) HALs for the Adreno VF assigned in ch39.
                        //       GpuDriverSource (MesaFreedrenoOpen / QualcommProprietary),
                        //       GrallocVersion (Hidl4 / Aidl2), HwcImplementation (DrmHwcomposer /
                        //       QualcommProprietary / SoftwareFallback), DisplayPipeline
                        //       (KernelModeSetting / VirtioGpuQemu), VulkanIcdConfig
                        //       (icd_json_path = /vendor/etc/vulkan/icd.d/freedreno.json,
                        //       library_path = /vendor/lib64/hw/vulkan.freedreno.so, api_version
                        //       1.3.0), GrallocHalConfig (render_node_path=/dev/dri/renderD128,
                        //       dma_heap_path=/dev/dma_heap/system), AdrenoRenderConfig
                        //       (aether_defaults: MesaFreedrenoOpen + DrmHwcomposer + Vulkan 1.3;
                        //       validate: rejects proprietary/SoftwareFallback/wrong-path/old-VkAPI),
                        //       AdrenoRenderError (ProprietaryDriverNotRedistributable/
                        //       HwcIncompatibleWithDriverSource/SoftwareFallbackForbiddenInProduction/
                        //       VulkanApiVersionTooOld/GrallocRenderNodePathEmpty/
                        //       GrallocDmaHeapPathEmpty/VulkanIcdPathNotInVendor/
                        //       VulkanLibraryNotInVendor), AdrenoRenderPhase (NotStarted→
                        //       DrmDriverBound→GrallocReady→HwcReady→VulkanReady→
                        //       RenderingActive→GatePassed), AdrenoRenderGate
                        //       (vulkan_shows_adreno + glmark2_es2_runs + youtube_1080p_plays;
                        //       passes() gate; gpu_visible() partial check),
                        //       AdrenoRenderState (phase + gate; process_line()/gate()),
                        //       ADRENO_RENDER_DEFCONFIG (12 entries: DRM/DRM_KMS_HELPER/DRM_MSM/
                        //       SYNC_FILE/DMA_SHARED_BUFFER/DMABUF_HEAPS/DMABUF_HEAPS_SYSTEM/
                        //       DRM_DISPLAY_CONNECTOR/MEDIA_SUPPORT/VIDEO_DEV/MEDIA_CONTROLLER
                        //       required + CONFIG_FB disabled; each with silent_failure doc),
                        //       ADRENO_SELINUX_RULES (7 TE rules: gralloc_default/
                        //       hal_graphics_composer_default/system_server/untrusted_app/
                        //       mediacodec; each with silent_failure doc),
                        //       ADRENO_AOSP_BUILD_VARS (5: BOARD_GPU_DRIVERS/
                        //       BOARD_USES_DRM_HWCOMPOSER/TARGET_USES_GRALLOC4/
                        //       TARGET_USES_HWC2/BOARD_USES_OPENGL_RENDERER),
                        //       ADRENO_PRODUCT_PACKAGES (8: allocator-V2-service/mapper/
                        //       composer/libEGL_mesa/libGLESv1_mesa/libGLESv2_mesa/
                        //       vulkan.freedreno/libvulkan_freedreno),
                        //       RENDER_UART_* signatures (5 byte-pattern constants),
                        //       init_adreno_render_pipeline(), contains_bytes().
                        //       Gate: vulkaninfo shows Adreno 0x17CB; glmark2-es2 runs;
                        //       YouTube plays 1080p with hardware decode.
pub mod virtual_sensors_modem; // ch47: Virtual Sensors and Modem — Live.
pub mod app_compat;      // ch49: App Compatibility Validation. Automated test harness that installs
                         //       the top-1000 Android APKs, runs UI Automator smoke tests against each
                         //       one, and records pass/fail. Fixes compatibility bugs found during the
                         //       run. AppTestCategory (13 categories: Messaging/SocialMedia/WebBrowsing/
                         //       MediaPlayback/MapsNavigation/Productivity/Shopping/Photography/
                         //       LightGaming/HeavyGaming/Utilities/HealthFitness/BankingPayment;
                         //       is_attestation_sensitive/uses_sensors/is_gpu_intensive),
                         //       SmokeTestStep (Launch/WaitForUi/TapFirstInteractive/AssertProcessAlive/
                         //       AssertNoCrashDialog/ForceStop; SMOKE_TEST_SEQUENCE 6-step fixed sequence;
                         //       SMOKE_TEST_WAIT_MS=5000), UiAutomatorOutcome (Passed/TimedOut/Crashed/
                         //       CrashDialogShown/InstallFailed; is_passing/needs_triage),
                         //       CompatFailureKind (AttestationRequired/MissingGmsService/CameraHalAbsent/
                         //       NfcRequired/BluetoothLeRequired/WidevineLevelOneRequired/
                         //       HypervisorDetected/FingerprintMismatch/NativeAbiMismatch/ArtJitAnomaly/
                         //       AndroidIdInconsistency/Unknown; is_attestation_only/requires_fix),
                         //       CompatBugSeverity (Critical/Major/Minor/Cosmetic; must_be_resolved),
                         //       CompatBugFix (SystemPropertyOverride/ManifestFeatureStub/CameraStubHal/
                         //       WidevineL3Config/SelinuxCompatRule/ArtJitWorkaround/AndroidIdPersistence/
                         //       MicrogGsfNoopDefer; description()), CompatBugRecord (package/category/
                         //       failure/severity/fix/resolved; needs_resolution()),
                         //       COMPAT_KNOWN_BUG_FIXES (8-entry table; all resolved=true),
                         //       COMPAT_SELINUX_RULES (4 TE rules: untrusted_app→aether_virtual_device/
                         //       aether_camera_stub_device/mediadrm_device/proc_cpuinfo; each with
                         //       silent_failure doc), COMPAT_PRODUCT_PACKAGES (4: AetherCompatHarness/
                         //       aether_camera_stub/aether_compat_props/AuroraStore),
                         //       AppCompatConfig (top_app_count=1000/required_pass_rate_tenths=950/
                         //       max_consecutive_timeouts=10/smoke_test_timeout_ms=5000 + validate()),
                         //       AppCompatGate (report_meets_target+no_unresolved_compat_bugs+
                         //       build_type_user; passes()), AppCompatPhase (NotStarted→HarnessReady→
                         //       ApksInstalled→SmokeTestsRunning→BugsTriaged→GatePassed),
                         //       AppCompatState (phase/apps_passing/apps_failing/apps_attestation/
                         //       consecutive_timeouts/bugs_resolved/build_type_user/gate_passed;
                         //       new()/process_line()/gate()/mark_harness_ready()/should_abort()/
                         //       total_tested()), UART_SIG_COMPAT_PASS/FAIL/ATTEST/HARNESS_INSTALLED/
                         //       HARNESS_COMPLETE/BUGS_RESOLVED/GATE_PASS/GATE_FAIL/FATAL_EXCEPTION/
                         //       ANR/BUILD_TYPE_USER byte-pattern constants, init_app_compat_validation(),
                         //       AppCompatError (ZeroAppCount/PassRateExceedsOneThousand/ZeroPassRate/
                         //       ZeroTimeoutLimit/ZeroSmokeTimeout), contains_bytes().
                         //       Gate: ≥950/1000 apps pass (attestation-only excluded); all Critical/
                         //       Major compat bugs resolved; ro.build.type=user.
pub mod phone_bridge;    // ch48: Phone Bridge Mode — End to End. Connects a real Android phone via
                         //       USB-C and routes its live sensor data and OEM identity strings to
                         //       the AETHER Android partition. Layers AETHER Bridge Protocol
                         //       (magic 0xAE_CA_FE_48; FRAME_TYPE_SENSOR/IDENTITY/HANDSHAKE) on
                         //       top of ADB WRTE USB bulk transfers. PhoneSensorFrame (accel/gyro/
                         //       mag + timestamp_lo; is_valid() rejects NaN/Inf), PhoneIdentity
                         //       (manufacturer/model/bootloader 64-byte ASCII fields; is_loaded()),
                         //       parse_bridge_frame() (magic check → type dispatch → payload decode;
                         //       BridgeFrameResult: Sensor/Identity/Handshake/Discard/TruncatedPayload/
                         //       VersionMismatch/MalformedPayload). ToggleBuffer (virtual_accel/gyro/
                         //       mag + bridge_accel/gyro/mag caches; read_accel/gyro/mag(mode) prefers
                         //       active source then falls back to the other → gap-free toggle guarantee;
                         //       update_virtual()/update_bridge()/has_bridge_sample()/bridge_frame_count).
                         //       PhoneBridgeReader (BRIDGE_RX_BUF_MAX accumulation buffer; process_rx_bytes
                         //       → parse loop with re-sync on magic mismatch; partial frame carry-forward;
                         //       handshake_complete / reset()). Global EL2 state: AETHER_TOGGLE_BUF /
                         //       AETHER_BRIDGE_READER / AETHER_PHONE_IDENTITY (addr_of_mut! safe).
                         //       on_bridge_usb_data() — entry from xHCI event ring (ch41).
                         //       bridge_read_accel/gyro/mag(mode) — called by HVC SENSOR_READ handler.
                         //       update_virtual_cache() — keeps ToggleBuffer fresh even when bridge active.
                         //       PhoneBridgeConfig (xhci_bar0_pa/stream_ids/stream_id_count + validate()),
                         //       PhoneBridgeGate (toggle_source_changes + no_timestamp_gap + identity_loaded;
                         //       passes()), PhoneBridgeError (InvalidUsbBase/NoStreamIds/TooManyStreamIds),
                         //       PhoneBridgePhase (NotStarted→UsbReady→AdbConnected→SensorStreamActive→
                         //       IdentityLoaded→GatePassed), UART_SIG_BRIDGE_* byte-pattern constants,
                         //       PhoneBridgeState (process_line()/gate()/phase()), BRIDGE_KERNEL_CONFIG
                         //       (4 entries: USB_CONFIGFS/F_FS/G_ANDROID/F_ACCESSORY), BRIDGE_SELINUX_RULES
                         //       (3 TE rules: aether_bridge_service/hal_sensors_default/system_server),
                         //       BRIDGE_PRODUCT_PACKAGES (3: aether_bridge_service/libaetherbridge/
                         //       AetherCompanionApp.apk), init_phone_bridge() — resets global state +
                         //       validates config → PhoneBridgePhase::UsbReady.
                         //       Gate: toggle ON/OFF changes data source with no gap in stream. AETHER HVC vendor range
                     //       (0x8600_0001–0x8600_0006): GET_VERSION, BRIDGE_MODE_GET/SET,
                     //       SENSOR_READ, UPDATE_STAGE (stub), DIAG_LOG_READ (stub).
                     //       SENSOR_READ HVC: x1=HvcSensorId (0=Accel/1=Gyro/2=Mag/3=Prox);
                     //       returns x0=0 (ok), x1=x_bits, x2=y_bits, x3=z_bits (f32 bit
                     //       patterns). Paravirt modem: 4 KiB shared page at AETHER_MODEM_IPA
                     //       (0x0B00_0000); layout: cmd_ready(u32)/cmd_len(u32)/cmd_buf(256B)
                     //       at 0x000, resp_ready(u32)/resp_len(u32)/resp_buf(256B) at 0x200.
                     //       Polled on every WFI exit via poll_modem_on_wfi() → VirtualModem::
                     //       process_command() (ch12 AT command set + AT+CPIN?/AT+CIMI for
                     //       No-SIM state). VirtualSensorsAndModemConfig (imei/prng_seed/
                     //       modem_ipa/sensor_odr_hz=100 + validate()), VirtualSensorsAndModemGate
                     //       (accel_visible + gyro_visible + mag_visible + no_sim_shown; passes()),
                     //       VirtualSensorsAndModemError (InvalidImei/InvalidOdr/ModemIpaNotAligned/
                     //       ZeroPrngSeed), VirtualSensorsAndModemPhase (NotStarted→HvcRegistered→
                     //       SensorHalStarted→ModemAttached→GatePassed), VirtualSensorsAndModemState
                     //       (process_line()/gate()/phase()), UART_SIG_* byte pattern constants,
                     //       is_aether_hvc(), dispatch_aether_hvc(), poll_modem_on_wfi(),
                     //       init_virtual_sensors_and_modem(). SENSOR_KERNEL_CONFIG (4 entries:
                     //       HVC_DRIVER/MISC_DEVICES/IIO/IIO_BUFFER), SENSOR_SELINUX_RULES (3 TE
                     //       rules: hal_sensors_default/sensorservice/system_server→aether_device),
                     //       SENSOR_PRODUCT_PACKAGES (3: sensors HAL service + aether_ril).
                     //       Gate: dumpsys sensorservice shows accel/gyro/mag; phone shows No SIM.
pub mod userspace_boot; // ch45: Android Userspace Boot. UART-based boot failure diagnostics,
                     //       SELinux policy violation detection, and HAL startup failure
                     //       classification for the Android partition boot sequence.
                     //       UserspaceBootPhase (KernelHandoff→FirstStageInit→SecondStageInit→
                     //       SystemDaemonsStarted→HalsRegistered→ZygoteReady→HomeScreenRendered),
                     //       BootFailureKind (FirstStageMountFailed/InitBinaryNotFound/
                     //       SelinuxPolicyLoadFailed/SelinuxAvcDenial/HalStartupFailed/
                     //       ZygoteCrashLoop/SystemServerCrash/SurfaceFlingerCrash/SmmuFault),
                     //       SelinuxViolationKind (GrallocDmaBuf/SensorsIioDevice/AetherHwbinder/
                     //       VoldNvmeDevice/UeventdDevNode/Other), SelinuxViolation + required_fix(),
                     //       SelinuxPolicyFix (AllowGrallocDmaBuf/AllowSensorsIioDevice/
                     //       BinderCallAetherHal/AllowVoldNvme/AllowUeventdDevNode/ReviewRequired)
                     //       + te_source(), HalName (GraphicsAllocator/GraphicsComposer/Sensors/
                     //       Audio/Radio/Health/Power) + interface_name()/binary_path()/
                     //       is_critical_path(), HalStartupFailure + HalFailureCause
                     //       (DeviceNodeMissing/SmmuFault/SelinuxDenial/BinaryNotFound/
                     //       RegistrationFailed), UART log signature constants
                     //       (UART_SIG_FIRST_STAGE_FAIL/INIT_NOT_FOUND/SELINUX_FAIL/AVC_DENIAL/
                     //       ZYGOTE_READY/HOME_SCREEN/SETTINGS/BUILD_TYPE_USER/SMMU_FAULT +
                     //       AVC sub-signatures), scan_uart_line() (byte-pattern matching,
                     //       no heap, no regex), contains_bytes() (O(n×m) window scan),
                     //       UserspaceBootConfig (uart_pa/max_zygote_restarts/require_all_hals/
                     //       expected_build_type; aether_defaults(); validate()),
                     //       UserspaceBootError (InvalidUartAddress/BuildTypeNotUser/
                     //       FirstStageFailed/SelinuxPolicyFailed/CriticalHalFailed/
                     //       ZygoteCrashLoop/SystemServerCrashed/BootStalled),
                     //       UserspaceBootState (phase/zygote_restarts/avc_denial_count/
                     //       home_screen_seen/settings_seen/build_type_user_seen/last_failure;
                     //       new()/process_line()/gate()), UserspaceBootGate
                     //       (home_screen_rendered + settings_opens + build_type_user; passes()),
                     //       AetherSepolicyFix (kind/source_file/te_rule),
                     //       AETHER_SEPOLICY_FIXES (5-entry table: gralloc/sensors/hwbinder/
                     //       vold/ueventd TE rules), init_userspace_boot_diagnostics() pipeline.
                     //       Gate: home screen renders; Settings opens; ro.build.type=user.
pub mod aosp;        // ch21: AOSP And The Android Userspace — PartitionLayout (A/B Android partitions,
                     //       size validation against NVMe namespace), TrebleManifest (HalInterface:
                     //       HIDL/AIDL HAL declarations, REQUIRED_HALS check), DeviceProperties
                     //       (AndroidProperty key/value, ro.build.type=user invariant, ro.adb.secure/
                     //       ro.secure enforcement), ArtConfig (Dalvik heap sizing: start/limit/max,
                     //       GC utilization), AospDeviceConfig (full validated configuration aggregate)
pub mod aosp_build;  // ch42: AOSP Device Configuration and Build — DeviceMk (PRODUCT_PACKAGES,
                     //       PRODUCT_COPY_FILES, PRODUCT_PROPERTY_OVERRIDES), BoardConfigMk
                     //       (TARGET_ARCH=arm64, BoardPartitionSizes, SelinuxPolicyType::Enforcing,
                     //       AvbKeySource, avb_enabled), AndroidBp (SoongModule HAL services +
                     //       gralloc + prebuilts), MicrogIntegration (GmsCore/FakeStore/GsfProxy/
                     //       UnifiedNlp at source level; SignatureSpoofingPolicy::Enabled required),
                     //       MicrogLocationBackend (MLS/Beacondb/GpsOnly), LunchTarget
                     //       (aether_arm64-user; AETHER_LUNCH_TARGET), OutputImage (Boot/System/
                     //       Vendor/Vbmeta/Userdata required; Dtbo/Product optional),
                     //       ImageGateState (produced/non_empty/within_size_limit; passes()),
                     //       AospBuildGate (lunch_target_registered + avb_verified + all required
                     //       images pass(); gate: lunch aether_arm64-user && m produces bootable
                     //       partition images), AospBuildConfig (device_mk/board_config/android_bp/
                     //       microg/lunch_target + validate(); default_aether() constructor).
                     //       Gate: lunch aether_arm64-user && m → boot.img system.img vendor.img
                     //       vbmeta.img userdata.img; avbtool verify_image passes.
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
pub mod roadmap_phase5; // ch33: Phase Five — Polish And Release. LicenseChoice
                        //       (GplV2/Mit/Apache2/CcBySa acceptable; Proprietary rejected),
                        //       LicenseAssignment (RECOMMENDED: hypervisor=GplV2, AOSP=Apache2,
                        //       docs=CcBySa, installer=Mit — AOSP must be Apache2 to inherit),
                        //       InstallerCapabilities (REQUIRED: auto_detect_tier +
                        //       partition_nvme + enroll_secure_boot_keys +
                        //       register_uefi_boot_entry + flash_android + recovery_image —
                        //       skipping Secure Boot enrollment weakens the security baseline),
                        //       DocumentationDeliverables (REQUIRED: user_manual +
                        //       contributor_guide + architecture_doc + troubleshooting_guide +
                        //       phase6_roadmap + coverage_report + security_disclosure),
                        //       SupportInfrastructure (REQUIRED: issue_tracker +
                        //       security_mailbox + code_review_workflow + cla_or_dco +
                        //       public_ci_dashboard), CrossPartitionInputSwitch (PRODUCTION:
                        //       hardware_trigger_active + software_trigger_rejected +
                        //       xhci_reset_on_reassignment + smmu_required_for_switch — every
                        //       ch16 invariant re-enforced), SustainabilityPlan (at least one
                        //       channel — commercial revenue OR contributor base — must be
                        //       viable; both_channels ideal), Phase5Milestone (9-step:
                        //       Phase4GateClosed → LicenseAssigned → InstallerFeatureComplete
                        //       → InputSwitchValidated → ConfigurationToolsShipped →
                        //       DocumentationDelivered → SupportInfrastructureLive →
                        //       ReleaseCandidatePublished → PublicReleaseShipped),
                        //       Phase5TimelineEstimate (README_LOWER 6→12→18 / README_UPPER
                        //       12→24→36 months), Phase5GateCriterion (7 booleans + no
                        //       workaround), Phase5Config (aggregate validate),
                        //       Phase5Summary (phase5_complete: closes the roadmap)

// Part X — x86 Tier (Chapters 50–54)
pub mod vtx;         // ch50: Intel VT-x Foundation — VMX detection (CPUID.1.ECX[5]),
                     //       IA32_FEATURE_CONTROL enable/lock, VMXON (enter VMX root mode),
                     //       VMCLEAR + VMPTRLD (per-vCPU VMCS initialization), VMCS host/guest
                     //       state fields (exact encodings from Intel SDM §24.11.2), VM-execution
                     //       controls (primary/secondary/exit/entry), EPT 4-level setup with WB
                     //       RAM and UC MMIO leaf entries, EPTP construction (WB memtype, 4-level
                     //       walk), INVEPT single-context after every EPT mapping change,
                     //       UNRESTRICTED_GUEST in secondary controls (allows pre-paging guest),
                     //       VtxExitReason decoder (EXIT_REASON HLT=12/EPT_VIOLATION=48/CPUID=10),
                     //       handle_vm_exit() dispatcher (HLT: advance RIP by 1, record gate;
                     //       CPUID: advance RIP by 2; EPT_VIOLATION: terminate),
                     //       VmxCpuFeatures (vmx_supported/true_controls_supported),
                     //       Ia32FeatureControlMsr (locked/vmx_outside_smx; enable_and_lock()),
                     //       VmxBasicMsr (revision_id/vmxon_region_size/true_controls),
                     //       VmxonRegion (4 KiB, 4 KiB-aligned; revision_id in dword 0),
                     //       VmcsRegion (4 KiB, 4 KiB-aligned; bit 31 cleared — no shadow VMCS),
                     //       EptTable (512 × u64, 4 KiB-aligned), Eptp (WB memtype, 4-level walk,
                     //       from_pml4_pa()), EptLeafEntry (normal_ram=WB/device_mmio=UC),
                     //       EptTableEntry (pointing_to()), InveptDescriptor,
                     //       invept_single_context(), VmcsGuestConfig (long_mode/real_mode),
                     //       vmcs_write_host_state() (CR0/CR3/CR4/RSP/RIP/EFER/PAT/segments),
                     //       vmcs_write_guest_state() (64-bit long mode or real mode entry),
                     //       vmcs_write_exec_controls() (EPT+UNRESTRICTED_GUEST+HLT_EXIT),
                     //       VtxFoundationConfig (vmxon_pa/vmcs_pa/ept_pml4_pa/kernel_entry_pa/
                     //       guest_ram_base/guest_ram_size/mmio_base/mmio_size/guest_64bit;
                     //       aether_defaults()/validate()),
                     //       VtxFoundationGate (hlt_handled+vmresume_succeeded+vmxon_succeeded+
                     //       ept_active+!ept_violation_seen; passes()),
                     //       VtxFoundationPhase (NotStarted→VmxDetected→FeatureControlSet→
                     //       VmxonComplete→VmcsInitialized→EptActive→GatePassed),
                     //       VtxFoundationState (record_hlt_exit()/gate()/is_gate_passed()),
                     //       VtxError (VmxNotSupported/FeatureControlLocked/VmxonFailed/
                     //       VmclearFailed/VmptrldFailed/VmwriteHostStateFailed/
                     //       VmwriteGuestStateFailed/VmwriteControlsFailed/Unaligned*/
                     //       ZeroGuestRamSize/VmlaunchFailed/VmresumeFailed),
                     //       init_vtx_foundation() — 8-step pipeline.
                     //       Gate: first VM exit EXIT_REASON=12 (HLT); VMRESUME returns to guest.
                     //       Raw x86 helpers: rdmsr/wrmsr/read_cr0/read_cr3/read_cr4/write_cr4,
                     //       vmwrite/vmread/vmxon/vmclear/vmptrld (all cfg(target_arch="x86_64")).
                     //       All non-x86_64 targets compile as no-ops (ARM64 host build safe).

// Support
pub mod uart;        // PL011 UART driver — polled TX for boot diagnostics
pub mod guest_stub;  // Test 2: minimal bare-metal ARM64 stub guest (prints "Guest EL1 OK", halts)
pub mod linux_boot;  // ch34: Linux kernel boot — DtbBuilder wiring, FDT emit, KernelState phase
                     //       machine, ERET to ARM64 GKI entry point. Gate: GKI boots to shell.
