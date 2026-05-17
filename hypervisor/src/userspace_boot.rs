// ch45: Android Userspace Boot
//
// Implements UART-based boot failure diagnostics, SELinux policy violation
// detection, and HAL startup failure classification for the Android partition.
//
// ── What This Module Does ─────────────────────────────────────────────────────
//
// ch44 (kernel_defconfig.rs) built the production Android DTB and GKI defconfig
// required for Android init to start. This chapter covers what happens after
// the kernel hands control to /init from the initrd — the Android userspace boot
// sequence from first-stage init through Zygote to a rendered home screen.
//
// Android's boot sequence has five observable phases, each with characteristic
// UART log signatures that indicate success or failure:
//
//   Phase 1 — First-stage init (from initrd)
//     Reads /firmware/android fstab DTB node, mounts /system and /vendor,
//     transitions to /init in the system partition. Failure signature:
//       "Failed to mount required partitions in first stage"
//
//   Phase 2 — Second-stage init (from /system/bin/init)
//     Parses init.rc and init.<device>.rc, starts ueventd, mounts tmpfs on
//     /dev, creates device nodes. Failure signature:
//       "Failed to find init binary: execv(/system/bin/init) failed"
//
//   Phase 3 — Core system daemons
//     logd, servicemanager, hwservicemanager, vold. SELinux policy is loaded
//     here. Failure signature (SELinux):
//       "SELinux: failed to load policy from /system/etc/selinux/precompiled_sepolicy"
//
//   Phase 4 — HAL bringup
//     gralloc, sensors, audio, camera, radio HALs register with
//     hwservicemanager. Failure signatures:
//       "HIDL HAL android.hardware.graphics.allocator@4.0 failed to start"
//       "AIDL HAL android.hardware.sensors.ISensors failed to start"
//
//   Phase 5 — Zygote and system_server
//     Zygote pre-forks JVM; system_server starts; SurfaceFlinger launches;
//     home screen Activity renders. Success signature:
//       "Zygote: Accepting command socket connections"
//       "ActivityManager: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.HOME]}"
//
// ── SELinux Policy in AETHER ─────────────────────────────────────────────────
//
// SELinux is always enforcing (ro.build.type=user invariant from ch21/ch42).
// The most common boot-blocking AVC denials in AETHER are:
//
//   1. gralloc.aether domain — ION/DMA-BUF access
//      avc: denied { ioctl } for pid=gralloc comm="gralloc" path="/dev/dma_heap/system"
//      Fix: allow gralloc_default dma_heap_device:chr_file { open read ioctl };
//
//   2. sensors HAL — /dev/iio:device0 access
//      avc: denied { read } for pid=sensors comm="sensors" path="/dev/iio:device0"
//      Fix: allow hal_sensors_default iio_device:chr_file { open read write ioctl };
//
//   3. aether_hwbinder — binder IPC between AETHER HAL and system_server
//      avc: denied { call } for scontext=system_server tcontext=hal_aether_default
//      Fix: binder_call(system_server, hal_aether_default)
//
//   4. vold — /dev/block/nvme device access
//      avc: denied { read write } for pid=vold comm="vold" path="/dev/block/nvme0n1p5"
//      Fix: allow vold nvme_device:blk_file { open read write ioctl };
//
// ── HAL Startup Failure Causes ───────────────────────────────────────────────
//
// AETHER HALs fail for three distinct reasons:
//
//   1. Missing device node — the HAL driver binary exists but the kernel did
//      not create the /dev node. Root cause: missing CONFIG_ option (ch44)
//      or SELinux denial on the device node creation (ueventd AVC).
//
//   2. SMMU fault — the HAL's DMA operation crosses a Stage 2 boundary.
//      Root cause: BAR map or SMMU STE configured with wrong VMID (ch39/ch40/ch41).
//      Log signature: "arm-smmu: [S2] fault addr 0x..." followed by HAL crash.
//
//   3. Wrong SELinux domain — the HAL executable is labelled with the default
//      domain (untrusted_app or unlabeled) instead of its HAL-specific domain.
//      Root cause: missing file_contexts entry in AETHER sepolicy.
//      Fix: add label for /vendor/bin/hw/<hal_binary> in file_contexts.
//
// ── UART Log Diagnostic Protocol ────────────────────────────────────────────
//
// EL2 reads the PL011 UART ring buffer (QEMU MMIO at 0x0900_0000) during each
// VM exit triggered by Android's UART write. The diagnostic engine scans each
// line for the failure signatures above and updates the boot phase state.
//
// Scanning is purely pattern-based: byte-by-byte comparison against a static
// table of known failure strings. No heap allocation; all buffers are static.
//
// ── Gate ─────────────────────────────────────────────────────────────────────
//
//   UserspaceBootGate.passes() requires all three:
//     home_screen_rendered  — ActivityManager logged HOME intent start
//     settings_opens        — ActivityManager logged Settings Activity start
//     build_type_user       — UART log shows ro.build.type=user
//
// References:
//   source.android.com/devices/architecture/boot/init-first-stage
//   source.android.com/devices/architecture/boot/init
//   source.android.com/security/selinux/implement
//   source.android.com/devices/architecture/hal
//   source.android.com/devices/tech/dalvik/configure

#[allow(unused_imports)]
use core::ptr::{addr_of, addr_of_mut};

// ─────────────────────────────────────────────────────────────────────────────
// Boot phase enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Observed Android userspace boot phase.
///
/// Phases are sequential. A boot failure terminates progress at the phase
/// in which it occurs; later phases are never reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserspaceBootPhase {
    /// Kernel handed control to /init from initrd. Awaiting first-stage log.
    KernelHandoff,
    /// First-stage init is running. Mounting /system and /vendor.
    FirstStageInit,
    /// First-stage succeeded. Second-stage init is running from /system.
    SecondStageInit,
    /// Core system daemons active (logd, servicemanager, vold).
    SystemDaemonsStarted,
    /// HAL services (gralloc, sensors, audio) registered with hwservicemanager.
    HalsRegistered,
    /// Zygote accepted connections; system_server booted.
    ZygoteReady,
    /// SurfaceFlinger rendered the home screen.
    HomeScreenRendered,
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot failure classification
// ─────────────────────────────────────────────────────────────────────────────

/// Category of Android userspace boot failure detected from UART log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFailureKind {
    /// First-stage init could not mount /system or /vendor.
    /// Root cause: missing /firmware/android/fstab in DTB (ch44) or
    /// AVB dm-verity rejection (ch43).
    FirstStageMountFailed,
    /// First-stage init could not find /init binary on the system partition.
    /// Root cause: system.img missing /init, or system partition not mounted.
    InitBinaryNotFound,
    /// SELinux policy load failed. Android aborts because ro.build.type=user
    /// requires enforcing mode, and enforcing mode requires a loaded policy.
    /// Root cause: CONFIG_EXT4_FS_SECURITY not set (ch44) or missing
    /// precompiled_sepolicy in system partition.
    SelinuxPolicyLoadFailed,
    /// An SELinux AVC denial blocked a critical operation.
    /// The inner value encodes which denial category was observed.
    SelinuxAvcDenial(SelinuxViolationKind),
    /// A required HAL service failed to start.
    HalStartupFailed(HalName),
    /// Zygote crashed or restarted more than twice.
    ZygoteCrashLoop,
    /// system_server exited before registering all system services.
    SystemServerCrash,
    /// SurfaceFlinger exited before rendering the first frame.
    SurfaceFlingerCrash,
    /// An SMMU fault was logged — DMA from a HAL crossed a Stage 2 boundary.
    SmmuFault,
    /// Unknown failure pattern not matching any known signature.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// SELinux violation kinds
// ─────────────────────────────────────────────────────────────────────────────

/// Category of SELinux AVC denial observed in the UART log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxViolationKind {
    /// gralloc HAL denied access to DMA-BUF heap device.
    GrallocDmaBuf,
    /// Sensors HAL denied access to IIO character device.
    SensorsIioDevice,
    /// AETHER HAL domain denied binder call from system_server.
    AetherHwbinder,
    /// vold denied read/write access to NVMe block device.
    VoldNvmeDevice,
    /// ueventd denied creation of /dev node for a HAL device.
    UeventdDevNode,
    /// An AVC denial not matching any AETHER-specific pattern.
    Other,
}

/// A concrete SELinux AVC denial captured from the UART log.
#[derive(Debug, Clone, Copy)]
pub struct SelinuxViolation {
    /// Category of this denial.
    pub kind: SelinuxViolationKind,
    /// The boot phase during which this denial occurred.
    pub phase: UserspaceBootPhase,
    /// Whether this denial was observed in an enforcing context (always true
    /// for AETHER — ro.build.type=user requires enforcing).
    pub enforcing: bool,
}

impl SelinuxViolation {
    /// Returns the required SELinux type-enforcement rule that fixes this denial.
    pub fn required_fix(&self) -> SelinuxPolicyFix {
        match self.kind {
            SelinuxViolationKind::GrallocDmaBuf =>
                SelinuxPolicyFix::AllowGrallocDmaBuf,
            SelinuxViolationKind::SensorsIioDevice =>
                SelinuxPolicyFix::AllowSensorsIioDevice,
            SelinuxViolationKind::AetherHwbinder =>
                SelinuxPolicyFix::BinderCallAetherHal,
            SelinuxViolationKind::VoldNvmeDevice =>
                SelinuxPolicyFix::AllowVoldNvme,
            SelinuxViolationKind::UeventdDevNode =>
                SelinuxPolicyFix::AllowUeventdDevNode,
            SelinuxViolationKind::Other =>
                SelinuxPolicyFix::ReviewRequired,
        }
    }
}

/// SELinux TE rule required to fix a specific AVC denial in AETHER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxPolicyFix {
    /// `allow gralloc_default dma_heap_device:chr_file { open read write ioctl };`
    /// Required for gralloc.aether to allocate GPU render targets via DMA-BUF.
    AllowGrallocDmaBuf,
    /// `allow hal_sensors_default iio_device:chr_file { open read write ioctl };`
    /// Required for the sensors HAL to access virtual IIO sensor devices.
    AllowSensorsIioDevice,
    /// `binder_call(system_server, hal_aether_default)`
    /// Required for system_server to call into AETHER-specific HAL services.
    BinderCallAetherHal,
    /// `allow vold nvme_device:blk_file { open read write ioctl };`
    /// Required for vold to manage the Android NVMe namespace partitions.
    AllowVoldNvme,
    /// `allow ueventd aether_device:chr_file { open read write create };`
    /// Required for ueventd to create /dev nodes for AETHER virtual devices.
    AllowUeventdDevNode,
    /// The AVC denial does not match a known AETHER pattern.
    /// Manual review of the UART log is required to write the correct TE rule.
    ReviewRequired,
}

impl SelinuxPolicyFix {
    /// Returns the TE source text for the policy rule.
    ///
    /// Returns None for ReviewRequired (no fixed text — depends on context).
    pub fn te_source(&self) -> Option<&'static str> {
        match self {
            Self::AllowGrallocDmaBuf =>
                Some("allow gralloc_default dma_heap_device:chr_file { open read write ioctl };"),
            Self::AllowSensorsIioDevice =>
                Some("allow hal_sensors_default iio_device:chr_file { open read write ioctl };"),
            Self::BinderCallAetherHal =>
                Some("binder_call(system_server, hal_aether_default)"),
            Self::AllowVoldNvme =>
                Some("allow vold nvme_device:blk_file { open read write ioctl };"),
            Self::AllowUeventdDevNode =>
                Some("allow ueventd aether_device:chr_file { open read write create };"),
            Self::ReviewRequired =>
                None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HAL name enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Android HAL service names required by the AETHER Android partition.
///
/// Each entry corresponds to a hwservicemanager or AIDL service registration.
/// All HALs listed here must be running for Zygote to start successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalName {
    /// `android.hardware.graphics.allocator@4.0::IAllocator`
    /// gralloc HAL — buffer allocation for SurfaceFlinger and GPU.
    /// AETHER implementation: gralloc.aether (ch42).
    GraphicsAllocator,
    /// `android.hardware.graphics.composer@2.4::IComposer`
    /// HWC HAL — hardware composition (passes-through to DRM/KMS in ch46).
    GraphicsComposer,
    /// `android.hardware.sensors@2.1::ISensors`
    /// Sensors HAL — accelerometer/gyro/magnetometer (paravirt in ch47).
    Sensors,
    /// `android.hardware.audio@7.0::IDevicesFactory`
    /// Audio HAL — PCM output for media playback.
    Audio,
    /// `android.hardware.radio@1.6::IRadio`
    /// Radio HAL — modem interface (virtual modem from ch12/paravirt).
    Radio,
    /// `android.hardware.health@2.1::IHealth`
    /// Health HAL — battery status reporting (always-full in AETHER).
    Health,
    /// `android.hardware.power@1.3::IPower`
    /// Power HAL — CPU performance hints from Android's PowerManagerService.
    Power,
}

impl HalName {
    /// HIDL/AIDL interface name for this HAL.
    pub fn interface_name(&self) -> &'static str {
        match self {
            Self::GraphicsAllocator => "android.hardware.graphics.allocator@4.0::IAllocator",
            Self::GraphicsComposer  => "android.hardware.graphics.composer@2.4::IComposer",
            Self::Sensors           => "android.hardware.sensors@2.1::ISensors",
            Self::Audio             => "android.hardware.audio@7.0::IDevicesFactory",
            Self::Radio             => "android.hardware.radio@1.6::IRadio",
            Self::Health            => "android.hardware.health@2.1::IHealth",
            Self::Power             => "android.hardware.power@1.3::IPower",
        }
    }

    /// Vendor binary path for this HAL's server process.
    pub fn binary_path(&self) -> &'static str {
        match self {
            Self::GraphicsAllocator => "/vendor/bin/hw/android.hardware.graphics.allocator@4.0-service.aether",
            Self::GraphicsComposer  => "/vendor/bin/hw/android.hardware.graphics.composer@2.4-service.aether",
            Self::Sensors           => "/vendor/bin/hw/android.hardware.sensors@2.1-service.aether",
            Self::Audio             => "/vendor/bin/hw/android.hardware.audio@7.0-service.aether",
            Self::Radio             => "/vendor/bin/hw/android.hardware.radio@1.6-service.aether",
            Self::Health            => "/vendor/bin/hw/android.hardware.health@2.1-service",
            Self::Power             => "/vendor/bin/hw/android.hardware.power@1.3-service",
        }
    }

    /// Whether this HAL must be running before Zygote can start.
    ///
    /// GraphicsAllocator and Health are critical path — Zygote will not
    /// start without them. Others are started concurrently and may arrive
    /// after Zygote is already running.
    pub fn is_critical_path(&self) -> bool {
        matches!(self, Self::GraphicsAllocator | Self::Health)
    }
}

/// A HAL startup failure event detected from UART log output.
#[derive(Debug, Clone, Copy)]
pub struct HalStartupFailure {
    /// Which HAL failed to start.
    pub hal: HalName,
    /// Root cause of the failure.
    pub cause: HalFailureCause,
}

/// Root cause of a HAL startup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalFailureCause {
    /// The /dev node for the HAL's hardware interface was not present.
    /// Root cause: missing kernel CONFIG_ or SELinux ueventd denial.
    DeviceNodeMissing,
    /// An SMMU fault blocked the HAL's DMA operation.
    /// Root cause: wrong VMID or unmapped IPA in Stage 2 (ch39/ch40/ch41).
    SmmuFault,
    /// SELinux denied the HAL's access to its device or service.
    /// Root cause: missing TE rule in AETHER sepolicy (ch42).
    SelinuxDenial(SelinuxViolationKind),
    /// The HAL binary was not found at the expected path.
    /// Root cause: missing PRODUCT_PACKAGES entry in device.mk (ch42).
    BinaryNotFound,
    /// hwservicemanager rejected the registration (version mismatch).
    RegistrationFailed,
}

// ─────────────────────────────────────────────────────────────────────────────
// UART log signature matching
//
// Each entry is a byte slice that, when found as a substring of a UART log
// line, identifies a specific boot event.  Matching is byte-for-byte; no
// regex, no heap.
// ─────────────────────────────────────────────────────────────────────────────

/// UART log signature for first-stage init partition mount failure.
pub const UART_SIG_FIRST_STAGE_FAIL: &[u8] =
    b"Failed to mount required partitions in first stage";

/// UART log signature for init binary not found.
pub const UART_SIG_INIT_NOT_FOUND: &[u8] =
    b"execv(/system/bin/init) failed";

/// UART log signature for SELinux policy load failure.
pub const UART_SIG_SELINUX_FAIL: &[u8] =
    b"SELinux: failed to load policy";

/// UART log signature for an SELinux AVC denial.
pub const UART_SIG_AVC_DENIAL: &[u8] = b"avc:  denied";

/// UART log signature for Zygote accepting connections (success indicator).
pub const UART_SIG_ZYGOTE_READY: &[u8] =
    b"Zygote: Accepting command socket connections";

/// UART log signature for home screen Activity start (success indicator).
pub const UART_SIG_HOME_SCREEN: &[u8] =
    b"cat=[android.intent.category.HOME]";

/// UART log signature for Settings Activity start (success indicator).
pub const UART_SIG_SETTINGS: &[u8] =
    b"com.android.settings/.Settings";

/// UART log signature for the ro.build.type property value (success indicator).
pub const UART_SIG_BUILD_TYPE_USER: &[u8] = b"ro.build.type=user";

/// UART log signature for SMMU fault.
pub const UART_SIG_SMMU_FAULT: &[u8] = b"arm-smmu";

/// UART log signature for gralloc DMA-BUF AVC.
pub const UART_SIG_AVC_GRALLOC: &[u8] = b"dma_heap_device";

/// UART log signature for sensors IIO AVC.
pub const UART_SIG_AVC_SENSORS: &[u8] = b"iio_device";

/// UART log signature for HAL startup failure.
pub const UART_SIG_HAL_FAILED: &[u8] = b"failed to start";

/// Scan a UART log line (byte slice, no null terminator required) for a
/// known failure or success signature.
///
/// Returns the matched `BootFailureKind` for failure signatures, or
/// `None` if the line does not match any known pattern.
///
/// On success signatures (Zygote ready, home screen, build type), the
/// caller should update the boot phase and gate state rather than recording
/// a failure.
pub fn scan_uart_line(line: &[u8]) -> Option<BootFailureKind> {
    if contains_bytes(line, UART_SIG_FIRST_STAGE_FAIL) {
        return Some(BootFailureKind::FirstStageMountFailed);
    }
    if contains_bytes(line, UART_SIG_INIT_NOT_FOUND) {
        return Some(BootFailureKind::InitBinaryNotFound);
    }
    if contains_bytes(line, UART_SIG_SELINUX_FAIL) {
        return Some(BootFailureKind::SelinuxPolicyLoadFailed);
    }
    if contains_bytes(line, UART_SIG_SMMU_FAULT) {
        return Some(BootFailureKind::SmmuFault);
    }
    if contains_bytes(line, UART_SIG_AVC_DENIAL) {
        let kind = if contains_bytes(line, UART_SIG_AVC_GRALLOC) {
            SelinuxViolationKind::GrallocDmaBuf
        } else if contains_bytes(line, UART_SIG_AVC_SENSORS) {
            SelinuxViolationKind::SensorsIioDevice
        } else if contains_bytes(line, b"nvme_device") {
            SelinuxViolationKind::VoldNvmeDevice
        } else if contains_bytes(line, b"hal_aether") {
            SelinuxViolationKind::AetherHwbinder
        } else if contains_bytes(line, b"ueventd") {
            SelinuxViolationKind::UeventdDevNode
        } else {
            SelinuxViolationKind::Other
        };
        return Some(BootFailureKind::SelinuxAvcDenial(kind));
    }
    if contains_bytes(line, UART_SIG_HAL_FAILED) {
        // Identify which HAL failed by matching the interface name substring.
        let hal = if contains_bytes(line, b"graphics.allocator") {
            HalName::GraphicsAllocator
        } else if contains_bytes(line, b"graphics.composer") {
            HalName::GraphicsComposer
        } else if contains_bytes(line, b"sensors") {
            HalName::Sensors
        } else if contains_bytes(line, b"audio") {
            HalName::Audio
        } else if contains_bytes(line, b"radio") {
            HalName::Radio
        } else if contains_bytes(line, b"health") {
            HalName::Health
        } else {
            HalName::Power
        };
        return Some(BootFailureKind::HalStartupFailed(hal));
    }
    None
}

/// Returns true if `haystack` contains `needle` as a contiguous subsequence.
///
/// Pure byte comparison — no heap, no regex.  O(n × m) worst case;
/// acceptable for UART log lines which are bounded to ~256 bytes.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// UserspaceBootConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the Android userspace boot diagnostic pipeline.
///
/// Holds per-deployment parameters used when interpreting UART log output
/// and when constructing the UserspaceBootGate.
#[derive(Debug, Clone, Copy)]
pub struct UserspaceBootConfig {
    /// IPA of the PL011 UART MMIO region (read-only from EL2).
    /// QEMU virt: 0x0900_0000.
    pub uart_pa: u64,
    /// Maximum number of Zygote restarts before declaring ZygoteCrashLoop.
    /// Production default: 2.
    pub max_zygote_restarts: u32,
    /// Whether to treat non-critical HAL failures as gate-blocking.
    /// Production: false (only GraphicsAllocator and Health are critical path).
    pub require_all_hals: bool,
    /// Expected ro.build.type string. Always "user" in AETHER.
    pub expected_build_type: &'static [u8],
}

impl UserspaceBootConfig {
    /// Default production configuration for AETHER on QEMU virt.
    pub const fn aether_defaults() -> Self {
        Self {
            uart_pa: 0x0900_0000,
            max_zygote_restarts: 2,
            require_all_hals: false,
            expected_build_type: b"user",
        }
    }

    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), UserspaceBootError> {
        if self.uart_pa == 0 {
            return Err(UserspaceBootError::InvalidUartAddress);
        }
        if self.uart_pa & 0xFFF != 0 {
            return Err(UserspaceBootError::InvalidUartAddress);
        }
        if self.expected_build_type != b"user" {
            return Err(UserspaceBootError::BuildTypeNotUser);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the Android userspace boot diagnostic pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserspaceBootError {
    /// The UART PA is zero or not page-aligned.
    InvalidUartAddress,
    /// expected_build_type is not "user" (AETHER invariant violation).
    BuildTypeNotUser,
    /// First-stage init failed to mount /system or /vendor.
    FirstStageFailed,
    /// SELinux policy load failed — policy binary missing or corrupt.
    SelinuxPolicyFailed,
    /// A critical HAL (GraphicsAllocator or Health) failed to start.
    CriticalHalFailed(HalName),
    /// Zygote crashed more than max_zygote_restarts times.
    ZygoteCrashLoop,
    /// system_server crashed before registering all services.
    SystemServerCrashed,
    /// Boot did not reach ZygoteReady within the expected phase sequence.
    BootStalled(UserspaceBootPhase),
}

// ─────────────────────────────────────────────────────────────────────────────
// UserspaceBootState — mutable runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable state accumulated while processing UART log lines.
///
/// Updated by `process_uart_line()` as each line arrives from EL2's
/// UART intercept handler.
#[derive(Debug)]
pub struct UserspaceBootState {
    /// Current boot phase.
    pub phase: UserspaceBootPhase,
    /// Number of times Zygote has restarted (crash indicator).
    pub zygote_restarts: u32,
    /// Number of AVC denials observed since boot started.
    pub avc_denial_count: u32,
    /// Whether the home screen HOME intent has been logged.
    pub home_screen_seen: bool,
    /// Whether the Settings Activity start has been logged.
    pub settings_seen: bool,
    /// Whether `ro.build.type=user` was observed in the UART output.
    pub build_type_user_seen: bool,
    /// Last failure kind observed (None if no failure).
    pub last_failure: Option<BootFailureKind>,
}

impl UserspaceBootState {
    /// Initial state at kernel handoff.
    pub const fn new() -> Self {
        Self {
            phase: UserspaceBootPhase::KernelHandoff,
            zygote_restarts: 0,
            avc_denial_count: 0,
            home_screen_seen: false,
            settings_seen: false,
            build_type_user_seen: false,
            last_failure: None,
        }
    }

    /// Process a single UART log line.
    ///
    /// Updates phase, counters, and last_failure based on known signatures.
    /// Called from the EL2 UART intercept handler for each newline-terminated
    /// byte sequence received from the Android partition.
    pub fn process_line(&mut self, line: &[u8]) {
        // Success signatures — advance phase and record gate conditions.
        if contains_bytes(line, UART_SIG_ZYGOTE_READY) {
            self.phase = UserspaceBootPhase::ZygoteReady;
        }
        if contains_bytes(line, UART_SIG_HOME_SCREEN) {
            self.phase = UserspaceBootPhase::HomeScreenRendered;
            self.home_screen_seen = true;
        }
        if contains_bytes(line, UART_SIG_SETTINGS) {
            self.settings_seen = true;
        }
        if contains_bytes(line, UART_SIG_BUILD_TYPE_USER) {
            self.build_type_user_seen = true;
        }
        // Phase advances from log signatures.
        if contains_bytes(line, b"init: first stage") {
            if self.phase < UserspaceBootPhase::FirstStageInit {
                self.phase = UserspaceBootPhase::FirstStageInit;
            }
        }
        if contains_bytes(line, b"init: second stage") || contains_bytes(line, b"Starting services...") {
            if self.phase < UserspaceBootPhase::SecondStageInit {
                self.phase = UserspaceBootPhase::SecondStageInit;
            }
        }
        if contains_bytes(line, b"servicemanager: Waiting for") {
            if self.phase < UserspaceBootPhase::SystemDaemonsStarted {
                self.phase = UserspaceBootPhase::SystemDaemonsStarted;
            }
        }
        if contains_bytes(line, b"hwservicemanager") && contains_bytes(line, b"registered") {
            if self.phase < UserspaceBootPhase::HalsRegistered {
                self.phase = UserspaceBootPhase::HalsRegistered;
            }
        }
        // Zygote restart detection.
        if contains_bytes(line, b"Zygote") && contains_bytes(line, b"SIGKILL") {
            self.zygote_restarts = self.zygote_restarts.saturating_add(1);
        }

        // Failure signatures — record but do not halt phase advance.
        if let Some(failure) = scan_uart_line(line) {
            if matches!(failure, BootFailureKind::SelinuxAvcDenial(_)) {
                self.avc_denial_count = self.avc_denial_count.saturating_add(1);
            }
            self.last_failure = Some(failure);
        }
    }

    /// Derive a `UserspaceBootGate` from the current accumulated state.
    pub fn gate(&self, cfg: &UserspaceBootConfig) -> UserspaceBootGate {
        UserspaceBootGate {
            home_screen_rendered: self.home_screen_seen,
            settings_opens: self.settings_seen,
            build_type_user: self.build_type_user_seen,
            zygote_stable: self.zygote_restarts <= cfg.max_zygote_restarts,
            avc_denial_count: self.avc_denial_count,
            final_phase: self.phase,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UserspaceBootGate
// ─────────────────────────────────────────────────────────────────────────────

/// Gate for Android userspace boot (Chapter 45).
///
/// passes() requires all three mandatory conditions:
///   - home_screen_rendered: ActivityManager logged HOME intent
///   - settings_opens: ActivityManager logged Settings Activity start
///   - build_type_user: UART log showed ro.build.type=user
///
/// Additional informational fields (zygote_stable, avc_denial_count,
/// final_phase) are recorded for diagnostics but do not gate boot.
///
/// How to verify manually:
///   1. Boot Android in QEMU: ./qemu/run-ch34.sh (with full Android images)
///   2. Wait for home screen — UART shows "cat=[android.intent.category.HOME]"
///   3. Open Settings: "adb shell am start -n com.android.settings/.Settings"
///      UART shows Settings Activity start
///   4. Run: adb shell getprop ro.build.type → must print "user"
///   5. Check avc_denial_count — ideally 0; any denial requires a sepolicy fix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserspaceBootGate {
    /// ActivityManager logged a HOME intent (home screen rendered).
    pub home_screen_rendered: bool,
    /// ActivityManager logged a Settings Activity start.
    pub settings_opens: bool,
    /// UART log showed `ro.build.type=user` (not userdebug or eng).
    pub build_type_user: bool,
    /// Zygote has not exceeded the restart threshold.
    pub zygote_stable: bool,
    /// Number of AVC denials observed. 0 is ideal; non-zero requires sepolicy.
    pub avc_denial_count: u32,
    /// Boot phase reached at the time the gate was evaluated.
    pub final_phase: UserspaceBootPhase,
}

impl UserspaceBootGate {
    /// Returns true when all three mandatory gate conditions are met.
    ///
    /// A passing gate means Android has booted to a functional home screen
    /// with the correct production build type.
    pub fn passes(&self) -> bool {
        self.home_screen_rendered && self.settings_opens && self.build_type_user
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Run the Android userspace boot diagnostic pipeline.
///
/// Validates the configuration, constructs initial state, and returns the
/// initial `UserspaceBootState` ready for UART line processing.
///
/// The caller is expected to call `state.process_line(line)` for each UART
/// log line received from the Android partition, then call `state.gate(cfg)`
/// when boot is complete (or when a timeout is reached) to evaluate whether
/// the gate passes.
///
/// # Steps
///
///   1. Validate `cfg` — fail early if UART address is zero or build type
///      is not "user".
///   2. Return `UserspaceBootState::new()` — all fields at initial values.
///
/// # Example
///
/// ```ignore
/// let cfg = UserspaceBootConfig::aether_defaults();
/// let mut state = init_userspace_boot_diagnostics(&cfg)?;
/// // ... for each UART line arriving from Android:
/// state.process_line(uart_line_bytes);
/// // ... at boot completion or timeout:
/// let gate = state.gate(&cfg);
/// assert!(gate.passes());
/// ```
pub fn init_userspace_boot_diagnostics(
    cfg: &UserspaceBootConfig,
) -> Result<UserspaceBootState, UserspaceBootError> {
    cfg.validate()?;
    Ok(UserspaceBootState::new())
}

// ─────────────────────────────────────────────────────────────────────────────
// SELinux policy fix table
//
// Exhaustive list of AETHER-specific SELinux TE rules required to boot
// Android userspace cleanly from first-stage init to home screen.
//
// Each entry pairs a ViolationKind (derived from AVC denial UART parsing)
// with the TE source text that must be added to
// device/aether/aether_arm64/sepolicy/*.te
// ─────────────────────────────────────────────────────────────────────────────

/// Complete AETHER sepolicy fix table.
///
/// An `AetherSepolicyFix` associates a denial category with the TE source
/// text that must be present in the AETHER sepolicy directory.  All entries
/// in this table must be applied before UserspaceBootGate can achieve zero
/// AVC denials.
#[derive(Debug, Clone, Copy)]
pub struct AetherSepolicyFix {
    /// Denial category this fix addresses.
    pub kind: SelinuxViolationKind,
    /// Source file name (relative to device/aether/aether_arm64/sepolicy/).
    pub source_file: &'static str,
    /// TE rule text.
    pub te_rule: &'static str,
}

/// All SELinux policy fixes required for AETHER Android userspace boot.
pub const AETHER_SEPOLICY_FIXES: &[AetherSepolicyFix] = &[
    AetherSepolicyFix {
        kind: SelinuxViolationKind::GrallocDmaBuf,
        source_file: "hal_graphics_allocator_aether.te",
        te_rule: "allow gralloc_default dma_heap_device:chr_file { open read write ioctl };",
    },
    AetherSepolicyFix {
        kind: SelinuxViolationKind::SensorsIioDevice,
        source_file: "hal_sensors_aether.te",
        te_rule: "allow hal_sensors_default iio_device:chr_file { open read write ioctl };",
    },
    AetherSepolicyFix {
        kind: SelinuxViolationKind::AetherHwbinder,
        source_file: "hal_aether.te",
        te_rule: "binder_call(system_server, hal_aether_default)",
    },
    AetherSepolicyFix {
        kind: SelinuxViolationKind::VoldNvmeDevice,
        source_file: "vold_aether.te",
        te_rule: "allow vold nvme_device:blk_file { open read write ioctl };",
    },
    AetherSepolicyFix {
        kind: SelinuxViolationKind::UeventdDevNode,
        source_file: "ueventd_aether.te",
        te_rule: "allow ueventd aether_device:chr_file { open read write create };",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_bytes_basic() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(!contains_bytes(b"hello world", b"missing"));
        assert!(contains_bytes(b"hello world", b""));
        assert!(!contains_bytes(b"short", b"much longer needle"));
    }

    #[test]
    fn scan_uart_line_first_stage_fail() {
        let line = b"init: Failed to mount required partitions in first stage";
        assert_eq!(scan_uart_line(line), Some(BootFailureKind::FirstStageMountFailed));
    }

    #[test]
    fn scan_uart_line_selinux_fail() {
        let line = b"SELinux: failed to load policy from /system/etc/selinux/precompiled_sepolicy";
        assert_eq!(scan_uart_line(line), Some(BootFailureKind::SelinuxPolicyLoadFailed));
    }

    #[test]
    fn scan_uart_line_avc_gralloc() {
        let line = b"avc:  denied { ioctl } for pid=234 comm=\"gralloc\" path=\"/dev/dma_heap_device\"";
        assert_eq!(
            scan_uart_line(line),
            Some(BootFailureKind::SelinuxAvcDenial(SelinuxViolationKind::GrallocDmaBuf))
        );
    }

    #[test]
    fn scan_uart_line_hal_failed() {
        let line = b"HIDL HAL android.hardware.graphics.allocator@4.0 failed to start";
        assert_eq!(
            scan_uart_line(line),
            Some(BootFailureKind::HalStartupFailed(HalName::GraphicsAllocator))
        );
    }

    #[test]
    fn scan_uart_line_no_match() {
        let line = b"init: Loading module /lib/modules/virtio_blk.ko";
        assert_eq!(scan_uart_line(line), None);
    }

    #[test]
    fn boot_state_processes_success_signatures() {
        let mut state = UserspaceBootState::new();
        state.process_line(UART_SIG_ZYGOTE_READY);
        assert_eq!(state.phase, UserspaceBootPhase::ZygoteReady);

        state.process_line(UART_SIG_HOME_SCREEN);
        assert_eq!(state.phase, UserspaceBootPhase::HomeScreenRendered);
        assert!(state.home_screen_seen);

        state.process_line(UART_SIG_SETTINGS);
        assert!(state.settings_seen);

        state.process_line(UART_SIG_BUILD_TYPE_USER);
        assert!(state.build_type_user_seen);
    }

    #[test]
    fn gate_passes_when_all_conditions_met() {
        let mut state = UserspaceBootState::new();
        state.home_screen_seen = true;
        state.settings_seen = true;
        state.build_type_user_seen = true;

        let cfg = UserspaceBootConfig::aether_defaults();
        let gate = state.gate(&cfg);
        assert!(gate.passes());
    }

    #[test]
    fn gate_fails_without_home_screen() {
        let mut state = UserspaceBootState::new();
        state.settings_seen = true;
        state.build_type_user_seen = true;

        let cfg = UserspaceBootConfig::aether_defaults();
        let gate = state.gate(&cfg);
        assert!(!gate.passes());
    }

    #[test]
    fn gate_fails_without_build_type_user() {
        let mut state = UserspaceBootState::new();
        state.home_screen_seen = true;
        state.settings_seen = true;

        let cfg = UserspaceBootConfig::aether_defaults();
        let gate = state.gate(&cfg);
        assert!(!gate.passes());
    }

    #[test]
    fn config_validate_rejects_misaligned_uart() {
        let cfg = UserspaceBootConfig {
            uart_pa: 0x0900_0001, // not page-aligned
            ..UserspaceBootConfig::aether_defaults()
        };
        assert_eq!(cfg.validate(), Err(UserspaceBootError::InvalidUartAddress));
    }

    #[test]
    fn config_validate_rejects_userdebug_build_type() {
        let cfg = UserspaceBootConfig {
            expected_build_type: b"userdebug",
            ..UserspaceBootConfig::aether_defaults()
        };
        assert_eq!(cfg.validate(), Err(UserspaceBootError::BuildTypeNotUser));
    }

    #[test]
    fn hal_name_critical_path() {
        assert!(HalName::GraphicsAllocator.is_critical_path());
        assert!(HalName::Health.is_critical_path());
        assert!(!HalName::Sensors.is_critical_path());
        assert!(!HalName::Audio.is_critical_path());
    }

    #[test]
    fn selinux_fix_te_source_present_for_all_known_kinds() {
        for fix in AETHER_SEPOLICY_FIXES {
            let violation = SelinuxViolation {
                kind: fix.kind,
                phase: UserspaceBootPhase::SystemDaemonsStarted,
                enforcing: true,
            };
            let policy_fix = violation.required_fix();
            assert!(
                policy_fix != SelinuxPolicyFix::ReviewRequired,
                "Missing TE source for {:?}", fix.kind
            );
            assert!(policy_fix.te_source().is_some());
        }
    }

    #[test]
    fn init_pipeline_validates_config() {
        let cfg = UserspaceBootConfig::aether_defaults();
        let result = init_userspace_boot_diagnostics(&cfg);
        assert!(result.is_ok());
    }
}
