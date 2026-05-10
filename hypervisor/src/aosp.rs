// ch21: AOSP And The Android Userspace
//
// AETHER's Android partition runs a full AOSP-derived Android stack above
// the Linux kernel. This module encodes the device configuration that the
// AOSP build system requires and that AETHER's EL2 code validates before
// handing control to the Android partition:
//
//   1. Android partition layout
//      Each logical partition (boot, system, vendor, userdata, …) maps to
//      a region of the NVMe namespace assigned to Android (ch14). Partition
//      sizes are declared here and validated against the NVMe namespace size
//      at build time. Incorrect sizes produce confusing boot failures.
//
//   2. Treble HAL manifest
//      Android Treble (introduced in Android 8) separates the AOSP framework
//      from device-specific hardware abstraction layer (HAL) code. Each HAL
//      is a versioned interface defined in HIDL or AIDL. AETHER declares which
//      HAL interfaces it implements in a Treble manifest (vintf/manifest.xml).
//      The Android framework checks this manifest at runtime and refuses to
//      start services whose HAL is not declared.
//
//      HIDL (HAL Interface Definition Language) — legacy format, versions as
//      @major.minor (e.g., android.hardware.sensors@2.1). Transport is either
//      passthrough (HAL in-process) or hwbinder (HAL in separate process).
//
//      AIDL (Android Interface Definition Language) — modern format, versions
//      as a single integer. All new HALs from Android 11+ use AIDL.
//
//   3. Android system properties
//      Android system properties (ro.*, persist.*, dalvik.*) define the
//      device's identity and runtime configuration. The most critical
//      invariant from CLAUDE.md §Hardware Authenticity:
//        ro.build.type = user   ← NEVER userdebug (SafetyNet checks this)
//        ro.adb.secure = 1      ← ADB disabled on production image
//        ro.secure = 1          ← Secure boot enforced
//
//   4. ART / Dalvik VM configuration
//      The Android Runtime (ART) compiles Android apps from DEX bytecode to
//      native ARM64 code. Heap sizes must be tuned to match the RAM budget
//      allocated to the Android partition.
//
//   5. BoardConfig validation
//      The AOSP BoardConfig.mk declares TARGET_ARCH, partition sizes, and
//      kernel configuration. These values are cross-checked against the
//      partition layout and NVMe namespace allocation.
//
// ── Android Treble Architecture ───────────────────────────────────────────────
//
//   Framework (system partition — generic AOSP code)
//     ↕ HIDL/AIDL binder IPC
//   Vendor HALs (vendor partition — device-specific code)
//     ↕ Linux kernel IOCTL / sysfs / character devices
//   Linux kernel drivers
//     ↕ hardware
//   Physical devices (passthrough) or paravirt devices (simulated)
//
//   AETHER implements vendor HALs for:
//     • Graphics (EGL/GLES/Vulkan): wraps the Adreno VF driver (ch13)
//     • Virtual Sensors: adapts VirtualSensorSuite (ch12) to the Sensors HAL
//     • Virtual Modem (RIL): adapts VirtualModem AT commands (ch12) to Radio HAL
//     • xHCI USB: wraps the assigned USB controllers (ch16)
//     • Audio: passthrough to the assigned audio hardware or silence stub
//     • Camera: stub ("camera not available") or Phone Bridge passthrough (ch12)
//     • Power: PSCI-backed suspend/idle through the hypervisor (ch09)
//     • Health: reports battery state (Phone Bridge) or "AC powered" stub
//
// ── Android Partition Layout ──────────────────────────────────────────────────
//
//   AETHER's Android image uses A/B (seamless) OTA partitioning:
//     boot_a / boot_b         — kernel + initrd (64 MB each)
//     system_a / system_b     — AOSP system image (3 GB each)
//     vendor_a / vendor_b     — device-specific HALs, firmware (1 GB each)
//     vbmeta_a / vbmeta_b     — AVB2 VBMeta tables (1 MB each)
//     userdata                — persistent user storage (remainder of namespace)
//     misc                    — BCB metadata for A/B, 4 MB
//
//   Slot-invariant partitions (not A/B): userdata, misc
//
// ── No std, No Alloc ─────────────────────────────────────────────────────────
//
//   All configuration is encoded in fixed-size arrays and static slices.
//   No heap allocation. Property values are &'static [u8] slices.
//
// References:
//   source.android.com/devices/architecture/hal — HAL overview
//   source.android.com/devices/architecture/hidl — HIDL reference
//   source.android.com/devices/architecture/aidl — AIDL for HALs
//   source.android.com/compatibility/cdd — Android CDD (mandatory HALs)
//   device/google/cuttlefish/ — closest AOSP reference for virtual devices
//   android.googlesource.com/platform/hardware/interfaces — HAL definitions
//   source.android.com/devices/tech/ota/ab — A/B seamless OTA

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during AOSP device configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AospError {
    /// The sum of all declared partition sizes exceeds the NVMe namespace size.
    PartitionTableOverflow,
    /// A partition size is not aligned to 4096 bytes (Android requires 4K
    /// block alignment for ext4, f2fs, and erofs partitions).
    PartitionNotAligned,
    /// A required HAL interface is missing from the Treble manifest.
    MissingRequiredHal,
    /// The HAL manifest already contains a duplicate entry for this interface
    /// (same name + instance + transport combination).
    DuplicateHalEntry,
    /// The HAL manifest is full (exceeded MAX_HAL_ENTRIES).
    HalManifestFull,
    /// `ro.build.type` is set to `userdebug` or `eng` — AETHER requires
    /// `user` on all production images (SafetyNet and attestation check this).
    BuildTypeNotUser,
    /// `ro.adb.secure` is not set to `1` (ADB must be disabled in production).
    AdbNotSecure,
    /// `ro.secure` is not set to `1` (secure boot enforcement must be on).
    SecureNotSet,
    /// The device properties table is full (exceeded MAX_PROPERTIES).
    PropertiesFull,
    /// A required property is missing from the device properties table.
    MissingRequiredProperty,
    /// An ART heap configuration value is invalid (e.g., start > limit > max).
    InvalidArtHeapConfig,
    /// The boot partition is smaller than the minimum required by the Android
    /// boot image specification (boot image header + kernel + ramdisk + DTB).
    BootPartitionTooSmall,
    /// The system partition is smaller than the minimum required for a full
    /// AOSP build (system image is typically 2–3 GB compressed).
    SystemPartitionTooSmall,
    /// The vendor partition is smaller than the minimum required for AETHER's
    /// HAL implementations and firmware blobs.
    VendorPartitionTooSmall,
    /// Too many partition specs have been added (exceeded MAX_PARTITIONS).
    TooManyPartitions,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capacity limits
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of partition entries in a PartitionLayout.
pub const MAX_PARTITIONS: usize = 24;

/// Maximum number of HAL interface entries in a TrebleManifest.
pub const MAX_HAL_ENTRIES: usize = 32;

/// Maximum number of key-value properties in a DeviceProperties table.
pub const MAX_PROPERTIES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Minimum partition sizes
//
// These reflect real minimum sizes for AOSP Android 13+ builds. Smaller
// values produce build-time or first-boot failures that are hard to diagnose.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum boot partition size: 64 MiB.
/// Must hold the kernel Image (≤ 32 MB), initramfs (≤ 16 MB), and DTB (≤ 4 MB).
pub const MIN_BOOT_PARTITION_BYTES: u64 = 64 * 1024 * 1024;

/// Minimum system partition size: 2 GiB.
/// A minimal AOSP build with no GMS produces a ~1.8 GB system image.
pub const MIN_SYSTEM_PARTITION_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Minimum vendor partition size: 512 MiB.
/// AETHER's vendor image includes Adreno user-space libs, virtual sensor HAL,
/// virtual modem RIL, and supporting firmware blobs.
pub const MIN_VENDOR_PARTITION_BYTES: u64 = 512 * 1024 * 1024;

/// Block size for partition alignment (4096 bytes — matches Android LBA shift).
pub const PARTITION_BLOCK_SIZE: u64 = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// Android partition layout
//
// Android uses A/B seamless OTA: most partitions exist in a "slot_a" and
// "slot_b" variant. The bootloader selects which slot to boot based on the
// BCB (Boot Control Block) in the misc partition.
//
// A/B partitions: boot, system, vendor, vbmeta
// Non-A/B partitions: userdata, misc
//
// Source: source.android.com/devices/tech/ota/ab/ab_implement
// ─────────────────────────────────────────────────────────────────────────────

/// The type of an Android partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    /// Kernel Image + initramfs + DTB. One copy per A/B slot.
    Boot,
    /// Android system (framework code, AOSP APKs, libc, etc.).
    /// Uses erofs or ext4, read-only in production.
    System,
    /// Device-specific HAL implementations, kernel modules, firmware blobs.
    /// Read-only in production. Contains AETHER's virtual HALs.
    Vendor,
    /// AVB2 VBMeta table for the boot + system + vendor chain.
    VbmetaSystem,
    /// Miscellaneous: BCB (Boot Control Block) for A/B slot metadata.
    /// Exactly 4 MiB, not A/B. Shared between both slots.
    Misc,
    /// Persistent user data (apps, accounts, media). Not A/B.
    /// f2fs or ext4, read-write.
    Userdata,
    /// Device Tree Overlay — applies per-device overlay DT fragments.
    Dtbo,
    /// Product partition — AETHER-specific APKs separate from system.
    Product,
}

impl PartitionKind {
    /// Whether this partition is duplicated per A/B slot.
    pub fn is_ab(self) -> bool {
        matches!(self, Self::Boot | Self::System | Self::Vendor
            | Self::VbmetaSystem | Self::Dtbo | Self::Product)
    }

    /// Human-readable ASCII label (for logging and BoardConfig generation).
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::Boot => b"boot",
            Self::System => b"system",
            Self::Vendor => b"vendor",
            Self::VbmetaSystem => b"vbmeta_system",
            Self::Misc => b"misc",
            Self::Userdata => b"userdata",
            Self::Dtbo => b"dtbo",
            Self::Product => b"product",
        }
    }
}

/// A single Android partition specification.
#[derive(Debug, Clone, Copy)]
pub struct PartitionSpec {
    /// The kind of partition.
    pub kind: PartitionKind,
    /// Size of one slot in bytes. Must be a multiple of PARTITION_BLOCK_SIZE.
    /// For A/B partitions this is the size of a single slot (both slots are
    /// equal in size). Total space consumed = size × (2 if is_ab else 1).
    pub size_bytes: u64,
}

impl PartitionSpec {
    /// Total bytes consumed on-disk (both A and B slots if applicable).
    pub fn total_bytes(&self) -> u64 {
        if self.kind.is_ab() {
            self.size_bytes * 2
        } else {
            self.size_bytes
        }
    }
}

/// Android partition layout for AETHER's Android partition.
///
/// Contains the set of `PartitionSpec` entries that together describe the
/// full Android partition table written to the NVMe namespace.
pub struct PartitionLayout {
    specs: [PartitionSpec; MAX_PARTITIONS],
    count: usize,
}

impl PartitionLayout {
    /// Create an empty partition layout.
    pub const fn new() -> Self {
        Self {
            specs: [PartitionSpec {
                kind: PartitionKind::Misc,
                size_bytes: 0,
            }; MAX_PARTITIONS],
            count: 0,
        }
    }

    /// Add a partition specification.
    pub fn add(&mut self, spec: PartitionSpec) -> Result<(), AospError> {
        if self.count >= MAX_PARTITIONS {
            return Err(AospError::TooManyPartitions);
        }
        self.specs[self.count] = spec;
        self.count += 1;
        Ok(())
    }

    /// Returns a slice of the declared partition specs.
    pub fn specs(&self) -> &[PartitionSpec] {
        &self.specs[..self.count]
    }

    /// Total disk space consumed by all partitions in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.specs().iter().map(|s| s.total_bytes()).sum()
    }

    /// Validate the layout against a NVMe namespace of `namespace_bytes` size.
    ///
    /// Checks:
    ///   1. Every partition size is a multiple of PARTITION_BLOCK_SIZE.
    ///   2. Total disk usage does not exceed the namespace.
    ///   3. Boot/system/vendor partitions meet their minimum size requirements.
    pub fn validate(&self, namespace_bytes: u64) -> Result<(), AospError> {
        for spec in self.specs() {
            if spec.size_bytes % PARTITION_BLOCK_SIZE != 0 {
                return Err(AospError::PartitionNotAligned);
            }
            match spec.kind {
                PartitionKind::Boot if spec.size_bytes < MIN_BOOT_PARTITION_BYTES => {
                    return Err(AospError::BootPartitionTooSmall);
                }
                PartitionKind::System if spec.size_bytes < MIN_SYSTEM_PARTITION_BYTES => {
                    return Err(AospError::SystemPartitionTooSmall);
                }
                PartitionKind::Vendor if spec.size_bytes < MIN_VENDOR_PARTITION_BYTES => {
                    return Err(AospError::VendorPartitionTooSmall);
                }
                _ => {}
            }
        }
        if self.total_bytes() > namespace_bytes {
            return Err(AospError::PartitionTableOverflow);
        }
        Ok(())
    }
}

/// AETHER's default Android partition layout for a 128 GB NVMe namespace.
///
/// Sizes chosen to allow a full AOSP build with AETHER HALs, microG, and
/// reasonable user storage. Adjust `USERDATA_BYTES` for the actual deployment
/// namespace size.
pub mod default_layout {
    use super::*;

    pub const BOOT_BYTES: u64 = 64 * 1024 * 1024;          // 64 MiB per slot
    pub const SYSTEM_BYTES: u64 = 3 * 1024 * 1024 * 1024;  // 3 GiB per slot
    pub const VENDOR_BYTES: u64 = 1 * 1024 * 1024 * 1024;  // 1 GiB per slot
    pub const VBMETA_SYSTEM_BYTES: u64 = 1 * 1024 * 1024;  // 1 MiB per slot
    pub const DTBO_BYTES: u64 = 8 * 1024 * 1024;           // 8 MiB per slot
    pub const PRODUCT_BYTES: u64 = 512 * 1024 * 1024;      // 512 MiB per slot
    pub const MISC_BYTES: u64 = 4 * 1024 * 1024;           // 4 MiB (non-A/B)
    pub const USERDATA_BYTES: u64 = 112 * 1024 * 1024 * 1024; // 112 GiB (non-A/B)

    /// Total bytes used by the default layout.
    ///
    /// A/B partitions × 2 + non-A/B partitions:
    ///   (64 + 3072 + 1024 + 1 + 8 + 512) × 2 + 4 + 114688
    ///   = 4681 × 2 + 114692 = 9362 + 114692 = 124054 MiB ≈ 121 GiB
    pub const TOTAL_BYTES: u64 = (BOOT_BYTES + SYSTEM_BYTES + VENDOR_BYTES
        + VBMETA_SYSTEM_BYTES + DTBO_BYTES + PRODUCT_BYTES) * 2
        + MISC_BYTES + USERDATA_BYTES;

    /// Build the default partition layout.
    pub fn build() -> Result<PartitionLayout, AospError> {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec { kind: PartitionKind::Boot, size_bytes: BOOT_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::System, size_bytes: SYSTEM_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::Vendor, size_bytes: VENDOR_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::VbmetaSystem, size_bytes: VBMETA_SYSTEM_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::Dtbo, size_bytes: DTBO_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::Product, size_bytes: PRODUCT_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::Misc, size_bytes: MISC_BYTES })?;
        layout.add(PartitionSpec { kind: PartitionKind::Userdata, size_bytes: USERDATA_BYTES })?;
        Ok(layout)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Treble HAL manifest
//
// The Treble manifest (vintf/manifest.xml) declares which HAL interfaces the
// device implements. The Android framework checks this manifest at boot time
// and refuses to start services for undeclared HALs.
//
// HIDL format: android.hardware.<subsystem>@<major>.<minor>::I<Interface>
// AIDL format: android.hardware.<subsystem>.I<Interface> (version in <version>)
//
// Sources:
//   source.android.com/devices/architecture/vintf/manifest — manifest format
//   android.googlesource.com/platform/hardware/interfaces — HAL definitions
//   android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android13-release
// ─────────────────────────────────────────────────────────────────────────────

/// HAL interface definition format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalFormat {
    /// HAL Interface Definition Language (legacy format, used through Android 10).
    /// Versioned as @major.minor (e.g., android.hardware.sensors@2.1).
    Hidl,
    /// Android Interface Definition Language (modern format, Android 11+).
    /// Versioned as a single integer (e.g., android.hardware.power@5).
    Aidl,
}

/// Transport mechanism for a HIDL HAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalTransport {
    /// HAL runs in the same process as the client (passthrough mode).
    /// Used only for specific graphics HALs (EGL loader, gralloc).
    HidlPassthrough,
    /// HAL runs in a separate process; communication via hwbinder IPC.
    /// Required for all HALs that need isolation from the framework process.
    HidlHwbinder,
    /// AIDL HAL; uses the standard binder IPC mechanism.
    AidlBinder,
}

/// A single HAL interface entry in the Treble manifest.
///
/// Together with the instance name, uniquely identifies a HAL implementation
/// that AETHER provides to the Android framework.
#[derive(Debug, Clone, Copy)]
pub struct HalInterface {
    /// HAL package name (e.g., `b"android.hardware.sensors"`).
    /// Does not include @version suffix or interface name.
    pub package: &'static [u8],
    /// Major version number (HIDL) or interface version (AIDL).
    pub major: u32,
    /// Minor version number (HIDL only; 0 for AIDL).
    pub minor: u32,
    /// Interface name within the package (e.g., `b"ISensors"`).
    pub interface: &'static [u8],
    /// Instance name (almost always `b"default"`).
    pub instance: &'static [u8],
    /// HAL definition format (HIDL or AIDL).
    pub format: HalFormat,
    /// Transport mechanism.
    pub transport: HalTransport,
}

impl HalInterface {
    /// Construct a HIDL hwbinder HAL entry at version @major.minor.
    pub const fn hidl_hwbinder(
        package: &'static [u8],
        major: u32,
        minor: u32,
        interface: &'static [u8],
    ) -> Self {
        Self {
            package,
            major,
            minor,
            interface,
            instance: b"default",
            format: HalFormat::Hidl,
            transport: HalTransport::HidlHwbinder,
        }
    }

    /// Construct an AIDL binder HAL entry at the given version.
    pub const fn aidl(
        package: &'static [u8],
        version: u32,
        interface: &'static [u8],
    ) -> Self {
        Self {
            package,
            major: version,
            minor: 0,
            interface,
            instance: b"default",
            format: HalFormat::Aidl,
            transport: HalTransport::AidlBinder,
        }
    }

    /// Construct a HIDL passthrough HAL entry (in-process, graphics only).
    pub const fn hidl_passthrough(
        package: &'static [u8],
        major: u32,
        minor: u32,
        interface: &'static [u8],
    ) -> Self {
        Self {
            package,
            major,
            minor,
            interface,
            instance: b"default",
            format: HalFormat::Hidl,
            transport: HalTransport::HidlPassthrough,
        }
    }
}

/// HAL interfaces that AETHER's Android partition declares in its Treble manifest.
///
/// Every entry here must have a corresponding HAL implementation in the vendor
/// partition. The Android framework checks this manifest at boot and refuses to
/// start framework services for HALs listed as required but absent.
///
/// Sources for version numbers:
///   hardware/interfaces/ in AOSP main at time of Android 13 release.
///   android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android13-release
pub const AETHER_HAL_MANIFEST: &[HalInterface] = &[
    // ── Graphics ─────────────────────────────────────────────────────────────
    // HWC3 (Hardware Composer 3) — drives display composition via Adreno VF.
    // Source: hardware/interfaces/graphics/composer/3.0/
    HalInterface::hidl_hwbinder(
        b"android.hardware.graphics.composer", 3, 0, b"IComposer",
    ),
    // Graphics allocator — allocates GPU-accessible gralloc buffers.
    // Source: hardware/interfaces/graphics/allocator/4.0/
    HalInterface::hidl_hwbinder(
        b"android.hardware.graphics.allocator", 4, 0, b"IAllocator",
    ),
    // Graphics mapper — maps gralloc buffers into process address space.
    // Source: hardware/interfaces/graphics/mapper/4.0/
    HalInterface::hidl_passthrough(
        b"android.hardware.graphics.mapper", 4, 0, b"IMapper",
    ),

    // ── Sensors ───────────────────────────────────────────────────────────────
    // Sensors HAL 2.1 — surfaces VirtualSensorSuite data (ch12) to Android.
    // Source: hardware/interfaces/sensors/2.1/
    HalInterface::hidl_hwbinder(
        b"android.hardware.sensors", 2, 1, b"ISensors",
    ),

    // ── Radio / Modem ─────────────────────────────────────────────────────────
    // Radio HAL 2.0 — surfaces VirtualModem AT commands (ch12) to Android RIL.
    // Source: hardware/interfaces/radio/2.0/
    HalInterface::hidl_hwbinder(
        b"android.hardware.radio", 2, 0, b"IRadio",
    ),
    // Radio config (SIM/slot configuration).
    HalInterface::hidl_hwbinder(
        b"android.hardware.radio.config", 2, 0, b"IRadioConfig",
    ),

    // ── Audio ─────────────────────────────────────────────────────────────────
    // Audio HAL 7.0 — routes audio to the assigned audio hardware or silence.
    // Source: hardware/interfaces/audio/7.0/
    HalInterface::hidl_hwbinder(
        b"android.hardware.audio", 7, 0, b"IDevicesFactory",
    ),
    HalInterface::hidl_hwbinder(
        b"android.hardware.audio.effect", 7, 0, b"IEffectsFactory",
    ),

    // ── Camera ────────────────────────────────────────────────────────────────
    // Camera provider 2.7 — stub ("no camera") or Phone Bridge passthrough.
    // Source: hardware/interfaces/camera/provider/2.7/
    HalInterface::hidl_hwbinder(
        b"android.hardware.camera.provider", 2, 7, b"ICameraProvider",
    ),

    // ── Bluetooth ─────────────────────────────────────────────────────────────
    // Bluetooth HAL — stub or Phone Bridge BT relay.
    // Source: hardware/interfaces/bluetooth/1.1/
    HalInterface::hidl_hwbinder(
        b"android.hardware.bluetooth", 1, 1, b"IBluetoothHci",
    ),

    // ── Power ─────────────────────────────────────────────────────────────────
    // Power HAL 5 (AIDL) — PSCI-backed suspend/idle via hypervisor (ch09).
    // Source: hardware/interfaces/power/aidl/android/hardware/power/IPower.aidl
    HalInterface::aidl(b"android.hardware.power", 5, b"IPower"),
    // Power stats (energy attribution for battery reporting).
    HalInterface::aidl(b"android.hardware.power.stats", 2, b"IPowerStats"),

    // ── Health / Battery ─────────────────────────────────────────────────────
    // Health HAL 2.1 — reports "AC powered" (no battery) or Phone Bridge battery.
    // Source: hardware/interfaces/health/2.1/
    HalInterface::hidl_hwbinder(
        b"android.hardware.health", 2, 1, b"IHealth",
    ),

    // ── USB ───────────────────────────────────────────────────────────────────
    // USB HAL 1.3 — wraps the xHCI controllers assigned to Android (ch16).
    // Source: hardware/interfaces/usb/1.3/
    HalInterface::hidl_hwbinder(
        b"android.hardware.usb", 1, 3, b"IUsb",
    ),

    // ── Thermal ───────────────────────────────────────────────────────────────
    // Thermal HAL 2.0 — stub returning nominal temperatures.
    // Source: hardware/interfaces/thermal/2.0/
    HalInterface::hidl_hwbinder(
        b"android.hardware.thermal", 2, 0, b"IThermal",
    ),

    // ── Vibrator ─────────────────────────────────────────────────────────────
    // Vibrator HAL 2 (AIDL) — stub (no vibration motor in AETHER).
    // Source: hardware/interfaces/vibrator/aidl/android/hardware/vibrator/IVibrator.aidl
    HalInterface::aidl(b"android.hardware.vibrator", 2, b"IVibrator"),

    // ── Light ─────────────────────────────────────────────────────────────────
    // Light HAL 2 (AIDL) — stub (no physical LEDs).
    // Source: hardware/interfaces/light/aidl/android/hardware/light/ILights.aidl
    HalInterface::aidl(b"android.hardware.light", 2, b"ILights"),

    // ── Keymaster / Identity ─────────────────────────────────────────────────
    // Keymaster 4.1 (HIDL) — cryptographic key storage.
    // In AETHER: software-backed keymaster (no secure element hardware).
    // Source: hardware/interfaces/keymaster/4.1/
    HalInterface::hidl_hwbinder(
        b"android.hardware.keymaster", 4, 1, b"IKeymasterDevice",
    ),
    // Identity credential store (AIDL, Android 11+).
    HalInterface::aidl(b"android.hardware.identity", 5, b"IIdentityCredentialStore"),

    // ── GNSS / Location ──────────────────────────────────────────────────────
    // GNSS HAL 2.1 — provides GPS from Phone Bridge (ch12) or software stub.
    // Source: hardware/interfaces/gnss/2.1/
    HalInterface::hidl_hwbinder(
        b"android.hardware.gnss", 2, 1, b"IGnss",
    ),

    // ── DRM ───────────────────────────────────────────────────────────────────
    // DRM HAL 1.4 — ClearKey implementation (no Widevine CDM).
    // Source: hardware/interfaces/drm/1.4/
    HalInterface::hidl_hwbinder(
        b"android.hardware.drm", 1, 4, b"ICryptoFactory",
    ),
];

/// Required HAL interfaces that AETHER MUST declare in its Treble manifest.
///
/// If any of these are absent from the manifest, the Android framework will
/// fail to start the corresponding system service at boot. These are the
/// HALs that the CDD marks as required (not optional) for phones.
pub const REQUIRED_HALS: &[&[u8]] = &[
    b"android.hardware.graphics.composer",
    b"android.hardware.graphics.allocator",
    b"android.hardware.sensors",
    b"android.hardware.audio",
    b"android.hardware.power",
    b"android.hardware.health",
    b"android.hardware.keymaster",
];

/// Treble HAL manifest for the AETHER Android partition.
pub struct TrebleManifest {
    entries: [HalInterface; MAX_HAL_ENTRIES],
    count: usize,
}

impl TrebleManifest {
    /// Create an empty manifest.
    pub const fn new() -> Self {
        Self {
            entries: [HalInterface::aidl(b"", 0, b""); MAX_HAL_ENTRIES],
            count: 0,
        }
    }

    /// Add a HAL interface declaration to the manifest.
    ///
    /// Returns `Err(AospError::HalManifestFull)` if the manifest is at
    /// capacity.
    pub fn declare(&mut self, hal: HalInterface) -> Result<(), AospError> {
        if self.count >= MAX_HAL_ENTRIES {
            return Err(AospError::HalManifestFull);
        }
        self.entries[self.count] = hal;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of declared HAL interfaces.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns the declared HAL interfaces as a slice.
    pub fn entries(&self) -> &[HalInterface] {
        &self.entries[..self.count]
    }

    /// Check whether the package `name` is declared in the manifest.
    pub fn contains(&self, package: &[u8]) -> bool {
        self.entries().iter().any(|e| e.package == package)
    }

    /// Validate that all required HAL packages are declared.
    pub fn validate(&self) -> Result<(), AospError> {
        for required in REQUIRED_HALS {
            if !self.contains(required) {
                return Err(AospError::MissingRequiredHal);
            }
        }
        Ok(())
    }

    /// Build a manifest from the AETHER default HAL list.
    pub fn from_default() -> Result<Self, AospError> {
        let mut m = Self::new();
        for hal in AETHER_HAL_MANIFEST {
            m.declare(*hal)?;
        }
        Ok(m)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Android system properties
//
// Android system properties control device identity, security posture, and
// runtime behaviour. They are set in /default.prop, /system/build.prop,
// /vendor/build.prop, and /product/build.prop. AETHER's device configuration
// sets them in vendor/build.prop and system/build.prop.
//
// Cross-cutting invariants (from CLAUDE.md §Hardware Authenticity):
//   ro.build.type = user        ← NEVER userdebug (SafetyNet checks this)
//   ro.adb.secure = 1           ← ADB disabled on production image
//   ro.secure = 1               ← Secure boot enforcement on
//   ro.debuggable = 0           ← Debuggable mode off
//
// Source: Android CDD §3.2.2 (Build parameters)
// ─────────────────────────────────────────────────────────────────────────────

/// Android build type. The CDD specifies that production devices must use
/// `user` build type. AETHER enforces this invariant: selecting `Userdebug`
/// or `Eng` is a configuration error.
///
/// SafetyNet, Google Play Integrity API, and hardware attestation all check
/// `ro.build.type` and will report the device as non-conforming if it is not
/// `user`. This breaks banking apps, streaming DRM, and attestation-dependent
/// games.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildType {
    /// Production build. ADB disabled, debuggable = 0, SELinux enforcing.
    /// The only valid build type for AETHER's Android partition.
    User,
    /// Developer build. ADB enabled, root accessible. Never used in production.
    Userdebug,
    /// Engineering build. Maximum debug access. Never shipped.
    Eng,
}

impl BuildType {
    /// Returns the string representation as used in `ro.build.type`.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::User => b"user",
            Self::Userdebug => b"userdebug",
            Self::Eng => b"eng",
        }
    }

    /// Whether this build type is acceptable for a production AETHER image.
    pub fn is_production(self) -> bool {
        matches!(self, Self::User)
    }
}

/// A single Android system property (key = value pair).
///
/// Both key and value are `&'static [u8]` byte slices for use in `no_std`.
#[derive(Debug, Clone, Copy)]
pub struct AndroidProperty {
    /// Property key (e.g., `b"ro.build.type"`).
    pub key: &'static [u8],
    /// Property value (e.g., `b"user"`).
    pub value: &'static [u8],
}

impl AndroidProperty {
    pub const fn new(key: &'static [u8], value: &'static [u8]) -> Self {
        Self { key, value }
    }
}

/// Required Android system properties for AETHER's device configuration.
///
/// These appear in `/vendor/build.prop` and `/system/build.prop` in the built
/// Android image. The framework reads these at boot time to configure itself.
///
/// Source: Android CDD §3.2.2 (Build parameters) and CLAUDE.md §Hardware Authenticity
pub const AETHER_DEVICE_PROPERTIES: &[AndroidProperty] = &[
    // ── Build identity ────────────────────────────────────────────────────────
    // CRITICAL: ro.build.type must be "user" — NEVER "userdebug" or "eng".
    AndroidProperty::new(b"ro.build.type", b"user"),
    AndroidProperty::new(b"ro.build.flavor", b"aether_x1-user"),
    AndroidProperty::new(b"ro.build.tags", b"release-keys"),
    AndroidProperty::new(b"ro.build.version.release", b"14"),  // Android 14
    AndroidProperty::new(b"ro.build.version.sdk", b"34"),
    AndroidProperty::new(b"ro.build.characteristics", b"default"),

    // ── Product identity ──────────────────────────────────────────────────────
    AndroidProperty::new(b"ro.product.manufacturer", b"AETHER"),
    AndroidProperty::new(b"ro.product.brand", b"AETHER"),
    AndroidProperty::new(b"ro.product.name", b"aether_x1"),
    AndroidProperty::new(b"ro.product.device", b"aether_x1"),
    AndroidProperty::new(b"ro.product.model", b"AETHER X1"),
    AndroidProperty::new(b"ro.hardware", b"aether"),
    AndroidProperty::new(b"ro.board.platform", b"aether_sdx"),

    // ── Security posture ──────────────────────────────────────────────────────
    // ro.secure = 1: security model enforced (block raw device access).
    AndroidProperty::new(b"ro.secure", b"1"),
    // ro.adb.secure = 1: ADB requires authentication (adb.keys), blocked by default.
    AndroidProperty::new(b"ro.adb.secure", b"1"),
    // ro.debuggable = 0: debuggable mode off (no su, no strace without auth).
    AndroidProperty::new(b"ro.debuggable", b"0"),

    // ── SELinux ───────────────────────────────────────────────────────────────
    // SELinux must be in enforcing mode. AETHER never ships a permissive build.
    // The actual enforcement is set by the kernel command line:
    //   androidboot.selinux=enforcing
    // but the property must also be consistent.
    AndroidProperty::new(b"ro.boot.selinux", b"enforcing"),

    // ── CPU / ABI ─────────────────────────────────────────────────────────────
    AndroidProperty::new(b"ro.product.cpu.abi", b"arm64-v8a"),
    AndroidProperty::new(b"ro.product.cpu.abilist", b"arm64-v8a"),
    AndroidProperty::new(b"ro.product.cpu.abilist64", b"arm64-v8a"),
    // No 32-bit ABI — AETHER's Android partition is 64-bit only.
    AndroidProperty::new(b"ro.product.cpu.abilist32", b""),

    // ── Memory (must match real phone-class values — see §Hardware Authenticity)
    // RAM size: use a round number matching real phone specs.
    // AETHER's Android partition gets 8 GB by default.
    AndroidProperty::new(b"ro.ram_size", b"8192"),  // MiB

    // ── Telephony ─────────────────────────────────────────────────────────────
    AndroidProperty::new(b"ro.telephony.default_network", b"10"),  // LTE-only
    AndroidProperty::new(b"ro.telephony.default_cdma_sub", b"0"),

    // ── Graphics ──────────────────────────────────────────────────────────────
    // OPENGLES_VERSION encodes the supported GLES version. Adreno 740 supports
    // OpenGL ES 3.2 (encoded as 0x00030002).
    AndroidProperty::new(b"ro.opengles.version", b"196610"),  // 0x30002 = GLES 3.2
    AndroidProperty::new(b"ro.hardware.egl", b"adreno"),

    // ── Verified Boot ─────────────────────────────────────────────────────────
    // androidboot.verifiedbootstate is set by the bootloader (ch19) to "green"
    // when the device is locked and all partitions pass AVB2 verification.
    // The ro.boot.* properties are set from kernel cmdline at boot time.
    AndroidProperty::new(b"ro.boot.flash.locked", b"1"),
    AndroidProperty::new(b"ro.boot.verifiedbootstate", b"green"),
    AndroidProperty::new(b"ro.boot.veritymode", b"enforcing"),

    // ── Misc ──────────────────────────────────────────────────────────────────
    AndroidProperty::new(b"persist.sys.usb.config", b"none"),
    AndroidProperty::new(b"ro.config.notifications_use_index", b"true"),
    AndroidProperty::new(b"ro.carrier", b"unknown"),
];

/// Device properties table for the AETHER Android partition.
pub struct DeviceProperties {
    entries: [AndroidProperty; MAX_PROPERTIES],
    count: usize,
}

impl DeviceProperties {
    /// Create an empty properties table.
    pub const fn new() -> Self {
        Self {
            entries: [AndroidProperty::new(b"", b""); MAX_PROPERTIES],
            count: 0,
        }
    }

    /// Add a property.
    pub fn add(&mut self, prop: AndroidProperty) -> Result<(), AospError> {
        if self.count >= MAX_PROPERTIES {
            return Err(AospError::PropertiesFull);
        }
        self.entries[self.count] = prop;
        self.count += 1;
        Ok(())
    }

    /// Look up a property value by key. Returns `None` if not found.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries[..self.count]
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value)
    }

    /// Validate the properties against AETHER's invariants.
    ///
    /// Checks:
    ///   - `ro.build.type` must be `user`
    ///   - `ro.adb.secure` must be `1`
    ///   - `ro.secure` must be `1`
    pub fn validate(&self) -> Result<(), AospError> {
        match self.get(b"ro.build.type") {
            Some(b"user") => {}
            Some(_) => return Err(AospError::BuildTypeNotUser),
            None => return Err(AospError::MissingRequiredProperty),
        }
        match self.get(b"ro.adb.secure") {
            Some(b"1") => {}
            _ => return Err(AospError::AdbNotSecure),
        }
        match self.get(b"ro.secure") {
            Some(b"1") => {}
            _ => return Err(AospError::SecureNotSet),
        }
        Ok(())
    }

    /// Build a properties table from the AETHER defaults.
    pub fn from_defaults() -> Result<Self, AospError> {
        let mut props = Self::new();
        for p in AETHER_DEVICE_PROPERTIES {
            props.add(*p)?;
        }
        Ok(props)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ART / Dalvik VM configuration
//
// The Android Runtime (ART) compiles DEX bytecode to native ARM64 at install
// time. The Dalvik VM heap sizes control memory usage for each app process.
// Values must be tuned to the RAM budget of the Android partition.
//
// Typical phone-class values for 8 GB RAM:
//   heapstartsize     = 8m   (initial heap size for each app)
//   heapgrowthlimit   = 256m (soft cap before system kills app)
//   heapsize          = 512m (hard cap — OOM kill if exceeded)
//   heaptargetutil    = 0.75 (GC target utilization)
//   heapmaxfree       = 8m   (max free memory retained after GC)
//   heapminfree       = 512k (min free memory triggering GC)
//
// Source: frameworks/base/core/jni/AndroidRuntime.cpp (dalvik.vm.* properties)
// ─────────────────────────────────────────────────────────────────────────────

/// ART / Dalvik VM heap configuration.
///
/// All sizes are in bytes. The invariant `start <= growth_limit <= max` must
/// hold; violation produces `AospError::InvalidArtHeapConfig`.
#[derive(Debug, Clone, Copy)]
pub struct ArtConfig {
    /// Initial heap size per app process (dalvik.vm.heapstartsize).
    pub heap_start_bytes: u64,
    /// Soft heap limit per process; GC runs aggressively above this (dalvik.vm.heapgrowthlimit).
    pub heap_growth_limit_bytes: u64,
    /// Hard heap limit per process; OOM kill if exceeded (dalvik.vm.heapsize).
    pub heap_max_bytes: u64,
    /// GC target utilization 0–100 (percent; dalvik.vm.heaptargetutilization × 100).
    pub heap_target_util_pct: u8,
    /// Max free memory retained after GC (dalvik.vm.heapmaxfree).
    pub heap_max_free_bytes: u64,
    /// Min free memory below which GC is triggered (dalvik.vm.heapminfree).
    pub heap_min_free_bytes: u64,
}

impl ArtConfig {
    /// ART configuration tuned for a phone-class device with 8 GB RAM.
    ///
    /// Matches the configuration used by high-end Android phones as of
    /// Android 14 (verified against AOSP device configurations).
    pub const PHONE_8GB: Self = Self {
        heap_start_bytes: 8 * 1024 * 1024,         // 8 MiB
        heap_growth_limit_bytes: 256 * 1024 * 1024, // 256 MiB
        heap_max_bytes: 512 * 1024 * 1024,          // 512 MiB
        heap_target_util_pct: 75,
        heap_max_free_bytes: 8 * 1024 * 1024,       // 8 MiB
        heap_min_free_bytes: 512 * 1024,             // 512 KiB
    };

    /// ART configuration tuned for a phone-class device with 12 GB RAM.
    pub const PHONE_12GB: Self = Self {
        heap_start_bytes: 16 * 1024 * 1024,         // 16 MiB
        heap_growth_limit_bytes: 384 * 1024 * 1024, // 384 MiB
        heap_max_bytes: 768 * 1024 * 1024,          // 768 MiB
        heap_target_util_pct: 75,
        heap_max_free_bytes: 8 * 1024 * 1024,
        heap_min_free_bytes: 512 * 1024,
    };

    /// Validate that heap size constraints form a valid ordering.
    pub fn validate(&self) -> Result<(), AospError> {
        if self.heap_start_bytes > self.heap_growth_limit_bytes {
            return Err(AospError::InvalidArtHeapConfig);
        }
        if self.heap_growth_limit_bytes > self.heap_max_bytes {
            return Err(AospError::InvalidArtHeapConfig);
        }
        if self.heap_target_util_pct == 0 || self.heap_target_util_pct > 100 {
            return Err(AospError::InvalidArtHeapConfig);
        }
        if self.heap_min_free_bytes > self.heap_max_free_bytes {
            return Err(AospError::InvalidArtHeapConfig);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Complete AOSP device configuration
//
// Aggregates partition layout, HAL manifest, device properties, and ART config
// into a single validated configuration object. AETHER validates this object
// before ERETing into the Android partition.
// ─────────────────────────────────────────────────────────────────────────────

/// Complete AOSP device configuration for AETHER's Android partition.
///
/// Contains every element needed to produce a valid AOSP build target and
/// runtime environment for the Android partition.
pub struct AospDeviceConfig {
    /// Partition layout validated against the NVMe namespace size.
    pub layout: PartitionLayout,
    /// Treble HAL manifest declaring all implemented HAL interfaces.
    pub manifest: TrebleManifest,
    /// Android system properties (ro.*, persist.*, etc.).
    pub properties: DeviceProperties,
    /// ART runtime heap configuration.
    pub art: ArtConfig,
    /// NVMe namespace size in bytes (used for partition layout validation).
    pub namespace_bytes: u64,
}

impl AospDeviceConfig {
    /// Validate all components of the AOSP device configuration.
    ///
    /// Returns `Ok(())` when the configuration is self-consistent and all
    /// required components are present.
    pub fn validate(&self) -> Result<(), AospError> {
        self.layout.validate(self.namespace_bytes)?;
        self.manifest.validate()?;
        self.properties.validate()?;
        self.art.validate()?;
        Ok(())
    }

    /// Build the default AETHER AOSP device configuration for a 128 GB NVMe
    /// namespace with 8 GB RAM assigned to the Android partition.
    pub fn default_128gb() -> Result<Self, AospError> {
        const NAMESPACE_128GB: u64 = 128 * 1024 * 1024 * 1024;
        Ok(Self {
            layout: default_layout::build()?,
            manifest: TrebleManifest::from_default()?,
            properties: DeviceProperties::from_defaults()?,
            art: ArtConfig::PHONE_8GB,
            namespace_bytes: NAMESPACE_128GB,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

/// HAL manifest must fit within the capacity limit.
#[allow(dead_code)]
const _HAL_COUNT_CHECK: () = {
    assert!(
        AETHER_HAL_MANIFEST.len() <= MAX_HAL_ENTRIES,
        "AETHER_HAL_MANIFEST exceeds MAX_HAL_ENTRIES — increase the limit"
    );
};

/// Default property list must fit within the capacity limit.
#[allow(dead_code)]
const _PROP_COUNT_CHECK: () = {
    assert!(
        AETHER_DEVICE_PROPERTIES.len() <= MAX_PROPERTIES,
        "AETHER_DEVICE_PROPERTIES exceeds MAX_PROPERTIES — increase the limit"
    );
};

/// Default partition layout total must not exceed 128 GB.
#[allow(dead_code)]
const _LAYOUT_SIZE_CHECK: () = {
    assert!(
        default_layout::TOTAL_BYTES <= 128 * 1024 * 1024 * 1024,
        "Default partition layout exceeds 128 GB NVMe namespace"
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PartitionKind ────────────────────────────────────────────────────────

    #[test]
    fn partition_kind_ab_flags() {
        assert!(PartitionKind::Boot.is_ab());
        assert!(PartitionKind::System.is_ab());
        assert!(PartitionKind::Vendor.is_ab());
        assert!(PartitionKind::VbmetaSystem.is_ab());
        assert!(PartitionKind::Dtbo.is_ab());
        assert!(PartitionKind::Product.is_ab());
        assert!(!PartitionKind::Misc.is_ab());
        assert!(!PartitionKind::Userdata.is_ab());
    }

    #[test]
    fn partition_kind_labels_non_empty() {
        let kinds = [
            PartitionKind::Boot, PartitionKind::System, PartitionKind::Vendor,
            PartitionKind::VbmetaSystem, PartitionKind::Misc, PartitionKind::Userdata,
            PartitionKind::Dtbo, PartitionKind::Product,
        ];
        for k in kinds {
            assert!(!k.label().is_empty(), "label must not be empty for {:?}", k);
        }
    }

    #[test]
    fn partition_spec_total_bytes_ab_doubled() {
        let spec = PartitionSpec { kind: PartitionKind::Boot, size_bytes: 64 * 1024 * 1024 };
        assert_eq!(spec.total_bytes(), 128 * 1024 * 1024);
    }

    #[test]
    fn partition_spec_total_bytes_non_ab_unchanged() {
        let spec = PartitionSpec { kind: PartitionKind::Userdata, size_bytes: 100 * 1024 * 1024 * 1024 };
        assert_eq!(spec.total_bytes(), 100 * 1024 * 1024 * 1024);
    }

    // ── PartitionLayout ──────────────────────────────────────────────────────

    #[test]
    fn partition_layout_empty_valid_against_large_ns() {
        let layout = PartitionLayout::new();
        assert!(layout.validate(128 * 1024 * 1024 * 1024).is_ok());
    }

    #[test]
    fn partition_layout_unaligned_rejected() {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec {
            kind: PartitionKind::Misc,
            size_bytes: 4096 + 1, // not aligned
        }).unwrap();
        assert_eq!(
            layout.validate(128 * 1024 * 1024 * 1024).unwrap_err(),
            AospError::PartitionNotAligned
        );
    }

    #[test]
    fn partition_layout_overflow_rejected() {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec {
            kind: PartitionKind::Userdata,
            size_bytes: 200 * 1024 * 1024 * 1024, // 200 GB > 128 GB namespace
        }).unwrap();
        assert_eq!(
            layout.validate(128 * 1024 * 1024 * 1024).unwrap_err(),
            AospError::PartitionTableOverflow
        );
    }

    #[test]
    fn partition_layout_boot_too_small() {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec {
            kind: PartitionKind::Boot,
            size_bytes: 4096, // way too small
        }).unwrap();
        assert_eq!(
            layout.validate(128 * 1024 * 1024 * 1024).unwrap_err(),
            AospError::BootPartitionTooSmall
        );
    }

    #[test]
    fn partition_layout_system_too_small() {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec {
            kind: PartitionKind::System,
            size_bytes: 64 * 1024 * 1024, // 64 MB: way too small
        }).unwrap();
        assert_eq!(
            layout.validate(128 * 1024 * 1024 * 1024).unwrap_err(),
            AospError::SystemPartitionTooSmall
        );
    }

    #[test]
    fn partition_layout_vendor_too_small() {
        let mut layout = PartitionLayout::new();
        layout.add(PartitionSpec {
            kind: PartitionKind::Vendor,
            size_bytes: 4096, // way too small
        }).unwrap();
        assert_eq!(
            layout.validate(128 * 1024 * 1024 * 1024).unwrap_err(),
            AospError::VendorPartitionTooSmall
        );
    }

    #[test]
    fn partition_layout_full_rejected() {
        let mut layout = PartitionLayout::new();
        for _ in 0..MAX_PARTITIONS {
            layout.add(PartitionSpec { kind: PartitionKind::Misc, size_bytes: 4096 }).unwrap();
        }
        assert_eq!(
            layout.add(PartitionSpec { kind: PartitionKind::Misc, size_bytes: 4096 }).unwrap_err(),
            AospError::TooManyPartitions
        );
    }

    #[test]
    fn default_layout_validates_against_128gb() {
        let layout = default_layout::build().unwrap();
        let ns = 128u64 * 1024 * 1024 * 1024;
        assert!(layout.validate(ns).is_ok());
        // Total must be less than 128 GB.
        assert!(layout.total_bytes() <= ns);
    }

    #[test]
    fn default_layout_total_bytes_const_matches_computed() {
        let layout = default_layout::build().unwrap();
        assert_eq!(layout.total_bytes(), default_layout::TOTAL_BYTES);
    }

    // ── HalInterface ─────────────────────────────────────────────────────────

    #[test]
    fn hal_interface_hidl_hwbinder_fields() {
        let hal = HalInterface::hidl_hwbinder(b"android.hardware.sensors", 2, 1, b"ISensors");
        assert_eq!(hal.package, b"android.hardware.sensors");
        assert_eq!(hal.major, 2);
        assert_eq!(hal.minor, 1);
        assert_eq!(hal.interface, b"ISensors");
        assert_eq!(hal.format, HalFormat::Hidl);
        assert_eq!(hal.transport, HalTransport::HidlHwbinder);
        assert_eq!(hal.instance, b"default");
    }

    #[test]
    fn hal_interface_aidl_fields() {
        let hal = HalInterface::aidl(b"android.hardware.power", 5, b"IPower");
        assert_eq!(hal.package, b"android.hardware.power");
        assert_eq!(hal.major, 5);
        assert_eq!(hal.minor, 0);
        assert_eq!(hal.interface, b"IPower");
        assert_eq!(hal.format, HalFormat::Aidl);
        assert_eq!(hal.transport, HalTransport::AidlBinder);
    }

    #[test]
    fn hal_interface_passthrough_transport() {
        let hal = HalInterface::hidl_passthrough(
            b"android.hardware.graphics.mapper", 4, 0, b"IMapper",
        );
        assert_eq!(hal.transport, HalTransport::HidlPassthrough);
    }

    // ── TrebleManifest ───────────────────────────────────────────────────────

    #[test]
    fn treble_manifest_default_validates() {
        let manifest = TrebleManifest::from_default().unwrap();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn treble_manifest_contains_required_hals() {
        let manifest = TrebleManifest::from_default().unwrap();
        for required in REQUIRED_HALS {
            assert!(
                manifest.contains(required),
                "Manifest missing required HAL: {:?}",
                core::str::from_utf8(required).unwrap_or("?")
            );
        }
    }

    #[test]
    fn treble_manifest_missing_hal_rejected() {
        let manifest = TrebleManifest::new(); // empty
        assert_eq!(manifest.validate().unwrap_err(), AospError::MissingRequiredHal);
    }

    #[test]
    fn treble_manifest_full_rejected() {
        let mut manifest = TrebleManifest::new();
        for _ in 0..MAX_HAL_ENTRIES {
            manifest.declare(HalInterface::aidl(b"x", 1, b"I")).unwrap();
        }
        assert_eq!(
            manifest.declare(HalInterface::aidl(b"y", 1, b"I")).unwrap_err(),
            AospError::HalManifestFull
        );
    }

    #[test]
    fn treble_manifest_count() {
        let manifest = TrebleManifest::from_default().unwrap();
        assert_eq!(manifest.len(), AETHER_HAL_MANIFEST.len());
    }

    // ── BuildType ─────────────────────────────────────────────────────────────

    #[test]
    fn build_type_user_is_production() {
        assert!(BuildType::User.is_production());
        assert!(!BuildType::Userdebug.is_production());
        assert!(!BuildType::Eng.is_production());
    }

    #[test]
    fn build_type_as_bytes() {
        assert_eq!(BuildType::User.as_bytes(), b"user");
        assert_eq!(BuildType::Userdebug.as_bytes(), b"userdebug");
        assert_eq!(BuildType::Eng.as_bytes(), b"eng");
    }

    // ── DeviceProperties ─────────────────────────────────────────────────────

    #[test]
    fn device_properties_from_defaults_validates() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert!(props.validate().is_ok());
    }

    #[test]
    fn device_properties_ro_build_type_is_user() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert_eq!(props.get(b"ro.build.type"), Some(b"user" as &[u8]));
    }

    #[test]
    fn device_properties_adb_secure() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert_eq!(props.get(b"ro.adb.secure"), Some(b"1" as &[u8]));
    }

    #[test]
    fn device_properties_ro_secure() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert_eq!(props.get(b"ro.secure"), Some(b"1" as &[u8]));
    }

    #[test]
    fn device_properties_ro_debuggable_off() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert_eq!(props.get(b"ro.debuggable"), Some(b"0" as &[u8]));
    }

    #[test]
    fn device_properties_userdebug_rejected() {
        let mut props = DeviceProperties::new();
        props.add(AndroidProperty::new(b"ro.build.type", b"userdebug")).unwrap();
        props.add(AndroidProperty::new(b"ro.adb.secure", b"1")).unwrap();
        props.add(AndroidProperty::new(b"ro.secure", b"1")).unwrap();
        assert_eq!(props.validate().unwrap_err(), AospError::BuildTypeNotUser);
    }

    #[test]
    fn device_properties_adb_insecure_rejected() {
        let mut props = DeviceProperties::new();
        props.add(AndroidProperty::new(b"ro.build.type", b"user")).unwrap();
        props.add(AndroidProperty::new(b"ro.adb.secure", b"0")).unwrap();
        props.add(AndroidProperty::new(b"ro.secure", b"1")).unwrap();
        assert_eq!(props.validate().unwrap_err(), AospError::AdbNotSecure);
    }

    #[test]
    fn device_properties_secure_off_rejected() {
        let mut props = DeviceProperties::new();
        props.add(AndroidProperty::new(b"ro.build.type", b"user")).unwrap();
        props.add(AndroidProperty::new(b"ro.adb.secure", b"1")).unwrap();
        props.add(AndroidProperty::new(b"ro.secure", b"0")).unwrap();
        assert_eq!(props.validate().unwrap_err(), AospError::SecureNotSet);
    }

    #[test]
    fn device_properties_missing_build_type_rejected() {
        let props = DeviceProperties::new(); // empty
        assert_eq!(props.validate().unwrap_err(), AospError::MissingRequiredProperty);
    }

    #[test]
    fn device_properties_full_rejected() {
        let mut props = DeviceProperties::new();
        for _ in 0..MAX_PROPERTIES {
            props.add(AndroidProperty::new(b"k", b"v")).unwrap();
        }
        assert_eq!(
            props.add(AndroidProperty::new(b"k2", b"v")).unwrap_err(),
            AospError::PropertiesFull
        );
    }

    #[test]
    fn device_properties_get_missing_returns_none() {
        let props = DeviceProperties::new();
        assert_eq!(props.get(b"ro.nonexistent"), None);
    }

    // ── ArtConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn art_config_phone_8gb_validates() {
        assert!(ArtConfig::PHONE_8GB.validate().is_ok());
    }

    #[test]
    fn art_config_phone_12gb_validates() {
        assert!(ArtConfig::PHONE_12GB.validate().is_ok());
    }

    #[test]
    fn art_config_start_exceeds_limit_rejected() {
        let cfg = ArtConfig {
            heap_start_bytes: 512 * 1024 * 1024,        // 512 MB
            heap_growth_limit_bytes: 256 * 1024 * 1024, // 256 MB < start
            heap_max_bytes: 512 * 1024 * 1024,
            heap_target_util_pct: 75,
            heap_max_free_bytes: 8 * 1024 * 1024,
            heap_min_free_bytes: 512 * 1024,
        };
        assert_eq!(cfg.validate().unwrap_err(), AospError::InvalidArtHeapConfig);
    }

    #[test]
    fn art_config_limit_exceeds_max_rejected() {
        let cfg = ArtConfig {
            heap_start_bytes: 8 * 1024 * 1024,
            heap_growth_limit_bytes: 768 * 1024 * 1024, // 768 MB > max
            heap_max_bytes: 512 * 1024 * 1024,
            heap_target_util_pct: 75,
            heap_max_free_bytes: 8 * 1024 * 1024,
            heap_min_free_bytes: 512 * 1024,
        };
        assert_eq!(cfg.validate().unwrap_err(), AospError::InvalidArtHeapConfig);
    }

    #[test]
    fn art_config_zero_util_rejected() {
        let cfg = ArtConfig {
            heap_target_util_pct: 0, // invalid
            ..ArtConfig::PHONE_8GB
        };
        assert_eq!(cfg.validate().unwrap_err(), AospError::InvalidArtHeapConfig);
    }

    #[test]
    fn art_config_util_over_100_rejected() {
        let cfg = ArtConfig {
            heap_target_util_pct: 101,
            ..ArtConfig::PHONE_8GB
        };
        assert_eq!(cfg.validate().unwrap_err(), AospError::InvalidArtHeapConfig);
    }

    #[test]
    fn art_config_min_free_exceeds_max_free_rejected() {
        let cfg = ArtConfig {
            heap_max_free_bytes: 1 * 1024 * 1024,  // 1 MB
            heap_min_free_bytes: 8 * 1024 * 1024,  // 8 MB > max_free
            ..ArtConfig::PHONE_8GB
        };
        assert_eq!(cfg.validate().unwrap_err(), AospError::InvalidArtHeapConfig);
    }

    // ── AospDeviceConfig ──────────────────────────────────────────────────────

    #[test]
    fn aosp_device_config_default_128gb_validates() {
        let cfg = AospDeviceConfig::default_128gb().unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn aosp_device_config_properties_have_user_build_type() {
        let cfg = AospDeviceConfig::default_128gb().unwrap();
        assert_eq!(
            cfg.properties.get(b"ro.build.type"),
            Some(b"user" as &[u8])
        );
    }

    #[test]
    fn aosp_device_config_manifest_has_all_required() {
        let cfg = AospDeviceConfig::default_128gb().unwrap();
        for required in REQUIRED_HALS {
            assert!(cfg.manifest.contains(required));
        }
    }

    #[test]
    fn aosp_device_config_art_valid() {
        let cfg = AospDeviceConfig::default_128gb().unwrap();
        assert!(cfg.art.validate().is_ok());
    }

    // ── Hardware Authenticity invariants (from CLAUDE.md cross-cutting) ───────

    #[test]
    fn build_type_user_invariant_enforced() {
        // Attempts to set userdebug must be rejected by validate().
        let mut props = DeviceProperties::new();
        props.add(AndroidProperty::new(b"ro.build.type", b"userdebug")).unwrap();
        props.add(AndroidProperty::new(b"ro.adb.secure", b"1")).unwrap();
        props.add(AndroidProperty::new(b"ro.secure", b"1")).unwrap();
        assert_eq!(
            props.validate().unwrap_err(),
            AospError::BuildTypeNotUser,
            "userdebug must be rejected by the property validator"
        );
    }

    #[test]
    fn selinux_enforcing_property_present() {
        let props = DeviceProperties::from_defaults().unwrap();
        // ro.boot.selinux should be enforcing.
        let selinux = props.get(b"ro.boot.selinux");
        assert_eq!(selinux, Some(b"enforcing" as &[u8]));
    }

    #[test]
    fn verified_boot_state_green() {
        let props = DeviceProperties::from_defaults().unwrap();
        assert_eq!(
            props.get(b"ro.boot.verifiedbootstate"),
            Some(b"green" as &[u8])
        );
    }

    #[test]
    fn ram_size_round_number() {
        // §Hardware Authenticity: RAM must be a round number (4GB, 6GB, 8GB, 12GB).
        let props = DeviceProperties::from_defaults().unwrap();
        let ram = props.get(b"ro.ram_size").unwrap_or(b"0");
        // Parse as integer and verify it's one of the accepted values.
        let mb: u64 = ram.iter().fold(0u64, |acc, &b| acc * 10 + (b - b'0') as u64);
        let valid_sizes_mb: &[u64] = &[4096, 6144, 8192, 12288, 16384];
        assert!(
            valid_sizes_mb.contains(&mb),
            "ro.ram_size must be a round phone-class value, got {}",
            mb
        );
    }

    #[test]
    fn opengles_version_is_gles_31_or_32() {
        let props = DeviceProperties::from_defaults().unwrap();
        let gles = props.get(b"ro.opengles.version").unwrap_or(b"0");
        let version: u32 = gles.iter().fold(0u32, |acc, &b| acc * 10 + (b - b'0') as u32);
        // 0x30001 = GLES 3.1 = 196609, 0x30002 = GLES 3.2 = 196610.
        assert!(
            version >= 196609,
            "Adreno GPU should support at least GLES 3.1 (0x30001 = 196609), got {}",
            version
        );
    }
}
