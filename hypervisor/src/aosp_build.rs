// ch42: AOSP Device Configuration and Build
//
// This module encodes the AOSP build system configuration that the AETHER
// Android partition requires. The AOSP build system is driven by three
// configuration artefacts:
//
//   1. device/aether/aether_arm64/device.mk
//      Declares product-level variables: PRODUCT_NAME, PRODUCT_DEVICE,
//      PRODUCT_BRAND, PRODUCT_PACKAGES (list of APKs and binaries to include),
//      PRODUCT_COPY_FILES (files copied verbatim into the image), PRODUCT_PROPERTY_OVERRIDES
//      (system-property defaults), and inheritance from AOSP generic targets.
//
//   2. device/aether/aether_arm64/BoardConfig.mk
//      Declares board-level variables: TARGET_ARCH, TARGET_CPU_ABI,
//      TARGET_BOARD_PLATFORM, partition sizes, kernel source path, SELinux
//      policy type, and AVB signing keys.
//
//   3. device/aether/aether_arm64/Android.bp
//      Soong build file declaring device-specific Rust/C++ targets and
//      microG integration modules.
//
//   4. microG source integration
//      microG replaces the Google Mobile Services (GMS) layer inside the
//      Android partition (ch22). At the build level this means adding the
//      microG source overlay to PRODUCT_PACKAGES and pointing the build
//      system at the microG prebuilt or source tree.
//
// The gate for this chapter is:
//   lunch aether_arm64-user && m
// which must produce:
//   boot.img, system.img, vendor.img, vbmeta.img, userdata.img
// All images must be non-empty, below the maximum sizes declared in
// BoardConfig.mk, and AVB-signed with the AETHER test keys.
//
// ── Device Tree Layout ───────────────────────────────────────────────────────
//
//   device/
//   └── aether/
//       └── aether_arm64/
//           ├── device.mk          ← PRODUCT_* variables
//           ├── BoardConfig.mk     ← TARGET_* + partition sizes
//           ├── Android.bp         ← Soong build targets
//           ├── AndroidProducts.mk ← registers aether_arm64-user target
//           ├── overlay/           ← resource overlays (frameworks/base, etc.)
//           ├── sepolicy/          ← AETHER-specific SELinux type enforcement
//           └── configs/           ← audio, media, and permissions configs
//
// ── microG Integration ───────────────────────────────────────────────────────
//
//   microG is integrated at source level (not as a prebuilt APK):
//     vendor/microg/                ← microG Android.mk / Android.bp
//       GmsCore/                    ← com.google.android.gms replacement
//       FakeStore/                  ← com.android.vending placeholder
//       GsfProxy/                   ← GSF shim
//       maps/                       ← Maps API backend
//
//   PRODUCT_PACKAGES += GmsCore FakeStore GsfProxy
//   PRODUCT_PACKAGES += UnifiedNlp
//
//   Signature spoofing: requires a frameworks/base patch that allows apps
//   to declare `android:requiredSystemPropertyName` and present a spoofed
//   signature to Play-Integrity-unaware apps. Without the patch, microG
//   cannot impersonate GMS to apps that check signatures directly.
//
// ── Build Invariants ─────────────────────────────────────────────────────────
//
//   Every board configuration value encoded here is cross-checked against:
//     - AospDeviceConfig (ch21) for partition sizes and ABI
//     - DeviceProperties (ch21) for ro.build.type = user
//     - TrebleManifest (ch21) for HAL coverage
//     - BootImageHeader (ch19) for boot partition compatibility
//
//   The AETHER build target is always aether_arm64-user (never -userdebug or
//   -eng). This invariant is encoded in BuildVariant::User and enforced by
//   AospBuildConfig::validate().
//
// References:
//   source.android.com/setup/build/building — AOSP build overview
//   source.android.com/setup/create/new-device — adding a new device
//   source.android.com/devices/tech/ota/ab — A/B partition requirements
//   source.android.com/security/verifiedboot/avb — AVB partition signing
//   source.android.com/devices/architecture/vintf — Treble manifest
//   microg.org — microG project documentation
//   android.googlesource.com/platform/build/soong — Soong build system

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during AOSP build configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AospBuildError {
    /// The build variant is not `user`. AETHER only ships `user` builds.
    BuildVariantNotUser,
    /// TARGET_ARCH is not `arm64`. AETHER's Android partition is ARM64-only.
    ArchNotArm64,
    /// A required PRODUCT_PACKAGE is missing from device.mk.
    MissingRequiredPackage,
    /// The packages list has exceeded its fixed-size capacity.
    PackageListFull,
    /// A required property override is missing from device.mk.
    MissingRequiredPropertyOverride,
    /// The property overrides list has exceeded its fixed-size capacity.
    PropertyOverridesFull,
    /// A required copy-file entry is missing.
    MissingRequiredCopyFile,
    /// The copy-files list has exceeded its fixed-size capacity.
    CopyFilesFull,
    /// A partition size declared in BoardConfig.mk is zero.
    ZeroPartitionSize,
    /// A partition size exceeds the maximum supported value (16 TiB).
    PartitionSizeTooLarge,
    /// A required Soong module is missing from Android.bp.
    MissingRequiredSoongModule,
    /// The Soong modules list has exceeded its fixed-size capacity.
    SoongModuleFull,
    /// microG is not enabled. The AETHER build requires microG at source level.
    MicrogNotEnabled,
    /// Signature spoofing is not enabled. Required for microG to function.
    SignatureSpoofingNotEnabled,
    /// AVB signing is not configured. All AETHER images must be AVB-signed.
    AvbNotConfigured,
    /// SELinux policy type is not set to `mac_only`. AETHER requires full
    /// SELinux enforcement.
    SelinuxPolicyInvalid,
    /// The AndroidProducts.mk lunch target is not registered.
    LunchTargetNotRegistered,
    /// The build does not produce all required output images (boot, system,
    /// vendor, vbmeta, userdata).
    MissingOutputImage,
    /// An output image is empty (zero bytes).
    OutputImageEmpty,
    /// An output image exceeds the partition size declared in BoardConfig.mk.
    OutputImageTooLarge,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capacity limits
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of entries in a PRODUCT_PACKAGES list.
pub const MAX_PACKAGES: usize = 64;

/// Maximum number of entries in a PRODUCT_COPY_FILES list.
pub const MAX_COPY_FILES: usize = 32;

/// Maximum number of entries in a PRODUCT_PROPERTY_OVERRIDES list.
pub const MAX_PROPERTY_OVERRIDES: usize = 48;

/// Maximum number of Soong module declarations in Android.bp.
pub const MAX_SOONG_MODULES: usize = 32;

/// Maximum supported partition size: 16 TiB.
pub const MAX_PARTITION_SIZE_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Build variant
// ─────────────────────────────────────────────────────────────────────────────

/// AOSP build variant. Only `User` is valid for AETHER production images.
///
/// AOSP lunch targets are `<product>-<variant>` (e.g., `aether_arm64-user`).
/// SafetyNet, Play Integrity, and hardware attestation all reject `userdebug`
/// and `eng` builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildVariant {
    /// Production. `ro.build.type=user`. ADB disabled. SELinux enforcing.
    User,
    /// Developer. `ro.build.type=userdebug`. ADB enabled by default.
    Userdebug,
    /// Engineering. Maximum debug access.
    Eng,
}

impl BuildVariant {
    /// The lunch target suffix string for this variant.
    pub fn suffix(self) -> &'static [u8] {
        match self {
            Self::User => b"user",
            Self::Userdebug => b"userdebug",
            Self::Eng => b"eng",
        }
    }

    /// Whether this variant is acceptable in a production AETHER image.
    pub fn is_production(self) -> bool {
        matches!(self, Self::User)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Target architecture
// ─────────────────────────────────────────────────────────────────────────────

/// TARGET_ARCH declared in BoardConfig.mk.
///
/// AETHER's Android partition is ARM64-only. The 32-bit ABI is not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    /// AArch64 — the only valid architecture for AETHER's Android partition.
    Arm64,
    /// AArch32 — not supported by AETHER.
    Arm,
    /// x86_64 — not applicable to AETHER's ARM Tier.
    X86_64,
    /// x86 — not applicable to AETHER's ARM Tier.
    X86,
}

impl TargetArch {
    /// The `TARGET_ARCH` string as written in BoardConfig.mk.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Arm64 => b"arm64",
            Self::Arm => b"arm",
            Self::X86_64 => b"x86_64",
            Self::X86 => b"x86",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SELinux policy type
// ─────────────────────────────────────────────────────────────────────────────

/// `BOARD_SEPOLICY_DIRS` style — SELinux enforcement mode declared at build.
///
/// AETHER uses `Enforcing` for all production images. `Permissive` is a
/// configuration error that causes `AospBuildError::SelinuxPolicyInvalid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxPolicyType {
    /// Full SELinux MAC enforcement. Required for all AETHER production builds.
    Enforcing,
    /// Permissive mode: policy violations are logged but not denied. Never
    /// acceptable in a production image.
    Permissive,
}

// ─────────────────────────────────────────────────────────────────────────────
// device.mk — product-level configuration
// ─────────────────────────────────────────────────────────────────────────────

/// PRODUCT_PACKAGES entry: name of an APK, binary, or library to include.
///
/// Each entry is a static byte slice matching the module name in Android.bp
/// or Android.mk.
#[derive(Debug, Clone, Copy)]
pub struct ProductPackage {
    /// Module name (e.g., `b"GmsCore"`, `b"Settings"`, `b"Dialer"`).
    pub name: &'static [u8],
}

impl ProductPackage {
    pub const fn new(name: &'static [u8]) -> Self {
        Self { name }
    }
}

/// PRODUCT_COPY_FILES entry: source path → destination path in the image.
///
/// Both paths are static byte slices.
#[derive(Debug, Clone, Copy)]
pub struct CopyFileEntry {
    /// Source path relative to the Android source root.
    pub src: &'static [u8],
    /// Destination path in the installed image (partition-relative).
    pub dst: &'static [u8],
}

impl CopyFileEntry {
    pub const fn new(src: &'static [u8], dst: &'static [u8]) -> Self {
        Self { src, dst }
    }
}

/// PRODUCT_PROPERTY_OVERRIDES entry: key = value pair written to build.prop.
#[derive(Debug, Clone, Copy)]
pub struct PropertyOverride {
    pub key: &'static [u8],
    pub value: &'static [u8],
}

impl PropertyOverride {
    pub const fn new(key: &'static [u8], value: &'static [u8]) -> Self {
        Self { key, value }
    }
}

/// AETHER required product packages declared in device.mk.
///
/// These modules must be present on the built system image. The build will
/// fail if any of them is missing.
///
/// Sources:
///   - AOSP generic phone product (build/target/product/telephony.mk)
///   - microG project (microg.org/packages)
///   - AETHER HAL implementations (device/aether/aether_arm64/)
pub const AETHER_PRODUCT_PACKAGES: &[ProductPackage] = &[
    // ── Core Android apps ─────────────────────────────────────────────────────
    ProductPackage::new(b"Settings"),
    ProductPackage::new(b"Contacts"),
    ProductPackage::new(b"Dialer"),
    ProductPackage::new(b"Launcher3"),
    ProductPackage::new(b"SystemUI"),
    ProductPackage::new(b"messaging"),
    ProductPackage::new(b"Camera2"),
    ProductPackage::new(b"Gallery2"),

    // ── microG GMS replacement ────────────────────────────────────────────────
    // GmsCore: replaces com.google.android.gms — provides the GMS APIs that
    // apps call (push notifications via FCM, location via FusedLocation, etc.).
    ProductPackage::new(b"GmsCore"),
    // FakeStore: replaces com.android.vending (Play Store) with a stub that
    // satisfies apps that check for Play Store presence without granting
    // catalog access. Real store access is via AuroraStore (ch22).
    ProductPackage::new(b"FakeStore"),
    // GsfProxy: Google Services Framework shim. Forwards GSF intent calls to
    // GmsCore. Required for apps that bind to com.google.android.gsf.
    ProductPackage::new(b"GsfProxy"),
    // UnifiedNlp: microG's network location provider. Routes location requests
    // to Mozilla Location Services or other backends (ch22).
    ProductPackage::new(b"UnifiedNlp"),

    // ── AETHER Virtual HAL services ───────────────────────────────────────────
    // Virtual sensors HAL — surfaces VirtualSensorSuite (ch12) data.
    ProductPackage::new(b"aether.sensors@2.1-service"),
    // Virtual modem RIL — surfaces VirtualModem AT commands (ch12).
    ProductPackage::new(b"aether.radio@2.0-service"),
    // Virtual camera stub — "no camera available" HAL (ch21).
    ProductPackage::new(b"aether.camera@2.7-service"),
    // Adreno GPU user-space driver + Gralloc allocator (ch13 / ch39).
    ProductPackage::new(b"libEGL_adreno"),
    ProductPackage::new(b"libGLESv2_adreno"),
    ProductPackage::new(b"vulkan.adreno"),
    ProductPackage::new(b"gralloc.aether"),

    // ── Power and health stubs ────────────────────────────────────────────────
    ProductPackage::new(b"aether.power@5-service"),
    ProductPackage::new(b"aether.health@2.1-service"),

    // ── ClearKey DRM ─────────────────────────────────────────────────────────
    ProductPackage::new(b"android.hardware.drm@1.4-service.clearkey"),
];

/// Required package names that AospBuildConfig::validate() checks are present.
pub const REQUIRED_PACKAGE_NAMES: &[&[u8]] = &[
    b"Settings",
    b"SystemUI",
    b"GmsCore",
    b"FakeStore",
    b"GsfProxy",
    b"gralloc.aether",
    b"aether.sensors@2.1-service",
];

/// AETHER PRODUCT_COPY_FILES entries — files copied verbatim into the image.
pub const AETHER_COPY_FILES: &[CopyFileEntry] = &[
    // Audio policy configuration.
    CopyFileEntry::new(
        b"device/aether/aether_arm64/configs/audio_policy_configuration.xml",
        b"system/etc/audio_policy_configuration.xml",
    ),
    // Media codecs list (declares hardware decoder support via Adreno).
    CopyFileEntry::new(
        b"device/aether/aether_arm64/configs/media_codecs.xml",
        b"system/etc/media_codecs.xml",
    ),
    // Media profiles — defines supported recording profiles.
    CopyFileEntry::new(
        b"device/aether/aether_arm64/configs/media_profiles.xml",
        b"system/etc/media_profiles.xml",
    ),
    // Permissions — declares which hardware features the device exposes.
    CopyFileEntry::new(
        b"device/aether/aether_arm64/configs/handheld_core_hardware.xml",
        b"system/etc/permissions/handheld_core_hardware.xml",
    ),
    // Network security config — prevents app MITM in production builds.
    CopyFileEntry::new(
        b"device/aether/aether_arm64/configs/network_security_config.xml",
        b"res/xml/network_security_config.xml",
    ),
    // AVB fstab — partition verification table (consumed by init).
    CopyFileEntry::new(
        b"device/aether/aether_arm64/fstab.aether",
        b"$(TARGET_COPY_OUT_RAMDISK)/fstab.aether",
    ),
    // VINTF manifest — Treble HAL declarations (ch21).
    CopyFileEntry::new(
        b"device/aether/aether_arm64/manifest.xml",
        b"vendor/etc/vintf/manifest.xml",
    ),
];

/// AETHER PRODUCT_PROPERTY_OVERRIDES written to vendor/build.prop.
///
/// These are build-time property defaults for the Android partition. They
/// complement the runtime properties in DeviceProperties (ch21).
pub const AETHER_PROPERTY_OVERRIDES: &[PropertyOverride] = &[
    // Build type invariant (Hardware Authenticity, CLAUDE.md).
    PropertyOverride::new(b"ro.build.type", b"user"),
    PropertyOverride::new(b"ro.build.tags", b"release-keys"),
    // ADB disabled in production.
    PropertyOverride::new(b"ro.adb.secure", b"1"),
    PropertyOverride::new(b"ro.secure", b"1"),
    PropertyOverride::new(b"ro.debuggable", b"0"),
    // SELinux enforcing via kernel command line and property.
    PropertyOverride::new(b"ro.boot.selinux", b"enforcing"),
    // Product identity.
    PropertyOverride::new(b"ro.product.name", b"aether_x1"),
    PropertyOverride::new(b"ro.product.device", b"aether_x1"),
    PropertyOverride::new(b"ro.product.brand", b"AETHER"),
    PropertyOverride::new(b"ro.product.manufacturer", b"AETHER"),
    PropertyOverride::new(b"ro.product.model", b"AETHER X1"),
    PropertyOverride::new(b"ro.hardware", b"aether"),
    PropertyOverride::new(b"ro.board.platform", b"aether_sdx"),
    // CPU ABI — ARM64 only, no 32-bit.
    PropertyOverride::new(b"ro.product.cpu.abi", b"arm64-v8a"),
    PropertyOverride::new(b"ro.product.cpu.abilist", b"arm64-v8a"),
    PropertyOverride::new(b"ro.product.cpu.abilist64", b"arm64-v8a"),
    PropertyOverride::new(b"ro.product.cpu.abilist32", b""),
    // RAM budget — 8 GiB; round number per §Hardware Authenticity.
    PropertyOverride::new(b"ro.ram_size", b"8192"),
    // Verified boot state set by AVB (ch19); declared here for completeness.
    PropertyOverride::new(b"ro.boot.verifiedbootstate", b"green"),
    PropertyOverride::new(b"ro.boot.flash.locked", b"1"),
    PropertyOverride::new(b"ro.boot.veritymode", b"enforcing"),
    // GLES version: Adreno 740 supports OpenGL ES 3.2.
    PropertyOverride::new(b"ro.opengles.version", b"196610"),
    PropertyOverride::new(b"ro.hardware.egl", b"adreno"),
    // microG: enable signature spoofing at the system level.
    PropertyOverride::new(b"sys.microg.signature_spoofing", b"1"),
];

/// device.mk configuration for AETHER's `aether_arm64` device.
pub struct DeviceMk {
    /// Product packages (PRODUCT_PACKAGES).
    packages: [ProductPackage; MAX_PACKAGES],
    packages_count: usize,

    /// Files copied verbatim (PRODUCT_COPY_FILES).
    copy_files: [CopyFileEntry; MAX_COPY_FILES],
    copy_files_count: usize,

    /// Property overrides (PRODUCT_PROPERTY_OVERRIDES).
    property_overrides: [PropertyOverride; MAX_PROPERTY_OVERRIDES],
    property_overrides_count: usize,
}

impl DeviceMk {
    /// Create an empty device.mk configuration.
    pub const fn new() -> Self {
        Self {
            packages: [ProductPackage::new(b""); MAX_PACKAGES],
            packages_count: 0,
            copy_files: [CopyFileEntry::new(b"", b""); MAX_COPY_FILES],
            copy_files_count: 0,
            property_overrides: [PropertyOverride::new(b"", b""); MAX_PROPERTY_OVERRIDES],
            property_overrides_count: 0,
        }
    }

    /// Add a PRODUCT_PACKAGES entry.
    pub fn add_package(&mut self, pkg: ProductPackage) -> Result<(), AospBuildError> {
        if self.packages_count >= MAX_PACKAGES {
            return Err(AospBuildError::PackageListFull);
        }
        self.packages[self.packages_count] = pkg;
        self.packages_count += 1;
        Ok(())
    }

    /// Add a PRODUCT_COPY_FILES entry.
    pub fn add_copy_file(&mut self, entry: CopyFileEntry) -> Result<(), AospBuildError> {
        if self.copy_files_count >= MAX_COPY_FILES {
            return Err(AospBuildError::CopyFilesFull);
        }
        self.copy_files[self.copy_files_count] = entry;
        self.copy_files_count += 1;
        Ok(())
    }

    /// Add a PRODUCT_PROPERTY_OVERRIDES entry.
    pub fn add_property(&mut self, prop: PropertyOverride) -> Result<(), AospBuildError> {
        if self.property_overrides_count >= MAX_PROPERTY_OVERRIDES {
            return Err(AospBuildError::PropertyOverridesFull);
        }
        self.property_overrides[self.property_overrides_count] = prop;
        self.property_overrides_count += 1;
        Ok(())
    }

    /// Returns the declared package list.
    pub fn packages(&self) -> &[ProductPackage] {
        &self.packages[..self.packages_count]
    }

    /// Returns the copy-files list.
    pub fn copy_files(&self) -> &[CopyFileEntry] {
        &self.copy_files[..self.copy_files_count]
    }

    /// Returns the property overrides list.
    pub fn property_overrides(&self) -> &[PropertyOverride] {
        &self.property_overrides[..self.property_overrides_count]
    }

    /// Check whether the package `name` is in the PRODUCT_PACKAGES list.
    pub fn has_package(&self, name: &[u8]) -> bool {
        self.packages().iter().any(|p| p.name == name)
    }

    /// Validate that all required packages are declared.
    pub fn validate_packages(&self) -> Result<(), AospBuildError> {
        for required in REQUIRED_PACKAGE_NAMES {
            if !self.has_package(required) {
                return Err(AospBuildError::MissingRequiredPackage);
            }
        }
        Ok(())
    }

    /// Build the default AETHER device.mk from the static package and property
    /// constants.
    pub fn from_defaults() -> Result<Self, AospBuildError> {
        let mut mk = Self::new();
        for pkg in AETHER_PRODUCT_PACKAGES {
            mk.add_package(*pkg)?;
        }
        for entry in AETHER_COPY_FILES {
            mk.add_copy_file(*entry)?;
        }
        for prop in AETHER_PROPERTY_OVERRIDES {
            mk.add_property(*prop)?;
        }
        Ok(mk)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BoardConfig.mk — board-level configuration
//
// BoardConfig.mk declares hardware-level constants used by the AOSP build
// system when compiling kernel modules, partition images, and platform
// libraries. Wrong values here produce images that do not match the runtime
// hardware and fail at first boot.
//
// Sources:
//   android.googlesource.com/platform/build/+/refs/heads/android14-release
//   source.android.com/devices/tech/ota/ab — partition size requirements
//   source.android.com/security/verifiedboot/avb — AVB configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Partition sizes declared in BoardConfig.mk (in bytes).
///
/// These must match (or exceed) the partition specs in PartitionLayout (ch21).
/// The build system uses these values when creating the sparse images.
#[derive(Debug, Clone, Copy)]
pub struct BoardPartitionSizes {
    /// BOARD_BOOTIMAGE_PARTITION_SIZE
    pub boot_bytes: u64,
    /// BOARD_SYSTEMIMAGE_PARTITION_SIZE
    pub system_bytes: u64,
    /// BOARD_VENDORIMAGE_PARTITION_SIZE
    pub vendor_bytes: u64,
    /// BOARD_PRODUCTIMAGE_PARTITION_SIZE
    pub product_bytes: u64,
    /// BOARD_DTBOIMAGE_PARTITION_SIZE
    pub dtbo_bytes: u64,
    /// BOARD_VBMETAIMAGE_PARTITION_SIZE (fixed at 64 KiB; AVB requirement)
    pub vbmeta_bytes: u64,
    /// BOARD_USERDATAIMAGE_PARTITION_SIZE
    pub userdata_bytes: u64,
}

impl BoardPartitionSizes {
    /// AETHER default partition sizes matching the PartitionLayout defaults
    /// declared in aosp.rs (ch21 default_layout).
    pub const AETHER_DEFAULT: Self = Self {
        boot_bytes: 64 * 1024 * 1024,              // 64 MiB
        system_bytes: 3 * 1024 * 1024 * 1024,      // 3 GiB
        vendor_bytes: 1 * 1024 * 1024 * 1024,      // 1 GiB
        product_bytes: 512 * 1024 * 1024,          // 512 MiB
        dtbo_bytes: 8 * 1024 * 1024,               // 8 MiB
        vbmeta_bytes: 64 * 1024,                   // 64 KiB (AVB requirement)
        userdata_bytes: 112 * 1024 * 1024 * 1024,  // 112 GiB
    };

    /// Validate that no partition size is zero or exceeds the 16 TiB cap.
    pub fn validate(&self) -> Result<(), AospBuildError> {
        let sizes = [
            self.boot_bytes,
            self.system_bytes,
            self.vendor_bytes,
            self.product_bytes,
            self.dtbo_bytes,
            self.vbmeta_bytes,
            self.userdata_bytes,
        ];
        for &s in &sizes {
            if s == 0 {
                return Err(AospBuildError::ZeroPartitionSize);
            }
            if s > MAX_PARTITION_SIZE_BYTES {
                return Err(AospBuildError::PartitionSizeTooLarge);
            }
        }
        Ok(())
    }
}

/// AVB (Android Verified Boot 2) signing configuration.
///
/// AETHER uses test keys for development builds. Production builds must
/// replace these with keys stored in a hardware security module.
///
/// Source: external/avb/README.md — avbtool usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvbKeySource {
    /// AOSP test keys (external/avb/test/data/testkey_rsa4096.pem).
    /// Acceptable in development; never in a public release.
    TestKeys,
    /// Production keys generated with avbtool and stored in HSM.
    ProductionKeys,
}

/// BoardConfig.mk aggregate for the AETHER `aether_arm64` board.
#[derive(Debug, Clone, Copy)]
pub struct BoardConfigMk {
    /// TARGET_ARCH
    pub target_arch: TargetArch,
    /// TARGET_ARCH_VARIANT (e.g., `armv8-2a` for Snapdragon X Elite)
    pub arch_variant: &'static [u8],
    /// TARGET_CPU_VARIANT (e.g., `cortex-a510` generic or `kryo`)
    pub cpu_variant: &'static [u8],
    /// TARGET_BOARD_PLATFORM
    pub board_platform: &'static [u8],
    /// Partition sizes for the build system.
    pub partition_sizes: BoardPartitionSizes,
    /// SELinux policy enforcement mode.
    pub selinux_policy: SelinuxPolicyType,
    /// AVB signing key source.
    pub avb_key_source: AvbKeySource,
    /// Whether BOARD_AVB_ENABLE is set.
    pub avb_enabled: bool,
    /// Whether PRODUCT_USE_DYNAMIC_PARTITIONS is set (super partition / LDM).
    pub dynamic_partitions: bool,
}

impl BoardConfigMk {
    /// AETHER's default BoardConfig.mk for the Snapdragon X Elite (aether_arm64).
    pub const AETHER_DEFAULT: Self = Self {
        target_arch: TargetArch::Arm64,
        arch_variant: b"armv8-2a",
        cpu_variant: b"cortex-a510",
        board_platform: b"aether_sdx",
        partition_sizes: BoardPartitionSizes::AETHER_DEFAULT,
        selinux_policy: SelinuxPolicyType::Enforcing,
        avb_key_source: AvbKeySource::TestKeys,
        avb_enabled: true,
        dynamic_partitions: true,
    };

    /// Validate the board configuration.
    pub fn validate(&self) -> Result<(), AospBuildError> {
        if self.target_arch != TargetArch::Arm64 {
            return Err(AospBuildError::ArchNotArm64);
        }
        self.partition_sizes.validate()?;
        if self.selinux_policy != SelinuxPolicyType::Enforcing {
            return Err(AospBuildError::SelinuxPolicyInvalid);
        }
        if !self.avb_enabled {
            return Err(AospBuildError::AvbNotConfigured);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Android.bp — Soong build system declarations
//
// Android.bp replaces Android.mk for new modules in AOSP. It uses a JSON-like
// syntax parsed by the Soong build system. AETHER declares its device-specific
// native modules (HAL services, kernel modules, etc.) here.
//
// Sources:
//   android.googlesource.com/platform/build/soong/+/refs/heads/main/README.md
//   source.android.com/setup/build/building#build-a-target — soong overview
// ─────────────────────────────────────────────────────────────────────────────

/// Soong module type — the build system rule to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoongModuleType {
    /// `cc_binary` — native C/C++ executable.
    CcBinary,
    /// `cc_library_shared` — native shared library (.so).
    CcLibraryShared,
    /// `cc_defaults` — common build flags shared across modules.
    CcDefaults,
    /// `rust_binary` — Rust executable.
    RustBinary,
    /// `rust_library` — Rust library (static or shared).
    RustLibrary,
    /// `android_app` — Android application (APK).
    AndroidApp,
    /// `prebuilt_etc` — prebuilt file installed to `/etc/`.
    PrebuiltEtc,
    /// `filegroup` — named group of files (no build output; used as input).
    Filegroup,
}

impl SoongModuleType {
    /// The Soong rule name as written in Android.bp.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CcBinary => b"cc_binary",
            Self::CcLibraryShared => b"cc_library_shared",
            Self::CcDefaults => b"cc_defaults",
            Self::RustBinary => b"rust_binary",
            Self::RustLibrary => b"rust_library",
            Self::AndroidApp => b"android_app",
            Self::PrebuiltEtc => b"prebuilt_etc",
            Self::Filegroup => b"filegroup",
        }
    }
}

/// A single Soong module declaration in Android.bp.
#[derive(Debug, Clone, Copy)]
pub struct SoongModule {
    /// Module type (e.g., `cc_binary`, `android_app`).
    pub module_type: SoongModuleType,
    /// Module name — must match the PRODUCT_PACKAGES entry that pulls it in.
    pub name: &'static [u8],
    /// Whether this module is installed to the vendor partition.
    pub vendor: bool,
    /// Whether this module is required for AETHER to boot.
    pub required: bool,
}

impl SoongModule {
    pub const fn new(
        module_type: SoongModuleType,
        name: &'static [u8],
        vendor: bool,
        required: bool,
    ) -> Self {
        Self { module_type, name, vendor, required }
    }
}

/// AETHER device-specific Soong modules declared in Android.bp.
///
/// These are the modules that the AETHER device tree contributes. AOSP core
/// modules (Settings, SystemUI, etc.) are declared in their own source trees.
pub const AETHER_SOONG_MODULES: &[SoongModule] = &[
    // ── Virtual Sensor HAL ────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcBinary,
        b"aether.sensors@2.1-service",
        true,
        true,
    ),
    // ── Virtual Modem RIL ─────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcBinary,
        b"aether.radio@2.0-service",
        true,
        true,
    ),
    // ── Camera stub HAL ───────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcBinary,
        b"aether.camera@2.7-service",
        true,
        false,
    ),
    // ── Power HAL ─────────────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcBinary,
        b"aether.power@5-service",
        true,
        true,
    ),
    // ── Health HAL ────────────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcBinary,
        b"aether.health@2.1-service",
        true,
        true,
    ),
    // ── Gralloc allocator ─────────────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::CcLibraryShared,
        b"gralloc.aether",
        true,
        true,
    ),
    // ── VINTF manifest prebuilt ───────────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::PrebuiltEtc,
        b"aether_vendor_manifest",
        true,
        true,
    ),
    // ── Audio policy config prebuilt ──────────────────────────────────────────
    SoongModule::new(
        SoongModuleType::PrebuiltEtc,
        b"aether_audio_policy",
        true,
        false,
    ),
];

/// Required module names for AospBuildConfig::validate_soong().
pub const REQUIRED_SOONG_MODULES: &[&[u8]] = &[
    b"aether.sensors@2.1-service",
    b"aether.radio@2.0-service",
    b"aether.power@5-service",
    b"aether.health@2.1-service",
    b"gralloc.aether",
];

/// Android.bp contents for the AETHER device tree.
pub struct AndroidBp {
    modules: [SoongModule; MAX_SOONG_MODULES],
    count: usize,
}

impl AndroidBp {
    /// Create an empty Android.bp.
    pub const fn new() -> Self {
        Self {
            modules: [SoongModule::new(SoongModuleType::Filegroup, b"", false, false);
                MAX_SOONG_MODULES],
            count: 0,
        }
    }

    /// Add a module declaration.
    pub fn add(&mut self, module: SoongModule) -> Result<(), AospBuildError> {
        if self.count >= MAX_SOONG_MODULES {
            return Err(AospBuildError::SoongModuleFull);
        }
        self.modules[self.count] = module;
        self.count += 1;
        Ok(())
    }

    /// Returns the declared modules.
    pub fn modules(&self) -> &[SoongModule] {
        &self.modules[..self.count]
    }

    /// Check whether a module with the given name is declared.
    pub fn has_module(&self, name: &[u8]) -> bool {
        self.modules().iter().any(|m| m.name == name)
    }

    /// Validate that all required modules are declared.
    pub fn validate(&self) -> Result<(), AospBuildError> {
        for required in REQUIRED_SOONG_MODULES {
            if !self.has_module(required) {
                return Err(AospBuildError::MissingRequiredSoongModule);
            }
        }
        Ok(())
    }

    /// Build Android.bp from the AETHER defaults.
    pub fn from_defaults() -> Result<Self, AospBuildError> {
        let mut bp = Self::new();
        for m in AETHER_SOONG_MODULES {
            bp.add(*m)?;
        }
        Ok(bp)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// microG source-level integration
//
// microG replaces Google Mobile Services (GMS) at the source level. It is
// declared as an AOSP module in vendor/microg/ and pulled in via
// PRODUCT_PACKAGES. The integration requires:
//
//   1. Signature spoofing patch applied to frameworks/base — allows an app to
//      declare that it wants to appear as another app (com.google.android.gms)
//      to callers that check signatures. Without this patch microG cannot
//      impersonate GMS.
//
//   2. GmsCore source or prebuilt placed in vendor/microg/GmsCore/ and
//      declared in vendor/microg/Android.bp.
//
//   3. FakeStore APK placed in vendor/microg/FakeStore/ — provides the Play
//      Store package name (com.android.vending) without the real store.
//
//   4. UnifiedNlp placed in vendor/microg/UnifiedNlp/ — provides the network
//      location backend registered as a LocationProvider.
//
// Sources:
//   github.com/microg/GmsCore — microG GmsCore source
//   github.com/microg/android_packages_apps_GmsCore — AOSP overlay
//   lineageos.org/signature-spoofing — signature spoofing explanation
// ─────────────────────────────────────────────────────────────────────────────

/// microG component — a submodule of the microG GMS replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrogComponent {
    /// GmsCore — replaces com.google.android.gms (FCM, location, auth, etc.).
    GmsCore,
    /// FakeStore — stub for com.android.vending (Play Store package name).
    FakeStore,
    /// GsfProxy — shim for legacy Google Services Framework calls.
    GsfProxy,
    /// UnifiedNlp — network location provider backend.
    UnifiedNlp,
}

impl MicrogComponent {
    /// The Android package name for this microG component.
    pub fn package_name(self) -> &'static [u8] {
        match self {
            Self::GmsCore => b"com.google.android.gms",
            Self::FakeStore => b"com.android.vending",
            Self::GsfProxy => b"com.google.android.gsf",
            Self::UnifiedNlp => b"org.microg.nlp",
        }
    }

    /// The PRODUCT_PACKAGES module name for this component.
    pub fn module_name(self) -> &'static [u8] {
        match self {
            Self::GmsCore => b"GmsCore",
            Self::FakeStore => b"FakeStore",
            Self::GsfProxy => b"GsfProxy",
            Self::UnifiedNlp => b"UnifiedNlp",
        }
    }

    /// The source tree path under vendor/microg/ for this component.
    pub fn source_path(self) -> &'static [u8] {
        match self {
            Self::GmsCore => b"vendor/microg/GmsCore",
            Self::FakeStore => b"vendor/microg/FakeStore",
            Self::GsfProxy => b"vendor/microg/GsfProxy",
            Self::UnifiedNlp => b"vendor/microg/UnifiedNlp",
        }
    }
}

/// Signature spoofing configuration.
///
/// Signature spoofing is the mechanism by which microG presents the
/// com.google.android.gms signature to apps that check it, even though
/// GmsCore is not signed by Google. This requires a frameworks/base patch
/// and is controlled by a system property at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSpoofingPolicy {
    /// Signature spoofing is enabled. Required for microG to function.
    Enabled,
    /// Signature spoofing is disabled. microG will not work correctly.
    Disabled,
}

/// microG source-level integration configuration.
#[derive(Debug, Clone, Copy)]
pub struct MicrogIntegration {
    /// Whether GmsCore is included in the build.
    pub gms_core: bool,
    /// Whether FakeStore is included in the build.
    pub fake_store: bool,
    /// Whether GsfProxy is included in the build.
    pub gsf_proxy: bool,
    /// Whether UnifiedNlp is included in the build.
    pub unified_nlp: bool,
    /// Signature spoofing configuration (frameworks/base patch).
    pub signature_spoofing: SignatureSpoofingPolicy,
    /// Location backend used by UnifiedNlp.
    pub location_backend: MicrogLocationBackend,
}

/// Location backend for UnifiedNlp (microG's network location provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrogLocationBackend {
    /// Mozilla Location Services (MLS) — open, crowd-sourced Wi-Fi DB.
    MozillaLocationServices,
    /// Beacondb — privacy-respecting Wi-Fi geolocation database.
    Beacondb,
    /// GPS only — no network location; uses GNSS directly.
    GpsOnly,
}

impl MicrogIntegration {
    /// AETHER's default microG integration: all four components, signature
    /// spoofing enabled, MLS location backend.
    pub const AETHER_DEFAULT: Self = Self {
        gms_core: true,
        fake_store: true,
        gsf_proxy: true,
        unified_nlp: true,
        signature_spoofing: SignatureSpoofingPolicy::Enabled,
        location_backend: MicrogLocationBackend::MozillaLocationServices,
    };

    /// Validate the microG integration configuration.
    ///
    /// Checks:
    ///   - GmsCore must be present (other components depend on it).
    ///   - Signature spoofing must be enabled (otherwise GmsCore is broken).
    pub fn validate(&self) -> Result<(), AospBuildError> {
        if !self.gms_core {
            return Err(AospBuildError::MicrogNotEnabled);
        }
        if self.signature_spoofing != SignatureSpoofingPolicy::Enabled {
            return Err(AospBuildError::SignatureSpoofingNotEnabled);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidProducts.mk — lunch target registration
//
// AndroidProducts.mk in device/aether/aether_arm64/ tells the AOSP lunch
// script which product targets this directory exports and which .mk file
// implements each target. AETHER exports exactly one target:
//   aether_arm64-user
//
// Source:
//   source.android.com/setup/create/new-device#set-up-the-product-definition
// ─────────────────────────────────────────────────────────────────────────────

/// A registered lunch target: `<product>-<variant>`.
#[derive(Debug, Clone, Copy)]
pub struct LunchTarget {
    /// Product name (e.g., `b"aether_arm64"`).
    pub product: &'static [u8],
    /// Build variant.
    pub variant: BuildVariant,
}

impl LunchTarget {
    pub const fn new(product: &'static [u8], variant: BuildVariant) -> Self {
        Self { product, variant }
    }

    /// Whether this target is acceptable for a production AETHER image.
    pub fn is_production(&self) -> bool {
        self.variant.is_production()
    }
}

/// The canonical AETHER lunch target: `aether_arm64-user`.
pub const AETHER_LUNCH_TARGET: LunchTarget =
    LunchTarget::new(b"aether_arm64", BuildVariant::User);

// ─────────────────────────────────────────────────────────────────────────────
// Build gate
//
// The gate for Chapter 42 is:
//   lunch aether_arm64-user && m
// producing: boot.img, system.img, vendor.img, vbmeta.img, userdata.img
//
// The gate is represented by AospBuildGate, which records whether each
// expected output image was produced (non-empty, within partition size).
// ─────────────────────────────────────────────────────────────────────────────

/// Expected output images from `lunch aether_arm64-user && m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputImage {
    Boot,
    System,
    Vendor,
    Vbmeta,
    Userdata,
    Dtbo,
    Product,
}

impl OutputImage {
    /// Image filename as produced by the AOSP build system.
    pub fn filename(self) -> &'static [u8] {
        match self {
            Self::Boot => b"boot.img",
            Self::System => b"system.img",
            Self::Vendor => b"vendor.img",
            Self::Vbmeta => b"vbmeta.img",
            Self::Userdata => b"userdata.img",
            Self::Dtbo => b"dtbo.img",
            Self::Product => b"product.img",
        }
    }

    /// Whether this image is required for the Chapter 42 gate to pass.
    pub fn is_required(self) -> bool {
        matches!(
            self,
            Self::Boot | Self::System | Self::Vendor | Self::Vbmeta | Self::Userdata
        )
    }
}

/// Gate state for a single output image.
#[derive(Debug, Clone, Copy)]
pub struct ImageGateState {
    /// The image type.
    pub image: OutputImage,
    /// Whether the image file was produced by the build.
    pub produced: bool,
    /// Whether the image is non-empty (size > 0).
    pub non_empty: bool,
    /// Whether the image size is within the BoardConfig.mk partition size.
    pub within_size_limit: bool,
}

impl ImageGateState {
    /// Whether this image passes the gate.
    pub fn passes(&self) -> bool {
        self.produced && self.non_empty && self.within_size_limit
    }
}

/// Gate for Chapter 42: records whether `lunch aether_arm64-user && m`
/// produces all required bootable partition images.
///
/// Gate passes when `passes()` returns `true`.
///
/// Verified by:
///   ls -la $OUT/boot.img $OUT/system.img $OUT/vendor.img \
///          $OUT/vbmeta.img $OUT/userdata.img
///   avbtool verify_image --image $OUT/vbmeta.img
#[derive(Debug, Clone, Copy)]
pub struct AospBuildGate {
    /// State for each required output image.
    pub boot: ImageGateState,
    pub system: ImageGateState,
    pub vendor: ImageGateState,
    pub vbmeta: ImageGateState,
    pub userdata: ImageGateState,
    /// Whether the lunch target was successfully registered and resolved.
    pub lunch_target_registered: bool,
    /// Whether the AVB signature on vbmeta.img verified correctly.
    pub avb_verified: bool,
}

impl AospBuildGate {
    /// Construct a gate state with all fields set to `false` (not yet built).
    pub const fn not_built() -> Self {
        let empty = ImageGateState {
            image: OutputImage::Boot,
            produced: false,
            non_empty: false,
            within_size_limit: false,
        };
        Self {
            boot: ImageGateState { image: OutputImage::Boot, ..empty },
            system: ImageGateState { image: OutputImage::System, ..empty },
            vendor: ImageGateState { image: OutputImage::Vendor, ..empty },
            vbmeta: ImageGateState { image: OutputImage::Vbmeta, ..empty },
            userdata: ImageGateState { image: OutputImage::Userdata, ..empty },
            lunch_target_registered: false,
            avb_verified: false,
        }
    }

    /// Gate passes when all required images are produced and AVB verifies.
    pub fn passes(&self) -> bool {
        self.lunch_target_registered
            && self.avb_verified
            && self.boot.passes()
            && self.system.passes()
            && self.vendor.passes()
            && self.vbmeta.passes()
            && self.userdata.passes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Complete AOSP build configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Complete AOSP build configuration for AETHER's `aether_arm64` device.
///
/// Aggregates device.mk, BoardConfig.mk, Android.bp, microG integration,
/// and the registered lunch target. Validated by `validate()` before the
/// build is considered correct.
pub struct AospBuildConfig {
    /// device/aether/aether_arm64/device.mk contents.
    pub device_mk: DeviceMk,
    /// device/aether/aether_arm64/BoardConfig.mk contents.
    pub board_config: BoardConfigMk,
    /// device/aether/aether_arm64/Android.bp contents.
    pub android_bp: AndroidBp,
    /// microG source integration settings.
    pub microg: MicrogIntegration,
    /// The registered lunch target (aether_arm64-user).
    pub lunch_target: LunchTarget,
}

impl AospBuildConfig {
    /// Validate the complete build configuration.
    ///
    /// Checks:
    ///   1. Build variant is `user`.
    ///   2. BoardConfig.mk is self-consistent (arch, partition sizes, SELinux, AVB).
    ///   3. device.mk contains all required packages.
    ///   4. Android.bp declares all required HAL service modules.
    ///   5. microG integration is valid.
    ///   6. lunch target is `user` variant.
    pub fn validate(&self) -> Result<(), AospBuildError> {
        if !self.lunch_target.is_production() {
            return Err(AospBuildError::BuildVariantNotUser);
        }
        self.board_config.validate()?;
        self.device_mk.validate_packages()?;
        self.android_bp.validate()?;
        self.microg.validate()?;
        Ok(())
    }

    /// Build the default AETHER AOSP build configuration.
    pub fn default_aether() -> Result<Self, AospBuildError> {
        Ok(Self {
            device_mk: DeviceMk::from_defaults()?,
            board_config: BoardConfigMk::AETHER_DEFAULT,
            android_bp: AndroidBp::from_defaults()?,
            microg: MicrogIntegration::AETHER_DEFAULT,
            lunch_target: AETHER_LUNCH_TARGET,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Product package list must fit within MAX_PACKAGES.
#[allow(dead_code)]
const _PKG_COUNT_CHECK: () = {
    assert!(
        AETHER_PRODUCT_PACKAGES.len() <= MAX_PACKAGES,
        "AETHER_PRODUCT_PACKAGES exceeds MAX_PACKAGES"
    );
};

/// Copy-files list must fit within MAX_COPY_FILES.
#[allow(dead_code)]
const _CF_COUNT_CHECK: () = {
    assert!(
        AETHER_COPY_FILES.len() <= MAX_COPY_FILES,
        "AETHER_COPY_FILES exceeds MAX_COPY_FILES"
    );
};

/// Property overrides list must fit within MAX_PROPERTY_OVERRIDES.
#[allow(dead_code)]
const _PO_COUNT_CHECK: () = {
    assert!(
        AETHER_PROPERTY_OVERRIDES.len() <= MAX_PROPERTY_OVERRIDES,
        "AETHER_PROPERTY_OVERRIDES exceeds MAX_PROPERTY_OVERRIDES"
    );
};

/// Soong modules list must fit within MAX_SOONG_MODULES.
#[allow(dead_code)]
const _SM_COUNT_CHECK: () = {
    assert!(
        AETHER_SOONG_MODULES.len() <= MAX_SOONG_MODULES,
        "AETHER_SOONG_MODULES exceeds MAX_SOONG_MODULES"
    );
};

/// vbmeta partition is 64 KiB per AVB requirement.
#[allow(dead_code)]
const _VBMETA_SIZE_CHECK: () = {
    assert!(
        BoardPartitionSizes::AETHER_DEFAULT.vbmeta_bytes == 64 * 1024,
        "vbmeta partition must be exactly 64 KiB"
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BuildVariant ──────────────────────────────────────────────────────────

    #[test]
    fn build_variant_user_is_production() {
        assert!(BuildVariant::User.is_production());
        assert!(!BuildVariant::Userdebug.is_production());
        assert!(!BuildVariant::Eng.is_production());
    }

    #[test]
    fn build_variant_suffix_bytes() {
        assert_eq!(BuildVariant::User.suffix(), b"user");
        assert_eq!(BuildVariant::Userdebug.suffix(), b"userdebug");
        assert_eq!(BuildVariant::Eng.suffix(), b"eng");
    }

    // ── TargetArch ────────────────────────────────────────────────────────────

    #[test]
    fn target_arch_arm64_as_bytes() {
        assert_eq!(TargetArch::Arm64.as_bytes(), b"arm64");
    }

    // ── BoardPartitionSizes ───────────────────────────────────────────────────

    #[test]
    fn board_partition_sizes_default_validates() {
        assert!(BoardPartitionSizes::AETHER_DEFAULT.validate().is_ok());
    }

    #[test]
    fn board_partition_sizes_zero_boot_rejected() {
        let mut sizes = BoardPartitionSizes::AETHER_DEFAULT;
        sizes.boot_bytes = 0;
        assert_eq!(sizes.validate().unwrap_err(), AospBuildError::ZeroPartitionSize);
    }

    #[test]
    fn board_partition_sizes_too_large_rejected() {
        let mut sizes = BoardPartitionSizes::AETHER_DEFAULT;
        sizes.system_bytes = MAX_PARTITION_SIZE_BYTES + 1;
        assert_eq!(sizes.validate().unwrap_err(), AospBuildError::PartitionSizeTooLarge);
    }

    #[test]
    fn board_partition_sizes_vbmeta_64kib() {
        assert_eq!(BoardPartitionSizes::AETHER_DEFAULT.vbmeta_bytes, 64 * 1024);
    }

    // ── BoardConfigMk ─────────────────────────────────────────────────────────

    #[test]
    fn board_config_default_validates() {
        assert!(BoardConfigMk::AETHER_DEFAULT.validate().is_ok());
    }

    #[test]
    fn board_config_non_arm64_rejected() {
        let mut cfg = BoardConfigMk::AETHER_DEFAULT;
        cfg.target_arch = TargetArch::X86_64;
        assert_eq!(cfg.validate().unwrap_err(), AospBuildError::ArchNotArm64);
    }

    #[test]
    fn board_config_permissive_selinux_rejected() {
        let mut cfg = BoardConfigMk::AETHER_DEFAULT;
        cfg.selinux_policy = SelinuxPolicyType::Permissive;
        assert_eq!(cfg.validate().unwrap_err(), AospBuildError::SelinuxPolicyInvalid);
    }

    #[test]
    fn board_config_avb_disabled_rejected() {
        let mut cfg = BoardConfigMk::AETHER_DEFAULT;
        cfg.avb_enabled = false;
        assert_eq!(cfg.validate().unwrap_err(), AospBuildError::AvbNotConfigured);
    }

    // ── DeviceMk ─────────────────────────────────────────────────────────────

    #[test]
    fn device_mk_from_defaults_validates() {
        let mk = DeviceMk::from_defaults().unwrap();
        assert!(mk.validate_packages().is_ok());
    }

    #[test]
    fn device_mk_has_gmscore() {
        let mk = DeviceMk::from_defaults().unwrap();
        assert!(mk.has_package(b"GmsCore"));
    }

    #[test]
    fn device_mk_has_fakestore() {
        let mk = DeviceMk::from_defaults().unwrap();
        assert!(mk.has_package(b"FakeStore"));
    }

    #[test]
    fn device_mk_has_gralloc() {
        let mk = DeviceMk::from_defaults().unwrap();
        assert!(mk.has_package(b"gralloc.aether"));
    }

    #[test]
    fn device_mk_missing_package_rejected() {
        let mk = DeviceMk::new(); // empty
        assert_eq!(mk.validate_packages().unwrap_err(), AospBuildError::MissingRequiredPackage);
    }

    #[test]
    fn device_mk_package_list_full_rejected() {
        let mut mk = DeviceMk::new();
        for _ in 0..MAX_PACKAGES {
            mk.add_package(ProductPackage::new(b"x")).unwrap();
        }
        assert_eq!(
            mk.add_package(ProductPackage::new(b"y")).unwrap_err(),
            AospBuildError::PackageListFull,
        );
    }

    #[test]
    fn device_mk_property_ro_build_type_user() {
        let mk = DeviceMk::from_defaults().unwrap();
        let found = mk.property_overrides()
            .iter()
            .any(|p| p.key == b"ro.build.type" && p.value == b"user");
        assert!(found, "ro.build.type=user must be in PRODUCT_PROPERTY_OVERRIDES");
    }

    #[test]
    fn device_mk_property_adb_secure() {
        let mk = DeviceMk::from_defaults().unwrap();
        let found = mk.property_overrides()
            .iter()
            .any(|p| p.key == b"ro.adb.secure" && p.value == b"1");
        assert!(found, "ro.adb.secure=1 must be in PRODUCT_PROPERTY_OVERRIDES");
    }

    #[test]
    fn device_mk_copy_files_non_empty() {
        let mk = DeviceMk::from_defaults().unwrap();
        assert!(!mk.copy_files().is_empty());
    }

    // ── AndroidBp ─────────────────────────────────────────────────────────────

    #[test]
    fn android_bp_from_defaults_validates() {
        let bp = AndroidBp::from_defaults().unwrap();
        assert!(bp.validate().is_ok());
    }

    #[test]
    fn android_bp_has_sensor_hal() {
        let bp = AndroidBp::from_defaults().unwrap();
        assert!(bp.has_module(b"aether.sensors@2.1-service"));
    }

    #[test]
    fn android_bp_has_radio_hal() {
        let bp = AndroidBp::from_defaults().unwrap();
        assert!(bp.has_module(b"aether.radio@2.0-service"));
    }

    #[test]
    fn android_bp_missing_module_rejected() {
        let bp = AndroidBp::new(); // empty
        assert_eq!(bp.validate().unwrap_err(), AospBuildError::MissingRequiredSoongModule);
    }

    #[test]
    fn android_bp_full_rejected() {
        let mut bp = AndroidBp::new();
        for _ in 0..MAX_SOONG_MODULES {
            bp.add(SoongModule::new(SoongModuleType::Filegroup, b"x", false, false)).unwrap();
        }
        assert_eq!(
            bp.add(SoongModule::new(SoongModuleType::Filegroup, b"y", false, false)).unwrap_err(),
            AospBuildError::SoongModuleFull,
        );
    }

    // ── MicrogComponent ───────────────────────────────────────────────────────

    #[test]
    fn microg_component_package_names() {
        assert_eq!(MicrogComponent::GmsCore.package_name(), b"com.google.android.gms");
        assert_eq!(MicrogComponent::FakeStore.package_name(), b"com.android.vending");
        assert_eq!(MicrogComponent::GsfProxy.package_name(), b"com.google.android.gsf");
        assert_eq!(MicrogComponent::UnifiedNlp.package_name(), b"org.microg.nlp");
    }

    #[test]
    fn microg_component_module_names() {
        assert_eq!(MicrogComponent::GmsCore.module_name(), b"GmsCore");
        assert_eq!(MicrogComponent::FakeStore.module_name(), b"FakeStore");
        assert_eq!(MicrogComponent::GsfProxy.module_name(), b"GsfProxy");
        assert_eq!(MicrogComponent::UnifiedNlp.module_name(), b"UnifiedNlp");
    }

    #[test]
    fn microg_component_source_paths_under_vendor() {
        for component in [
            MicrogComponent::GmsCore,
            MicrogComponent::FakeStore,
            MicrogComponent::GsfProxy,
            MicrogComponent::UnifiedNlp,
        ] {
            let path = component.source_path();
            assert!(
                path.starts_with(b"vendor/microg/"),
                "microG component source must be under vendor/microg/"
            );
        }
    }

    // ── MicrogIntegration ─────────────────────────────────────────────────────

    #[test]
    fn microg_integration_default_validates() {
        assert!(MicrogIntegration::AETHER_DEFAULT.validate().is_ok());
    }

    #[test]
    fn microg_integration_gmscore_disabled_rejected() {
        let mut m = MicrogIntegration::AETHER_DEFAULT;
        m.gms_core = false;
        assert_eq!(m.validate().unwrap_err(), AospBuildError::MicrogNotEnabled);
    }

    #[test]
    fn microg_integration_spoofing_disabled_rejected() {
        let mut m = MicrogIntegration::AETHER_DEFAULT;
        m.signature_spoofing = SignatureSpoofingPolicy::Disabled;
        assert_eq!(m.validate().unwrap_err(), AospBuildError::SignatureSpoofingNotEnabled);
    }

    // ── LunchTarget ───────────────────────────────────────────────────────────

    #[test]
    fn lunch_target_aether_arm64_user_is_production() {
        assert!(AETHER_LUNCH_TARGET.is_production());
    }

    #[test]
    fn lunch_target_product_name() {
        assert_eq!(AETHER_LUNCH_TARGET.product, b"aether_arm64");
    }

    #[test]
    fn lunch_target_variant_is_user() {
        assert_eq!(AETHER_LUNCH_TARGET.variant, BuildVariant::User);
    }

    // ── OutputImage ───────────────────────────────────────────────────────────

    #[test]
    fn output_image_required_set() {
        assert!(OutputImage::Boot.is_required());
        assert!(OutputImage::System.is_required());
        assert!(OutputImage::Vendor.is_required());
        assert!(OutputImage::Vbmeta.is_required());
        assert!(OutputImage::Userdata.is_required());
        assert!(!OutputImage::Dtbo.is_required());
        assert!(!OutputImage::Product.is_required());
    }

    #[test]
    fn output_image_filenames() {
        assert_eq!(OutputImage::Boot.filename(), b"boot.img");
        assert_eq!(OutputImage::System.filename(), b"system.img");
        assert_eq!(OutputImage::Vendor.filename(), b"vendor.img");
        assert_eq!(OutputImage::Vbmeta.filename(), b"vbmeta.img");
        assert_eq!(OutputImage::Userdata.filename(), b"userdata.img");
    }

    // ── AospBuildGate ─────────────────────────────────────────────────────────

    #[test]
    fn gate_not_built_does_not_pass() {
        let gate = AospBuildGate::not_built();
        assert!(!gate.passes());
    }

    #[test]
    fn gate_passes_when_all_images_produced() {
        let ok = ImageGateState {
            image: OutputImage::Boot,
            produced: true,
            non_empty: true,
            within_size_limit: true,
        };
        let gate = AospBuildGate {
            boot: ImageGateState { image: OutputImage::Boot, ..ok },
            system: ImageGateState { image: OutputImage::System, ..ok },
            vendor: ImageGateState { image: OutputImage::Vendor, ..ok },
            vbmeta: ImageGateState { image: OutputImage::Vbmeta, ..ok },
            userdata: ImageGateState { image: OutputImage::Userdata, ..ok },
            lunch_target_registered: true,
            avb_verified: true,
        };
        assert!(gate.passes());
    }

    #[test]
    fn gate_fails_when_avb_not_verified() {
        let ok = ImageGateState {
            image: OutputImage::Boot,
            produced: true,
            non_empty: true,
            within_size_limit: true,
        };
        let gate = AospBuildGate {
            boot: ImageGateState { image: OutputImage::Boot, ..ok },
            system: ImageGateState { image: OutputImage::System, ..ok },
            vendor: ImageGateState { image: OutputImage::Vendor, ..ok },
            vbmeta: ImageGateState { image: OutputImage::Vbmeta, ..ok },
            userdata: ImageGateState { image: OutputImage::Userdata, ..ok },
            lunch_target_registered: true,
            avb_verified: false, // ← missing
        };
        assert!(!gate.passes());
    }

    #[test]
    fn gate_fails_when_image_empty() {
        let ok = ImageGateState {
            image: OutputImage::Boot,
            produced: true,
            non_empty: true,
            within_size_limit: true,
        };
        let gate = AospBuildGate {
            boot: ImageGateState {
                image: OutputImage::Boot,
                produced: true,
                non_empty: false, // ← empty
                within_size_limit: true,
            },
            system: ImageGateState { image: OutputImage::System, ..ok },
            vendor: ImageGateState { image: OutputImage::Vendor, ..ok },
            vbmeta: ImageGateState { image: OutputImage::Vbmeta, ..ok },
            userdata: ImageGateState { image: OutputImage::Userdata, ..ok },
            lunch_target_registered: true,
            avb_verified: true,
        };
        assert!(!gate.passes());
    }

    // ── AospBuildConfig ───────────────────────────────────────────────────────

    #[test]
    fn aosp_build_config_default_validates() {
        let cfg = AospBuildConfig::default_aether().unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn aosp_build_config_lunch_target_is_user() {
        let cfg = AospBuildConfig::default_aether().unwrap();
        assert!(cfg.lunch_target.is_production());
        assert_eq!(cfg.lunch_target.product, b"aether_arm64");
    }

    #[test]
    fn aosp_build_config_board_is_arm64() {
        let cfg = AospBuildConfig::default_aether().unwrap();
        assert_eq!(cfg.board_config.target_arch, TargetArch::Arm64);
    }

    #[test]
    fn aosp_build_config_microg_enabled() {
        let cfg = AospBuildConfig::default_aether().unwrap();
        assert!(cfg.microg.gms_core);
        assert!(cfg.microg.fake_store);
        assert_eq!(cfg.microg.signature_spoofing, SignatureSpoofingPolicy::Enabled);
    }

    #[test]
    fn aosp_build_config_userdebug_rejected() {
        let mut cfg = AospBuildConfig::default_aether().unwrap();
        cfg.lunch_target.variant = BuildVariant::Userdebug;
        assert_eq!(cfg.validate().unwrap_err(), AospBuildError::BuildVariantNotUser);
    }

    // ── Hardware Authenticity cross-checks (CLAUDE.md §Hardware Authenticity) ─

    #[test]
    fn ro_build_type_user_invariant() {
        let mk = DeviceMk::from_defaults().unwrap();
        let found = mk.property_overrides()
            .iter()
            .any(|p| p.key == b"ro.build.type" && p.value == b"user");
        assert!(found, "ro.build.type must be 'user' — NEVER userdebug");
    }

    #[test]
    fn selinux_enforcing_invariant() {
        assert_eq!(
            BoardConfigMk::AETHER_DEFAULT.selinux_policy,
            SelinuxPolicyType::Enforcing,
            "SELinux must be Enforcing in all AETHER production builds"
        );
    }

    #[test]
    fn avb_enabled_invariant() {
        assert!(
            BoardConfigMk::AETHER_DEFAULT.avb_enabled,
            "AVB must be enabled — all AETHER images must be AVB-signed"
        );
    }

    #[test]
    fn ram_size_round_number_in_property_overrides() {
        let mk = DeviceMk::from_defaults().unwrap();
        let ram = mk.property_overrides()
            .iter()
            .find(|p| p.key == b"ro.ram_size")
            .map(|p| p.value)
            .unwrap_or(b"0");
        let mb: u64 = ram.iter().fold(0u64, |acc, &b| acc * 10 + (b - b'0') as u64);
        let valid_sizes_mb: &[u64] = &[4096, 6144, 8192, 12288, 16384];
        assert!(
            valid_sizes_mb.contains(&mb),
            "ro.ram_size must be a round phone-class value, got {}",
            mb
        );
    }

    #[test]
    fn target_arch_is_arm64_only() {
        assert_eq!(
            BoardConfigMk::AETHER_DEFAULT.target_arch,
            TargetArch::Arm64,
            "AETHER Android partition is ARM64-only"
        );
    }
}
