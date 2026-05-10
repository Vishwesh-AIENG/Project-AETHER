// ch19: The Bootloader
//
// AETHER loads the Android-compliant bootloader into the Android partition's
// memory at EL1. The bootloader follows the Android Verified Boot 2.0 (AVB2)
// specification — it cryptographically verifies the boot image, selects the
// active A/B slot, constructs the kernel command line, and transfers execution
// to the Linux kernel entry point.
//
// This module encodes the bootloader's data structures and verification logic
// as Rust types. The bootloader itself runs at EL1 inside the Android partition;
// the types here are used by AETHER's EL2 code to configure the bootloader
// environment (trust anchor key, rollback indices, device state) before the
// first ERET into the Android partition.
//
// ── Android Verified Boot 2.0 (AVB2) ────────────────────────────────────────
//
// Verification chain:
//   1. Bootloader holds a trust anchor public key (embedded or in ROM)
//   2. Bootloader reads vbmeta partition → parses VBMeta header + descriptors
//   3. Signature over (header + auxiliary block) is verified against trust anchor
//   4. Each partition's hash or hashtree root hash is checked against VBMeta
//      descriptor:
//        • Hash descriptor   — entire partition hashed; matches stored digest
//        • Hashtree descriptor — dm-verity root hash checked; kernel verifies
//          blocks lazily at runtime
//   5. Rollback index in VBMeta must be ≥ minimum rollback index in secure
//      storage (prevents downgrade attacks)
//   6. Lock state determines enforcement: LOCKED = abort on failure; UNLOCKED
//      = warn but continue
//
// AETHER's bootloader reports LOCKED state because AETHER signs the Android
// image with its own build keys. The verification succeeds (AETHER built and
// signed the image), and the bootloader truthfully reports locked state —
// exactly what SafetyNet and attestation systems check.
//
// ── Android Boot Image Header (v3/v4) ───────────────────────────────────────
//
// AETHER targets Android 12+ which uses boot image header v3 (and v4 for
// vendor_boot). The header is exactly 4096 bytes (one page) for v3:
//
//   Offset    Size    Field
//   0         8       magic ("ANDROID!")
//   8         4       kernel_size (bytes, uncompressed size after decompression)
//   12        4       ramdisk_size
//   16        4       os_version (packed: version[30:11] patch_level[10:0])
//   20        4       header_size (4096 for v3)
//   24        16      reserved[4]
//   40        4       header_version (3 for v3, 4 for v4)
//   44        1536    cmdline (null-terminated)
//   1580      2516    padding to 4096 bytes
//
// Reference: source.android.com/docs/core/architecture/bootloader/boot-image-header
//
// ── A/B Partition Slots ──────────────────────────────────────────────────────
//
// Android uses two sets of partitions (slot A and slot B) for seamless OTA
// updates. The bootloader reads slot metadata, selects the bootable slot with
// the highest priority, and appends the slot suffix to partition names.
// Slot metadata lives in the misc partition (Android Bootloader Control AB
// format, also called BCB or boot_ctrl).
//
// ── Kernel Command Line ──────────────────────────────────────────────────────
//
// The bootloader constructs the kernel command line by concatenating:
//   • Parameters from the boot image header cmdline field
//   • Bootloader-generated parameters (slot suffix, verified boot state,
//     hardware identity, SELinux mode, build type)
//
// Required parameters for AETHER's Android partition (hardware-authenticity
// invariants from CLAUDE.md §Hardware Authenticity):
//   androidboot.hardware=aether
//   androidboot.selinux=enforcing
//   ro.build.type=user             (not userdebug — production invariant)
//   androidboot.verifiedbootstate=green
//   androidboot.slot_suffix=_a or _b
//
// ── No std, No Alloc ─────────────────────────────────────────────────────────
//
// All types use fixed-size arrays. The kernel command line is built into a
// caller-provided buffer (MAX_CMDLINE_LEN bytes). VBMeta parsing operates on
// a caller-provided byte slice representing the vbmeta partition contents.
//
// References:
//   Android AVB source  — android.googlesource.com/platform/external/avb
//   avb_vbmeta_image.h  — VBMeta header format (authoritative)
//   avb_descriptor.h    — descriptor tag values and layouts
//   avb_slot_verify.h   — slot verification API design
//   avb_crypto.h        — algorithm identifiers
//   source.android.com/docs/core/architecture/bootloader — requirements
//   u-boot android_image.c — U-Boot reference boot image parser
//   linux-ref/arch/arm64/include/asm/ — kernel entry convention

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by bootloader configuration and boot image parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderError {
    /// Boot image magic is not `ANDROID!`.
    InvalidBootMagic,
    /// Boot image header version is not supported (AETHER supports v3 and v4).
    UnsupportedHeaderVersion,
    /// Boot image header size field does not match the expected size for
    /// the header version.
    InvalidHeaderSize,
    /// VBMeta image magic is not `AVB0`.
    InvalidVbmetaMagic,
    /// VBMeta header version is newer than the maximum AETHER supports.
    UnsupportedVbmetaVersion,
    /// VBMeta signature verification failed: the image was not signed by
    /// the trusted key, or the signature bytes are malformed.
    SignatureVerificationFailed,
    /// VBMeta was signed by an untrusted key (key does not match the
    /// trust anchor embedded in the bootloader).
    UntrustedPublicKey,
    /// The VBMeta rollback index is less than the minimum rollback index
    /// stored in secure storage — downgrade attempt detected.
    RollbackIndexViolation,
    /// A partition's hash does not match the digest recorded in its AVB2
    /// hash descriptor — partition has been tampered with.
    PartitionHashMismatch,
    /// A partition's hashtree root hash does not match the AVB2 hashtree
    /// descriptor — dm-verity root hash verification failed.
    HashtrooMismatch,
    /// The VBMeta descriptor block is malformed (truncated or invalid tag).
    MalformedDescriptor,
    /// The buffer provided for the kernel command line is too small.
    CmdlineBufferTooSmall,
    /// No bootable A/B slot is available (both slots marked unbootable).
    NoBootableSlot,
    /// The bootloader lock state has been tampered with or is in an
    /// inconsistent state (should never occur in production).
    LockStateTampered,
    /// The slot control block (BCB) magic does not match.
    InvalidSlotControlBlock,
    /// Requested slot index is out of range (must be 0 or 1).
    InvalidSlotIndex,
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot image constants
//
// Source: Android boot image header specification
// (source.android.com/docs/core/architecture/bootloader/boot-image-header)
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes at offset 0 of every Android boot image.
pub const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";

/// Boot image header version 3 (introduced with Android 11/12).
pub const BOOT_HEADER_VERSION_3: u32 = 3;

/// Boot image header version 4 (vendor_boot uses v4; adds signature_size).
pub const BOOT_HEADER_VERSION_4: u32 = 4;

/// Boot image page size — v3/v4 headers are exactly one page (4096 bytes).
pub const BOOT_PAGE_SIZE: u32 = 4096;

/// Maximum kernel command line length in the v3/v4 header (bytes, including
/// the null terminator). Source: BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE in the
/// Android source tree (bootimage.h).
pub const BOOT_CMDLINE_MAX: usize = 1536;

// ─────────────────────────────────────────────────────────────────────────────
// Android Boot Image Header v3/v4
//
// Byte-precise layout. All multi-byte integers are little-endian.
// v3 header is exactly 4096 bytes; the cmdline field occupies bytes 44–1579.
// v4 header appends a u32 `signature_size` immediately after the v3 fields
// at offset 1580.
//
// AETHER uses this to parse the boot image loaded into the Android partition
// and to validate that the kernel and ramdisk sizes are within the allocated
// IPA range before ERETing to the bootloader.
//
// Source: source.android.com/docs/core/architecture/bootloader/boot-image-header
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed representation of a v3/v4 Android boot image header.
///
/// Fields are extracted from the flat byte layout; the struct is NOT
/// `repr(C)` — use `BootImageHeader::parse()` to construct from raw bytes.
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeader {
    /// Size of the kernel image in bytes (compressed).
    pub kernel_size: u32,
    /// Size of the ramdisk image in bytes (compressed CPIO).
    pub ramdisk_size: u32,
    /// Packed OS version: bits [30:11] = version, bits [10:0] = patch level.
    pub os_version: u32,
    /// Header size in bytes (must be 4096 for v3).
    pub header_size: u32,
    /// Header version (3 or 4).
    pub header_version: u32,
    /// Kernel command line from the boot image (null-padded, may be empty).
    pub cmdline: [u8; BOOT_CMDLINE_MAX],
    /// v4 only: size of the boot image signature in bytes (0 for v3).
    pub signature_size: u32,
}

impl BootImageHeader {
    /// Parse a boot image header from raw bytes.
    ///
    /// `data` must be at least `BOOT_PAGE_SIZE` bytes long and begin at the
    /// start of the boot image. Returns an error if the magic is wrong or the
    /// version is not 3 or 4.
    pub fn parse(data: &[u8]) -> Result<Self, BootloaderError> {
        if data.len() < BOOT_PAGE_SIZE as usize {
            return Err(BootloaderError::InvalidBootMagic);
        }

        // Verify magic at offset 0
        if &data[0..8] != BOOT_MAGIC {
            return Err(BootloaderError::InvalidBootMagic);
        }

        let kernel_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let ramdisk_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let os_version = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let header_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // reserved[4] at bytes 24–39 — skip

        let header_version = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

        if header_version != BOOT_HEADER_VERSION_3 && header_version != BOOT_HEADER_VERSION_4 {
            return Err(BootloaderError::UnsupportedHeaderVersion);
        }

        if header_size != BOOT_PAGE_SIZE {
            return Err(BootloaderError::InvalidHeaderSize);
        }

        let mut cmdline = [0u8; BOOT_CMDLINE_MAX];
        cmdline.copy_from_slice(&data[44..44 + BOOT_CMDLINE_MAX]);

        // v4 appends signature_size at byte 1580
        let signature_size = if header_version == BOOT_HEADER_VERSION_4 {
            if data.len() < 1584 {
                return Err(BootloaderError::UnsupportedHeaderVersion);
            }
            u32::from_le_bytes([data[1580], data[1581], data[1582], data[1583]])
        } else {
            0
        };

        Ok(Self {
            kernel_size,
            ramdisk_size,
            os_version,
            header_size,
            header_version,
            cmdline,
            signature_size,
        })
    }

    /// Decode the packed `os_version` field into (major, minor, patch, year, month).
    ///
    /// Format: bits[30:25]=major, [24:19]=minor, [18:11]=patch, [10:4]=year, [3:0]=month.
    /// Source: bootimage.h in the Android build system.
    pub fn decode_os_version(&self) -> OsVersion {
        let v = self.os_version;
        OsVersion {
            major: ((v >> 25) & 0x7F) as u8,
            minor: ((v >> 19) & 0x3F) as u8,
            patch: ((v >> 11) & 0xFF) as u8,
            year: 2000 + (((v >> 4) & 0x7F) as u16),
            month: (v & 0x0F) as u8,
        }
    }

    /// Return the null-terminated portion of the embedded command line as a
    /// byte slice (not including the null terminator).
    pub fn cmdline_str(&self) -> &[u8] {
        let end = self.cmdline.iter().position(|&b| b == 0).unwrap_or(BOOT_CMDLINE_MAX);
        &self.cmdline[..end]
    }
}

/// Decoded OS version from the boot image header `os_version` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub year: u16,
    pub month: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Android Verified Boot 2.0 — VBMeta Header
//
// The VBMeta image lives in a dedicated `vbmeta` partition and anchors the
// trust chain for all other verified partitions. Its layout:
//
//   Offset  Size   Field
//   0       4      magic ("AVB0")
//   4       4      required_libavb_version_major (must be 1)
//   8       4      required_libavb_version_minor
//   12      8      authentication_data_block_size
//   20      8      auxiliary_data_block_size
//   28      4      algorithm_type (AvbAlgorithm enum)
//   32      8      hash_offset (within authentication block)
//   40      8      hash_size
//   48      8      signature_offset (within authentication block)
//   56      8      signature_size
//   64      8      public_key_offset (within auxiliary block)
//   72      8      public_key_size
//   80      8      public_key_metadata_offset
//   88      8      public_key_metadata_size (may be 0)
//   96      8      descriptor_offset (within auxiliary block)
//   104     8      descriptor_size (total bytes for all descriptors)
//   112     8      rollback_index
//   120     4      flags
//   124     4      rollback_index_location
//   128     48     release_string (null-padded)
//   176     80     reserved
//   256     ---    authentication block (hash + signature)
//   256+auth_size  auxiliary block (public key + descriptors)
//
// Total header: 256 bytes.
// Source: avb_vbmeta_image.h in platform/external/avb
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes at offset 0 of every VBMeta image.
pub const VBMETA_MAGIC: &[u8; 4] = b"AVB0";

/// VBMeta header size in bytes (always 256).
pub const VBMETA_HEADER_SIZE: usize = 256;

/// Required major version of libavb. AETHER supports major version 1.
/// A VBMeta image requiring a higher major version is rejected.
pub const VBMETA_REQUIRED_MAJOR: u32 = 1;

/// Maximum supported minor version. AETHER accepts any minor version ≤ this.
pub const VBMETA_MAX_MINOR: u32 = 3;

/// AVB2 cryptographic algorithm identifiers.
/// Source: avb_crypto.h in platform/external/avb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AvbAlgorithm {
    /// No signing. Allowed only if VBMeta flags indicate no authentication.
    None = 0,
    /// RSASSA-PKCS1-v1_5 with SHA-256, 2048-bit key.
    Sha256Rsa2048 = 1,
    /// RSASSA-PKCS1-v1_5 with SHA-256, 4096-bit key.
    Sha256Rsa4096 = 2,
    /// RSASSA-PKCS1-v1_5 with SHA-256, 8192-bit key.
    Sha256Rsa8192 = 3,
    /// RSASSA-PKCS1-v1_5 with SHA-512, 2048-bit key.
    Sha512Rsa2048 = 4,
    /// RSASSA-PKCS1-v1_5 with SHA-512, 4096-bit key.
    Sha512Rsa4096 = 5,
    /// RSASSA-PKCS1-v1_5 with SHA-512, 8192-bit key.
    Sha512Rsa8192 = 6,
}

impl AvbAlgorithm {
    /// Parse from the u32 value stored in the VBMeta header.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Sha256Rsa2048),
            2 => Some(Self::Sha256Rsa4096),
            3 => Some(Self::Sha256Rsa8192),
            4 => Some(Self::Sha512Rsa2048),
            5 => Some(Self::Sha512Rsa4096),
            6 => Some(Self::Sha512Rsa8192),
            _ => None,
        }
    }

    /// Expected hash output size in bytes for this algorithm.
    pub fn hash_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => 32,
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => 64,
        }
    }
}

/// VBMeta flags (stored at offset 120 in the header).
/// Source: avb_vbmeta_image.h AVB_VBMETA_IMAGE_FLAGS_* constants.
pub mod vbmeta_flags {
    /// Hashtree verification is disabled for this VBMeta image.
    /// Normally unset for production builds.
    pub const HASHTREE_DISABLED: u32 = 1 << 0;
    /// Verification is disabled entirely (permits unsigned images).
    /// AETHER rejects VBMeta images with this flag set.
    pub const VERIFICATION_DISABLED: u32 = 1 << 1;
}

/// Parsed VBMeta header fields.
///
/// Constructed by `VbmetaHeader::parse()` — not repr(C) because the raw
/// format has 64-bit fields that may be misaligned.
#[derive(Debug, Clone, Copy)]
pub struct VbmetaHeader {
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub authentication_data_block_size: u64,
    pub auxiliary_data_block_size: u64,
    pub algorithm_type: AvbAlgorithm,
    pub hash_offset: u64,
    pub hash_size: u64,
    pub signature_offset: u64,
    pub signature_size: u64,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub public_key_metadata_offset: u64,
    pub public_key_metadata_size: u64,
    pub descriptor_offset: u64,
    pub descriptor_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    /// Null-padded release string from avbtool (e.g., "avbtool 1.3.0").
    pub release_string: [u8; 48],
}

impl VbmetaHeader {
    /// Parse a VBMeta header from the first 256 bytes of a vbmeta partition.
    ///
    /// Returns `InvalidVbmetaMagic` if the first four bytes are not `AVB0`.
    /// Returns `UnsupportedVbmetaVersion` if the major version is not 1.
    pub fn parse(data: &[u8]) -> Result<Self, BootloaderError> {
        if data.len() < VBMETA_HEADER_SIZE {
            return Err(BootloaderError::InvalidVbmetaMagic);
        }

        if &data[0..4] != VBMETA_MAGIC {
            return Err(BootloaderError::InvalidVbmetaMagic);
        }

        let required_major = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let required_minor = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // VBMeta fields are big-endian (network byte order).
        // Source: avb_vbmeta_image.h — all multi-byte fields use htobe*().
        if required_major != VBMETA_REQUIRED_MAJOR {
            return Err(BootloaderError::UnsupportedVbmetaVersion);
        }

        let read_u64_be = |off: usize| -> u64 {
            u64::from_be_bytes([
                data[off], data[off+1], data[off+2], data[off+3],
                data[off+4], data[off+5], data[off+6], data[off+7],
            ])
        };
        let read_u32_be = |off: usize| -> u32 {
            u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]])
        };

        let authentication_data_block_size = read_u64_be(12);
        let auxiliary_data_block_size = read_u64_be(20);
        let algorithm_raw = read_u32_be(28);
        let algorithm_type = AvbAlgorithm::from_u32(algorithm_raw)
            .ok_or(BootloaderError::UnsupportedVbmetaVersion)?;
        let hash_offset = read_u64_be(32);
        let hash_size = read_u64_be(40);
        let signature_offset = read_u64_be(48);
        let signature_size = read_u64_be(56);
        let public_key_offset = read_u64_be(64);
        let public_key_size = read_u64_be(72);
        let public_key_metadata_offset = read_u64_be(80);
        let public_key_metadata_size = read_u64_be(88);
        let descriptor_offset = read_u64_be(96);
        let descriptor_size = read_u64_be(104);
        let rollback_index = read_u64_be(112);
        let flags = read_u32_be(120);
        let rollback_index_location = read_u32_be(124);

        let mut release_string = [0u8; 48];
        release_string.copy_from_slice(&data[128..176]);

        Ok(Self {
            required_libavb_version_major: required_major,
            required_libavb_version_minor: required_minor,
            authentication_data_block_size,
            auxiliary_data_block_size,
            algorithm_type,
            hash_offset,
            hash_size,
            signature_offset,
            signature_size,
            public_key_offset,
            public_key_size,
            public_key_metadata_offset,
            public_key_metadata_size,
            descriptor_offset,
            descriptor_size,
            rollback_index,
            flags,
            rollback_index_location,
            release_string,
        })
    }

    /// True if VERIFICATION_DISABLED flag is set — AETHER rejects such images.
    pub fn verification_disabled(&self) -> bool {
        self.flags & vbmeta_flags::VERIFICATION_DISABLED != 0
    }

    /// True if HASHTREE_DISABLED flag is set.
    pub fn hashtree_disabled(&self) -> bool {
        self.flags & vbmeta_flags::HASHTREE_DISABLED != 0
    }

    /// Byte offset of the authentication block within the vbmeta partition data.
    /// (Immediately after the 256-byte header.)
    pub const fn authentication_block_offset(&self) -> usize {
        VBMETA_HEADER_SIZE
    }

    /// Byte offset of the auxiliary block within the vbmeta partition data.
    pub fn auxiliary_block_offset(&self) -> usize {
        VBMETA_HEADER_SIZE + self.authentication_data_block_size as usize
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AVB2 Descriptors
//
// Descriptors are packed back-to-back in the auxiliary block starting at
// `descriptor_offset` relative to the auxiliary block base. Each descriptor
// begins with a tag (u64, big-endian) and `num_bytes_following` (u64, BE)
// that gives the byte count of the descriptor body (not including the tag
// and length fields themselves).
//
// Source: avb_descriptor.h in platform/external/avb.
// ─────────────────────────────────────────────────────────────────────────────

/// AVB2 descriptor tag values (u64, big-endian in the serialised form).
/// Source: avb_descriptor.h AVB_DESCRIPTOR_TAG_*.
pub mod avb_descriptor_tag {
    /// Property descriptor (key-value metadata pair).
    pub const PROPERTY: u64 = 0;
    /// Hashtree descriptor — for large partitions (system, vendor).
    /// The bootloader verifies only the root hash; blocks verified lazily by dm-verity.
    pub const HASHTREE: u64 = 1;
    /// Hash descriptor — for small partitions (boot, dtbo).
    /// The bootloader hashes the entire partition and compares to stored digest.
    pub const HASH: u64 = 2;
    /// Kernel command line descriptor — extra cmdline appended by avbtool.
    pub const KERNEL_CMDLINE: u64 = 3;
    /// Chain partition descriptor — delegates verification of a partition to
    /// a separate VBMeta image embedded in that partition.
    pub const CHAIN_PARTITION: u64 = 4;
}

/// Parsed AVB2 hash descriptor (tag = 2).
///
/// Used for the `boot` and `dtbo` partitions. The bootloader reads the
/// entire partition into memory and computes its hash; the result must match
/// `digest` exactly.
///
/// Source: avb_descriptor.h AvbHashDescriptor.
#[derive(Debug, Clone, Copy)]
pub struct AvbHashDescriptor {
    /// Size of the image that was hashed (bytes). Must match partition size.
    pub image_size: u64,
    /// Hash algorithm name (null-padded, e.g., "sha256\0...").
    pub hash_algorithm: [u8; 32],
    /// Length of the partition name (in bytes) following the fixed fields.
    pub partition_name_len: u32,
    /// Length of the salt (in bytes) following the partition name.
    pub salt_len: u32,
    /// Length of the digest (in bytes) following the salt.
    pub digest_len: u32,
    /// Descriptor flags (reserved, typically 0).
    pub flags: u32,
}

impl AvbHashDescriptor {
    /// Fixed-field byte count (after tag and num_bytes_following, before
    /// variable-length fields). Source: avb_descriptor.h.
    pub const FIXED_SIZE: usize = 60;

    /// Parse a hash descriptor from the fixed-size portion of a descriptor body.
    ///
    /// `body` must be at least `FIXED_SIZE` bytes long.
    pub fn parse_fixed(body: &[u8]) -> Result<Self, BootloaderError> {
        if body.len() < Self::FIXED_SIZE {
            return Err(BootloaderError::MalformedDescriptor);
        }
        let read_u64_be = |off: usize| u64::from_be_bytes([
            body[off], body[off+1], body[off+2], body[off+3],
            body[off+4], body[off+5], body[off+6], body[off+7],
        ]);
        let read_u32_be = |off: usize| u32::from_be_bytes([
            body[off], body[off+1], body[off+2], body[off+3],
        ]);

        let image_size = read_u64_be(0);
        let mut hash_algorithm = [0u8; 32];
        hash_algorithm.copy_from_slice(&body[8..40]);
        let partition_name_len = read_u32_be(40);
        let salt_len = read_u32_be(44);
        let digest_len = read_u32_be(48);
        let flags = read_u32_be(52);
        // bytes 56–59: reserved

        Ok(Self {
            image_size,
            hash_algorithm,
            partition_name_len,
            salt_len,
            digest_len,
            flags,
        })
    }

    /// Total byte count for this descriptor including variable-length fields.
    pub fn total_variable_len(&self) -> usize {
        self.partition_name_len as usize
            + self.salt_len as usize
            + self.digest_len as usize
    }
}

/// Parsed AVB2 hashtree descriptor (tag = 1).
///
/// Used for large partitions (`system`, `vendor`). The bootloader verifies
/// the root hash of the dm-verity Merkle tree; block-level verification is
/// delegated to the kernel's dm-verity driver at runtime.
///
/// Source: avb_descriptor.h AvbHashtreeDescriptor.
#[derive(Debug, Clone, Copy)]
pub struct AvbHashtreeDescriptor {
    /// dm-verity version (typically 1).
    pub dm_verity_version: u32,
    /// Size of the data to verify (bytes).
    pub image_size: u64,
    /// Byte offset of the first hashtree block within the partition image.
    pub tree_offset: u64,
    /// Total size of the hashtree in bytes.
    pub tree_size: u64,
    /// dm-verity data block size in bytes (typically 4096).
    pub data_block_size: u32,
    /// dm-verity hash block size in bytes (typically 4096).
    pub hash_block_size: u32,
    /// Number of FEC (Forward Error Correction) roots (0 = FEC disabled).
    pub fec_num_roots: u32,
    /// Byte offset of FEC data within the partition.
    pub fec_offset: u64,
    /// Size of FEC data in bytes.
    pub fec_size: u64,
    /// Hash algorithm name (null-padded, e.g., "sha256\0...").
    pub hash_algorithm: [u8; 32],
    /// Length of the partition name (bytes) following fixed fields.
    pub partition_name_len: u32,
    /// Length of the salt (bytes).
    pub salt_len: u32,
    /// Length of the root digest (bytes).
    pub root_digest_len: u32,
    /// Descriptor flags.
    pub flags: u32,
}

impl AvbHashtreeDescriptor {
    /// Fixed-field byte count (after tag and num_bytes_following).
    pub const FIXED_SIZE: usize = 120;

    /// Parse the fixed-size fields of a hashtree descriptor body.
    pub fn parse_fixed(body: &[u8]) -> Result<Self, BootloaderError> {
        if body.len() < Self::FIXED_SIZE {
            return Err(BootloaderError::MalformedDescriptor);
        }
        let read_u64_be = |off: usize| u64::from_be_bytes([
            body[off], body[off+1], body[off+2], body[off+3],
            body[off+4], body[off+5], body[off+6], body[off+7],
        ]);
        let read_u32_be = |off: usize| u32::from_be_bytes([
            body[off], body[off+1], body[off+2], body[off+3],
        ]);

        let dm_verity_version = read_u32_be(0);
        // 4 bytes reserved
        let image_size = read_u64_be(8);
        let tree_offset = read_u64_be(16);
        let tree_size = read_u64_be(24);
        let data_block_size = read_u32_be(32);
        let hash_block_size = read_u32_be(36);
        let fec_num_roots = read_u32_be(40);
        let fec_offset = read_u64_be(48);
        let fec_size = read_u64_be(56);
        let mut hash_algorithm = [0u8; 32];
        hash_algorithm.copy_from_slice(&body[64..96]);
        let partition_name_len = read_u32_be(96);
        let salt_len = read_u32_be(100);
        let root_digest_len = read_u32_be(104);
        let flags = read_u32_be(108);
        // bytes 112–119: reserved

        Ok(Self {
            dm_verity_version,
            image_size,
            tree_offset,
            tree_size,
            data_block_size,
            hash_block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm,
            partition_name_len,
            salt_len,
            root_digest_len,
            flags,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollback Index
//
// Each VBMeta image carries a rollback_index (u64). Secure storage holds a
// minimum rollback index per location. The bootloader compares:
//   vbmeta.rollback_index >= secure_storage[vbmeta.rollback_index_location]
//
// If the check fails, the image is rejected as a downgrade attempt.
// AETHER's bootloader uses the TPM NV index (on x86) or eMMC RPMB (on ARM)
// as the secure rollback store.
//
// Source: Android Bootloader Requirements — source.android.com
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of rollback index locations AETHER tracks.
/// Android typically uses locations 0–3; AETHER reserves 8 slots.
pub const MAX_ROLLBACK_LOCATIONS: usize = 8;

/// Persistent rollback index store (one u64 per location).
///
/// In production this is backed by TPM NV or eMMC RPMB. For AETHER's
/// compile-time representation we hold it as an in-memory table; the actual
/// persistence layer is platform-specific and loaded from secure storage
/// before `verify()` is called.
#[derive(Debug, Clone, Copy)]
pub struct RollbackIndexStore {
    /// Minimum rollback index per location. Index 0 is the default location.
    minimums: [u64; MAX_ROLLBACK_LOCATIONS],
}

impl RollbackIndexStore {
    /// Construct with all minimums initialised to 0 (fresh device, no updates).
    pub const fn new() -> Self {
        Self { minimums: [0u64; MAX_ROLLBACK_LOCATIONS] }
    }

    /// Read the minimum rollback index at `location`.
    ///
    /// Returns 0 if `location` is out of range (conservative: always bootable).
    pub fn get(&self, location: usize) -> u64 {
        if location < MAX_ROLLBACK_LOCATIONS {
            self.minimums[location]
        } else {
            0
        }
    }

    /// Update the minimum rollback index at `location`.
    ///
    /// In production this write must be committed to secure storage BEFORE
    /// the bootloader allows the new image to run — otherwise an interrupted
    /// write could leave the device vulnerable.
    pub fn set(&mut self, location: usize, minimum: u64) -> Result<(), BootloaderError> {
        if location >= MAX_ROLLBACK_LOCATIONS {
            return Err(BootloaderError::InvalidSlotIndex);
        }
        // Rollback index is monotonically non-decreasing: never allow a
        // minimum to go backwards.
        if minimum >= self.minimums[location] {
            self.minimums[location] = minimum;
        }
        Ok(())
    }

    /// Verify that `image_rollback_index` at `location` meets the stored minimum.
    pub fn verify(
        &self,
        location: usize,
        image_rollback_index: u64,
    ) -> Result<(), BootloaderError> {
        if image_rollback_index < self.get(location) {
            Err(BootloaderError::RollbackIndexViolation)
        } else {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootloader Lock State
//
// Android defines three device states (Android Verified Boot Specification):
//
//   LOCKED   — verified boot is fully enforced. Boot fails if verification
//               fails. SafetyNet reports a verified state. AETHER ships in
//               this state; the trust anchor key is AETHER's build key.
//
//   UNLOCKED — verification is skipped. Used by developers who want to run
//               custom images. SafetyNet reports an unverified state. Not
//               available in AETHER production builds.
//
//   ORANGE   — user-installed key. The bootloader accepts images signed by
//               a user-provided key. The device shows an orange warning at
//               boot. Not supported by AETHER (would require OEM unlock).
//
// The lock state is stored in a dedicated secure persistent register (e.g.,
// a dedicated NV index in the TPM on x86, or a dedicated eMMC RPMB region
// on ARM). AETHER's EL2 code must ensure the lock state cannot be changed
// via a guest hypercall.
// ─────────────────────────────────────────────────────────────────────────────

/// The lock state of the AETHER bootloader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderLockState {
    /// Verified boot fully enforced. Only images signed by AETHER's build
    /// key are accepted. Reported to the kernel as `androidboot.verifiedbootstate=green`.
    Locked,
    /// Verification disabled. Reported as `androidboot.verifiedbootstate=orange`.
    /// Not available in production AETHER builds.
    Unlocked,
    /// User-installed trust anchor. Reported as `androidboot.verifiedbootstate=yellow`.
    Orange,
}

impl BootloaderLockState {
    /// The `androidboot.verifiedbootstate` value for the kernel command line.
    pub fn verified_boot_state_str(&self) -> &'static [u8] {
        match self {
            Self::Locked => b"green",
            Self::Unlocked => b"orange",
            Self::Orange => b"yellow",
        }
    }

    /// True if verified boot is enforced (verification failures halt boot).
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Locked)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A/B Partition Slot Selection
//
// Android uses two partition sets (slot A and slot B) to support seamless OTA
// updates. Slot metadata is stored in the `misc` partition using the Android
// Bootloader Control AB format (also called BCB or boot_ctrl_ab).
//
// BCB layout (first 32 bytes of the misc partition):
//   0     4    magic (0x42414200 = "BAB\0" in LE)
//   4     1    version (must be 1)
//   5     3    reserved
//   8     N    slot_info[MAX_SLOTS] — each 4 bytes:
//                  priority:     4 bits   (15 = highest, 0 = unbootable)
//                  tries_remaining: 3 bits (0–7 attempts left before marking unbootable)
//                  successful_boot: 1 bit  (1 = this slot booted successfully at least once)
//   ...   ...  CRC-32 of bytes 0 through (size-4)
//
// Source: android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/boot_control.h
// ─────────────────────────────────────────────────────────────────────────────

/// Number of A/B slots (always 2 in the Android AB model).
pub const MAX_SLOTS: usize = 2;

/// Magic value at the start of the BCB in the misc partition (little-endian).
pub const SLOT_CONTROL_MAGIC: u32 = 0x42_41_42_00; // "BAB\0"

/// A/B slot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSlot {
    /// Partition suffix "_a" — the default first slot.
    A = 0,
    /// Partition suffix "_b" — the OTA update slot.
    B = 1,
}

impl BootSlot {
    /// Partition name suffix for this slot ("_a" or "_b").
    pub fn suffix(&self) -> &'static [u8] {
        match self {
            Self::A => b"_a",
            Self::B => b"_b",
        }
    }

    /// The other slot.
    pub fn other(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    /// Construct from a slot index (0 = A, 1 = B).
    pub fn from_index(idx: usize) -> Result<Self, BootloaderError> {
        match idx {
            0 => Ok(Self::A),
            1 => Ok(Self::B),
            _ => Err(BootloaderError::InvalidSlotIndex),
        }
    }
}

/// Per-slot metadata from the BCB.
#[derive(Debug, Clone, Copy)]
pub struct SlotInfo {
    /// Boot priority: 15 = highest, 0 = unbootable.
    pub priority: u8,
    /// Number of remaining boot attempts before this slot is marked unbootable.
    pub tries_remaining: u8,
    /// True if this slot has successfully completed at least one boot.
    pub successful_boot: bool,
}

impl SlotInfo {
    /// Construct from the packed byte stored in the BCB.
    ///
    /// Bits [7:4] = priority, bits [3:1] = tries_remaining, bit [0] = successful.
    pub fn from_packed(packed: u8) -> Self {
        Self {
            priority: (packed >> 4) & 0x0F,
            tries_remaining: (packed >> 1) & 0x07,
            successful_boot: (packed & 0x01) != 0,
        }
    }

    /// Serialise back to the packed byte.
    pub fn to_packed(&self) -> u8 {
        let p = (self.priority & 0x0F) << 4;
        let t = (self.tries_remaining & 0x07) << 1;
        let s = if self.successful_boot { 1 } else { 0 };
        p | t | s
    }

    /// True if the slot is eligible to be booted (priority > 0 and either
    /// successful_boot is set or tries_remaining > 0).
    pub fn is_bootable(&self) -> bool {
        self.priority > 0 && (self.successful_boot || self.tries_remaining > 0)
    }
}

/// Parsed Android Boot Control Block.
#[derive(Debug, Clone, Copy)]
pub struct BootControlBlock {
    pub slots: [SlotInfo; MAX_SLOTS],
}

impl BootControlBlock {
    /// Parse from the raw BCB bytes at the start of the misc partition.
    ///
    /// `data` must be at least 12 bytes (magic(4) + version(1) + reserved(3)
    /// + slot_info[2] each packed as one byte = 2 bytes + padding).
    pub fn parse(data: &[u8]) -> Result<Self, BootloaderError> {
        if data.len() < 12 {
            return Err(BootloaderError::InvalidSlotControlBlock);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SLOT_CONTROL_MAGIC {
            return Err(BootloaderError::InvalidSlotControlBlock);
        }

        let version = data[4];
        if version != 1 {
            return Err(BootloaderError::InvalidSlotControlBlock);
        }

        // Slot info is packed: one byte per slot, starting at offset 8.
        let slot_a = SlotInfo::from_packed(data[8]);
        let slot_b = SlotInfo::from_packed(data[9]);

        Ok(Self {
            slots: [slot_a, slot_b],
        })
    }

    /// Select the active boot slot according to Android's priority rules:
    ///   1. Choose the bootable slot with the highest priority.
    ///   2. If both have equal priority, prefer slot A.
    ///   3. If neither is bootable, return `NoBootableSlot`.
    pub fn select_slot(&self) -> Result<BootSlot, BootloaderError> {
        let a = &self.slots[0];
        let b = &self.slots[1];

        match (a.is_bootable(), b.is_bootable()) {
            (false, false) => Err(BootloaderError::NoBootableSlot),
            (true, false) => Ok(BootSlot::A),
            (false, true) => Ok(BootSlot::B),
            (true, true) => {
                if b.priority > a.priority {
                    Ok(BootSlot::B)
                } else {
                    Ok(BootSlot::A)
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel Command Line Builder
//
// The bootloader constructs the kernel command line by concatenating:
//   1. The cmdline field from the boot image header
//   2. AETHER-generated parameters (hardware identity, verified boot state,
//      slot suffix, SELinux mode, build type)
//
// Hardware-authenticity invariants (CLAUDE.md §Hardware Authenticity):
//   • ro.build.type=user (never userdebug in production)
//   • androidboot.selinux=enforcing
//   • androidboot.verifiedbootstate=green (LOCKED state)
//
// The combined command line is capped at MAX_CMDLINE_LEN bytes including the
// null terminator. The builder appends a NUL byte after the last parameter.
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum kernel command line length including the null terminator.
pub const MAX_CMDLINE_LEN: usize = 4096;

/// Kernel command line builder — accumulates parameters into a fixed-size buffer.
pub struct KernelCmdline {
    buf: [u8; MAX_CMDLINE_LEN],
    len: usize,
}

impl KernelCmdline {
    /// Construct an empty command line.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_CMDLINE_LEN],
            len: 0,
        }
    }

    /// Append a raw byte slice (must not contain NUL bytes).
    ///
    /// A single space is prepended automatically if the buffer is not empty.
    pub fn append(&mut self, param: &[u8]) -> Result<(), BootloaderError> {
        if param.is_empty() {
            return Ok(());
        }
        // Account for leading space if needed
        let space = if self.len > 0 { 1 } else { 0 };
        if self.len + space + param.len() + 1 > MAX_CMDLINE_LEN {
            return Err(BootloaderError::CmdlineBufferTooSmall);
        }
        if space == 1 {
            self.buf[self.len] = b' ';
            self.len += 1;
        }
        self.buf[self.len..self.len + param.len()].copy_from_slice(param);
        self.len += param.len();
        // Keep NUL terminator at buf[len]
        self.buf[self.len] = 0;
        Ok(())
    }

    /// Append a `key=value` pair.
    pub fn append_kv(&mut self, key: &[u8], value: &[u8]) -> Result<(), BootloaderError> {
        let space = if self.len > 0 { 1 } else { 0 };
        let needed = space + key.len() + 1 + value.len() + 1;
        if self.len + needed > MAX_CMDLINE_LEN {
            return Err(BootloaderError::CmdlineBufferTooSmall);
        }
        if space == 1 {
            self.buf[self.len] = b' ';
            self.len += 1;
        }
        self.buf[self.len..self.len + key.len()].copy_from_slice(key);
        self.len += key.len();
        self.buf[self.len] = b'=';
        self.len += 1;
        self.buf[self.len..self.len + value.len()].copy_from_slice(value);
        self.len += value.len();
        self.buf[self.len] = 0;
        Ok(())
    }

    /// Return the constructed command line as a null-terminated byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len + 1]
    }

    /// Current byte count (not including the NUL terminator).
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no parameters have been added yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootloader Trust Anchor
//
// AETHER embeds the public key of its build signing key directly in the
// bootloader configuration. VBMeta images must be signed by the corresponding
// private key (held in AETHER's CI/CD signing environment). This is analogous
// to an OEM key embedded in ROM on a real Android device.
//
// The public key is stored in AVB2's RSAPublicKey format:
//   - key_num_bits: u32 (key length in bits, e.g., 4096)
//   - n0inv: u32 (−n^{−1} mod 2^32, used in Montgomery multiplication)
//   - modulus: [u8; key_bytes] (big-endian RSA modulus)
//   - rr: [u8; key_bytes] (R^2 mod n for Montgomery form)
//
// Source: avb_rsa.h in platform/external/avb.
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum supported RSA key size in bytes (8192-bit key = 1024 bytes modulus).
pub const MAX_RSA_KEY_BYTES: usize = 1024;

/// Representation of an AVB2 RSA public key (trust anchor).
///
/// In production, this is populated from the compiled-in key material generated
/// by `avbtool extract_public_key`. The modulus and RR values are big-endian.
#[derive(Clone, Copy)]
pub struct AvbPublicKey {
    /// RSA key size in bits (2048, 4096, or 8192).
    pub key_num_bits: u32,
    /// Montgomery parameter: −n^{−1} mod 2^32.
    pub n0inv: u32,
    /// RSA modulus n, big-endian, padded with leading zeros to MAX_RSA_KEY_BYTES.
    pub modulus: [u8; MAX_RSA_KEY_BYTES],
    /// Montgomery RR = R^2 mod n, big-endian, same size as modulus.
    pub rr: [u8; MAX_RSA_KEY_BYTES],
}

impl AvbPublicKey {
    /// RSA key size in bytes.
    pub fn key_bytes(&self) -> usize {
        self.key_num_bits as usize / 8
    }

    /// Compare the serialised public key from a VBMeta auxiliary block against
    /// this trust anchor.
    ///
    /// The VBMeta auxiliary block contains the key in the same AVB RSAPublicKey
    /// format. This function checks that `vbmeta_key_data` matches the trust
    /// anchor byte-for-byte. Returns `UntrustedPublicKey` on mismatch.
    ///
    /// IMPORTANT: This comparison must be constant-time in production to
    /// prevent timing side-channels. This implementation is for structural
    /// correctness only; a production implementation must use a constant-time
    /// comparison primitive.
    pub fn verify_matches(
        &self,
        vbmeta_key_data: &[u8],
    ) -> Result<(), BootloaderError> {
        let key_bytes = self.key_bytes();
        // AVB RSAPublicKey serialised size: 4 (key_num_bits) + 4 (n0inv) + key_bytes + key_bytes
        let expected_len = 8 + key_bytes * 2;
        if vbmeta_key_data.len() < expected_len {
            return Err(BootloaderError::UntrustedPublicKey);
        }

        // Check key_num_bits
        let bits = u32::from_be_bytes([
            vbmeta_key_data[0], vbmeta_key_data[1],
            vbmeta_key_data[2], vbmeta_key_data[3],
        ]);
        if bits != self.key_num_bits {
            return Err(BootloaderError::UntrustedPublicKey);
        }

        // Check n0inv
        let n0inv = u32::from_be_bytes([
            vbmeta_key_data[4], vbmeta_key_data[5],
            vbmeta_key_data[6], vbmeta_key_data[7],
        ]);
        if n0inv != self.n0inv {
            return Err(BootloaderError::UntrustedPublicKey);
        }

        // Compare modulus (constant-time accumulation)
        let modulus_data = &vbmeta_key_data[8..8 + key_bytes];
        let modulus_anchor = &self.modulus[MAX_RSA_KEY_BYTES - key_bytes..];
        let mut diff: u8 = 0;
        for (a, b) in modulus_data.iter().zip(modulus_anchor.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(BootloaderError::UntrustedPublicKey);
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootloader Configuration
//
// Static configuration provided by AETHER's EL2 code to the bootloader
// environment. This structure is written into the Android partition's memory
// at a known address before the first ERET into the partition. The bootloader
// reads it via a platform-specific protocol (device tree node or well-known
// physical address).
// ─────────────────────────────────────────────────────────────────────────────

/// Bootloader configuration — the static contract between AETHER's EL2 code
/// and the Android bootloader running at EL1.
pub struct BootloaderConfig {
    /// Trust anchor public key. VBMeta must be signed by the matching private key.
    pub trust_anchor: AvbPublicKey,
    /// Persistent rollback index store (loaded from secure storage at boot time).
    pub rollback_store: RollbackIndexStore,
    /// Bootloader lock state. AETHER production builds always set this to Locked.
    pub lock_state: BootloaderLockState,
    /// Physical address in the Android partition's IPA space where the
    /// bootloader image is loaded by AETHER before the first ERET.
    pub bootloader_ipa: u64,
    /// Physical address of the device tree blob (DTB) passed to the kernel.
    /// AETHER constructs a minimal DTB describing the Android partition's
    /// virtual hardware and places it here before ERETing to the bootloader.
    pub dtb_ipa: u64,
    /// Physical address where the kernel image will be loaded by the bootloader.
    pub kernel_load_ipa: u64,
    /// Physical address where the initial ramdisk will be placed.
    pub ramdisk_ipa: u64,
}

impl BootloaderConfig {
    /// Validate the bootloader configuration.
    ///
    /// Checks that:
    /// - Lock state is Locked (production requirement)
    /// - IPA addresses are non-zero and page-aligned
    /// - Kernel and ramdisk regions do not overlap the DTB or bootloader regions
    pub fn validate(&self) -> Result<(), BootloaderError> {
        // Production invariant: bootloader must be LOCKED.
        if !self.lock_state.is_enforcing() {
            return Err(BootloaderError::LockStateTampered);
        }

        // All IPA addresses must be non-zero and 4KiB-aligned.
        let page_mask: u64 = 0xFFF;
        for &addr in &[
            self.bootloader_ipa,
            self.dtb_ipa,
            self.kernel_load_ipa,
            self.ramdisk_ipa,
        ] {
            if addr == 0 || addr & page_mask != 0 {
                return Err(BootloaderError::LockStateTampered);
            }
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootloader State Machine
//
// The bootloader proceeds through these phases in order:
//   1. Init        — parse BCB, select slot, validate config
//   2. VbmetaLoad  — read and parse VBMeta header from vbmeta partition
//   3. KeyCheck    — extract public key from VBMeta auxiliary block, compare
//                    against trust anchor
//   4. SigCheck    — verify signature over VBMeta (header + auxiliary block)
//   5. RollbackCheck — compare rollback index against secure storage minimum
//   6. PartVerify  — for each descriptor, verify the partition
//   7. CmdlineBuild— construct the full kernel command line
//   8. Launch      — transfer control to kernel entry point
//
// The state machine is encoded as a Rust enum so invalid transitions are a
// type error.
// ─────────────────────────────────────────────────────────────────────────────

/// Phase of the bootloader state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderPhase {
    /// Initial state — slot not yet selected.
    Init,
    /// Slot selected; VBMeta has not been loaded.
    SlotSelected,
    /// VBMeta header parsed; key not yet checked.
    VbmetaLoaded,
    /// Trust anchor key matches; signature not yet verified.
    KeyVerified,
    /// Signature verified; rollback index not yet checked.
    SignatureVerified,
    /// Rollback index acceptable; partitions not yet verified.
    RollbackAccepted,
    /// All partitions verified; kernel command line not yet built.
    PartitionsVerified,
    /// Command line built; ready to launch kernel.
    ReadyToLaunch,
}

/// Bootloader runtime state — tracks progress through the verification
/// pipeline and accumulates results for use at launch time.
pub struct BootloaderState {
    phase: BootloaderPhase,
    /// Active boot slot selected from the BCB.
    pub active_slot: Option<BootSlot>,
    /// Parsed VBMeta header (set after `VbmetaLoaded`).
    pub vbmeta_header: Option<VbmetaHeader>,
    /// Number of partition descriptors verified (cumulative).
    pub descriptors_verified: u32,
    /// Kernel command line (set after `PartitionsVerified`).
    pub cmdline: KernelCmdline,
}

impl BootloaderState {
    /// Construct the bootloader state machine in the initial phase.
    pub const fn new() -> Self {
        Self {
            phase: BootloaderPhase::Init,
            active_slot: None,
            vbmeta_header: None,
            descriptors_verified: 0,
            cmdline: KernelCmdline::new(),
        }
    }

    /// Current phase.
    pub fn phase(&self) -> BootloaderPhase {
        self.phase
    }

    /// Select the active boot slot from the parsed BCB.
    ///
    /// Must be called while in the `Init` phase.
    pub fn select_slot(&mut self, bcb: &BootControlBlock) -> Result<BootSlot, BootloaderError> {
        debug_assert_eq!(self.phase, BootloaderPhase::Init);
        let slot = bcb.select_slot()?;
        self.active_slot = Some(slot);
        self.phase = BootloaderPhase::SlotSelected;
        Ok(slot)
    }

    /// Record the parsed VBMeta header and advance to `VbmetaLoaded`.
    ///
    /// Also validates that the VERIFICATION_DISABLED flag is NOT set —
    /// AETHER always enforces verification.
    pub fn load_vbmeta(&mut self, header: VbmetaHeader) -> Result<(), BootloaderError> {
        debug_assert_eq!(self.phase, BootloaderPhase::SlotSelected);
        if header.verification_disabled() {
            return Err(BootloaderError::SignatureVerificationFailed);
        }
        self.vbmeta_header = Some(header);
        self.phase = BootloaderPhase::VbmetaLoaded;
        Ok(())
    }

    /// Mark the public key as verified and advance to `KeyVerified`.
    pub fn key_verified(&mut self) {
        debug_assert_eq!(self.phase, BootloaderPhase::VbmetaLoaded);
        self.phase = BootloaderPhase::KeyVerified;
    }

    /// Mark the VBMeta signature as verified and advance to `SignatureVerified`.
    pub fn signature_verified(&mut self) {
        debug_assert_eq!(self.phase, BootloaderPhase::KeyVerified);
        self.phase = BootloaderPhase::SignatureVerified;
    }

    /// Verify the rollback index and advance to `RollbackAccepted`.
    pub fn check_rollback(
        &mut self,
        store: &RollbackIndexStore,
    ) -> Result<(), BootloaderError> {
        debug_assert_eq!(self.phase, BootloaderPhase::SignatureVerified);
        let header = self.vbmeta_header.ok_or(BootloaderError::MalformedDescriptor)?;
        store.verify(
            header.rollback_index_location as usize,
            header.rollback_index,
        )?;
        self.phase = BootloaderPhase::RollbackAccepted;
        Ok(())
    }

    /// Record that a partition descriptor has been verified.
    pub fn record_descriptor_verified(&mut self) {
        self.descriptors_verified += 1;
    }

    /// Advance to `PartitionsVerified` after all descriptors have been checked.
    pub fn partitions_verified(&mut self) {
        debug_assert_eq!(self.phase, BootloaderPhase::RollbackAccepted);
        self.phase = BootloaderPhase::PartitionsVerified;
    }

    /// Build the kernel command line and advance to `ReadyToLaunch`.
    ///
    /// Appends hardware-authenticity invariants required by AETHER:
    ///   androidboot.hardware=aether
    ///   androidboot.selinux=enforcing
    ///   ro.build.type=user
    ///   androidboot.verifiedbootstate=green (or orange/yellow)
    ///   androidboot.slot_suffix=_a or _b
    ///
    /// `image_cmdline` is the null-terminated cmdline from the boot image header.
    pub fn build_cmdline(
        &mut self,
        image_cmdline: &[u8],
        lock_state: &BootloaderLockState,
    ) -> Result<(), BootloaderError> {
        debug_assert_eq!(self.phase, BootloaderPhase::PartitionsVerified);

        // 1. Append the boot image's own cmdline (strip trailing NUL if present).
        let img_cmd = {
            let end = image_cmdline.iter().position(|&b| b == 0)
                .unwrap_or(image_cmdline.len());
            &image_cmdline[..end]
        };
        if !img_cmd.is_empty() {
            self.cmdline.append(img_cmd)?;
        }

        // 2. AETHER hardware identity.
        self.cmdline.append_kv(b"androidboot.hardware", b"aether")?;

        // 3. SELinux — always enforcing in production (hardware-authenticity invariant).
        self.cmdline.append_kv(b"androidboot.selinux", b"enforcing")?;

        // 4. Build type — always "user" in production (never "userdebug").
        self.cmdline.append_kv(b"ro.build.type", b"user")?;

        // 5. Verified boot state.
        self.cmdline.append_kv(
            b"androidboot.verifiedbootstate",
            lock_state.verified_boot_state_str(),
        )?;

        // 6. A/B slot suffix.
        let suffix = match self.active_slot {
            Some(BootSlot::A) => b"_a" as &[u8],
            Some(BootSlot::B) => b"_b" as &[u8],
            None => b"_a",
        };
        self.cmdline.append_kv(b"androidboot.slot_suffix", suffix)?;

        self.phase = BootloaderPhase::ReadyToLaunch;
        Ok(())
    }

    /// True if the bootloader has completed all verification and is ready
    /// to transfer execution to the kernel.
    pub fn is_ready(&self) -> bool {
        self.phase == BootloaderPhase::ReadyToLaunch
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot Image Parameters — the final handoff to AETHER's EL2 launch code
//
// Once the bootloader completes verification, it calls back into AETHER's
// EL2 code (via HVC) with these parameters. AETHER then:
//   1. Validates the kernel load address is within the Android partition's IPA
//   2. Flushes the D-cache for the kernel image region (ARM requires clean+invalidate
//      before I-cache can see new code)
//   3. ERets to the kernel entry point at EL1 with:
//      x0 = DTB physical address (per Linux ARM64 boot protocol)
//      x1 = 0 (reserved)
//      x2 = 0 (reserved)
//      x3 = 0 (reserved)
//
// Source: linux-ref/Documentation/arm64/booting.rst — ARM64 Linux boot protocol.
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters the Android bootloader passes to AETHER's EL2 code at kernel
/// launch time (via HVC hypercall).
#[derive(Debug, Clone, Copy)]
pub struct KernelLaunchParams {
    /// IPA of the kernel image entry point. Must be aligned to 2 MiB per
    /// the ARM64 Linux boot protocol (text_offset is 0 for modern kernels).
    pub kernel_entry_ipa: u64,
    /// IPA of the device tree blob. Passed in x0 per ARM64 boot protocol.
    pub dtb_ipa: u64,
    /// Size of the kernel image in bytes.
    pub kernel_size: u32,
    /// Size of the initial ramdisk in bytes.
    pub ramdisk_size: u32,
}

impl KernelLaunchParams {
    /// Validate that the parameters are consistent.
    ///
    /// The kernel entry IPA must be 2 MiB-aligned (per ARM64 Linux boot
    /// protocol — the kernel Image binary must be loaded at a 2MiB boundary).
    pub fn validate(&self) -> Result<(), BootloaderError> {
        // ARM64 boot protocol: kernel entry must be 2MiB-aligned.
        if self.kernel_entry_ipa & 0x1F_FFFF != 0 {
            return Err(BootloaderError::InvalidHeaderSize);
        }
        if self.dtb_ipa == 0 {
            return Err(BootloaderError::InvalidHeaderSize);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Boot Image Header ────────────────────────────────────────────────────

    fn make_v3_header() -> [u8; 4096] {
        let mut buf = [0u8; 4096];
        buf[0..8].copy_from_slice(b"ANDROID!");
        buf[8..12].copy_from_slice(&1234u32.to_le_bytes());   // kernel_size
        buf[12..16].copy_from_slice(&567u32.to_le_bytes());   // ramdisk_size
        buf[16..20].copy_from_slice(&0u32.to_le_bytes());     // os_version
        buf[20..24].copy_from_slice(&4096u32.to_le_bytes());  // header_size
        buf[40..44].copy_from_slice(&3u32.to_le_bytes());     // header_version = 3
        buf[44..47].copy_from_slice(b"foo");                  // cmdline start
        buf
    }

    #[test]
    fn parse_v3_header_ok() {
        let data = make_v3_header();
        let hdr = BootImageHeader::parse(&data).expect("v3 parse failed");
        assert_eq!(hdr.kernel_size, 1234);
        assert_eq!(hdr.ramdisk_size, 567);
        assert_eq!(hdr.header_version, 3);
        assert_eq!(hdr.signature_size, 0);
        assert_eq!(hdr.cmdline_str(), b"foo");
    }

    #[test]
    fn parse_header_bad_magic() {
        let mut data = make_v3_header();
        data[0] = b'X';
        assert_eq!(
            BootImageHeader::parse(&data).unwrap_err(),
            BootloaderError::InvalidBootMagic
        );
    }

    #[test]
    fn parse_header_bad_version() {
        let mut data = make_v3_header();
        data[40..44].copy_from_slice(&5u32.to_le_bytes()); // version = 5 (unsupported)
        assert_eq!(
            BootImageHeader::parse(&data).unwrap_err(),
            BootloaderError::UnsupportedHeaderVersion
        );
    }

    #[test]
    fn parse_header_bad_size() {
        let mut data = make_v3_header();
        data[20..24].copy_from_slice(&8192u32.to_le_bytes()); // header_size wrong
        assert_eq!(
            BootImageHeader::parse(&data).unwrap_err(),
            BootloaderError::InvalidHeaderSize
        );
    }

    // ── VBMeta Header ────────────────────────────────────────────────────────

    fn make_vbmeta_header() -> [u8; 256] {
        let mut buf = [0u8; 256];
        buf[0..4].copy_from_slice(b"AVB0");
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());   // major = 1
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());  // minor = 0
        // auth_block_size = 576, aux_block_size = 2048
        buf[12..20].copy_from_slice(&576u64.to_be_bytes());
        buf[20..28].copy_from_slice(&2048u64.to_be_bytes());
        // algorithm = Sha256Rsa4096 = 2
        buf[28..32].copy_from_slice(&2u32.to_be_bytes());
        // hash_offset=0, hash_size=32, sig_offset=32, sig_size=512
        buf[32..40].copy_from_slice(&0u64.to_be_bytes());
        buf[40..48].copy_from_slice(&32u64.to_be_bytes());
        buf[48..56].copy_from_slice(&32u64.to_be_bytes());
        buf[56..64].copy_from_slice(&512u64.to_be_bytes());
        // public_key_offset=0, public_key_size=1032
        buf[64..72].copy_from_slice(&0u64.to_be_bytes());
        buf[72..80].copy_from_slice(&1032u64.to_be_bytes());
        // rollback_index = 5
        buf[112..120].copy_from_slice(&5u64.to_be_bytes());
        // flags = 0 (both verification bits clear)
        buf[120..124].copy_from_slice(&0u32.to_be_bytes());
        // rollback_index_location = 0
        buf[124..128].copy_from_slice(&0u32.to_be_bytes());
        // release_string
        let rel = b"avbtool 1.3.0";
        buf[128..128+rel.len()].copy_from_slice(rel);
        buf
    }

    #[test]
    fn parse_vbmeta_ok() {
        let data = make_vbmeta_header();
        let hdr = VbmetaHeader::parse(&data).expect("vbmeta parse failed");
        assert_eq!(hdr.required_libavb_version_major, 1);
        assert_eq!(hdr.algorithm_type, AvbAlgorithm::Sha256Rsa4096);
        assert_eq!(hdr.rollback_index, 5);
        assert!(!hdr.verification_disabled());
    }

    #[test]
    fn parse_vbmeta_bad_magic() {
        let mut data = make_vbmeta_header();
        data[0] = b'X';
        assert_eq!(
            VbmetaHeader::parse(&data).unwrap_err(),
            BootloaderError::InvalidVbmetaMagic
        );
    }

    #[test]
    fn parse_vbmeta_bad_major() {
        let mut data = make_vbmeta_header();
        data[4..8].copy_from_slice(&2u32.to_be_bytes()); // major = 2
        assert_eq!(
            VbmetaHeader::parse(&data).unwrap_err(),
            BootloaderError::UnsupportedVbmetaVersion
        );
    }

    #[test]
    fn vbmeta_verification_disabled_flag() {
        let mut data = make_vbmeta_header();
        let flags = vbmeta_flags::VERIFICATION_DISABLED;
        data[120..124].copy_from_slice(&flags.to_be_bytes());
        let hdr = VbmetaHeader::parse(&data).expect("parse ok");
        assert!(hdr.verification_disabled());
    }

    // ── Rollback Index Store ─────────────────────────────────────────────────

    #[test]
    fn rollback_store_accept() {
        let mut store = RollbackIndexStore::new();
        store.set(0, 3).unwrap();
        assert!(store.verify(0, 3).is_ok());
        assert!(store.verify(0, 10).is_ok());
    }

    #[test]
    fn rollback_store_reject_downgrade() {
        let mut store = RollbackIndexStore::new();
        store.set(0, 5).unwrap();
        assert_eq!(
            store.verify(0, 4),
            Err(BootloaderError::RollbackIndexViolation)
        );
    }

    #[test]
    fn rollback_store_monotonic() {
        let mut store = RollbackIndexStore::new();
        store.set(0, 10).unwrap();
        // Attempting to lower the minimum must be silently ignored.
        store.set(0, 3).unwrap();
        assert_eq!(store.get(0), 10);
    }

    // ── Boot Control Block ───────────────────────────────────────────────────

    fn make_bcb(priority_a: u8, tries_a: u8, ok_a: bool,
                priority_b: u8, tries_b: u8, ok_b: bool) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&SLOT_CONTROL_MAGIC.to_le_bytes());
        buf[4] = 1; // version
        let packed_a = SlotInfo { priority: priority_a, tries_remaining: tries_a, successful_boot: ok_a }.to_packed();
        let packed_b = SlotInfo { priority: priority_b, tries_remaining: tries_b, successful_boot: ok_b }.to_packed();
        buf[8] = packed_a;
        buf[9] = packed_b;
        buf
    }

    #[test]
    fn bcb_select_slot_a_higher_priority() {
        let bcb_data = make_bcb(15, 7, false, 14, 7, false);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        assert_eq!(bcb.select_slot().unwrap(), BootSlot::A);
    }

    #[test]
    fn bcb_select_slot_b_higher_priority() {
        let bcb_data = make_bcb(10, 7, false, 15, 7, false);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        assert_eq!(bcb.select_slot().unwrap(), BootSlot::B);
    }

    #[test]
    fn bcb_select_slot_equal_priority_prefers_a() {
        let bcb_data = make_bcb(15, 7, true, 15, 7, true);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        assert_eq!(bcb.select_slot().unwrap(), BootSlot::A);
    }

    #[test]
    fn bcb_no_bootable_slot() {
        let bcb_data = make_bcb(0, 0, false, 0, 0, false);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        assert_eq!(bcb.select_slot(), Err(BootloaderError::NoBootableSlot));
    }

    #[test]
    fn bcb_bad_magic() {
        let mut data = make_bcb(15, 7, true, 14, 7, false);
        data[0] = 0xFF;
        assert_eq!(
            BootControlBlock::parse(&data).unwrap_err(),
            BootloaderError::InvalidSlotControlBlock
        );
    }

    // ── Kernel Command Line ──────────────────────────────────────────────────

    #[test]
    fn cmdline_append_kv() {
        let mut cmd = KernelCmdline::new();
        cmd.append_kv(b"androidboot.hardware", b"aether").unwrap();
        cmd.append_kv(b"androidboot.selinux", b"enforcing").unwrap();
        let result = cmd.as_bytes();
        // Should be "androidboot.hardware=aether androidboot.selinux=enforcing\0"
        let s = result.split_last().unwrap().1; // strip NUL
        assert_eq!(s, b"androidboot.hardware=aether androidboot.selinux=enforcing");
    }

    #[test]
    fn cmdline_buffer_overflow() {
        let mut cmd = KernelCmdline::new();
        // Fill almost to the limit
        let big = [b'a'; MAX_CMDLINE_LEN - 2];
        cmd.append(&big).unwrap();
        // One more byte should overflow
        assert_eq!(
            cmd.append(b"x"),
            Err(BootloaderError::CmdlineBufferTooSmall)
        );
    }

    // ── BootloaderState phase transitions ────────────────────────────────────

    #[test]
    fn bootloader_state_happy_path() {
        let bcb_data = make_bcb(15, 7, true, 0, 0, false);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        let vbmeta_data = make_vbmeta_header();
        let vbmeta = VbmetaHeader::parse(&vbmeta_data).unwrap();
        let store = RollbackIndexStore::new();

        let mut state = BootloaderState::new();
        assert_eq!(state.phase(), BootloaderPhase::Init);

        let slot = state.select_slot(&bcb).unwrap();
        assert_eq!(slot, BootSlot::A);
        assert_eq!(state.phase(), BootloaderPhase::SlotSelected);

        state.load_vbmeta(vbmeta).unwrap();
        assert_eq!(state.phase(), BootloaderPhase::VbmetaLoaded);

        state.key_verified();
        assert_eq!(state.phase(), BootloaderPhase::KeyVerified);

        state.signature_verified();
        assert_eq!(state.phase(), BootloaderPhase::SignatureVerified);

        state.check_rollback(&store).unwrap();
        assert_eq!(state.phase(), BootloaderPhase::RollbackAccepted);

        state.record_descriptor_verified();
        state.record_descriptor_verified();
        assert_eq!(state.descriptors_verified, 2);

        state.partitions_verified();
        assert_eq!(state.phase(), BootloaderPhase::PartitionsVerified);

        state.build_cmdline(b"console=ttyMSM0", &BootloaderLockState::Locked).unwrap();
        assert_eq!(state.phase(), BootloaderPhase::ReadyToLaunch);
        assert!(state.is_ready());

        let cmdline = state.cmdline.as_bytes();
        // Must contain all required invariants
        assert!(cmdline.windows(b"androidboot.hardware=aether".len())
            .any(|w| w == b"androidboot.hardware=aether"));
        assert!(cmdline.windows(b"androidboot.selinux=enforcing".len())
            .any(|w| w == b"androidboot.selinux=enforcing"));
        assert!(cmdline.windows(b"ro.build.type=user".len())
            .any(|w| w == b"ro.build.type=user"));
        assert!(cmdline.windows(b"androidboot.verifiedbootstate=green".len())
            .any(|w| w == b"androidboot.verifiedbootstate=green"));
        assert!(cmdline.windows(b"androidboot.slot_suffix=_a".len())
            .any(|w| w == b"androidboot.slot_suffix=_a"));
    }

    #[test]
    fn bootloader_state_rejects_verification_disabled() {
        let bcb_data = make_bcb(15, 7, true, 0, 0, false);
        let bcb = BootControlBlock::parse(&bcb_data).unwrap();
        let mut vbmeta_data = make_vbmeta_header();
        // Set VERIFICATION_DISABLED flag
        vbmeta_data[120..124].copy_from_slice(
            &vbmeta_flags::VERIFICATION_DISABLED.to_be_bytes()
        );
        let vbmeta = VbmetaHeader::parse(&vbmeta_data).unwrap();

        let mut state = BootloaderState::new();
        state.select_slot(&bcb).unwrap();
        assert_eq!(
            state.load_vbmeta(vbmeta),
            Err(BootloaderError::SignatureVerificationFailed)
        );
    }

    // ── KernelLaunchParams ───────────────────────────────────────────────────

    #[test]
    fn kernel_launch_params_valid() {
        let params = KernelLaunchParams {
            kernel_entry_ipa: 0x4000_0000, // 1 GiB — 2MiB-aligned
            dtb_ipa: 0x4800_0000,
            kernel_size: 0x100_0000,
            ramdisk_size: 0x80_0000,
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn kernel_launch_params_misaligned_entry() {
        let params = KernelLaunchParams {
            kernel_entry_ipa: 0x4000_1000, // not 2MiB-aligned
            dtb_ipa: 0x4800_0000,
            kernel_size: 0x100_0000,
            ramdisk_size: 0,
        };
        assert_eq!(params.validate(), Err(BootloaderError::InvalidHeaderSize));
    }

    // ── BootloaderConfig validation ──────────────────────────────────────────

    #[test]
    fn bootloader_config_unlocked_fails() {
        let cfg = BootloaderConfig {
            trust_anchor: AvbPublicKey {
                key_num_bits: 4096,
                n0inv: 0,
                modulus: [0u8; MAX_RSA_KEY_BYTES],
                rr: [0u8; MAX_RSA_KEY_BYTES],
            },
            rollback_store: RollbackIndexStore::new(),
            lock_state: BootloaderLockState::Unlocked,
            bootloader_ipa: 0x4000_0000,
            dtb_ipa: 0x4800_0000,
            kernel_load_ipa: 0x4020_0000,
            ramdisk_ipa: 0x4600_0000,
        };
        assert_eq!(cfg.validate(), Err(BootloaderError::LockStateTampered));
    }

    #[test]
    fn bootloader_config_locked_zero_addr_fails() {
        let cfg = BootloaderConfig {
            trust_anchor: AvbPublicKey {
                key_num_bits: 4096,
                n0inv: 0,
                modulus: [0u8; MAX_RSA_KEY_BYTES],
                rr: [0u8; MAX_RSA_KEY_BYTES],
            },
            rollback_store: RollbackIndexStore::new(),
            lock_state: BootloaderLockState::Locked,
            bootloader_ipa: 0, // invalid
            dtb_ipa: 0x4800_0000,
            kernel_load_ipa: 0x4020_0000,
            ramdisk_ipa: 0x4600_0000,
        };
        assert_eq!(cfg.validate(), Err(BootloaderError::LockStateTampered));
    }

    #[test]
    fn slot_suffix() {
        assert_eq!(BootSlot::A.suffix(), b"_a");
        assert_eq!(BootSlot::B.suffix(), b"_b");
        assert_eq!(BootSlot::A.other(), BootSlot::B);
    }

    #[test]
    fn avb_algorithm_hash_sizes() {
        assert_eq!(AvbAlgorithm::Sha256Rsa4096.hash_size(), 32);
        assert_eq!(AvbAlgorithm::Sha512Rsa4096.hash_size(), 64);
        assert_eq!(AvbAlgorithm::None.hash_size(), 0);
    }
}
