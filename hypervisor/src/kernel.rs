// ch20: The Linux Kernel
//
// AETHER's Android partition boots a Linux kernel built from the Android Common
// Kernel (ACK) source tree. This module encodes the data structures and
// configuration for the kernel environment that AETHER prepares before the
// first ERET into the Android partition:
//
//   1. ARM64 kernel Image header parsing and validation
//      Every ARM64 Linux kernel Image binary carries a 64-byte header at
//      offset 0. AETHER validates this header before mapping the kernel into
//      the Android partition's Stage 2 address space. The header contains:
//        • "MZ" at bytes [0:2] — PE/COFF compatibility (bootloaders scan for MZ)
//        • text_offset (u64 LE) at bytes [8:16] — load offset from 2MiB boundary
//        • image_size (u64 LE) at bytes [16:24] — effective kernel image size
//        • flags (u64 LE) at bytes [24:32] — endianness, page size, placement
//        • 0x644D5241 ("ARMd") at bytes [56:60] — ARM64 kernel identity magic
//
//   2. Flat Device Tree (FDT/DTB) builder
//      AETHER constructs a device tree blob (DTB) describing the Android
//      partition's hardware inventory. The kernel uses this blob to discover
//      and configure every device it will drive. The Android DTB includes:
//        • Root node with address/size cell declarations
//        • /memory — assigned physical address range
//        • /cpus — assigned CPU cores with MPIDR affinity values
//        • /psci — PSCI 1.0 via HVC (AETHER intercepts at EL2)
//        • /intc — GICv3 interrupt controller with GICD/GICR addresses
//        • /timer — ARM architectural timer (4 PPIs)
//        • /serial — PL011 UART for early kernel console
//        • /chosen — kernel command line and stdout-path
//
//   3. GKI (Generic Kernel Image) configuration requirements
//      Android 12+ kernels must satisfy GKI mandatory configuration options
//      defined in android/configs/ of the Android Common Kernel. AETHER tracks
//      which options are required so the build system can verify the kernel
//      config before packaging.
//
// ── ARM64 Boot Protocol (Documentation/arm64/booting.rst) ────────────────────
//
//   At kernel entry:
//     • x0 = physical address of the FDT blob (device tree)
//     • x1 = 0 (reserved; must be zero)
//     • x2 = 0 (reserved; must be zero)
//     • x3 = 0 (reserved; must be zero)
//     • Primary CPU executes at kernel Image entry point (text_offset from
//       the 2MiB-aligned load address; for modern kernels text_offset = 0)
//     • MMU off, D-cache off; I-cache may be on or off
//
//   Modern kernels (4.6+) set text_offset = 0. The kernel entry point is
//   therefore at the same address as the 2MiB-aligned load address.
//
// ── FDT Binary Format (Device Tree Specification v0.3, §5) ───────────────────
//
//   DTB layout (all multi-byte integers are big-endian — unlike ACPI):
//     [0..40]   FDT header (40 bytes; version 17, last_comp_version 16)
//     [40..56]  Memory reservation block (terminator: two u64 zeros)
//     [56..]    Structure block (4-byte aligned; token stream)
//     [end]     Strings block (null-terminated property name strings)
//
//   Structure block tokens (big-endian u32):
//     FDT_BEGIN_NODE = 0x00000001  followed by null-terminated node name
//     FDT_END_NODE   = 0x00000002  closes the most recent BEGIN_NODE
//     FDT_PROP       = 0x00000003  followed by len(4) + nameoff(4) + data
//     FDT_NOP        = 0x00000004  ignored by parsers; used for alignment
//     FDT_END        = 0x00000009  terminates the entire structure block
//
// ── GICv3 Interrupt Specifiers (3 cells) ────────────────────────────────────
//
//   When the interrupt controller node declares #interrupt-cells = <3>, each
//   interrupt specifier in any node's `interrupts` property is a 3-cell tuple:
//     cell 0: type  — 0 = SPI, 1 = PPI
//     cell 1: intid — 0-based within type range:
//               SPI: absolute INTID − 32 (e.g., INTID 64 → DT intid 32)
//               PPI: absolute INTID − 16 (e.g., INTID 27 → DT intid 11)
//     cell 2: flags — 1 = edge rising, 4 = level high (most common on ARM)
//
//   ARM architectural timer PPIs (INTID → DT intid):
//     Secure EL1 physical:    INTID 29 → DT 13
//     Non-Secure EL1 physical:INTID 30 → DT 14
//     Virtual EL1:            INTID 27 → DT 11
//     EL2 hypervisor:         INTID 26 → DT 10
//
//   AETHER presents all four timer PPIs to Android. The hypervisor-facing PPI
//   (INTID 26) is included because the Android kernel programs the virtual
//   timer through EL1; the hypervisor physical timer (EL2) is not used by
//   Android.
//
// ── No std, No Alloc ─────────────────────────────────────────────────────────
//
//   DtbBuilder uses two fixed-size arrays: DTB_STRUCT_CAP bytes for the
//   structure block and DTB_STRINGS_CAP bytes for property name strings.
//   String interning uses a linear scan (the strings block is small).
//
// References:
//   Documentation/arm64/booting.rst          — authoritative boot protocol
//   linux-ref/arch/arm64/include/asm/image.h — ARM64 Image header layout
//   Device Tree Specification v0.3           — devicetree.org (FDT binary fmt)
//   Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.yaml
//   Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
//   Documentation/devicetree/bindings/arm/psci.yaml
//   Documentation/devicetree/bindings/serial/arm,pl011.yaml
//   android.googlesource.com/kernel/common   — Android Common Kernel

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by kernel image parsing, DTB construction, and config
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// The ARM64 Linux Image binary magic (0x644D5241 at offset 56) is absent.
    /// This indicates the file is not a Linux ARM64 kernel Image.
    InvalidImageMagic,
    /// The kernel Image is smaller than the 64-byte header.
    ImageTooSmall,
    /// The kernel entry IPA is not aligned to 2MiB as required by the ARM64
    /// boot protocol.
    KernelNotAligned,
    /// The device tree blob physical address is zero; x0 must be non-zero at
    /// kernel entry.
    DtbAddressZero,
    /// The DTB structure block buffer is full; increase DTB_STRUCT_CAP.
    DtbStructFull,
    /// The DTB strings block buffer is full; increase DTB_STRINGS_CAP.
    DtbStringsFull,
    /// The output buffer provided to finalize_into is too small to hold the
    /// assembled DTB.
    DtbOutputTooSmall,
    /// A begin_node/end_node was called while no enclosing node is open.
    DtbNoOpenNode,
    /// A property was written outside any node (after end_node but before the
    /// next begin_node).
    DtbPropertyOutsideNode,
    /// The DTB cannot be finalized while one or more nodes are still open.
    DtbOpenNodesRemain,
    /// The kernel command line is longer than MAX_KERNEL_CMDLINE_LEN.
    CmdlineTooLong,
    /// The number of CPU cores exceeds MAX_ANDROID_CPUS.
    TooManyCpus,
    /// A required GKI configuration option is absent from the supplied config.
    MissingRequiredKconfig,
}

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 Linux kernel Image header constants
//
// Source: linux-ref/arch/arm64/include/asm/image.h (authoritative layout)
// ─────────────────────────────────────────────────────────────────────────────

/// Magic value at bytes [56:60] of the ARM64 Linux Image header ("ARMd" in
/// little-endian u32; 'd' = 0x64 is the ELF machine byte for AArch64).
/// Source: linux/arch/arm64/include/asm/image.h ARM64_IMAGE_MAGIC.
pub const LINUX_ARM64_IMAGE_MAGIC: u32 = 0x644D_5241;

/// PE/COFF compatibility magic at bytes [0:2] of the ARM64 Image header.
/// Many firmware implementations scan for "MZ" to detect a PE/COFF binary;
/// the ARM64 kernel header starts with this to be picked up by UEFI firmware.
pub const LINUX_IMAGE_PE_MAGIC: &[u8; 2] = b"MZ";

/// Minimum size of an ARM64 Linux kernel Image binary (64-byte header).
pub const LINUX_IMAGE_HEADER_SIZE: usize = 64;

/// Offset of the text_offset field within the Linux Image header.
pub const LINUX_IMAGE_TEXT_OFFSET: usize = 8;

/// Offset of the image_size field within the Linux Image header.
pub const LINUX_IMAGE_SIZE_OFFSET: usize = 16;

/// Offset of the flags field within the Linux Image header.
pub const LINUX_IMAGE_FLAGS_OFFSET: usize = 24;

/// Offset of the ARM64 magic value (0x644D5241) within the Linux Image header.
pub const LINUX_IMAGE_MAGIC_OFFSET: usize = 56;

/// Kernel load alignment (2 MiB) required by the ARM64 boot protocol.
/// The kernel Image binary must be loaded at a 2MiB-aligned physical address.
pub const KERNEL_LOAD_ALIGN: u64 = 2 * 1024 * 1024; // 2 MiB

/// Image header flag bit 0: endianness (0 = little-endian, 1 = big-endian).
pub const IMAGE_FLAG_BE: u64 = 1 << 0;

/// Image header flag bits [2:1]: page size hint.
/// 0b00 = unspecified; 0b01 = 4KB; 0b10 = 16KB; 0b11 = 64KB.
pub const IMAGE_FLAG_PAGE_SIZE_SHIFT: u64 = 1;
pub const IMAGE_FLAG_PAGE_SIZE_MASK: u64 = 0b11 << IMAGE_FLAG_PAGE_SIZE_SHIFT;

/// Image header flag bit 3: physical placement (0 = anywhere in RAM;
/// 1 = must be placed at >= text_offset from start of RAM).
pub const IMAGE_FLAG_PHYS_PLACEMENT: u64 = 1 << 3;

// ─────────────────────────────────────────────────────────────────────────────
// FDT binary format constants
//
// Source: Device Tree Specification v0.3, §5 (devicetree.org)
// ─────────────────────────────────────────────────────────────────────────────

/// Magic number at offset 0 of every valid FDT blob (big-endian).
pub const FDT_MAGIC: u32 = 0xD00D_FEED;

/// FDT format version used by DtbBuilder. Version 17 is the current standard.
pub const FDT_VERSION: u32 = 17;

/// Last compatible FDT version (parsers implementing v16 can parse our blobs).
pub const FDT_LAST_COMP_VERSION: u32 = 16;

/// Size of the FDT header in bytes (version 17 adds size_dt_struct at offset 36).
pub const FDT_HEADER_SIZE: usize = 40;

/// Size of the memory reservation block terminator (two u64 zeros = 16 bytes).
pub const FDT_MEM_RSVMAP_SIZE: usize = 16;

/// Offset at which the structure block begins (header + mem_rsvmap = 56 bytes).
pub const FDT_STRUCT_OFFSET: usize = FDT_HEADER_SIZE + FDT_MEM_RSVMAP_SIZE;

/// FDT structure block token: begin a device node.
pub const FDT_BEGIN_NODE: u32 = 0x0000_0001;

/// FDT structure block token: end the current device node.
pub const FDT_END_NODE: u32 = 0x0000_0002;

/// FDT structure block token: property entry (followed by len, nameoff, data).
pub const FDT_PROP: u32 = 0x0000_0003;

/// FDT structure block token: no-op (used for alignment padding).
pub const FDT_NOP: u32 = 0x0000_0004;

/// FDT structure block token: end of structure block.
pub const FDT_END: u32 = 0x0000_0009;

// ─────────────────────────────────────────────────────────────────────────────
// GICv3 interrupt specifier constants (3-cell format)
//
// Source: Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.yaml
// ─────────────────────────────────────────────────────────────────────────────

/// Interrupt type cell value: Shared Peripheral Interrupt (INTID >= 32).
pub const GIC_SPI: u32 = 0;

/// Interrupt type cell value: Private Peripheral Interrupt (INTID 16–31).
pub const GIC_PPI: u32 = 1;

/// Interrupt flags cell value: level-triggered, active high.
/// Required for GICv3 SPIs on ARM (most devices use level-high).
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

/// ARM architectural timer: Secure EL1 physical timer PPI.
/// Absolute INTID 29 → DT intid 13 (29 − 16 = 13).
pub const TIMER_SECURE_PPI_DT: u32 = 13;

/// ARM architectural timer: Non-Secure EL1 physical timer PPI.
/// Absolute INTID 30 → DT intid 14 (30 − 16 = 14).
pub const TIMER_NON_SECURE_PPI_DT: u32 = 14;

/// ARM architectural timer: Virtual EL1 timer PPI.
/// Absolute INTID 27 → DT intid 11 (27 − 16 = 11).
pub const TIMER_VIRTUAL_PPI_DT: u32 = 11;

/// ARM architectural timer: EL2 hypervisor timer PPI.
/// Absolute INTID 26 → DT intid 10 (26 − 16 = 10).
pub const TIMER_HYP_PPI_DT: u32 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// PSCI constants
//
// Source: ARM DEN0022D — Power State Coordination Interface (PSCI) spec
// ─────────────────────────────────────────────────────────────────────────────

/// PSCI v1.0 function identifier: VERSION (SMC32, Fast call).
pub const PSCI_VERSION_FN: u32 = 0x8400_0000;

/// PSCI v1.0 function identifier: CPU_ON (SMC64, Fast call).
pub const PSCI_CPU_ON_FN: u32 = 0xC400_0003;

/// PSCI v1.0 function identifier: CPU_OFF (SMC32, Fast call).
pub const PSCI_CPU_OFF_FN: u32 = 0x8400_0002;

/// PSCI v1.0 function identifier: CPU_SUSPEND (SMC64, Fast call).
pub const PSCI_CPU_SUSPEND_FN: u32 = 0xC400_0001;

/// PSCI v1.0 function identifier: MIGRATE_INFO_TYPE (SMC32, Fast call).
pub const PSCI_MIGRATE_INFO_TYPE_FN: u32 = 0x8400_0006;

// ─────────────────────────────────────────────────────────────────────────────
// Capacity limits
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of CPU cores assignable to the Android partition.
pub const MAX_ANDROID_CPUS: usize = 8;

/// Maximum kernel command line length passed through the DTB /chosen node.
pub const MAX_KERNEL_CMDLINE_LEN: usize = 4096;

/// Capacity of the DTB structure block buffer in bytes.
pub const DTB_STRUCT_CAP: usize = 4096;

/// Capacity of the DTB strings block buffer in bytes.
pub const DTB_STRINGS_CAP: usize = 512;

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 Linux kernel Image header
//
// Source: linux-ref/arch/arm64/include/asm/image.h
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed representation of the 64-byte ARM64 Linux kernel Image header.
///
/// All fields are decoded from the little-endian byte layout of the Image
/// binary. This struct is NOT `repr(C)` — use `Arm64ImageHeader::parse()`.
#[derive(Debug, Clone, Copy)]
pub struct Arm64ImageHeader {
    /// Load offset from the start of the 2MiB-aligned load address.
    /// Modern kernels (4.6+) set this to 0; entry is at the load address.
    pub text_offset: u64,
    /// Effective size of the kernel Image binary in bytes.
    /// The Stage 2 mapping must cover at least this many bytes.
    pub image_size: u64,
    /// Image flags (endianness, page size hint, physical placement).
    pub flags: u64,
    /// Whether the Image binary starts with the "MZ" PE/COFF magic.
    /// Required by UEFI firmware that scans for PE/COFF binaries.
    pub has_pe_magic: bool,
}

impl Arm64ImageHeader {
    /// Parse the 64-byte ARM64 Linux kernel Image header from `data`.
    ///
    /// Returns `Err(KernelError::ImageTooSmall)` if `data` is shorter than
    /// 64 bytes, or `Err(KernelError::InvalidImageMagic)` if the ARM64 magic
    /// at offset 56 is absent.
    pub fn parse(data: &[u8]) -> Result<Self, KernelError> {
        if data.len() < LINUX_IMAGE_HEADER_SIZE {
            return Err(KernelError::ImageTooSmall);
        }

        // Verify ARM64 magic at offset 56 (little-endian u32).
        let magic = u32::from_le_bytes([
            data[LINUX_IMAGE_MAGIC_OFFSET],
            data[LINUX_IMAGE_MAGIC_OFFSET + 1],
            data[LINUX_IMAGE_MAGIC_OFFSET + 2],
            data[LINUX_IMAGE_MAGIC_OFFSET + 3],
        ]);
        if magic != LINUX_ARM64_IMAGE_MAGIC {
            return Err(KernelError::InvalidImageMagic);
        }

        let text_offset = u64::from_le_bytes(
            data[LINUX_IMAGE_TEXT_OFFSET..LINUX_IMAGE_TEXT_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let image_size = u64::from_le_bytes(
            data[LINUX_IMAGE_SIZE_OFFSET..LINUX_IMAGE_SIZE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let flags = u64::from_le_bytes(
            data[LINUX_IMAGE_FLAGS_OFFSET..LINUX_IMAGE_FLAGS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let has_pe_magic = data[0] == LINUX_IMAGE_PE_MAGIC[0]
            && data[1] == LINUX_IMAGE_PE_MAGIC[1];

        Ok(Self { text_offset, image_size, flags, has_pe_magic })
    }

    /// Returns true if the Image uses little-endian data (expected for Android).
    pub fn is_little_endian(&self) -> bool {
        self.flags & IMAGE_FLAG_BE == 0
    }

    /// Returns the page size hint from the flags field (in bytes), or 0 if
    /// the hint is unspecified.
    pub fn page_size_hint(&self) -> u64 {
        match (self.flags & IMAGE_FLAG_PAGE_SIZE_MASK) >> IMAGE_FLAG_PAGE_SIZE_SHIFT {
            0b01 => 4 * 1024,
            0b10 => 16 * 1024,
            0b11 => 64 * 1024,
            _ => 0,
        }
    }

    /// Compute the kernel entry IPA given the 2MiB-aligned load IPA.
    ///
    /// For modern kernels (text_offset = 0), this returns `load_ipa`
    /// unchanged. For older kernels with a non-zero text_offset, the entry
    /// point is `load_ipa + text_offset`.
    pub fn entry_ipa(&self, load_ipa: u64) -> u64 {
        load_ipa + self.text_offset
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flat Device Tree (FDT) builder
//
// Constructs a DTB (Device Tree Blob) for AETHER's Android partition.
// No heap allocation — two fixed-size arrays hold the structure and strings
// blocks until finalize_into() assembles the complete FDT into the caller's
// buffer.
//
// FDT header layout (all fields big-endian, per DTSpec §5.2):
//   [0..4]   magic           = FDT_MAGIC (0xD00DFEED)
//   [4..8]   totalsize
//   [8..12]  off_dt_struct
//   [12..16] off_dt_strings
//   [16..20] off_mem_rsvmap  = FDT_HEADER_SIZE (= 40)
//   [20..24] version         = 17
//   [24..28] last_comp_ver   = 16
//   [28..32] boot_cpuid_phys
//   [32..36] size_dt_strings
//   [36..40] size_dt_struct
// ─────────────────────────────────────────────────────────────────────────────

/// Flat Device Tree builder.
///
/// Accumulates the FDT structure block and strings block independently, then
/// assembles them into a complete DTB in `finalize_into()`.
///
/// Usage pattern:
/// ```ignore
/// let mut builder = DtbBuilder::new();
/// builder.begin_node(b"")?;            // root node
/// builder.prop_u32(b"#address-cells", 2)?;
/// builder.prop_u32(b"#size-cells", 2)?;
/// // ... add child nodes ...
/// builder.end_node()?;                 // close root
/// let n = builder.finalize_into(&mut out_buf)?;
/// ```
pub struct DtbBuilder {
    struct_buf: [u8; DTB_STRUCT_CAP],
    struct_len: usize,
    strings_buf: [u8; DTB_STRINGS_CAP],
    strings_len: usize,
    open_nodes: usize,
    boot_cpuid_phys: u32,
}

impl DtbBuilder {
    /// Create a new empty DtbBuilder with zero open nodes.
    pub const fn new() -> Self {
        Self {
            struct_buf: [0u8; DTB_STRUCT_CAP],
            struct_len: 0,
            strings_buf: [0u8; DTB_STRINGS_CAP],
            strings_len: 0,
            open_nodes: 0,
            boot_cpuid_phys: 0,
        }
    }

    /// Set the `boot_cpuid_phys` field in the FDT header.
    ///
    /// Should be set to the MPIDR value of the primary CPU (the core that
    /// enters the kernel at boot time). Defaults to 0.
    pub fn set_boot_cpuid(&mut self, mpidr: u32) {
        self.boot_cpuid_phys = mpidr;
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Append a big-endian u32 to the structure block.
    fn write_struct_u32(&mut self, val: u32) -> Result<(), KernelError> {
        let bytes = val.to_be_bytes();
        self.write_struct_bytes(&bytes)
    }

    /// Append raw bytes to the structure block.
    fn write_struct_bytes(&mut self, data: &[u8]) -> Result<(), KernelError> {
        let end = self.struct_len + data.len();
        if end > DTB_STRUCT_CAP {
            return Err(KernelError::DtbStructFull);
        }
        self.struct_buf[self.struct_len..end].copy_from_slice(data);
        self.struct_len = end;
        Ok(())
    }

    /// Pad the structure block to the next 4-byte boundary with zero bytes.
    fn pad_struct_to_4(&mut self) -> Result<(), KernelError> {
        let rem = self.struct_len % 4;
        if rem != 0 {
            let pad = 4 - rem;
            for _ in 0..pad {
                let end = self.struct_len + 1;
                if end > DTB_STRUCT_CAP {
                    return Err(KernelError::DtbStructFull);
                }
                self.struct_buf[self.struct_len] = 0;
                self.struct_len = end;
            }
        }
        Ok(())
    }

    /// Intern `name` into the strings block, returning its byte offset.
    ///
    /// If `name` is already present in the strings block, returns the offset
    /// of the existing entry without duplicating it.
    fn intern_string(&mut self, name: &[u8]) -> Result<u32, KernelError> {
        // Linear scan for an existing entry.
        let mut i = 0usize;
        while i < self.strings_len {
            let start = i;
            // Find end of this null-terminated string.
            while i < self.strings_len && self.strings_buf[i] != 0 {
                i += 1;
            }
            let existing = &self.strings_buf[start..i];
            if existing == name {
                return Ok(start as u32);
            }
            i += 1; // skip null terminator
        }

        // Not found — append name + null terminator.
        let offset = self.strings_len as u32;
        let needed = name.len() + 1;
        if self.strings_len + needed > DTB_STRINGS_CAP {
            return Err(KernelError::DtbStringsFull);
        }
        self.strings_buf[self.strings_len..self.strings_len + name.len()]
            .copy_from_slice(name);
        self.strings_buf[self.strings_len + name.len()] = 0;
        self.strings_len += needed;
        Ok(offset)
    }

    // ── Public DTB building API ──────────────────────────────────────────────

    /// Begin a device node with the given name.
    ///
    /// The root node uses an empty name (`b""`). Child nodes use their
    /// device name, optionally followed by `@<unit-address>`.
    pub fn begin_node(&mut self, name: &[u8]) -> Result<(), KernelError> {
        self.write_struct_u32(FDT_BEGIN_NODE)?;
        self.write_struct_bytes(name)?;
        self.write_struct_bytes(&[0u8])?; // null terminator
        self.pad_struct_to_4()?;
        self.open_nodes += 1;
        Ok(())
    }

    /// End the current device node.
    ///
    /// Returns `Err(KernelError::DtbNoOpenNode)` if there is no open node.
    pub fn end_node(&mut self) -> Result<(), KernelError> {
        if self.open_nodes == 0 {
            return Err(KernelError::DtbNoOpenNode);
        }
        self.write_struct_u32(FDT_END_NODE)?;
        self.open_nodes -= 1;
        Ok(())
    }

    /// Write a property with arbitrary byte data.
    pub fn prop(&mut self, name: &[u8], data: &[u8]) -> Result<(), KernelError> {
        if self.open_nodes == 0 {
            return Err(KernelError::DtbPropertyOutsideNode);
        }
        let nameoff = self.intern_string(name)?;
        self.write_struct_u32(FDT_PROP)?;
        self.write_struct_u32(data.len() as u32)?;
        self.write_struct_u32(nameoff)?;
        self.write_struct_bytes(data)?;
        self.pad_struct_to_4()?;
        Ok(())
    }

    /// Write a property with a single big-endian u32 value.
    pub fn prop_u32(&mut self, name: &[u8], val: u32) -> Result<(), KernelError> {
        self.prop(name, &val.to_be_bytes())
    }

    /// Write a property with a single big-endian u64 value (two cells).
    pub fn prop_u64(&mut self, name: &[u8], val: u64) -> Result<(), KernelError> {
        self.prop(name, &val.to_be_bytes())
    }

    /// Write a property with a null-terminated string value.
    ///
    /// The value bytes are written followed by a null terminator, matching the
    /// FDT string property format (DTSpec §2.2.4).
    pub fn prop_str(&mut self, name: &[u8], val: &[u8]) -> Result<(), KernelError> {
        if self.open_nodes == 0 {
            return Err(KernelError::DtbPropertyOutsideNode);
        }
        let nameoff = self.intern_string(name)?;
        let data_len = (val.len() + 1) as u32; // +1 for null terminator
        self.write_struct_u32(FDT_PROP)?;
        self.write_struct_u32(data_len)?;
        self.write_struct_u32(nameoff)?;
        self.write_struct_bytes(val)?;
        self.write_struct_bytes(&[0u8])?; // null terminator
        self.pad_struct_to_4()?;
        Ok(())
    }

    /// Write a property as a sequence of big-endian u32 cells.
    ///
    /// Used for `reg`, `interrupts`, `ranges`, and other cell-encoded
    /// properties.
    pub fn prop_cells(&mut self, name: &[u8], cells: &[u32]) -> Result<(), KernelError> {
        if self.open_nodes == 0 {
            return Err(KernelError::DtbPropertyOutsideNode);
        }
        let nameoff = self.intern_string(name)?;
        let data_len = cells.len() * 4;
        self.write_struct_u32(FDT_PROP)?;
        self.write_struct_u32(data_len as u32)?;
        self.write_struct_u32(nameoff)?;
        for &cell in cells {
            self.write_struct_u32(cell)?;
        }
        // Cell data is already 4-byte aligned (each cell is 4 bytes).
        Ok(())
    }

    /// Write an empty (boolean) property (e.g., `interrupt-controller`).
    pub fn prop_empty(&mut self, name: &[u8]) -> Result<(), KernelError> {
        self.prop(name, &[])
    }

    /// Returns the total assembled DTB size in bytes (for buffer pre-sizing).
    ///
    /// Includes the FDT_END token in the structure block.
    pub fn total_size(&self) -> usize {
        FDT_STRUCT_OFFSET + self.struct_len + 4 /* FDT_END */ + self.strings_len
    }

    /// Assemble the complete FDT binary into `out` and return the byte count.
    ///
    /// Returns `Err(KernelError::DtbOpenNodesRemain)` if any nodes are still
    /// open. Returns `Err(KernelError::DtbOutputTooSmall)` if `out` is too
    /// small. The caller must allocate at least `total_size()` bytes.
    pub fn finalize_into(&self, out: &mut [u8]) -> Result<usize, KernelError> {
        if self.open_nodes != 0 {
            return Err(KernelError::DtbOpenNodesRemain);
        }

        // Account for FDT_END token (4 bytes) at end of struct block.
        let struct_block_size = self.struct_len + 4;
        let strings_offset = FDT_STRUCT_OFFSET + struct_block_size;
        let total = strings_offset + self.strings_len;

        if out.len() < total {
            return Err(KernelError::DtbOutputTooSmall);
        }

        // Zero the entire output region.
        out[..total].fill(0);

        // ── FDT header (40 bytes, all big-endian) ────────────────────────────
        out[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        out[8..12].copy_from_slice(&(FDT_STRUCT_OFFSET as u32).to_be_bytes());
        out[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        out[16..20].copy_from_slice(&(FDT_HEADER_SIZE as u32).to_be_bytes());
        out[20..24].copy_from_slice(&FDT_VERSION.to_be_bytes());
        out[24..28].copy_from_slice(&FDT_LAST_COMP_VERSION.to_be_bytes());
        out[28..32].copy_from_slice(&self.boot_cpuid_phys.to_be_bytes());
        out[32..36].copy_from_slice(&(self.strings_len as u32).to_be_bytes());
        out[36..40].copy_from_slice(&(struct_block_size as u32).to_be_bytes());

        // ── Memory reservation block [40..56]: two u64 zeros ─────────────────
        // Already zeroed above.

        // ── Structure block ───────────────────────────────────────────────────
        let s = FDT_STRUCT_OFFSET;
        out[s..s + self.struct_len].copy_from_slice(&self.struct_buf[..self.struct_len]);
        // FDT_END token at the end of the structure block.
        out[s + self.struct_len..s + self.struct_len + 4]
            .copy_from_slice(&FDT_END.to_be_bytes());

        // ── Strings block ─────────────────────────────────────────────────────
        out[strings_offset..strings_offset + self.strings_len]
            .copy_from_slice(&self.strings_buf[..self.strings_len]);

        Ok(total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Android partition device tree configuration
//
// Encapsulates the parameters that vary between AETHER deployments (CPU MPIDR
// values, GIC addresses, etc.) and produces a DTB suitable for the Android
// partition.
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration parameters for building the Android partition DTB.
///
/// All physical addresses are IPAs from the Android partition's perspective
/// (the hypervisor maps them via Stage 2 tables).
pub struct AndroidDtbConfig {
    /// Number of CPU cores assigned to the Android partition (1..MAX_ANDROID_CPUS).
    pub cpu_count: usize,
    /// MPIDR_EL1 affinity values for each assigned core. Only cpu_count entries
    /// are used; extra entries are ignored.
    pub cpu_mpidr: [u64; MAX_ANDROID_CPUS],
    /// Base IPA of the Android partition's contiguous RAM region.
    pub memory_base: u64,
    /// Size of the Android partition's RAM region in bytes.
    pub memory_size: u64,
    /// IPA of the GIC Distributor (GICD) base.
    pub gicd_base: u64,
    /// Size of the GICD register region in bytes (typically 0x10000).
    pub gicd_size: u64,
    /// IPA of the GIC Redistributor (GICR) base for all assigned cores.
    pub gicr_base: u64,
    /// Size of the GICR region in bytes (64KB × 2 per core: RD_base + SGI_base).
    pub gicr_size: u64,
    /// IPA of the PL011 UART used as the early kernel console.
    pub uart_base: u64,
    /// Interrupt number of the PL011 UART (SPI INTID; DT intid = INTID − 32).
    pub uart_irq_spi: u32,
    /// Kernel command line (passed to the kernel through /chosen bootargs).
    /// Must be a null-terminated byte slice of at most MAX_KERNEL_CMDLINE_LEN.
    pub cmdline: [u8; MAX_KERNEL_CMDLINE_LEN],
    /// Length of the valid portion of cmdline (not including null terminator).
    pub cmdline_len: usize,
}

impl AndroidDtbConfig {
    /// Validate configuration before DTB construction.
    pub fn validate(&self) -> Result<(), KernelError> {
        if self.cpu_count == 0 || self.cpu_count > MAX_ANDROID_CPUS {
            return Err(KernelError::TooManyCpus);
        }
        if self.cmdline_len > MAX_KERNEL_CMDLINE_LEN {
            return Err(KernelError::CmdlineTooLong);
        }
        Ok(())
    }
}

/// Build a complete Android partition device tree blob into `out`.
///
/// Returns the number of bytes written on success.
///
/// # Device tree structure produced
///
/// ```text
/// / {
///     #address-cells = <2>;
///     #size-cells = <2>;
///     compatible = "aether,android-partition";
///     memory@<base> { device_type = "memory"; reg = <base size>; }
///     cpus { #address-cells = <2>; #size-cells = <0>;
///         cpu@<mpidr> { compatible = "arm,armv8"; device_type = "cpu";
///                        reg = <mpidr>; enable-method = "psci"; }
///         ...
///     }
///     psci { compatible = "arm,psci-1.0"; method = "hvc";
///            cpu_on = <CPU_ON>; cpu_off = <CPU_OFF>;
///            cpu_suspend = <CPU_SUSPEND>; }
///     intc: interrupt-controller@<gicd_base> {
///         compatible = "arm,gic-v3";
///         #interrupt-cells = <3>;
///         interrupt-controller;
///         reg = <gicd gicd_size gicr gicr_size>;
///     }
///     timer { compatible = "arm,armv8-timer";
///             interrupts = <PPI 13 4  PPI 14 4  PPI 11 4  PPI 10 4>; }
///     serial@<uart_base> { compatible = "arm,pl011"; reg = <base size>;
///                           interrupts = <SPI irq 4>; }
///     chosen { bootargs = <cmdline>; stdout-path = "/serial@..."; }
/// }
/// ```
pub fn build_android_dtb(
    cfg: &AndroidDtbConfig,
    out: &mut [u8],
) -> Result<usize, KernelError> {
    cfg.validate()?;

    let mut b = DtbBuilder::new();

    // Set boot CPUID to the MPIDR of the first (primary) CPU.
    b.set_boot_cpuid(cfg.cpu_mpidr[0] as u32);

    // ── Root node ─────────────────────────────────────────────────────────────
    b.begin_node(b"")?;
    b.prop_u32(b"#address-cells", 2)?;
    b.prop_u32(b"#size-cells", 2)?;
    b.prop_str(b"compatible", b"aether,android-partition")?;

    // ── /memory ───────────────────────────────────────────────────────────────
    {
        let mut mem_name = [0u8; 32];
        let prefix = b"memory@";
        mem_name[..prefix.len()].copy_from_slice(prefix);
        let addr_str = hex_u64(&mut mem_name[prefix.len()..], cfg.memory_base);
        b.begin_node(&mem_name[..prefix.len() + addr_str])?;
        b.prop_str(b"device_type", b"memory")?;
        b.prop_cells(b"reg", &[
            (cfg.memory_base >> 32) as u32,
            cfg.memory_base as u32,
            (cfg.memory_size >> 32) as u32,
            cfg.memory_size as u32,
        ])?;
        b.end_node()?;
    }

    // ── /cpus ─────────────────────────────────────────────────────────────────
    b.begin_node(b"cpus")?;
    b.prop_u32(b"#address-cells", 2)?;
    b.prop_u32(b"#size-cells", 0)?;
    for i in 0..cfg.cpu_count {
        let mpidr = cfg.cpu_mpidr[i];
        let mut cpu_name = [0u8; 24];
        let prefix = b"cpu@";
        cpu_name[..prefix.len()].copy_from_slice(prefix);
        let n = hex_u64(&mut cpu_name[prefix.len()..], mpidr);
        b.begin_node(&cpu_name[..prefix.len() + n])?;
        // "arm,armv8" is the correct compatible string for a generic ARM64 CPU.
        // Source: Documentation/devicetree/bindings/arm/cpus.yaml
        b.prop_str(b"compatible", b"arm,armv8")?;
        b.prop_str(b"device_type", b"cpu")?;
        b.prop_cells(b"reg", &[(mpidr >> 32) as u32, mpidr as u32])?;
        // PSCI is how the Android kernel brings secondary CPUs online.
        b.prop_str(b"enable-method", b"psci")?;
        b.end_node()?;
    }
    b.end_node()?; // /cpus

    // ── /psci ─────────────────────────────────────────────────────────────────
    b.begin_node(b"psci")?;
    // "arm,psci-1.0" signals PSCI version 1.0 compliance.
    // Source: Documentation/devicetree/bindings/arm/psci.yaml
    b.prop_str(b"compatible", b"arm,psci-1.0")?;
    // AETHER intercepts HVC at EL2; Android uses HVC (not SMC) for PSCI.
    b.prop_str(b"method", b"hvc")?;
    b.prop_u32(b"cpu_on", PSCI_CPU_ON_FN)?;
    b.prop_u32(b"cpu_off", PSCI_CPU_OFF_FN)?;
    b.prop_u32(b"cpu_suspend", PSCI_CPU_SUSPEND_FN)?;
    b.prop_u32(b"migrate", PSCI_MIGRATE_INFO_TYPE_FN)?;
    b.end_node()?; // /psci

    // ── /interrupt-controller (GICv3) ────────────────────────────────────────
    {
        let mut intc_name = [0u8; 32];
        let prefix = b"interrupt-controller@";
        intc_name[..prefix.len()].copy_from_slice(prefix);
        let n = hex_u64(&mut intc_name[prefix.len()..], cfg.gicd_base);
        b.begin_node(&intc_name[..prefix.len() + n])?;
        // Exact compatible string for GICv3.
        // Source: Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.yaml
        b.prop_str(b"compatible", b"arm,gic-v3")?;
        // Three cells per interrupt specifier: <type intid flags>.
        b.prop_u32(b"#interrupt-cells", 3)?;
        b.prop_empty(b"interrupt-controller")?;
        b.prop_cells(b"reg", &[
            (cfg.gicd_base >> 32) as u32, cfg.gicd_base as u32,
            (cfg.gicd_size >> 32) as u32, cfg.gicd_size as u32,
            (cfg.gicr_base >> 32) as u32, cfg.gicr_base as u32,
            (cfg.gicr_size >> 32) as u32, cfg.gicr_size as u32,
        ])?;
        // GICv3 redistributors have a 2-cell address (1 cell for the base,
        // 1 cell for the stride). Address cells = 2, size cells = 2 inherited
        // from root. The GIC redistributor region covers all assigned cores.
        b.prop_u32(b"#address-cells", 2)?;
        b.prop_u32(b"#size-cells", 2)?;
        b.end_node()?; // /interrupt-controller
    }

    // ── /timer (ARM architectural timer) ─────────────────────────────────────
    b.begin_node(b"timer")?;
    // "arm,armv8-timer" is the correct compatible string for the ARMv8 arch timer.
    // Source: Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
    b.prop_str(b"compatible", b"arm,armv8-timer")?;
    // Four timer PPIs: secure EL1, non-secure EL1, virtual EL1, EL2 hypervisor.
    // AETHER exposes all four because the Android kernel configures all of them.
    // DT intid = absolute INTID − 16 for PPIs.
    b.prop_cells(b"interrupts", &[
        GIC_PPI, TIMER_SECURE_PPI_DT,     IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_NON_SECURE_PPI_DT, IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_VIRTUAL_PPI_DT,    IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_HYP_PPI_DT,        IRQ_TYPE_LEVEL_HIGH,
    ])?;
    b.prop_empty(b"always-on")?;
    b.end_node()?; // /timer

    // ── /serial (PL011 UART — early console) ─────────────────────────────────
    {
        let mut serial_name = [0u8; 24];
        let prefix = b"serial@";
        serial_name[..prefix.len()].copy_from_slice(prefix);
        let n = hex_u64(&mut serial_name[prefix.len()..], cfg.uart_base);
        b.begin_node(&serial_name[..prefix.len() + n])?;
        // "arm,pl011" is the exact compatible string for the ARM PL011 UART.
        // Source: Documentation/devicetree/bindings/serial/arm,pl011.yaml
        b.prop_str(b"compatible", b"arm,pl011")?;
        b.prop_cells(b"reg", &[
            (cfg.uart_base >> 32) as u32, cfg.uart_base as u32,
            0u32, 0x1000u32, // PL011 register region is 4KB
        ])?;
        // UART SPI: DT intid = absolute INTID − 32.
        let uart_dt_intid = cfg.uart_irq_spi.saturating_sub(32);
        b.prop_cells(b"interrupts", &[GIC_SPI, uart_dt_intid, IRQ_TYPE_LEVEL_HIGH])?;
        b.prop_empty(b"interrupt-parent")?; // uses root interrupt-controller
        b.end_node()?; // /serial
    }

    // ── /chosen ───────────────────────────────────────────────────────────────
    b.begin_node(b"chosen")?;
    // bootargs: kernel command line (null-terminated string property).
    b.prop_str(b"bootargs", &cfg.cmdline[..cfg.cmdline_len])?;

    // stdout-path: points to the serial node.
    {
        let mut stdout_path = [0u8; 48];
        let prefix = b"/serial@";
        stdout_path[..prefix.len()].copy_from_slice(prefix);
        let n = hex_u64(&mut stdout_path[prefix.len()..], cfg.uart_base);
        b.prop_str(b"stdout-path", &stdout_path[..prefix.len() + n])?;
    }
    b.end_node()?; // /chosen

    b.end_node()?; // root

    b.finalize_into(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: write u64 as lowercase hex into a byte buffer.
// Returns the number of bytes written (without null terminator).
// Used to construct device node unit addresses (e.g., "cpu@0001000000000000").
// ─────────────────────────────────────────────────────────────────────────────

fn hex_u64(buf: &mut [u8], val: u64) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Skip leading zeros but always write at least one digit.
    let mut started = false;
    let mut pos = 0usize;
    for shift in (0..16).rev() {
        let nibble = ((val >> (shift * 4)) & 0xF) as usize;
        if nibble != 0 || started || shift == 0 {
            if pos < buf.len() {
                buf[pos] = HEX[nibble];
                pos += 1;
            }
            started = true;
        }
    }
    pos
}

// ─────────────────────────────────────────────────────────────────────────────
// GKI (Generic Kernel Image) mandatory configuration
//
// Android 12+ requires kernels to satisfy GKI mandatory config options.
// This module tracks the required options so the build system can verify
// the kernel .config before packaging.
//
// Source: android.googlesource.com/kernel/common android/configs/
// ─────────────────────────────────────────────────────────────────────────────

/// A single GKI mandatory kernel configuration option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GkiRequiredOption {
    /// CONFIG_ option name (e.g., b"CONFIG_ANDROID_BINDER_IPC").
    pub name: &'static [u8],
    /// Whether the option must be set to `y` (true) or must NOT be set (false).
    pub required_enabled: bool,
}

impl GkiRequiredOption {
    const fn must_enable(name: &'static [u8]) -> Self {
        Self { name, required_enabled: true }
    }

    const fn must_disable(name: &'static [u8]) -> Self {
        Self { name, required_enabled: false }
    }
}

/// GKI mandatory kernel configuration options for Android 12+.
///
/// All options in this table must be present (enabled or disabled as indicated)
/// in any kernel configuration used for AETHER's Android partition.
///
/// Sources:
///   android.googlesource.com/kernel/common android/configs/android-base.config
///   android.googlesource.com/kernel/common android/configs/android-recommended.config
pub const GKI_REQUIRED_OPTIONS: &[GkiRequiredOption] = &[
    // Android Binder IPC — required by all Android userspace (init, system_server).
    GkiRequiredOption::must_enable(b"CONFIG_ANDROID_BINDER_IPC"),
    // Android Anonymous Shared Memory — required by graphics stack and media.
    GkiRequiredOption::must_enable(b"CONFIG_MEMFD_CREATE"),
    // SELinux — Android enforces SELinux; without it the system refuses to boot.
    GkiRequiredOption::must_enable(b"CONFIG_SECURITY_SELINUX"),
    // Audit subsystem — required by SELinux policy enforcement.
    GkiRequiredOption::must_enable(b"CONFIG_AUDIT"),
    // Mandatory access control (foundation of SELinux).
    GkiRequiredOption::must_enable(b"CONFIG_SECURITY"),
    // Network namespaces — required by Android's network isolation model.
    GkiRequiredOption::must_enable(b"CONFIG_NET_NS"),
    // User namespaces — required by Android's container/sandbox model.
    GkiRequiredOption::must_enable(b"CONFIG_USER_NS"),
    // Control Groups v2 — required by Android's process management.
    GkiRequiredOption::must_enable(b"CONFIG_CGROUPS"),
    GkiRequiredOption::must_enable(b"CONFIG_CGROUP_FREEZER"),
    GkiRequiredOption::must_enable(b"CONFIG_CGROUP_CPUACCT"),
    GkiRequiredOption::must_enable(b"CONFIG_BLK_CGROUP"),
    // ION memory allocator — required by Android HAL and graphics pipeline.
    GkiRequiredOption::must_enable(b"CONFIG_DMABUF_HEAPS"),
    GkiRequiredOption::must_enable(b"CONFIG_DMABUF_HEAPS_SYSTEM"),
    // EXT4 — required for Android system/vendor partition read-only mounts.
    GkiRequiredOption::must_enable(b"CONFIG_EXT4_FS"),
    // F2FS — required for Android userdata partition.
    GkiRequiredOption::must_enable(b"CONFIG_F2FS_FS"),
    // SquashFS — used by some vendor overlay images.
    GkiRequiredOption::must_enable(b"CONFIG_SQUASHFS"),
    // EROFS — Android 11+ compressed read-only filesystem for system/vendor.
    GkiRequiredOption::must_enable(b"CONFIG_EROFS_FS"),
    // dm-verity — integrity verification for Android system partitions (AVB2).
    GkiRequiredOption::must_enable(b"CONFIG_DM_VERITY"),
    // Overlayfs — used by Android's dynamic partitions and DSU.
    GkiRequiredOption::must_enable(b"CONFIG_OVERLAY_FS"),
    // IOMMU — SMMU consumer driver; AETHER maps devices via Stage 2 + SMMU.
    GkiRequiredOption::must_enable(b"CONFIG_IOMMU_SUPPORT"),
    GkiRequiredOption::must_enable(b"CONFIG_ARM_SMMU_V3"),
    // NVMe — for the NVMe VF assigned to the Android partition (ch14).
    GkiRequiredOption::must_enable(b"CONFIG_NVME_CORE"),
    GkiRequiredOption::must_enable(b"CONFIG_BLK_DEV_NVME"),
    // USB xHCI — for the xHCI controllers assigned to Android (ch16).
    GkiRequiredOption::must_enable(b"CONFIG_USB_XHCI_HCD"),
    GkiRequiredOption::must_enable(b"CONFIG_USB_HID"),
    // GICv3 — interrupt controller driver.
    GkiRequiredOption::must_enable(b"CONFIG_IRQCHIP"),
    GkiRequiredOption::must_enable(b"CONFIG_ARM_GIC_V3"),
    // ARM architectural timer.
    GkiRequiredOption::must_enable(b"CONFIG_ARM_ARCH_TIMER"),
    // PL011 UART — early console.
    GkiRequiredOption::must_enable(b"CONFIG_SERIAL_AMBA_PL011"),
    GkiRequiredOption::must_enable(b"CONFIG_SERIAL_AMBA_PL011_CONSOLE"),
    // ARM64 must never run in big-endian mode for Android.
    GkiRequiredOption::must_disable(b"CONFIG_CPU_BIG_ENDIAN"),
];

/// GKI configuration state tracker.
///
/// Records which required GKI options have been confirmed present in the
/// Android kernel configuration. All entries in `GKI_REQUIRED_OPTIONS` must
/// be satisfied before a kernel configuration can be used.
pub struct GkiConfig {
    /// Bitmask of satisfied options (bit N = GKI_REQUIRED_OPTIONS[N] satisfied).
    satisfied: u64,
}

impl GkiConfig {
    /// Create a new GkiConfig with no options satisfied.
    pub const fn new() -> Self {
        Self { satisfied: 0 }
    }

    /// Record that a configuration option is present with the given state.
    ///
    /// `name` is the CONFIG_ option name (e.g., `b"CONFIG_ANDROID_BINDER_IPC"`).
    /// `enabled` is true if the option is set to `y` or `m`, false if unset.
    pub fn record(&mut self, name: &[u8], enabled: bool) {
        for (i, opt) in GKI_REQUIRED_OPTIONS.iter().enumerate() {
            if opt.name == name && opt.required_enabled == enabled {
                self.satisfied |= 1u64 << i;
                return;
            }
        }
    }

    /// Returns true if all required GKI options are satisfied.
    pub fn all_satisfied(&self) -> bool {
        let required_mask = (1u64 << GKI_REQUIRED_OPTIONS.len()) - 1;
        self.satisfied & required_mask == required_mask
    }

    /// Returns the name of the first unsatisfied required option, if any.
    pub fn first_missing(&self) -> Option<&'static [u8]> {
        for (i, opt) in GKI_REQUIRED_OPTIONS.iter().enumerate() {
            if self.satisfied & (1u64 << i) == 0 {
                return Some(opt.name);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel load configuration and launch state
//
// Validates the kernel launch parameters and tracks which verification steps
// have been completed before AETHER EREs to the Android partition kernel.
// ─────────────────────────────────────────────────────────────────────────────

/// Validated kernel load configuration.
///
/// Holds the addresses AETHER has loaded the kernel and DTB into, along with
/// the parsed image header for sanity-checking before the boot ERET.
#[derive(Debug, Clone, Copy)]
pub struct KernelLoadConfig {
    /// IPA at which the kernel Image binary is loaded. Must be 2MiB-aligned.
    pub kernel_load_ipa: u64,
    /// Size of the kernel image in bytes.
    pub kernel_size: u64,
    /// IPA at which the device tree blob is placed. Passed in x0 at kernel entry.
    pub dtb_ipa: u64,
    /// Size of the device tree blob in bytes.
    pub dtb_size: u32,
    /// IPA of the initial ramdisk (initramfs). 0 if not used.
    pub initrd_ipa: u64,
    /// Size of the initial ramdisk in bytes. 0 if not used.
    pub initrd_size: u32,
}

impl KernelLoadConfig {
    /// Validate that the kernel load parameters satisfy the ARM64 boot protocol.
    pub fn validate(&self) -> Result<(), KernelError> {
        // ARM64 boot protocol: kernel_load_ipa must be 2MiB-aligned.
        if self.kernel_load_ipa & (KERNEL_LOAD_ALIGN - 1) != 0 {
            return Err(KernelError::KernelNotAligned);
        }
        // x0 at kernel entry must be non-zero (DTB address).
        if self.dtb_ipa == 0 {
            return Err(KernelError::DtbAddressZero);
        }
        Ok(())
    }

    /// Compute the kernel entry IPA given a parsed image header.
    ///
    /// Modern kernels (text_offset = 0) enter at `kernel_load_ipa` directly.
    pub fn entry_ipa(&self, hdr: &Arm64ImageHeader) -> u64 {
        hdr.entry_ipa(self.kernel_load_ipa)
    }
}

/// Phase of the kernel preparation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPhase {
    /// Initial state — no kernel image has been loaded.
    Init,
    /// Kernel Image has been loaded and the Image header has been validated.
    ImageValidated,
    /// Device tree blob has been constructed and placed in memory.
    DtbPlaced,
    /// GKI configuration has been verified against required options.
    ConfigVerified,
    /// All preparation complete; AETHER may ERET to the kernel.
    ReadyToLaunch,
}

/// Android partition kernel preparation state machine.
///
/// Tracks which of the required preparation steps have been completed before
/// AETHER performs the boot ERET into the Android partition's Linux kernel.
///
/// Steps:
///   1. `validate_image()` — parse and validate the ARM64 Image header
///   2. `place_dtb()` — record DTB load address and size
///   3. `verify_config()` — confirm GKI mandatory config is satisfied
///   4. `ready()` — final pre-launch check; returns `KernelLoadConfig`
pub struct KernelState {
    phase: KernelPhase,
    load_cfg: KernelLoadConfig,
    image_hdr: Option<Arm64ImageHeader>,
}

impl KernelState {
    /// Create a new KernelState in the `Init` phase.
    pub const fn new() -> Self {
        Self {
            phase: KernelPhase::Init,
            load_cfg: KernelLoadConfig {
                kernel_load_ipa: 0,
                kernel_size: 0,
                dtb_ipa: 0,
                dtb_size: 0,
                initrd_ipa: 0,
                initrd_size: 0,
            },
            image_hdr: None,
        }
    }

    /// Current phase of the state machine.
    pub fn phase(&self) -> KernelPhase {
        self.phase
    }

    /// Parse the ARM64 Image header at `kernel_load_ipa` from the provided
    /// raw bytes slice, validate it, and advance to `ImageValidated`.
    pub fn validate_image(
        &mut self,
        kernel_load_ipa: u64,
        image_bytes: &[u8],
    ) -> Result<&Arm64ImageHeader, KernelError> {
        if kernel_load_ipa & (KERNEL_LOAD_ALIGN - 1) != 0 {
            return Err(KernelError::KernelNotAligned);
        }
        let hdr = Arm64ImageHeader::parse(image_bytes)?;
        self.load_cfg.kernel_load_ipa = kernel_load_ipa;
        self.load_cfg.kernel_size = hdr.image_size;
        self.image_hdr = Some(hdr);
        self.phase = KernelPhase::ImageValidated;
        Ok(self.image_hdr.as_ref().unwrap())
    }

    /// Record the DTB load address and advance to `DtbPlaced`.
    ///
    /// Must be called after `validate_image()`.
    pub fn place_dtb(
        &mut self,
        dtb_ipa: u64,
        dtb_size: u32,
    ) -> Result<(), KernelError> {
        if self.phase != KernelPhase::ImageValidated {
            return Err(KernelError::DtbAddressZero);
        }
        if dtb_ipa == 0 {
            return Err(KernelError::DtbAddressZero);
        }
        self.load_cfg.dtb_ipa = dtb_ipa;
        self.load_cfg.dtb_size = dtb_size;
        self.phase = KernelPhase::DtbPlaced;
        Ok(())
    }

    /// Verify that all GKI mandatory configuration options are satisfied and
    /// advance to `ConfigVerified`.
    ///
    /// Must be called after `place_dtb()`.
    pub fn verify_config(&mut self, gki: &GkiConfig) -> Result<(), KernelError> {
        if self.phase != KernelPhase::DtbPlaced {
            return Err(KernelError::MissingRequiredKconfig);
        }
        if !gki.all_satisfied() {
            return Err(KernelError::MissingRequiredKconfig);
        }
        self.phase = KernelPhase::ConfigVerified;
        Ok(())
    }

    /// Complete preparation and return the validated `KernelLoadConfig`.
    ///
    /// Must be called after `verify_config()`. After this call the phase
    /// is `ReadyToLaunch` and the caller may ERET to the kernel.
    pub fn ready(&mut self) -> Result<KernelLoadConfig, KernelError> {
        if self.phase != KernelPhase::ConfigVerified {
            return Err(KernelError::DtbAddressZero);
        }
        self.load_cfg.validate()?;
        self.phase = KernelPhase::ReadyToLaunch;
        Ok(self.load_cfg)
    }

    /// Returns true when all preparation is complete and launch may proceed.
    pub fn is_ready(&self) -> bool {
        self.phase == KernelPhase::ReadyToLaunch
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertion: GKI option count fits in u64 bitmask
// ─────────────────────────────────────────────────────────────────────────────

// The const_assert is expressed as a named constant so it is evaluated at
// compile time without a dependency on external assertion macros.
#[allow(dead_code)]
const _GKI_COUNT_CHECK: () = {
    assert!(
        GKI_REQUIRED_OPTIONS.len() <= 64,
        "GKI_REQUIRED_OPTIONS exceeds 64 entries; expand GkiConfig.satisfied to u128"
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Arm64ImageHeader ─────────────────────────────────────────────────────

    fn make_valid_image() -> [u8; 128] {
        let mut buf = [0u8; 128];
        // PE/COFF magic at [0:2]
        buf[0] = b'M';
        buf[1] = b'Z';
        // text_offset = 0 at [8:16] (already zero)
        // image_size = 0x100000 (1MB) at [16:24]
        buf[16..24].copy_from_slice(&0x0010_0000u64.to_le_bytes());
        // flags = 0 (LE, page size unspecified, anywhere) at [24:32]
        // ARM64 magic at [56:60]
        buf[56..60].copy_from_slice(&LINUX_ARM64_IMAGE_MAGIC.to_le_bytes());
        buf
    }

    #[test]
    fn parse_valid_arm64_image() {
        let img = make_valid_image();
        let hdr = Arm64ImageHeader::parse(&img).expect("parse failed");
        assert_eq!(hdr.text_offset, 0);
        assert_eq!(hdr.image_size, 0x0010_0000);
        assert_eq!(hdr.flags, 0);
        assert!(hdr.has_pe_magic);
        assert!(hdr.is_little_endian());
        assert_eq!(hdr.page_size_hint(), 0); // unspecified
    }

    #[test]
    fn parse_image_too_small() {
        let small = [0u8; 32];
        assert_eq!(
            Arm64ImageHeader::parse(&small).unwrap_err(),
            KernelError::ImageTooSmall
        );
    }

    #[test]
    fn parse_image_bad_magic() {
        let mut img = make_valid_image();
        img[56] = 0xDE; // corrupt the ARM64 magic
        assert_eq!(
            Arm64ImageHeader::parse(&img).unwrap_err(),
            KernelError::InvalidImageMagic
        );
    }

    #[test]
    fn image_entry_ipa_zero_text_offset() {
        let img = make_valid_image();
        let hdr = Arm64ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.entry_ipa(0x4000_0000), 0x4000_0000);
    }

    #[test]
    fn image_entry_ipa_nonzero_text_offset() {
        let mut img = make_valid_image();
        img[8..16].copy_from_slice(&0x0008_0000u64.to_le_bytes()); // text_offset = 512KB
        let hdr = Arm64ImageHeader::parse(&img).unwrap();
        // entry = load_ipa + text_offset = 0x4000_0000 + 0x80000
        assert_eq!(hdr.entry_ipa(0x4000_0000), 0x4008_0000);
    }

    #[test]
    fn image_flag_big_endian() {
        let mut img = make_valid_image();
        img[24] = 0x01; // flags bit 0 = BE
        let hdr = Arm64ImageHeader::parse(&img).unwrap();
        assert!(!hdr.is_little_endian());
    }

    #[test]
    fn image_page_size_hint_4k() {
        let mut img = make_valid_image();
        img[24] = 0x02; // flags bits [2:1] = 0b01 → 4KB
        let hdr = Arm64ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.page_size_hint(), 4 * 1024);
    }

    // ── DtbBuilder ───────────────────────────────────────────────────────────

    #[test]
    fn dtb_empty_tree_roundtrip() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap(); // root
        b.end_node().unwrap();

        let mut out = [0u8; 256];
        let n = b.finalize_into(&mut out).unwrap();
        assert!(n >= FDT_STRUCT_OFFSET);

        // Magic at offset 0 must be 0xD00DFEED (big-endian).
        let magic = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(magic, FDT_MAGIC);

        // version at offset 20 must be 17.
        let version = u32::from_be_bytes([out[20], out[21], out[22], out[23]]);
        assert_eq!(version, FDT_VERSION);

        // totalsize must match n.
        let totalsize = u32::from_be_bytes([out[4], out[5], out[6], out[7]]) as usize;
        assert_eq!(totalsize, n);
    }

    #[test]
    fn dtb_prop_u32() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap();
        b.prop_u32(b"#address-cells", 2).unwrap();
        b.end_node().unwrap();

        let mut out = [0u8; 512];
        let n = b.finalize_into(&mut out).unwrap();
        assert!(n > FDT_STRUCT_OFFSET);
    }

    #[test]
    fn dtb_missing_end_node_errors() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap();
        // Forgot end_node — finalize should fail.
        let mut out = [0u8; 512];
        assert_eq!(
            b.finalize_into(&mut out).unwrap_err(),
            KernelError::DtbOpenNodesRemain
        );
    }

    #[test]
    fn dtb_end_node_without_begin_errors() {
        let mut b = DtbBuilder::new();
        assert_eq!(b.end_node().unwrap_err(), KernelError::DtbNoOpenNode);
    }

    #[test]
    fn dtb_prop_outside_node_errors() {
        let mut b = DtbBuilder::new();
        assert_eq!(
            b.prop_u32(b"foo", 1).unwrap_err(),
            KernelError::DtbPropertyOutsideNode
        );
    }

    #[test]
    fn dtb_string_interning_deduplicates() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap();
        b.prop_u32(b"cells", 1).unwrap();
        b.prop_u32(b"cells", 2).unwrap(); // same name — should deduplicate
        b.end_node().unwrap();

        let mut out = [0u8; 512];
        let n = b.finalize_into(&mut out).unwrap();

        // Strings block size should be: len("cells") + 1 = 6 bytes.
        let strings_size =
            u32::from_be_bytes([out[32], out[33], out[34], out[35]]) as usize;
        assert_eq!(strings_size, b"cells\0".len());
        // Total output is well-formed.
        assert!(n > 0);
    }

    #[test]
    fn dtb_output_too_small_errors() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap();
        b.end_node().unwrap();
        let mut out = [0u8; 4]; // far too small
        assert_eq!(
            b.finalize_into(&mut out).unwrap_err(),
            KernelError::DtbOutputTooSmall
        );
    }

    #[test]
    fn dtb_nested_nodes() {
        let mut b = DtbBuilder::new();
        b.begin_node(b"").unwrap();
        b.prop_u32(b"#address-cells", 2).unwrap();
        b.prop_u32(b"#size-cells", 2).unwrap();
        b.begin_node(b"cpus").unwrap();
        b.prop_u32(b"#address-cells", 2).unwrap();
        b.prop_u32(b"#size-cells", 0).unwrap();
        b.begin_node(b"cpu@0").unwrap();
        b.prop_str(b"compatible", b"arm,armv8").unwrap();
        b.prop_str(b"device_type", b"cpu").unwrap();
        b.prop_cells(b"reg", &[0, 0]).unwrap();
        b.end_node().unwrap(); // cpu@0
        b.end_node().unwrap(); // cpus
        b.end_node().unwrap(); // root

        let mut out = [0u8; 1024];
        let n = b.finalize_into(&mut out).unwrap();

        let magic = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(magic, FDT_MAGIC);
        assert!(n <= 1024);
    }

    // ── GkiConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn gki_all_satisfied() {
        let mut cfg = GkiConfig::new();
        assert!(!cfg.all_satisfied());

        for opt in GKI_REQUIRED_OPTIONS {
            cfg.record(opt.name, opt.required_enabled);
        }
        assert!(cfg.all_satisfied());
        assert!(cfg.first_missing().is_none());
    }

    #[test]
    fn gki_first_missing_reported() {
        let cfg = GkiConfig::new();
        let missing = cfg.first_missing();
        assert!(missing.is_some());
        // First required option is CONFIG_ANDROID_BINDER_IPC.
        assert_eq!(missing.unwrap(), b"CONFIG_ANDROID_BINDER_IPC");
    }

    #[test]
    fn gki_record_unknown_option_ignored() {
        let mut cfg = GkiConfig::new();
        cfg.record(b"CONFIG_NOT_IN_TABLE", true);
        // Satisfied count should still be zero.
        assert!(!cfg.all_satisfied());
    }

    // ── KernelLoadConfig ─────────────────────────────────────────────────────

    #[test]
    fn kernel_load_config_valid() {
        let cfg = KernelLoadConfig {
            kernel_load_ipa: 0x4000_0000, // 1GiB, 2MiB-aligned
            kernel_size: 0x0200_0000,
            dtb_ipa: 0x4800_0000,
            dtb_size: 4096,
            initrd_ipa: 0,
            initrd_size: 0,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn kernel_load_config_unaligned_ipa() {
        let cfg = KernelLoadConfig {
            kernel_load_ipa: 0x4010_0000, // not 2MiB-aligned
            kernel_size: 0x100_0000,
            dtb_ipa: 0x4800_0000,
            dtb_size: 4096,
            initrd_ipa: 0,
            initrd_size: 0,
        };
        assert_eq!(cfg.validate().unwrap_err(), KernelError::KernelNotAligned);
    }

    #[test]
    fn kernel_load_config_zero_dtb() {
        let cfg = KernelLoadConfig {
            kernel_load_ipa: 0x4000_0000,
            kernel_size: 0x100_0000,
            dtb_ipa: 0, // missing DTB
            dtb_size: 0,
            initrd_ipa: 0,
            initrd_size: 0,
        };
        assert_eq!(cfg.validate().unwrap_err(), KernelError::DtbAddressZero);
    }

    // ── KernelState phase machine ─────────────────────────────────────────────

    #[test]
    fn kernel_state_full_lifecycle() {
        let img = make_valid_image();
        let mut state = KernelState::new();
        assert_eq!(state.phase(), KernelPhase::Init);

        // Step 1: validate image at 2MiB-aligned IPA.
        state.validate_image(0x4000_0000, &img).unwrap();
        assert_eq!(state.phase(), KernelPhase::ImageValidated);

        // Step 2: place DTB.
        state.place_dtb(0x4800_0000, 4096).unwrap();
        assert_eq!(state.phase(), KernelPhase::DtbPlaced);

        // Step 3: verify GKI config.
        let mut gki = GkiConfig::new();
        for opt in GKI_REQUIRED_OPTIONS {
            gki.record(opt.name, opt.required_enabled);
        }
        state.verify_config(&gki).unwrap();
        assert_eq!(state.phase(), KernelPhase::ConfigVerified);

        // Step 4: ready.
        let load_cfg = state.ready().unwrap();
        assert!(state.is_ready());
        assert_eq!(load_cfg.kernel_load_ipa, 0x4000_0000);
        assert_eq!(load_cfg.dtb_ipa, 0x4800_0000);
    }

    #[test]
    fn kernel_state_unaligned_ipa_rejected() {
        let img = make_valid_image();
        let mut state = KernelState::new();
        assert_eq!(
            state.validate_image(0x4001_0000, &img).unwrap_err(),
            KernelError::KernelNotAligned
        );
    }

    #[test]
    fn kernel_state_incomplete_gki_rejected() {
        let img = make_valid_image();
        let mut state = KernelState::new();
        state.validate_image(0x4000_0000, &img).unwrap();
        state.place_dtb(0x4800_0000, 4096).unwrap();
        let gki = GkiConfig::new(); // nothing satisfied
        assert_eq!(
            state.verify_config(&gki).unwrap_err(),
            KernelError::MissingRequiredKconfig
        );
    }

    // ── hex_u64 ──────────────────────────────────────────────────────────────

    #[test]
    fn hex_u64_zero() {
        let mut buf = [0u8; 16];
        let n = hex_u64(&mut buf, 0);
        assert_eq!(&buf[..n], b"0");
    }

    #[test]
    fn hex_u64_ffff() {
        let mut buf = [0u8; 16];
        let n = hex_u64(&mut buf, 0xffff);
        assert_eq!(&buf[..n], b"ffff");
    }

    #[test]
    fn hex_u64_full() {
        let mut buf = [0u8; 20];
        let n = hex_u64(&mut buf, u64::MAX);
        assert_eq!(&buf[..n], b"ffffffffffffffff");
    }
}
