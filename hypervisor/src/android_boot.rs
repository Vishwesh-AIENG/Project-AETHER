// Android Boot Image Loading — target-arch-agnostic
//
// Locates an Android v3/v4 boot.img in a provided physical-memory region, parses
// the header (delegating to the existing ch19 `BootImageHeader::parse`), and
// reports kernel + ramdisk physical addresses and sizes ready for handoff.
//
// Discovery: linear scan of `region_pa..region_pa+region_size` on
// `BOOT_PAGE_SIZE` boundaries looking for the "ANDROID!" magic at offset 0 of
// the candidate page. When found, the full 4 KiB header is parsed via
// `BootImageHeader::parse` and image offsets are computed per the Android boot
// image layout:
//
//   page 0          : header
//   page 1..        : kernel       (rounded up to BOOT_PAGE_SIZE)
//   then ramdisk    : ramdisk      (rounded up to BOOT_PAGE_SIZE)
//
// On x86 the discovered kernel is an ARM64 GKI Image; FEX translates it. On
// ARM64 (Snapdragon tier) the kernel is loaded into Stage-2-mapped guest IPA
// and ERET'd to directly. Either way, the parsing is identical, which is why
// this module is target-arch-agnostic and does not require `cfg` gates.
//
// No heap, no alloc. All scanning operates on a `&[u8]` view of the region.

use crate::bootloader::{BootImageHeader, BOOT_MAGIC, BOOT_PAGE_SIZE};

/// Physical layout of a discovered Android boot image.
#[derive(Debug, Clone, Copy)]
pub struct AndroidBootLayout {
    /// PA of the boot.img header (page-aligned).
    pub header_pa:  u64,
    /// PA of the kernel payload (page after header).
    pub kernel_pa:  u64,
    /// Kernel size in bytes (from header.kernel_size).
    pub kernel_size: u32,
    /// PA of the ramdisk payload (page after kernel, page-aligned).
    pub ramdisk_pa:  u64,
    /// Ramdisk size in bytes (may be 0).
    pub ramdisk_size: u32,
    /// Header version (3 or 4).
    pub header_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidBootError {
    /// No "ANDROID!" magic was found in the scanned region.
    NotFound,
    /// Magic matched but header parse failed.
    InvalidHeader,
    /// Kernel offset would extend past the provided region.
    KernelOutOfRange,
    /// Region size is smaller than one boot page.
    RegionTooSmall,
}

/// Round `n` up to the next multiple of `BOOT_PAGE_SIZE`.
#[inline]
fn page_round_up(n: u32) -> u32 {
    let mask = BOOT_PAGE_SIZE - 1;
    n.wrapping_add(mask) & !mask
}

/// Scan `region` for an Android boot image. Returns the layout for the first
/// header found. The region must be byte-readable; the caller is responsible
/// for any cache maintenance needed to make DMA-staged bytes visible.
///
/// `region_pa` is the physical address corresponding to `&region[0]`; on UEFI
/// with the firmware identity map active, VA == PA so this is normally just
/// `region.as_ptr() as u64`.
pub fn scan_for_boot_image(region: &[u8], region_pa: u64) -> Result<AndroidBootLayout, AndroidBootError> {
    if region.len() < BOOT_PAGE_SIZE as usize {
        return Err(AndroidBootError::RegionTooSmall);
    }

    let stride = BOOT_PAGE_SIZE as usize;
    let max_off = region.len() - stride;
    let mut off = 0usize;
    while off <= max_off {
        if &region[off..off + 8] == BOOT_MAGIC {
            // Found candidate; parse full header.
            let header_slice = &region[off..off + stride];
            let hdr = BootImageHeader::parse(header_slice)
                .map_err(|_| AndroidBootError::InvalidHeader)?;

            let header_pa  = region_pa + off as u64;
            let kernel_pa  = header_pa + BOOT_PAGE_SIZE as u64;
            let kernel_end = kernel_pa
                .checked_add(page_round_up(hdr.kernel_size) as u64)
                .ok_or(AndroidBootError::KernelOutOfRange)?;
            let ramdisk_pa = kernel_end;

            // Bounds check: kernel must fit within the scanned region.
            let kernel_off_end = (kernel_pa - region_pa) as usize + hdr.kernel_size as usize;
            if kernel_off_end > region.len() {
                return Err(AndroidBootError::KernelOutOfRange);
            }

            return Ok(AndroidBootLayout {
                header_pa,
                kernel_pa,
                kernel_size:    hdr.kernel_size,
                ramdisk_pa,
                ramdisk_size:   hdr.ramdisk_size,
                header_version: hdr.header_version,
            });
        }
        off += stride;
    }
    Err(AndroidBootError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(kernel_size: u32, ramdisk_size: u32, version: u32) -> [u8; 4096] {
        let mut buf = [0u8; 4096];
        buf[0..8].copy_from_slice(BOOT_MAGIC);
        buf[8..12].copy_from_slice(&kernel_size.to_le_bytes());
        buf[12..16].copy_from_slice(&ramdisk_size.to_le_bytes());
        buf[20..24].copy_from_slice(&BOOT_PAGE_SIZE.to_le_bytes());
        buf[40..44].copy_from_slice(&version.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_too_small() {
        let r = scan_for_boot_image(&[0u8; 16], 0).unwrap_err();
        assert_eq!(r, AndroidBootError::RegionTooSmall);
    }

    #[test]
    fn finds_header_at_offset_zero() {
        let mut region = [0u8; 8192];
        let hdr = make_header(1024, 256, 3);
        region[..4096].copy_from_slice(&hdr);
        let layout = scan_for_boot_image(&region, 0x1000_0000).unwrap();
        assert_eq!(layout.header_pa, 0x1000_0000);
        assert_eq!(layout.kernel_pa, 0x1000_0000 + 4096);
        assert_eq!(layout.kernel_size, 1024);
        assert_eq!(layout.header_version, 3);
    }

    #[test]
    fn finds_header_at_later_page() {
        let mut region = [0u8; 4096 * 4];
        let hdr = make_header(512, 0, 3);
        // Place at page 2.
        region[4096 * 2 .. 4096 * 3].copy_from_slice(&hdr);
        let layout = scan_for_boot_image(&region, 0x2000_0000).unwrap();
        assert_eq!(layout.header_pa, 0x2000_0000 + 8192);
    }

    #[test]
    fn not_found_when_no_magic() {
        let region = [0u8; 8192];
        let r = scan_for_boot_image(&region, 0).unwrap_err();
        assert_eq!(r, AndroidBootError::NotFound);
    }
}
