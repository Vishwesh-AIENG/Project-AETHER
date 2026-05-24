//! `.text` section extraction for ELF64 and PE32+ binaries.
//!
//! Phase A AT-3/4/5 fill: the AT-5 plan calls for ELF audit of Android
//! `system.img` libraries. On hosts without GSI extract tooling we still
//! want to validate against real ARM64 binaries — and AETHER itself builds
//! to `aarch64-unknown-uefi` (PE32+) so the hypervisor's own object code is
//! a real-world AArch64 corpus.
//!
//! Both extractors return the raw `.text` section bytes ready for the
//! 4-byte-stride decoder walk.

/// Try ELF64 first, then PE32+. Returns the `.text` bytes or `None` if the
/// file isn't a recognised AArch64 binary.
pub fn extract_text(bytes: &[u8]) -> Option<Vec<u8>> {
    extract_elf64_text(bytes).or_else(|| extract_pe32plus_text(bytes))
}

/// ELF64 `.text` extractor.
pub fn extract_elf64_text(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 {
        return None;
    }
    let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
    let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().ok()?) as usize;
    let e_shstrndx = u16::from_le_bytes(bytes[62..64].try_into().ok()?) as usize;

    let shstr_off = e_shoff as usize + e_shstrndx * e_shentsize;
    let shstr_hdr = bytes.get(shstr_off..shstr_off + e_shentsize)?;
    let shstr_section_off =
        u64::from_le_bytes(shstr_hdr[24..32].try_into().ok()?) as usize;
    let shstr_section_size =
        u64::from_le_bytes(shstr_hdr[32..40].try_into().ok()?) as usize;
    let shstr = bytes.get(shstr_section_off..shstr_section_off + shstr_section_size)?;

    for i in 0..e_shnum {
        let off = e_shoff as usize + i * e_shentsize;
        let hdr = bytes.get(off..off + e_shentsize)?;
        let name_off = u32::from_le_bytes(hdr[0..4].try_into().ok()?) as usize;
        let name_end = shstr[name_off..].iter().position(|&b| b == 0)? + name_off;
        let name = &shstr[name_off..name_end];
        if name == b".text" {
            let s_off = u64::from_le_bytes(hdr[24..32].try_into().ok()?) as usize;
            let s_sz = u64::from_le_bytes(hdr[32..40].try_into().ok()?) as usize;
            return bytes.get(s_off..s_off + s_sz).map(<[u8]>::to_vec);
        }
    }
    None
}

/// PE32+ (`hypervisor.efi`) `.text` extractor. The AETHER hypervisor builds
/// to `aarch64-unknown-uefi` which is PE32+ with `IMAGE_FILE_MACHINE_ARM64
/// = 0xAA64` and section names like `.text`.
pub fn extract_pe32plus_text(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
        return None;
    }
    // PE header offset at 0x3C.
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    // COFF header starts at pe_off + 4. Machine type at +0 (u16).
    let coff = pe_off + 4;
    let machine = u16::from_le_bytes(bytes[coff..coff + 2].try_into().ok()?);
    // 0xAA64 = ARM64.
    if machine != 0xAA64 {
        return None;
    }
    let n_sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_hdr_size =
        u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().ok()?) as usize;
    // Optional header follows COFF header (size 20 bytes).
    let sections_off = coff + 20 + opt_hdr_size;

    for i in 0..n_sections {
        let s = sections_off + i * 40;
        let hdr = bytes.get(s..s + 40)?;
        // Name field is 8 bytes (NUL-padded).
        let mut name_end = 8;
        for j in 0..8 {
            if hdr[j] == 0 {
                name_end = j;
                break;
            }
        }
        let name = &hdr[..name_end];
        if name == b".text" {
            let vsize = u32::from_le_bytes(hdr[8..12].try_into().ok()?) as usize;
            let raw_size =
                u32::from_le_bytes(hdr[16..20].try_into().ok()?) as usize;
            let raw_off = u32::from_le_bytes(hdr[20..24].try_into().ok()?) as usize;
            let size = vsize.min(raw_size);
            return bytes.get(raw_off..raw_off + size).map(<[u8]>::to_vec);
        }
    }
    None
}
