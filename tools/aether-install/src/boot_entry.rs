// boot_entry.rs -- EFI_LOAD_OPTION (Boot#### variable) binary encoding.
//
// UEFI Spec v2.10 §3.1.3 defines EFI_LOAD_OPTION:
//
//     u32      Attributes               (LOAD_OPTION_ACTIVE etc.)
//     u16      FilePathListLength       (Length of FilePathList in bytes)
//     CHAR16[] Description              (UTF-16LE NUL-terminated)
//     EFI_DEVICE_PATH_PROTOCOL[]        (FilePathList)
//     u8[]     OptionalData             (optional, often empty)
//
// Common AI mistake (from P5-SKILLS.md): emitting the boot entry as a plain
// UTF-16 string. Firmware then silently ignores the variable or shows garbage
// in the boot menu. The exact wire format is what makes a Boot#### entry
// "real" -- get any field wrong and the firmware will reject it.
//
// BootOrder format: u16[] of boot entry numbers in priority order. To make
// AETHER the default boot target without overwriting Windows: prepend
// AETHER's entry number to the existing BootOrder array.

use crate::device_path::{HardDriveNode, device_path_list};

// EFI_LOAD_OPTION attribute bits (UEFI Spec §3.1.3).
pub const LOAD_OPTION_ACTIVE:           u32 = 0x0000_0001;
#[allow(dead_code)] // exported for future selector.efi entries
pub const LOAD_OPTION_FORCE_RECONNECT:  u32 = 0x0000_0002;
#[allow(dead_code)] // exported; used by recovery-mode boot entries (Ch 62)
pub const LOAD_OPTION_HIDDEN:           u32 = 0x0000_0008;

// EFI variable attributes (UEFI Spec §7.2).
pub const EFI_VARIABLE_NON_VOLATILE:                    u32 = 0x0000_0001;
pub const EFI_VARIABLE_BOOTSERVICE_ACCESS:              u32 = 0x0000_0002;
pub const EFI_VARIABLE_RUNTIME_ACCESS:                  u32 = 0x0000_0004;

/// Standard NV+BS+RT attributes for any boot entry / BootOrder variable.
/// All three flags are mandatory -- without NV the variable disappears at
/// reboot, without RT the OS cannot read it after ExitBootServices.
pub const BOOT_VAR_ATTRS: u32 = EFI_VARIABLE_NON_VOLATILE
    | EFI_VARIABLE_BOOTSERVICE_ACCESS
    | EFI_VARIABLE_RUNTIME_ACCESS;

/// EFI_GLOBAL_VARIABLE GUID -- the GUID under which all Boot####, BootOrder,
/// BootCurrent, etc., live.
pub const EFI_GLOBAL_VARIABLE_GUID: &str = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";

// ---- Boot#### entry serialisation -------------------------------------------

#[derive(Debug, Clone)]
pub struct BootEntry {
    pub attributes:    u32,             // LOAD_OPTION_ACTIVE etc.
    pub description:   String,          // shown in firmware boot menu
    pub hard_drive:    HardDriveNode,   // partition pointer
    pub file_path:     String,          // file within partition (e.g. \EFI\AETHER\selector.efi)
    pub optional_data: Vec<u8>,         // optional, typically empty
}

impl BootEntry {
    /// Serialize the entire Boot#### variable data blob.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Build the file-path list first so we know its length.
        let fp_list = device_path_list(&self.hard_drive, &self.file_path);
        let fp_len = fp_list.len();
        assert!(fp_len <= u16::MAX as usize, "device path list too long");

        // UTF-16LE NUL-terminated description.
        let desc_utf16: Vec<u16> = self.description
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

        let total = 4 /* attrs */
            + 2 /* fp len */
            + desc_utf16.len() * 2
            + fp_len
            + self.optional_data.len();

        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.attributes.to_le_bytes());
        buf.extend_from_slice(&(fp_len as u16).to_le_bytes());
        for w in &desc_utf16 {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        buf.extend_from_slice(&fp_list);
        buf.extend_from_slice(&self.optional_data);
        debug_assert_eq!(buf.len(), total);
        buf
    }
}

// ---- Boot#### variable name -------------------------------------------------

/// Format a "Boot####" variable name with a 4-hex-digit index, uppercase.
/// UEFI Spec §3.1.1: "These variables are stored as Boot#### where #### is a
/// printed hex value".
pub fn boot_var_name(index: u16) -> String {
    format!("Boot{:04X}", index)
}

// ---- BootOrder helpers ------------------------------------------------------

/// Decode the BootOrder variable data into a Vec<u16>. BootOrder is just a
/// little-endian array of u16, no header.
pub fn decode_boot_order(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// Encode a Vec<u16> back into BootOrder bytes.
pub fn encode_boot_order(order: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(order.len() * 2);
    for &i in order {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

/// Prepend `idx` to BootOrder so AETHER boots first. If `idx` is already
/// present anywhere in the list, it is moved to the front (idempotent).
pub fn boot_order_prepend(current: &[u16], idx: u16) -> Vec<u16> {
    let filtered: Vec<u16> = current.iter().copied().filter(|&i| i != idx).collect();
    let mut out = Vec::with_capacity(filtered.len() + 1);
    out.push(idx);
    out.extend(filtered);
    out
}

/// Remove `idx` from BootOrder entirely (used by uninstall).
pub fn boot_order_remove(current: &[u16], idx: u16) -> Vec<u16> {
    current.iter().copied().filter(|&i| i != idx).collect()
}

/// Pick the first unused Boot#### index. UEFI imposes no order, but
/// convention is to allocate the lowest unused index starting at 0x0000.
pub fn pick_free_boot_index(used: &[u16]) -> Option<u16> {
    for candidate in 0..=0xFFFFu16 {
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_path::GptGuid;

    fn make_entry() -> BootEntry {
        BootEntry {
            attributes: LOAD_OPTION_ACTIVE,
            description: "AETHER".to_string(),
            hard_drive: HardDriveNode {
                partition_number: 1,
                partition_start_lba: 2048,
                partition_size_lba: 1_048_576,
                partition_guid: GptGuid([0xAB; 16]),
            },
            file_path: "\\EFI\\AETHER\\selector.efi".to_string(),
            optional_data: Vec::new(),
        }
    }

    #[test]
    fn boot_entry_layout_is_correct() {
        let e = make_entry();
        let bytes = e.to_bytes();

        // First 4 bytes = attributes LE.
        let attrs = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(attrs, LOAD_OPTION_ACTIVE);

        // Next 2 bytes = FilePathListLength LE.
        let fp_len = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;

        // Description starts at byte 6, UTF-16LE NUL terminated. "AETHER" = 6 chars + NUL = 14 bytes.
        let desc_bytes = 14;
        assert_eq!(bytes[6], b'A');
        assert_eq!(bytes[7], 0);
        // NUL at offset 6 + 12.
        assert_eq!(bytes[18], 0);
        assert_eq!(bytes[19], 0);

        // After description, FilePathList of fp_len bytes, ending with end node.
        let fp_start = 6 + desc_bytes;
        let fp_end   = fp_start + fp_len;
        // End-of-device-path: last 4 bytes = 7F FF 04 00.
        assert_eq!(&bytes[fp_end-4..fp_end], &[0x7F, 0xFF, 0x04, 0x00]);

        // No optional data -> total length matches.
        assert_eq!(bytes.len(), fp_end);
    }

    #[test]
    fn description_utf16_nul_terminated() {
        let e = BootEntry { description: "ABC".into(), ..make_entry() };
        let bytes = e.to_bytes();
        // After 4+2 header bytes, 'A' 0 'B' 0 'C' 0 0 0
        assert_eq!(&bytes[6..14], &[b'A', 0, b'B', 0, b'C', 0, 0, 0]);
    }

    #[test]
    fn boot_var_name_zero_padded_uppercase() {
        assert_eq!(boot_var_name(0),      "Boot0000");
        assert_eq!(boot_var_name(0x1),    "Boot0001");
        assert_eq!(boot_var_name(0xAB),   "Boot00AB");
        assert_eq!(boot_var_name(0xFFFF), "BootFFFF");
    }

    #[test]
    fn decode_encode_boot_order_round_trip() {
        let order = vec![0x0001u16, 0x0007, 0x0042, 0xFFFF];
        let bytes = encode_boot_order(&order);
        assert_eq!(bytes.len(), 8);
        // LE: 01 00 07 00 42 00 FF FF
        assert_eq!(bytes, vec![0x01, 0x00, 0x07, 0x00, 0x42, 0x00, 0xFF, 0xFF]);
        let back = decode_boot_order(&bytes);
        assert_eq!(back, order);
    }

    #[test]
    fn boot_order_prepend_new_entry() {
        let cur = vec![0x0001, 0x0002, 0x0003];
        let next = boot_order_prepend(&cur, 0x0042);
        assert_eq!(next, vec![0x0042, 0x0001, 0x0002, 0x0003]);
    }

    #[test]
    fn boot_order_prepend_idempotent_when_already_present() {
        let cur = vec![0x0001, 0x0042, 0x0003];
        let next = boot_order_prepend(&cur, 0x0042);
        // 0x0042 should be moved to front, not duplicated.
        assert_eq!(next, vec![0x0042, 0x0001, 0x0003]);
        assert_eq!(next.len(), 3);
    }

    #[test]
    fn boot_order_prepend_again_is_noop() {
        let cur = vec![0x0001, 0x0002];
        let once = boot_order_prepend(&cur, 0x0042);
        let twice = boot_order_prepend(&once, 0x0042);
        assert_eq!(once, twice);
    }

    #[test]
    fn boot_order_remove_strips_entry() {
        let cur = vec![0x0042, 0x0001, 0x0042, 0x0002];
        let stripped = boot_order_remove(&cur, 0x0042);
        assert_eq!(stripped, vec![0x0001, 0x0002]);
    }

    #[test]
    fn pick_free_boot_index_skips_used() {
        let used = vec![0x0000, 0x0001, 0x0002];
        assert_eq!(pick_free_boot_index(&used), Some(0x0003));
    }

    #[test]
    fn pick_free_boot_index_finds_gap() {
        let used = vec![0x0000, 0x0002, 0x0003];
        assert_eq!(pick_free_boot_index(&used), Some(0x0001));
    }

    #[test]
    fn boot_var_attrs_includes_all_three_flags() {
        assert!(BOOT_VAR_ATTRS & EFI_VARIABLE_NON_VOLATILE       != 0);
        assert!(BOOT_VAR_ATTRS & EFI_VARIABLE_BOOTSERVICE_ACCESS != 0);
        assert!(BOOT_VAR_ATTRS & EFI_VARIABLE_RUNTIME_ACCESS     != 0);
        assert_eq!(BOOT_VAR_ATTRS, 0x07);
    }
}
