// device_path.rs -- EFI_DEVICE_PATH_PROTOCOL encoding.
//
// UEFI Spec v2.10 §10 defines device paths. A device path is a sequence of
// nodes, each with the structure:
//
//     u8   Type        (e.g., 4 = Media Device Path)
//     u8   SubType     (e.g., 1 = Hard Drive, 4 = File Path)
//     u16  Length      (Length of THIS node including the 4-byte header,
//                       little-endian, byte-counted not element-counted)
//     u8[] TypeData    (Length - 4 bytes of payload)
//
// The sequence terminates with an End-of-Hardware node:
//     Type=0x7F, SubType=0xFF, Length=4
//
// We build the two node types we need for a boot entry pointing at
// \EFI\AETHER\hypervisor.efi on a specific GPT partition:
//
//   1. Hard Drive node (Type=4, SubType=1, Length=42)
//        u32  PartitionNumber       1-based GPT partition number
//        u64  PartitionStart        LBA of partition start
//        u64  PartitionSize         Partition size in LBAs
//        u8[16] Signature           GPT partition GUID
//        u8   MBRType               0x02 = GPT
//        u8   SignatureType         0x02 = GPT GUID
//
//   2. File Path node (Type=4, SubType=4, Length=4 + 2*chars)
//        CHAR16[] PathName          UTF-16LE NUL-terminated path
//
//   3. End node (Type=0x7F, SubType=0xFF, Length=4)
//
// Common AI mistake (from P5-SKILLS.md): writing the file path as a plain
// UTF-16 string with no device-path header. Firmware then silently ignores
// the boot entry or shows garbage in the menu.

// ---- Public types -----------------------------------------------------------

/// 128-bit GPT partition GUID, stored in the on-disk byte order (mixed-endian
/// per Microsoft GUID convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptGuid(pub [u8; 16]);

impl GptGuid {
    /// Parse a canonical GUID string "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".
    /// The first three groups are interpreted as little-endian; the last two
    /// as big-endian, per RFC 4122 / Microsoft GUID convention.
    #[allow(dead_code)] // used by tests + future ESP-probe path; kept on the public API
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        // Strip optional braces.
        let s = s.trim_start_matches('{').trim_end_matches('}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 { return None; }
        if parts[0].len() != 8 || parts[1].len() != 4 || parts[2].len() != 4
            || parts[3].len() != 4 || parts[4].len() != 12 {
            return None;
        }
        let d1 = u32::from_str_radix(parts[0], 16).ok()?;
        let d2 = u16::from_str_radix(parts[1], 16).ok()?;
        let d3 = u16::from_str_radix(parts[2], 16).ok()?;

        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&d1.to_le_bytes());
        bytes[4..6].copy_from_slice(&d2.to_le_bytes());
        bytes[6..8].copy_from_slice(&d3.to_le_bytes());

        let g4 = decode_hex_bytes::<2>(parts[3])?;
        let g5 = decode_hex_bytes::<6>(parts[4])?;
        bytes[8..10].copy_from_slice(&g4);
        bytes[10..16].copy_from_slice(&g5);

        Some(GptGuid(bytes))
    }

    /// Format as canonical "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".
    pub fn to_string_canonical(&self) -> String {
        let b = &self.0;
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            d1, d2, d3,
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}

#[allow(dead_code)] // called from GptGuid::parse which is itself a public API
fn decode_hex_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 { return None; }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i*2..i*2+2], 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct HardDriveNode {
    pub partition_number: u32,
    pub partition_start_lba: u64,
    pub partition_size_lba: u64,
    pub partition_guid: GptGuid,
}

// ---- Node serializers -------------------------------------------------------

const TYPE_MEDIA:        u8 = 0x04;
const SUBTYPE_HARD_DRIVE: u8 = 0x01;
const SUBTYPE_FILE_PATH:  u8 = 0x04;

const TYPE_END_HW:        u8 = 0x7F;
const SUBTYPE_END_ENTIRE: u8 = 0xFF;

const MBR_TYPE_GPT:      u8 = 0x02;
const SIG_TYPE_GPT_GUID: u8 = 0x02;

/// Serialize a Hard Drive node into a 42-byte buffer.
pub fn hard_drive_node(hd: &HardDriveNode) -> Vec<u8> {
    let mut buf = Vec::with_capacity(42);
    buf.push(TYPE_MEDIA);
    buf.push(SUBTYPE_HARD_DRIVE);
    buf.extend_from_slice(&42u16.to_le_bytes());
    buf.extend_from_slice(&hd.partition_number.to_le_bytes());
    buf.extend_from_slice(&hd.partition_start_lba.to_le_bytes());
    buf.extend_from_slice(&hd.partition_size_lba.to_le_bytes());
    buf.extend_from_slice(&hd.partition_guid.0);
    buf.push(MBR_TYPE_GPT);
    buf.push(SIG_TYPE_GPT_GUID);
    debug_assert_eq!(buf.len(), 42);
    buf
}

/// Serialize a File Path node. The path is converted to UTF-16LE and
/// NUL-terminated. Forward slashes are converted to backslashes -- UEFI
/// uses backslash-separated paths.
pub fn file_path_node(path: &str) -> Vec<u8> {
    let utf16: Vec<u16> = path
        .replace('/', "\\")
        .encode_utf16()
        .chain(std::iter::once(0u16)) // NUL terminator
        .collect();
    let path_bytes = utf16.len() * 2;
    let total_len = 4 + path_bytes;
    assert!(total_len <= u16::MAX as usize, "file path node too long");

    let mut buf = Vec::with_capacity(total_len);
    buf.push(TYPE_MEDIA);
    buf.push(SUBTYPE_FILE_PATH);
    buf.extend_from_slice(&(total_len as u16).to_le_bytes());
    for w in utf16 {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    debug_assert_eq!(buf.len(), total_len);
    buf
}

/// Serialize the End-of-Device-Path node. Always 4 bytes.
pub fn end_node() -> [u8; 4] {
    [TYPE_END_HW, SUBTYPE_END_ENTIRE, 0x04, 0x00]
}

/// Build the full device-path list for a UEFI boot entry pointing at a file
/// on a GPT partition.
pub fn device_path_list(hd: &HardDriveNode, file_path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hard_drive_node(hd));
    buf.extend_from_slice(&file_path_node(file_path));
    buf.extend_from_slice(&end_node());
    buf
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trip() {
        // Microsoft Basic Data partition GUID.
        let s = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
        let g = GptGuid::parse(s).expect("parse");
        assert_eq!(g.to_string_canonical(), s);
        // Sanity: first byte should be 0xA2 (little-endian of 0xEBD0A0A2).
        assert_eq!(g.0[0], 0xA2);
        assert_eq!(g.0[1], 0xA0);
        assert_eq!(g.0[2], 0xD0);
        assert_eq!(g.0[3], 0xEB);
    }

    #[test]
    fn guid_parse_with_braces() {
        let s = "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}";
        let g = GptGuid::parse(s).expect("parse with braces");
        assert_eq!(g.to_string_canonical(), "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }

    #[test]
    fn guid_parse_rejects_bad_lengths() {
        assert!(GptGuid::parse("short").is_none());
        assert!(GptGuid::parse("EBD0A0A2B9E54433-87C0-68B6B72699C7").is_none());
    }

    #[test]
    fn hard_drive_node_is_42_bytes() {
        let hd = HardDriveNode {
            partition_number: 1,
            partition_start_lba: 2048,
            partition_size_lba: 1_000_000,
            partition_guid: GptGuid([0xCC; 16]),
        };
        let buf = hard_drive_node(&hd);
        assert_eq!(buf.len(), 42);
        assert_eq!(buf[0], 0x04);  // type = media
        assert_eq!(buf[1], 0x01);  // subtype = hard drive
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 42);
        assert_eq!(buf[40], 0x02); // MBR type = GPT
        assert_eq!(buf[41], 0x02); // signature type = GPT GUID
    }

    #[test]
    fn file_path_node_encodes_utf16_with_nul() {
        let buf = file_path_node("\\EFI\\AETHER\\hypervisor.efi");
        // Header: type=0x04, subtype=0x04
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1], 0x04);
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(buf.len(), len);
        // Last two bytes are UTF-16LE NUL.
        assert_eq!(&buf[len-2..], &[0x00, 0x00]);
        // First UTF-16 char is '\\' = 0x005C LE = [0x5C, 0x00]
        assert_eq!(buf[4], 0x5C);
        assert_eq!(buf[5], 0x00);
    }

    #[test]
    fn file_path_converts_forward_slashes_to_backslashes() {
        let buf = file_path_node("/EFI/AETHER/hypervisor.efi");
        // First few chars should be '\\', 'E', 'F', 'I', '\\' ...
        // bytes 4..6 = first UTF-16 char = 0x005C LE
        assert_eq!(buf[4], 0x5C, "forward slash should become backslash");
        assert_eq!(buf[5], 0x00);
    }

    #[test]
    fn end_node_is_exactly_4_bytes() {
        let e = end_node();
        assert_eq!(e, [0x7F, 0xFF, 0x04, 0x00]);
    }

    #[test]
    fn full_path_list_terminates_with_end_node() {
        let hd = HardDriveNode {
            partition_number: 1,
            partition_start_lba: 2048,
            partition_size_lba: 1_000_000,
            partition_guid: GptGuid([0xAA; 16]),
        };
        let buf = device_path_list(&hd, "\\EFI\\AETHER\\hypervisor.efi");
        // First 42 bytes = hard drive node.
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 42);
        // Last 4 bytes = end node.
        assert_eq!(&buf[buf.len()-4..], &[0x7F, 0xFF, 0x04, 0x00]);
    }
}
