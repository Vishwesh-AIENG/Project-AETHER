// gpt.rs -- locate the EFI System Partition by reading the GPT directly.
//
// The UEFI Boot#### entry (Ch56 step 7) needs a Hard Drive device-path node
// that matches the ESP exactly: 1-based partition number, start LBA, size in
// LBAs, and the partition's *unique* GUID. Firmware matches the entry to a
// partition by that GUID, so a zeroed GUID produces an entry that never boots.
//
// Rather than per-OS IOCTLs (IOCTL_DISK_GET_DRIVE_LAYOUT_EX / blkid), we read
// the GPT straight off the whole-disk device through `BlockDevice::read_at`,
// which works identically on `\\.\PHYSICALDRIVEn` and `/dev/nvme0n1`.
//
// UEFI Spec v2.10 §5.3:
//   LBA 0  protective MBR
//   LBA 1  GPT header: "EFI PART" signature, HeaderSize @12, HeaderCRC32 @16
//          (computed with the field zeroed), PartitionEntryLBA @72,
//          NumberOfPartitionEntries @80, SizeOfPartitionEntry @84,
//          PartitionEntryArrayCRC32 @88.
//   Entry  PartitionTypeGUID @0, UniquePartitionGUID @16, StartingLBA @32,
//          EndingLBA @40 (inclusive).
//
// Raw-disk reads on Windows must be sector-aligned and a multiple of the
// sector size, so every read here is a 4096-byte multiple at an aligned offset
// (valid for both 512-byte and 4Kn logical sectors).

use crate::device_path::{GptGuid, HardDriveNode};

/// ESP partition type GUID C12A7328-F81F-11D2-BA4B-00A0C93EC93B, on-disk order.
pub const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const READ_ALIGN: u64 = 4096;
/// Sanity cap on the entry array (spec minimum is 16 KiB; real disks use 128×128).
const MAX_ENTRY_ARRAY_BYTES: u64 = 1024 * 1024;

/// The ESP as found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspInfo {
    pub partition_number: u32,
    pub start_lba: u64,
    pub size_lba: u64,
    pub unique_guid: GptGuid,
    pub sector_size: u64,
}

impl EspInfo {
    pub fn hard_drive_node(&self) -> HardDriveNode {
        HardDriveNode {
            partition_number:    self.partition_number,
            partition_start_lba: self.start_lba,
            partition_size_lba:  self.size_lba,
            partition_guid:      self.unique_guid,
        }
    }
}

/// Find the ESP on a GPT disk. `read(byte_offset, buf)` must fill `buf`
/// exactly; offsets and lengths passed to it are always 4096-aligned.
pub fn find_esp<F>(mut read: F) -> Result<EspInfo, String>
where
    F: FnMut(u64, &mut [u8]) -> std::io::Result<()>,
{
    // LBA 0..1 for both sector sizes lives in the first 8 KiB.
    let mut head = vec![0u8; 2 * READ_ALIGN as usize];
    read(0, &mut head).map_err(|e| format!("reading GPT header: {}", e))?;

    let sector_size = [512u64, 4096]
        .into_iter()
        .find(|&s| &head[s as usize..s as usize + 8] == GPT_SIGNATURE)
        .ok_or("no GPT header (\"EFI PART\") at LBA 1 — disk is not GPT-partitioned")?;
    let hdr = &head[sector_size as usize..];

    let header_size = le_u32(hdr, 12) as usize;
    if !(92..=sector_size as usize).contains(&header_size) {
        return Err(format!("GPT header size {} out of range", header_size));
    }
    let mut hdr_copy = hdr[..header_size].to_vec();
    hdr_copy[16..20].fill(0);
    if crc32(&hdr_copy) != le_u32(hdr, 16) {
        return Err("GPT header CRC32 mismatch (corrupt or not a GPT disk)".into());
    }

    let entry_lba   = le_u64(hdr, 72);
    let num_entries = le_u32(hdr, 80) as u64;
    let entry_size  = le_u32(hdr, 84) as u64;
    let array_crc   = le_u32(hdr, 88);
    if entry_size < 128 || entry_size % 8 != 0 {
        return Err(format!("GPT entry size {} invalid", entry_size));
    }
    let array_bytes = num_entries * entry_size;
    if array_bytes == 0 || array_bytes > MAX_ENTRY_ARRAY_BYTES {
        return Err(format!("GPT entry array size {} out of range", array_bytes));
    }

    let array_off = entry_lba * sector_size;
    let aligned_off = array_off - array_off % READ_ALIGN;
    let lead = (array_off - aligned_off) as usize;
    let read_len = (lead as u64 + array_bytes).div_ceil(READ_ALIGN) * READ_ALIGN;
    let mut buf = vec![0u8; read_len as usize];
    read(aligned_off, &mut buf).map_err(|e| format!("reading GPT entry array: {}", e))?;
    let array = &buf[lead..lead + array_bytes as usize];
    if crc32(array) != array_crc {
        return Err("GPT partition entry array CRC32 mismatch".into());
    }

    for (idx, e) in array.chunks_exact(entry_size as usize).enumerate() {
        if e[0..16] != ESP_TYPE_GUID {
            continue;
        }
        let start = le_u64(e, 32);
        let end   = le_u64(e, 40);
        if end < start {
            return Err(format!("ESP entry {} has EndingLBA < StartingLBA", idx + 1));
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&e[16..32]);
        return Ok(EspInfo {
            partition_number: idx as u32 + 1,
            start_lba: start,
            size_lba: end - start + 1,
            unique_guid: GptGuid(guid),
            sector_size,
        });
    }
    Err("GPT has no EFI System Partition (type C12A7328-F81F-11D2-BA4B-00A0C93EC93B)".into())
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// CRC-32/ISO-HDLC (the GPT CRC): reflected polynomial 0xEDB88320.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESP_UNIQUE: [u8; 16] = [0xAA; 16];

    /// Build a minimal GPT disk image: protective MBR, header at LBA 1, a
    /// 128-entry array at LBA 2, with a non-ESP partition in slot 1 and the
    /// ESP in slot 2.
    fn build_gpt(sector: u64) -> Vec<u8> {
        let num_entries = 128u32;
        let entry_size = 128u32;
        let array_lba = 2u64;
        let mut disk = vec![0u8; (array_lba * sector + 128 * 128 + 8192) as usize];

        let mut array = vec![0u8; (num_entries * entry_size) as usize];
        // Slot 1: Microsoft basic data (EBD0A0A2-B9E5-4433-87C0-68B6B72699C7).
        array[0..16].copy_from_slice(&[
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
            0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
        ]);
        array[32..40].copy_from_slice(&4096u64.to_le_bytes());
        array[40..48].copy_from_slice(&999_999u64.to_le_bytes());
        // Slot 2: the ESP.
        let e = &mut array[128..256];
        e[0..16].copy_from_slice(&ESP_TYPE_GUID);
        e[16..32].copy_from_slice(&ESP_UNIQUE);
        e[32..40].copy_from_slice(&2048u64.to_le_bytes());
        e[40..48].copy_from_slice(&(2048u64 + 204_800 - 1).to_le_bytes());

        let a_off = (array_lba * sector) as usize;
        disk[a_off..a_off + array.len()].copy_from_slice(&array);

        let mut hdr = vec![0u8; 92];
        hdr[0..8].copy_from_slice(GPT_SIGNATURE);
        hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes());
        hdr[72..80].copy_from_slice(&array_lba.to_le_bytes());
        hdr[80..84].copy_from_slice(&num_entries.to_le_bytes());
        hdr[84..88].copy_from_slice(&entry_size.to_le_bytes());
        hdr[88..92].copy_from_slice(&crc32(&array).to_le_bytes());
        let hcrc = crc32(&hdr);
        hdr[16..20].copy_from_slice(&hcrc.to_le_bytes());
        disk[sector as usize..sector as usize + 92].copy_from_slice(&hdr);
        disk
    }

    fn reader(disk: &[u8]) -> impl FnMut(u64, &mut [u8]) -> std::io::Result<()> + '_ {
        move |off, buf| {
            assert_eq!(off % READ_ALIGN, 0, "unaligned offset");
            assert_eq!(buf.len() as u64 % READ_ALIGN, 0, "unaligned length");
            let o = off as usize;
            let n = buf.len().min(disk.len().saturating_sub(o));
            buf[..n].copy_from_slice(&disk[o..o + n]);
            buf[n..].fill(0);
            Ok(())
        }
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn esp_type_guid_matches_canonical_string() {
        let g = GptGuid::parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap();
        assert_eq!(g.0, ESP_TYPE_GUID);
    }

    #[test]
    fn finds_esp_on_512_byte_sector_disk() {
        let disk = build_gpt(512);
        let esp = find_esp(reader(&disk)).unwrap();
        assert_eq!(esp, EspInfo {
            partition_number: 2,
            start_lba: 2048,
            size_lba: 204_800,
            unique_guid: GptGuid(ESP_UNIQUE),
            sector_size: 512,
        });
    }

    #[test]
    fn finds_esp_on_4kn_disk() {
        let disk = build_gpt(4096);
        let esp = find_esp(reader(&disk)).unwrap();
        assert_eq!(esp.sector_size, 4096);
        assert_eq!(esp.partition_number, 2);
        assert_eq!(esp.unique_guid, GptGuid(ESP_UNIQUE));
    }

    #[test]
    fn rejects_corrupt_header() {
        let mut disk = build_gpt(512);
        disk[512 + 80] ^= 1; // flip a bit in NumberOfPartitionEntries
        assert!(find_esp(reader(&disk)).unwrap_err().contains("header CRC32"));
    }

    #[test]
    fn rejects_corrupt_entry_array() {
        let mut disk = build_gpt(512);
        disk[2 * 512 + 128 + 40] ^= 1; // flip a bit in the ESP's EndingLBA
        assert!(find_esp(reader(&disk)).unwrap_err().contains("entry array CRC32"));
    }

    #[test]
    fn rejects_non_gpt_disk() {
        let disk = vec![0u8; 64 * 1024];
        assert!(find_esp(reader(&disk)).unwrap_err().contains("not GPT"));
    }

    #[test]
    fn hard_drive_node_carries_real_guid() {
        let disk = build_gpt(512);
        let hd = find_esp(reader(&disk)).unwrap().hard_drive_node();
        assert_eq!(hd.partition_guid, GptGuid(ESP_UNIQUE));
        assert_ne!(hd.partition_size_lba, 0);
    }
}
