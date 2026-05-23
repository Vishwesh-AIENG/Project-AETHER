// block_io.rs — cross-platform block-device write helper for the installer.
//
// Phase 3 deliverable. De-stubs the `[stub] would dd ...` line in install.rs.
//
// Today this is std::fs-based on both Linux and Windows. That is:
//   * Linux: `OpenOptions::new().read(true).write(true).open("/dev/nvme0n1")`
//            works directly when invoked as root.
//   * Windows: `\\.\PHYSICALDRIVE1` works through `OpenOptions` provided
//            the process has Administrator + the disk is unmounted. For
//            production we will want CreateFileW with FILE_FLAG_NO_BUFFERING
//            + FILE_FLAG_WRITE_THROUGH and sector-aligned buffers; this
//            simpler path is Phase 3 minimum and is enough for the verify
//            re-read of the boot.img header at LBA 8192.
//
// The Linux `O_DIRECT` flag and Windows `FILE_FLAG_NO_BUFFERING` upgrades
// are tracked as Phase 4 follow-ups in the plan.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// A read/write handle on a block device (whole disk or namespace).
pub struct BlockDevice {
    file: File,
    path: String,
}

impl BlockDevice {
    /// Open a block device for read+write.
    ///
    /// On Linux pass `/dev/nvme0n1` (or a loop device for testing).
    /// On Windows pass `\\.\PHYSICALDRIVE1` (or a file path for testing).
    pub fn open(path: &str) -> io::Result<Self> {
        let p = Path::new(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)?;
        Ok(Self { file, path: path.to_string() })
    }

    /// Write `data` at `byte_offset`. Synchronises after the write so that
    /// the re-read in `verify_at` sees the same bytes.
    pub fn write_at(&mut self, byte_offset: u64, data: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(byte_offset))?;
        self.file.write_all(data)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Read `dst.len()` bytes from `byte_offset`.
    pub fn read_at(&mut self, byte_offset: u64, dst: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(byte_offset))?;
        self.file.read_exact(dst)?;
        Ok(())
    }

    /// Stream a source file onto the block device starting at `byte_offset`
    /// in 1 MiB chunks. Returns the number of bytes written.
    pub fn dd_file(&mut self, src_path: &str, byte_offset: u64) -> io::Result<u64> {
        const CHUNK: usize = 1024 * 1024; // 1 MiB
        let mut src = File::open(src_path)?;
        self.file.seek(SeekFrom::Start(byte_offset))?;
        let mut buf = vec![0u8; CHUNK];
        let mut written: u64 = 0;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 { break; }
            self.file.write_all(&buf[..n])?;
            written += n as u64;
        }
        self.file.sync_data()?;
        Ok(written)
    }

    /// Verify that `expected_prefix` is present at `byte_offset` by reading
    /// the device. Used after writes to confirm `boot.img` magic bytes.
    pub fn verify_prefix(&mut self, byte_offset: u64, expected_prefix: &[u8]) -> io::Result<bool> {
        let mut buf = vec![0u8; expected_prefix.len()];
        self.read_at(byte_offset, &mut buf)?;
        Ok(buf == expected_prefix)
    }

    /// Path the device was opened with — used in diagnostics.
    pub fn path(&self) -> &str { &self.path }
}

/// Convert a partition LBA offset (4-KiB sectors per `avb_boot.rs`) into a
/// byte offset suitable for `write_at` / `read_at`.
///
/// The hypervisor's `AvbPartitionLayout` declares all offsets in
/// `lba_count * 4096`-byte units; the installer mirrors that convention so
/// re-reads land at the same physical bytes the EL2 NVMe driver later
/// fetches at boot.
pub const AVB_SECTOR_BYTES: u64 = 4096;

#[inline]
pub const fn lba_to_byte_offset(lba: u64) -> u64 {
    lba * AVB_SECTOR_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn lba_offset_conversion() {
        assert_eq!(lba_to_byte_offset(0), 0);
        assert_eq!(lba_to_byte_offset(8192), 8192 * 4096);
        assert_eq!(lba_to_byte_offset(40960), 40960 * 4096);
    }

    #[test]
    fn round_trip_through_temp_file() -> io::Result<()> {
        let dir = std::env::temp_dir();
        let path = dir.join("aether-blockio-test.bin");
        // Pre-create with some size.
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&path)?;
            f.write_all(&vec![0u8; 64 * 1024])?;
        }
        let mut dev = BlockDevice::open(path.to_str().unwrap())?;
        dev.write_at(8192, b"ANDROID!")?;
        let mut buf = [0u8; 8];
        dev.read_at(8192, &mut buf)?;
        assert_eq!(&buf, b"ANDROID!");
        assert!(dev.verify_prefix(8192, b"ANDROID!")?);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn dd_file_copies_bytes() -> io::Result<()> {
        let dir = std::env::temp_dir();
        let src_path = dir.join("aether-blockio-src.bin");
        let dst_path = dir.join("aether-blockio-dst.bin");

        let payload: Vec<u8> = (0..(64 * 1024u32)).map(|i| i as u8).collect();
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&src_path)?;
            f.write_all(&payload)?;
        }
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&dst_path)?;
            f.write_all(&vec![0u8; 256 * 1024])?;
        }

        let mut dev = BlockDevice::open(dst_path.to_str().unwrap())?;
        let n = dev.dd_file(src_path.to_str().unwrap(), 4096)?;
        assert_eq!(n, payload.len() as u64);

        let mut buf = vec![0u8; payload.len()];
        dev.read_at(4096, &mut buf)?;
        assert_eq!(buf, payload);

        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
        Ok(())
    }
}
