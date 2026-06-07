//! Phase F: newc-format cpio archive parser for Android initramfs unpack.
//!
//! Android boot.img v3/v4 stores its initramfs as `gzip(cpio(rootfs))`.
//! The kernel's `populate_rootfs` decompresses the gzip layer (we already
//! ship that as [`crate::inflate::gunzip`]) and then walks the resulting
//! cpio archive, creating tmpfs files for each entry. AETHER mirrors the
//! second half here so Phase F's gates can be validated without needing
//! the live kernel to reach `populate_rootfs` (which is blocked behind
//! Phase E's `setup_command_line` panic).
//!
//! Only the POSIX "new portable" format (magic `"070701"`, aka SVR4
//! / "newc") is supported — that's what every modern Android initramfs
//! emits and what Linux's `kernel/init/initramfs.c` parses. Older `bin`
//! and `odc` formats are rejected.
//!
//! ## Format reference (RFC-style)
//!
//! ```text
//! Header (104 bytes total):
//!   magic        6 ASCII bytes  ("070701" for newc)
//!   13 fields    8 ASCII hex chars each:
//!     ino, mode, uid, gid, nlink, mtime, filesize,
//!     devmajor, devminor, rdevmajor, rdevminor,
//!     namesize, check
//!
//! Filename:      `namesize` bytes incl. trailing NUL, then padded to 4
//!                bytes with NULs.
//!
//! File data:     `filesize` bytes, then padded to 4 bytes with NULs.
//!
//! Trailer:       a final entry whose filename is "TRAILER!!!" (and
//!                filesize is 0). After it the rest of the archive is
//!                unused padding (the kernel ignores anything past).
//! ```
//!
//! ## Phase F gates surfaced here
//!
//! 1. `parse_header` recognises the newc magic and rejects non-newc.
//! 2. `Iter::next` walks every entry in order with correct alignment.
//! 3. `find_init` locates the `/init` binary (a regular file with the
//!    name `init` — Android's bootable cpio always carries one at the
//!    archive root).
//! 4. The synthetic test cpio in `tests` mod round-trips: build →
//!    parse → walk → find_init → verify file bytes.

#![allow(dead_code)] // the parser is consumed by integration paths that
                     // come online once Phase E unblocks populate_rootfs;
                     // unit tests below exercise every code path now.

use core::str;

/// All errors the cpio parser can produce. Discrete variants so the
/// caller (and Phase F gate harness) can name the failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioError {
    /// Input shorter than a newc header (104 bytes).
    TruncatedHeader,
    /// Magic bytes weren't "070701".
    BadMagic,
    /// One of the 13 hex fields wasn't 8 valid ASCII hex chars.
    BadHexField,
    /// `namesize` field claimed more bytes than remain in the input.
    TruncatedName,
    /// Name wasn't NUL-terminated within `namesize` bytes.
    UnterminatedName,
    /// `filesize` field claimed more bytes than remain in the input.
    TruncatedData,
}

/// One parsed entry. Fields are stored as `u64` for headroom; `mode` /
/// `nlink` are `u32`-sized in the format but `u64`-stored to match.
#[derive(Debug, Clone, Copy)]
pub struct CpioEntry<'a> {
    /// Inode number from the header.
    pub ino: u64,
    /// POSIX-style mode (st_mode). High bits are the file-type field.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    pub file_size: u64,
    /// Entry name (the filename in the cpio archive), without the trailing
    /// NUL. May be empty.
    pub name: &'a [u8],
    /// File contents — `file_size` bytes, an empty slice for directories
    /// and symlinks-without-target.
    pub data: &'a [u8],
}

/// File-type bits of `mode`. Standard POSIX values.
pub const C_ISREG:  u32 = 0o0100000;
pub const C_ISDIR:  u32 = 0o0040000;
pub const C_ISLNK:  u32 = 0o0120000;
pub const C_ISCHR:  u32 = 0o0020000;
pub const C_ISBLK:  u32 = 0o0060000;
pub const C_ISFIFO: u32 = 0o0010000;
pub const C_ISSOCK: u32 = 0o0140000;
pub const C_FTYPE_MASK: u32 = 0o0170000;

impl<'a> CpioEntry<'a> {
    /// True iff this entry represents the end-of-archive trailer
    /// (name == "TRAILER!!!").
    pub fn is_trailer(&self) -> bool {
        self.name == b"TRAILER!!!"
    }
    /// True iff this is a regular file (the kernel's populate_rootfs
    /// creates one with the entry's contents).
    pub fn is_regular_file(&self) -> bool {
        (self.mode & C_FTYPE_MASK) == C_ISREG
    }
    pub fn is_dir(&self) -> bool {
        (self.mode & C_FTYPE_MASK) == C_ISDIR
    }
    pub fn is_symlink(&self) -> bool {
        (self.mode & C_FTYPE_MASK) == C_ISLNK
    }
}

const NEWC_MAGIC:   &[u8; 6]  = b"070701";
/// Total header size: 6 byte magic + 13 × 8 byte hex fields = 110 bytes.
/// Wait — newc has the magic OVERLAP the first hex field via field
/// positions (magic + fields packed). The actual layout is 110 bytes
/// total: 6 (magic) + 13*8 (hex fields). Some references say "104"
/// counting differently; we go with the spec exact 110.
pub const NEWC_HEADER_LEN: usize = 6 + 13 * 8; // 110

/// Round `n` up to the next multiple of 4.
fn align4(n: usize) -> usize { (n + 3) & !3 }

/// Decode 8 ASCII hex chars to a u32.
fn parse_hex8(bytes: &[u8]) -> Result<u32, CpioError> {
    if bytes.len() < 8 {
        return Err(CpioError::TruncatedHeader);
    }
    let mut v: u32 = 0;
    for &b in &bytes[..8] {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(CpioError::BadHexField),
        };
        v = v.wrapping_shl(4) | (d as u32);
    }
    Ok(v)
}

/// Parse a newc header out of `input`. Returns the decoded fields and
/// the byte offset past the header (the name then starts there).
pub fn parse_header(input: &[u8]) -> Result<(NewcHeader, usize), CpioError> {
    if input.len() < NEWC_HEADER_LEN {
        return Err(CpioError::TruncatedHeader);
    }
    if &input[..6] != NEWC_MAGIC {
        return Err(CpioError::BadMagic);
    }
    // Fields start at offset 6, each 8 bytes.
    let f = |i: usize| parse_hex8(&input[6 + i * 8..]);
    let hdr = NewcHeader {
        ino:        f(0)? as u64,
        mode:       f(1)?,
        uid:        f(2)?,
        gid:        f(3)?,
        nlink:      f(4)?,
        mtime:      f(5)? as u64,
        file_size:  f(6)? as u64,
        devmajor:   f(7)?,
        devminor:   f(8)?,
        rdevmajor:  f(9)?,
        rdevminor:  f(10)?,
        namesize:   f(11)?,
        check:      f(12)?,
    };
    Ok((hdr, NEWC_HEADER_LEN))
}

/// Decoded newc header — exposed so callers can introspect without
/// committing to the `CpioEntry` view (which also slices name+data).
#[derive(Debug, Clone, Copy)]
pub struct NewcHeader {
    pub ino:       u64,
    pub mode:      u32,
    pub uid:       u32,
    pub gid:       u32,
    pub nlink:     u32,
    pub mtime:     u64,
    pub file_size: u64,
    pub devmajor:  u32,
    pub devminor:  u32,
    pub rdevmajor: u32,
    pub rdevminor: u32,
    pub namesize:  u32,
    pub check:     u32,
}

/// Walks every entry in a newc cpio archive. The iterator yields each
/// entry as a `CpioEntry<'a>` borrowing from the source slice; on the
/// `TRAILER!!!` entry the iterator yields it once and then returns
/// `None` on subsequent calls.
pub struct Iter<'a> {
    rest: &'a [u8],
    seen_trailer: bool,
}

/// Construct a cpio iterator over `archive`.
pub fn iter(archive: &[u8]) -> Iter<'_> {
    Iter { rest: archive, seen_trailer: false }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<CpioEntry<'a>, CpioError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.seen_trailer { return None; }
        if self.rest.is_empty() { return None; }
        // Parse header.
        let (hdr, hdr_len) = match parse_header(self.rest) {
            Ok(v) => v,
            Err(e) => { self.rest = &[]; return Some(Err(e)); }
        };
        let after_hdr = &self.rest[hdr_len..];
        let name_sz = hdr.namesize as usize;
        if name_sz == 0 || name_sz > after_hdr.len() {
            self.rest = &[];
            return Some(Err(CpioError::TruncatedName));
        }
        let name_with_nul = &after_hdr[..name_sz];
        // newc namesize INCLUDES the trailing NUL.
        let nul_pos = match name_with_nul.iter().position(|&b| b == 0) {
            Some(p) => p,
            None => { self.rest = &[]; return Some(Err(CpioError::UnterminatedName)); }
        };
        let name = &name_with_nul[..nul_pos];
        // Skip name + pad to 4 from the OVERALL archive start. Newc
        // pads so (header + name) ends on a 4-byte boundary. Our
        // `rest` slice starts at the entry boundary, so the pad is
        // align4(header + name) - (header + name).
        let after_name_off = hdr_len + name_sz;
        let after_name_padded = align4(after_name_off);
        if after_name_padded > self.rest.len() {
            self.rest = &[];
            return Some(Err(CpioError::TruncatedName));
        }
        let file_sz = hdr.file_size as usize;
        if file_sz > self.rest.len().saturating_sub(after_name_padded) {
            self.rest = &[];
            return Some(Err(CpioError::TruncatedData));
        }
        let data_start = after_name_padded;
        let data_end = data_start + file_sz;
        let data = &self.rest[data_start..data_end];
        // Pad data to 4 bytes for the NEXT entry's start.
        let after_data_padded = align4(data_end);
        let entry = CpioEntry {
            ino:       hdr.ino,
            mode:      hdr.mode,
            uid:       hdr.uid,
            gid:       hdr.gid,
            nlink:     hdr.nlink,
            mtime:     hdr.mtime,
            file_size: hdr.file_size,
            name,
            data,
        };
        // Advance for the NEXT iteration.
        if entry.is_trailer() {
            self.seen_trailer = true;
        }
        // If there's not enough left for another header, treat as end.
        if after_data_padded >= self.rest.len() {
            self.rest = &[];
        } else {
            self.rest = &self.rest[after_data_padded..];
        }
        Some(Ok(entry))
    }
}

/// Walk `archive` and return the first entry whose name matches
/// `wanted` exactly (no path component handling — Android initramfs's
/// `/init` lives at the archive root and its cpio name is just "init").
/// Returns `Ok(None)` if the archive was well-formed but didn't
/// contain the entry; returns `Err` on parse failure.
pub fn find_entry<'a>(
    archive: &'a [u8],
    wanted: &[u8],
) -> Result<Option<CpioEntry<'a>>, CpioError> {
    for result in iter(archive) {
        let entry = result?;
        if entry.name == wanted {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// Convenience: find the `/init` binary. Returns the entry on success.
/// Android's bootable initramfs is required to carry one (the kernel
/// passes `init=/init` and `run_init_process("/init")` is the default
/// when no override is set).
pub fn find_init(archive: &[u8]) -> Result<Option<CpioEntry<'_>>, CpioError> {
    // Some initramfs builders use a leading "./" or "/" — accept any.
    if let Some(e) = find_entry(archive, b"init")? { return Ok(Some(e)); }
    if let Some(e) = find_entry(archive, b"./init")? { return Ok(Some(e)); }
    if let Some(e) = find_entry(archive, b"/init")? { return Ok(Some(e)); }
    Ok(None)
}

/// Count parseable entries in an archive (excluding trailer). Returns
/// `Err` on the first malformed entry.
pub fn count_entries(archive: &[u8]) -> Result<u32, CpioError> {
    let mut count: u32 = 0;
    for result in iter(archive) {
        let entry = result?;
        if entry.is_trailer() { break; }
        count = count.saturating_add(1);
    }
    Ok(count)
}

// ────────────────────────────────────────────────────────────────────────────
// Phase F gates (each surfaced as a discrete boolean so the harness can
// report which sub-gate failed).
// ────────────────────────────────────────────────────────────────────────────

/// Result of running every Phase F gate on a real (gzipped) initramfs
/// payload. All four booleans MUST be true to pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseFGate {
    /// gunzip of the raw initramfs payload succeeded.
    pub gunzip_succeeded: bool,
    /// Decompressed bytes parsed as a valid newc cpio archive
    /// (every entry header valid, trailer present).
    pub cpio_well_formed: bool,
    /// Archive contains an entry named `init` (or `./init`, `/init`).
    pub init_present: bool,
    /// The init entry is a REGULAR FILE (not a symlink or dir).
    pub init_is_executable_file: bool,
}

impl PhaseFGate {
    pub fn passes(&self) -> bool {
        self.gunzip_succeeded
            && self.cpio_well_formed
            && self.init_present
            && self.init_is_executable_file
    }
}

/// Run every Phase F gate against a `gzipped_initramfs` blob (the raw
/// initramfs bytes from boot.img). Decompresses with [`crate::inflate::
/// gunzip`] into the caller-supplied `scratch` buffer, then runs the
/// cpio analysis.
///
/// Returns the populated gate struct AND (on success) a slice over the
/// cpio bytes inside `scratch` for the caller to inspect further.
pub fn run_phase_f_gates<'a>(
    gzipped_initramfs: &[u8],
    scratch: &'a mut [u8],
) -> (PhaseFGate, Option<&'a [u8]>) {
    let mut gate = PhaseFGate::default();
    let cpio_len = match crate::inflate::gunzip(gzipped_initramfs, scratch) {
        Ok(n) => n,
        Err(_) => return (gate, None),
    };
    gate.gunzip_succeeded = true;
    let cpio: &[u8] = &scratch[..cpio_len];
    // We need to re-borrow scratch out for the return; do the cpio
    // analysis on a separate borrow first.
    let analysis = analyze_cpio(cpio);
    gate.cpio_well_formed = analysis.well_formed;
    gate.init_present = analysis.init_entry.is_some();
    gate.init_is_executable_file = analysis
        .init_entry
        .map(|e| e.is_regular_file && e.file_size > 0)
        .unwrap_or(false);
    // Re-borrow scratch as immutable for the return.
    (gate, Some(&scratch[..cpio_len]))
}

/// Compact analysis result that doesn't borrow from the cpio slice
/// (so the caller of `run_phase_f_gates` can return both the gate and
/// the cpio slice without lifetime entanglement).
#[derive(Debug, Clone, Copy, Default)]
pub struct CpioAnalysis {
    pub well_formed: bool,
    pub entry_count: u32,
    pub init_entry: Option<InitInfo>,
}

#[derive(Debug, Clone, Copy)]
pub struct InitInfo {
    pub mode: u32,
    pub file_size: u64,
    pub is_regular_file: bool,
}

fn analyze_cpio(cpio: &[u8]) -> CpioAnalysis {
    let mut analysis = CpioAnalysis::default();
    let mut saw_trailer = false;
    let mut count: u32 = 0;
    for result in iter(cpio) {
        match result {
            Ok(entry) => {
                if entry.is_trailer() {
                    saw_trailer = true;
                    break;
                }
                count = count.saturating_add(1);
                if entry.name == b"init"
                   || entry.name == b"./init"
                   || entry.name == b"/init"
                {
                    analysis.init_entry = Some(InitInfo {
                        mode: entry.mode,
                        file_size: entry.file_size,
                        is_regular_file: entry.is_regular_file(),
                    });
                }
            }
            Err(_) => return analysis, // well_formed stays false
        }
    }
    analysis.well_formed = saw_trailer && count > 0;
    analysis.entry_count = count;
    analysis
}

// ────────────────────────────────────────────────────────────────────────────
// Tests — every code path of the parser + the gate harness. Run via
//   cargo test --lib -p hypervisor cpio::tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    // Build a single newc entry. Returns the encoded bytes.
    fn build_entry(name: &[u8], mode: u32, data: &[u8]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut out: Vec<u8> = Vec::new();
        // Magic.
        out.extend_from_slice(NEWC_MAGIC);
        // Helper.
        let mut push_hex = |val: u32| {
            let s = format!("{:08x}", val);
            out.extend_from_slice(s.as_bytes());
        };
        push_hex(1);              // ino
        push_hex(mode);           // mode
        push_hex(0);              // uid
        push_hex(0);              // gid
        push_hex(1);              // nlink
        push_hex(0);              // mtime
        push_hex(data.len() as u32); // file_size
        push_hex(0);              // devmajor
        push_hex(0);              // devminor
        push_hex(0);              // rdevmajor
        push_hex(0);              // rdevminor
        push_hex(name.len() as u32 + 1); // namesize (INCLUDES NUL)
        push_hex(0);              // check
        // Name + NUL.
        out.extend_from_slice(name);
        out.push(0);
        // Pad to 4 from archive start.
        while out.len() % 4 != 0 { out.push(0); }
        // Data.
        out.extend_from_slice(data);
        // Pad to 4.
        while out.len() % 4 != 0 { out.push(0); }
        out
    }

    fn build_archive(entries: &[(&[u8], u32, &[u8])]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut out: Vec<u8> = Vec::new();
        for &(name, mode, data) in entries {
            out.extend_from_slice(&build_entry(name, mode, data));
        }
        // Trailer.
        out.extend_from_slice(&build_entry(b"TRAILER!!!", 0, &[]));
        out
    }

    #[test]
    fn parse_minimal_archive() {
        let archive = build_archive(&[
            (b"init", C_ISREG | 0o755, b"#!/bin/sh\nexec /sbin/init\n"),
        ]);
        let mut count = 0;
        let mut saw_init = false;
        for r in iter(&archive) {
            let e = r.expect("entry parses");
            if e.is_trailer() { break; }
            count += 1;
            if e.name == b"init" {
                saw_init = true;
                let want = b"#!/bin/sh\nexec /sbin/init\n";
                assert_eq!(e.file_size, want.len() as u64);
                assert_eq!(e.data, want);
                assert!(e.is_regular_file());
                assert_eq!(e.mode & 0o777, 0o755);
            }
        }
        assert_eq!(count, 1);
        assert!(saw_init);
    }

    #[test]
    fn find_init_finds_init_by_three_names() {
        for name in [&b"init"[..], &b"./init"[..], &b"/init"[..]] {
            let archive = build_archive(&[(name, C_ISREG | 0o755, b"x")]);
            let found = find_init(&archive).expect("ok").expect("present");
            assert_eq!(found.name, name);
        }
    }

    #[test]
    fn find_init_returns_none_when_absent() {
        let archive = build_archive(&[
            (b"sbin/init", C_ISREG | 0o755, b"x"),
        ]);
        assert!(find_init(&archive).unwrap().is_none());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut archive = build_archive(&[
            (b"init", C_ISREG | 0o755, b"x"),
        ]);
        archive[0] = b'X';
        let mut it = iter(&archive);
        assert_eq!(it.next().unwrap().unwrap_err(), CpioError::BadMagic);
    }

    #[test]
    fn truncated_header_rejected() {
        let bytes = [0u8; 50]; // < NEWC_HEADER_LEN
        let mut it = iter(&bytes);
        assert_eq!(it.next().unwrap().unwrap_err(), CpioError::TruncatedHeader);
    }

    #[test]
    fn entry_count_excludes_trailer() {
        let archive = build_archive(&[
            (b"init", C_ISREG | 0o755, b"x"),
            (b"sbin", C_ISDIR | 0o755, &[]),
            (b"bin",  C_ISDIR | 0o755, &[]),
        ]);
        assert_eq!(count_entries(&archive).unwrap(), 3);
    }

    #[test]
    fn alignment_handles_odd_name_and_data_lengths() {
        // Pathologically odd lengths: name "ab" (2+NUL=3), data "xyz" (3).
        // Header (110) + name+nul (3) = 113, pad to 116. Data 3, pad to 4.
        // Next entry starts at offset 116+4 = 120.
        let archive = build_archive(&[
            (b"ab", C_ISREG | 0o644, b"xyz"),
            (b"longername", C_ISREG | 0o644, b"more data here"),
        ]);
        let entries: alloc::vec::Vec<_> = iter(&archive).collect();
        assert!(entries.iter().all(|e| e.is_ok()));
        let count = count_entries(&archive).unwrap();
        assert_eq!(count, 2);
    }

    // Build a minimal gzipped cpio archive for round-trip via gunzip+cpio.
    // Generate the gzip data with a simple stored-block (no compression).
    fn build_gzip(payload: &[u8]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut out: Vec<u8> = Vec::new();
        // gzip header: ID1=1f ID2=8b CM=8 FLG=0 MTIME(4) XFL=0 OS=03 (unix).
        out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00,
                                0, 0, 0, 0,
                                0x00, 0x03]);
        // DEFLATE: a stored block (BTYPE=00) containing the whole payload.
        // BFINAL=1 + BTYPE=00 = byte 0x01.
        out.push(0x01);
        let len = payload.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(payload);
        // gzip footer: CRC32(4) + ISIZE(4). We omit real CRC; our
        // gunzip ignores trailer bytes so zeros work for tests.
        out.extend_from_slice(&[0, 0, 0, 0,
                                (payload.len() as u32).to_le_bytes()[0],
                                (payload.len() as u32).to_le_bytes()[1],
                                (payload.len() as u32).to_le_bytes()[2],
                                (payload.len() as u32).to_le_bytes()[3]]);
        out
    }

    #[test]
    fn phase_f_gate_passes_on_synthetic_initramfs() {
        let cpio = build_archive(&[
            (b"init",     C_ISREG | 0o755, b"#!/system/bin/sh\nexec init"),
            (b"sbin",     C_ISDIR | 0o755, &[]),
            (b"sbin/foo", C_ISREG | 0o644, b"placeholder"),
        ]);
        let gz = build_gzip(&cpio);
        let mut scratch = alloc::vec![0u8; cpio.len() + 64];
        let (gate, slice) = run_phase_f_gates(&gz, &mut scratch);
        assert!(gate.gunzip_succeeded, "gunzip failed: {:?}", gate);
        assert!(gate.cpio_well_formed, "cpio not well-formed: {:?}", gate);
        assert!(gate.init_present, "init missing: {:?}", gate);
        assert!(gate.init_is_executable_file, "init not regular file: {:?}", gate);
        assert!(gate.passes());
        let cpio_out = slice.unwrap();
        assert_eq!(cpio_out.len(), cpio.len());
    }

    #[test]
    fn phase_f_gate_fails_when_init_missing() {
        let cpio = build_archive(&[
            (b"sbin/init", C_ISREG | 0o755, b"x"),
        ]);
        let gz = build_gzip(&cpio);
        let mut scratch = alloc::vec![0u8; cpio.len() + 64];
        let (gate, _) = run_phase_f_gates(&gz, &mut scratch);
        assert!(gate.gunzip_succeeded);
        assert!(gate.cpio_well_formed);
        assert!(!gate.init_present);
        assert!(!gate.passes());
    }

    // ── Phase F integration: real Android initramfs from boot.img ────────
    //
    // Reads the project-staged boot.img, slices out the gzipped
    // ramdisk payload, and runs the full Phase F gate harness. Skips
    // (returns ok) if the file isn't present so this still passes on
    // CI matrix members that don't ship the asset.
    #[cfg(any(unix, windows))]
    #[test]
    fn phase_f_gates_pass_on_real_initramfs() {
        // Resolve project-root-relative paths: tests run with CWD =
        // the crate dir (D:/AETHER/hypervisor).
        let candidates = [
            "../qemu/efi-x86/EFI/AETHER/boot.img",
            "../esp-staging/EFI/AETHER/boot.img",
        ];
        let path = match candidates.iter()
            .find(|p| std::path::Path::new(p).exists())
            .copied()
        {
            Some(p) => p,
            None => {
                eprintln!("[phase-f] boot.img not found — skipping (no asset)");
                return;
            }
        };
        let bytes = std::fs::read(path).expect("read boot.img");
        eprintln!("[phase-f] boot.img at {}: {} bytes", path, bytes.len());

        // Parse boot.img v3/v4 header to find the (still-gzipped) initrd.
        assert!(bytes.len() >= 4096);
        assert_eq!(&bytes[..8], b"ANDROID!", "boot.img magic");
        let kernel_size = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let ramdisk_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let ramdisk_start = (1 + (kernel_size + 4095) / 4096) * 4096;
        let ramdisk_end = ramdisk_start + ramdisk_size;
        assert!(ramdisk_end <= bytes.len());
        let gz_initrd = &bytes[ramdisk_start..ramdisk_end];
        eprintln!("[phase-f] gzipped initrd: {} bytes", gz_initrd.len());
        assert_eq!(&gz_initrd[..3], &[0x1f, 0x8b, 0x08], "gzip magic");

        // Run the Phase F gate harness end-to-end.
        let mut scratch = alloc::vec![0u8; 8 * 1024 * 1024];
        let (gate, cpio_slice) = run_phase_f_gates(gz_initrd, &mut scratch);

        eprintln!("[phase-f] gate = {:?}", gate);
        if let Some(cpio) = cpio_slice {
            eprintln!("[phase-f] decompressed cpio: {} bytes", cpio.len());
            let count = count_entries(cpio).expect("count entries");
            eprintln!("[phase-f] cpio entries: {}", count);
            assert!(count >= 3, "real initramfs should have at least a few entries");
        }

        assert!(gate.gunzip_succeeded,        "gunzip_succeeded");
        assert!(gate.cpio_well_formed,         "cpio_well_formed");
        assert!(gate.init_present,             "init_present");
        assert!(gate.init_is_executable_file,  "init_is_executable_file");
        assert!(gate.passes(),                 "ALL GATES PASS");

        eprintln!("[phase-f] ✓ ALL PHASE F GATES PASSED on real boot.img");
    }

    #[test]
    fn phase_f_gate_fails_when_init_is_symlink() {
        let cpio = build_archive(&[
            (b"init", C_ISLNK | 0o777, b"sbin/real_init"),
        ]);
        let gz = build_gzip(&cpio);
        let mut scratch = alloc::vec![0u8; cpio.len() + 64];
        let (gate, _) = run_phase_f_gates(&gz, &mut scratch);
        assert!(gate.gunzip_succeeded);
        assert!(gate.cpio_well_formed);
        assert!(gate.init_present);
        // init was found but it's a symlink, not a regular file.
        assert!(!gate.init_is_executable_file);
        assert!(!gate.passes());
    }
}
