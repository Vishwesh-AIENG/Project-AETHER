//! UEFI File-Protocol shim — reads a file from the ESP at boot time.
//!
//! Plumbs the missing wire between the AETHER UEFI handoff and
//! [`boot_x86_avb::load_boot_img`]. The shim chains:
//!
//!   1. `BootServices.HandleProtocol(image_handle, &LOADED_IMAGE_GUID, …)`
//!      → `EfiLoadedImage.device_handle`  (the ESP block device)
//!   2. `BootServices.HandleProtocol(device_handle, &SFS_GUID, …)`
//!      → `EfiSimpleFileSystem`
//!   3. `EfiSimpleFileSystem.OpenVolume(&mut root)`
//!      → root `EfiFile` for the ESP filesystem
//!   4. `root.Open(&mut file, "\\AETHER\\boot.img", READ, 0)`
//!   5. (optional) `file.GetInfo(EFI_FILE_INFO_GUID, …)` to size the buffer
//!   6. `file.Read(&mut size, buf.as_mut_ptr())` — fills `buf`
//!   7. `file.Close()` + `root.Close()`
//!
//! Must run BEFORE `ExitBootServices`. After ExitBootServices the boot-
//! services table is undefined; firmware will fault on any call.
//!
//! Production path: caller passes the returned `&[u8]` to
//! [`crate::boot_x86_avb::load_boot_img`] which AVB-verifies and copies
//! kernel + ramdisk into guest RAM. The DBT dispatcher's first VMRUN/
//! VMRESUME then translates the kernel entry via the Step A pipeline.

#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;

use crate::boot::{EfiBootServices, EfiGuid, EfiHandle, EfiStatus, EfiSystemTable, EFI_SUCCESS};

// ── Protocol GUIDs ────────────────────────────────────────────────────────────

/// `EFI_LOADED_IMAGE_PROTOCOL_GUID` — 5B1B31A1-9562-11D2-8E3F-00A0C969723B.
/// Surfaces the device handle the image was loaded from. UEFI Spec 2.10 §9.1.
pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x5B1B_31A1,
    data2: 0x9562,
    data3: 0x11D2,
    data4: [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID` — 964E5B22-6459-11D2-8E39-00A0C969723B.
/// Lives on the ESP block-device handle. UEFI Spec 2.10 §13.4.
pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x964E_5B22,
    data2: 0x6459,
    data3: 0x11D2,
    data4: [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

// ── File open mode ────────────────────────────────────────────────────────────

/// `EFI_FILE_MODE_READ` — open existing file for reading. UEFI Spec 2.10 §13.5.
pub const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;

// ── Loaded Image protocol ─────────────────────────────────────────────────────

/// EFI_LOADED_IMAGE_PROTOCOL — minimal subset (UEFI Spec 2.10 §9.1).
/// We only consume `device_handle`; the other fields are kept for layout.
#[repr(C)]
pub struct EfiLoadedImage {
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *const EfiSystemTable,
    pub device_handle: EfiHandle,
    pub file_path:    *const c_void,
    pub reserved:     *const c_void,
    pub load_options_size: u32,
    pub load_options: *const c_void,
    pub image_base:   *const c_void,
    pub image_size:   u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

// ── Simple File System + File protocols ──────────────────────────────────────

/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL — UEFI Spec 2.10 §13.4.
#[repr(C)]
pub struct EfiSimpleFileSystem {
    pub revision: u64,
    /// `OpenVolume(this, &mut root)` — returns the root [`EfiFile`].
    pub open_volume: unsafe extern "efiapi" fn(
        this:    *mut EfiSimpleFileSystem,
        root:    *mut *mut EfiFile,
    ) -> EfiStatus,
}

/// EFI_FILE_PROTOCOL revision 1 — UEFI Spec 2.10 §13.5.
///
/// Only the methods used by `read_esp_file` are typed; the rest are
/// kept as opaque `usize` to preserve vtable layout.
#[repr(C)]
pub struct EfiFile {
    pub revision: u64,
    /// Open(this, &mut new, name_utf16z, open_mode, attributes).
    pub open: unsafe extern "efiapi" fn(
        this:       *mut EfiFile,
        new_handle: *mut *mut EfiFile,
        file_name:  *const u16,
        open_mode:  u64,
        attributes: u64,
    ) -> EfiStatus,
    pub close: unsafe extern "efiapi" fn(this: *mut EfiFile) -> EfiStatus,
    pub delete: usize,
    /// Read(this, &mut buffer_size, buffer). On entry `buffer_size` =
    /// available bytes; on success the firmware overwrites it with the
    /// number of bytes actually read.
    pub read: unsafe extern "efiapi" fn(
        this:        *mut EfiFile,
        buffer_size: *mut usize,
        buffer:      *mut u8,
    ) -> EfiStatus,
    pub write: usize,
    pub get_position: usize,
    pub set_position: unsafe extern "efiapi" fn(this: *mut EfiFile, position: u64) -> EfiStatus,
    pub get_info: usize,
    pub set_info: usize,
    pub flush:    usize,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspReadError {
    /// `HandleProtocol(image_handle, LOADED_IMAGE)` failed. Image handle
    /// was not loaded by firmware, or LoadedImage isn't installed.
    LoadedImageNotFound(EfiStatus),
    /// `HandleProtocol(device_handle, SIMPLE_FILE_SYSTEM)` failed. The
    /// device the hypervisor was loaded from doesn't expose a filesystem
    /// (e.g. loaded from RAM or via PXE).
    NoFileSystem(EfiStatus),
    /// `OpenVolume` failed.
    OpenVolumeFailed(EfiStatus),
    /// `Open` failed — file doesn't exist or path is wrong.
    OpenFileFailed(EfiStatus),
    /// File exists but reading it returned an EFI error.
    ReadFailed(EfiStatus),
    /// File is larger than the supplied buffer.
    BufferTooSmall { needed_hint: usize, supplied: usize },
}

// ── ASCII → UTF-16Z helper ────────────────────────────────────────────────────

/// Convert an ASCII path like `b"\\AETHER\\boot.img"` to a NUL-terminated
/// UTF-16 string in `out`. Returns `Err(BufferTooSmall)` if `out` is too
/// small to hold the conversion (one u16 per ASCII byte plus the NUL).
///
/// UEFI paths use backslashes as separators; pass `\\` in Rust byte literals.
pub fn ascii_to_utf16z(ascii: &[u8], out: &mut [u16]) -> Result<usize, EspReadError> {
    if out.len() < ascii.len() + 1 {
        return Err(EspReadError::BufferTooSmall {
            needed_hint: ascii.len() + 1,
            supplied:    out.len(),
        });
    }
    for (i, &b) in ascii.iter().enumerate() {
        out[i] = b as u16;
    }
    out[ascii.len()] = 0;
    Ok(ascii.len() + 1)
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Read a file from the ESP into `buffer`. Returns the number of bytes read.
///
/// Must be called BEFORE `ExitBootServices`. `image_handle` is the handle
/// firmware passed to `efi_main`. `system_table` is the same pointer
/// firmware passed; we re-derive `BootServices` from it.
///
/// `path_ascii` uses backslash separators per UEFI convention,
/// e.g. `b"\\AETHER\\boot.img"`.
///
/// # Safety
/// `image_handle` and `system_table` must be the values firmware passed to
/// `efi_main` of THIS image. `boot_services_table->handle_protocol` must
/// not have been called for sloppy handles before this returns.
pub unsafe fn read_esp_file(
    image_handle: EfiHandle,
    system_table: *const EfiSystemTable,
    path_ascii:   &[u8],
    buffer:       &mut [u8],
) -> Result<usize, EspReadError> {
    // SAFETY: caller's contract.
    let bs: &EfiBootServices = unsafe { &*(*system_table).boot_services };

    // ── 1. Image handle → LoadedImage → device_handle ─────────────────────
    let mut loaded_image_ptr: *mut c_void = core::ptr::null_mut();
    let s = unsafe {
        (bs.handle_protocol)(
            image_handle,
            &EFI_LOADED_IMAGE_PROTOCOL_GUID,
            &mut loaded_image_ptr,
        )
    };
    if s != EFI_SUCCESS {
        return Err(EspReadError::LoadedImageNotFound(s));
    }
    let loaded_image = loaded_image_ptr as *const EfiLoadedImage;
    let device_handle = unsafe { (*loaded_image).device_handle };

    // ── 2. device_handle → SimpleFileSystem ───────────────────────────────
    let mut sfs_ptr: *mut c_void = core::ptr::null_mut();
    let s = unsafe {
        (bs.handle_protocol)(
            device_handle,
            &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
            &mut sfs_ptr,
        )
    };
    if s != EFI_SUCCESS {
        return Err(EspReadError::NoFileSystem(s));
    }
    let sfs = sfs_ptr as *mut EfiSimpleFileSystem;

    // ── 3. SimpleFileSystem.OpenVolume → root ─────────────────────────────
    let mut root: *mut EfiFile = core::ptr::null_mut();
    let s = unsafe { ((*sfs).open_volume)(sfs, &mut root) };
    if s != EFI_SUCCESS {
        return Err(EspReadError::OpenVolumeFailed(s));
    }

    // ── 4. root.Open(path) ────────────────────────────────────────────────
    // 256 u16s = 512 bytes — enough for any sane ESP path.
    let mut path_utf16: [u16; 256] = [0; 256];
    ascii_to_utf16z(path_ascii, &mut path_utf16)?;
    let mut file: *mut EfiFile = core::ptr::null_mut();
    let s = unsafe {
        ((*root).open)(root, &mut file, path_utf16.as_ptr(), EFI_FILE_MODE_READ, 0)
    };
    if s != EFI_SUCCESS {
        // Best-effort cleanup: close root before propagating.
        unsafe { let _ = ((*root).close)(root); }
        return Err(EspReadError::OpenFileFailed(s));
    }

    // ── 5/6. file.Read → buffer ───────────────────────────────────────────
    let mut size: usize = buffer.len();
    let s = unsafe { ((*file).read)(file, &mut size, buffer.as_mut_ptr()) };

    // ── 7. Close everything regardless of read outcome ────────────────────
    unsafe {
        let _ = ((*file).close)(file);
        let _ = ((*root).close)(root);
    }

    if s != EFI_SUCCESS {
        return Err(EspReadError::ReadFailed(s));
    }
    Ok(size)
}

// ── Convenience wrapper for the boot.img path ─────────────────────────────────

/// Canonical AETHER boot.img path on the ESP.
/// Production installer drops boot.img alongside `\EFI\AETHER\hypervisor.efi`.
pub const AETHER_BOOT_IMG_PATH: &[u8] = b"\\EFI\\AETHER\\boot.img";

/// Canonical vbmeta path on the ESP.
pub const AETHER_VBMETA_PATH: &[u8]   = b"\\EFI\\AETHER\\vbmeta.img";

/// Try to read `\EFI\AETHER\boot.img` into `buffer`. Returns the number of
/// bytes read, or `Ok(0)` if the file is absent / unreadable (so the boot
/// pipeline can fall back to the foundation-gate kernel without aborting).
///
/// # Safety
/// Same contract as [`read_esp_file`].
pub unsafe fn try_read_boot_img(
    image_handle: EfiHandle,
    system_table: *const EfiSystemTable,
    buffer:       &mut [u8],
) -> usize {
    match unsafe {
        read_esp_file(image_handle, system_table, AETHER_BOOT_IMG_PATH, buffer)
    } {
        Ok(n) => n,
        Err(_) => 0,
    }
}

/// Same shape for vbmeta. Production builds should error on absent vbmeta;
/// the caller chooses the policy.
///
/// # Safety
/// Same contract as [`read_esp_file`].
pub unsafe fn try_read_vbmeta(
    image_handle: EfiHandle,
    system_table: *const EfiSystemTable,
    buffer:       &mut [u8],
) -> usize {
    match unsafe {
        read_esp_file(image_handle, system_table, AETHER_VBMETA_PATH, buffer)
    } {
        Ok(n) => n,
        Err(_) => 0,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────
//
// We can't exercise the firmware path on the host. These tests cover the
// pure-Rust helpers that don't depend on UEFI being present.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_to_utf16z_roundtrip() {
        let mut out = [0u16; 32];
        let n = ascii_to_utf16z(b"\\AETHER\\boot.img", &mut out).unwrap();
        assert_eq!(n, 17, "16 chars + NUL");
        assert_eq!(out[0], b'\\' as u16);
        assert_eq!(out[1], b'A'  as u16);
        assert_eq!(out[16], 0,             "trailing NUL");
    }

    #[test]
    fn ascii_to_utf16z_rejects_too_small_buffer() {
        let mut out = [0u16; 4];
        let r = ascii_to_utf16z(b"abcde", &mut out);
        assert!(matches!(r, Err(EspReadError::BufferTooSmall { .. })));
    }

    #[test]
    fn guids_match_uefi_spec() {
        // 5B1B31A1-9562-11D2-8E3F-00A0C969723B
        assert_eq!(EFI_LOADED_IMAGE_PROTOCOL_GUID.data1, 0x5B1B_31A1);
        assert_eq!(EFI_LOADED_IMAGE_PROTOCOL_GUID.data4[0], 0x8E);
        // 964E5B22-6459-11D2-8E39-00A0C969723B
        assert_eq!(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID.data1, 0x964E_5B22);
        assert_eq!(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID.data4[0], 0x8E);
    }

    #[test]
    fn boot_img_path_is_uefi_style() {
        assert!(AETHER_BOOT_IMG_PATH.starts_with(b"\\"));
        assert!(!AETHER_BOOT_IMG_PATH.contains(&b'/'));
    }
}
