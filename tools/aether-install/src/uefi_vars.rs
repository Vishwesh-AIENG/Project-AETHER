// uefi_vars.rs -- Cross-platform UEFI variable I/O.
//
// Three back-ends:
//   - Linux:   /sys/firmware/efi/efivars/{Name}-{GUID}
//     File layout: first 4 bytes = attributes (LE u32), rest = variable data.
//     Requires root. efivarfs files are usually `chattr +i` (immutable);
//     we strip the immutable flag before writing.
//
//   - Windows: GetFirmwareEnvironmentVariableExW / SetFirmwareEnvironmentVariableExW
//     in kernel32.dll. Requires admin AND SeSystemEnvironmentPrivilege.
//
//   - Anything else: returns NotSupported on every call.
//
// All paths return the SAME error type so the install pipeline doesn't have
// to know which OS it's running on.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

// ---- Errors -----------------------------------------------------------------

#[derive(Debug)]
#[allow(dead_code)] // InvalidGuid is reserved for future GUID-parse paths
pub enum UefiVarError {
    NotSupported(String),
    PermissionDenied(String),
    NotFound(String),
    Io(std::io::Error),
    InvalidGuid(String),
    Other(String),
}

impl std::fmt::Display for UefiVarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UefiVarError::NotSupported(s)    => write!(f, "UEFI variables not supported: {}", s),
            UefiVarError::PermissionDenied(s)=> write!(f, "permission denied: {}", s),
            UefiVarError::NotFound(s)        => write!(f, "variable not found: {}", s),
            UefiVarError::Io(e)              => write!(f, "I/O error: {}", e),
            UefiVarError::InvalidGuid(s)     => write!(f, "invalid GUID: {}", s),
            UefiVarError::Other(s)           => write!(f, "{}", s),
        }
    }
}

impl From<std::io::Error> for UefiVarError {
    fn from(e: std::io::Error) -> Self { UefiVarError::Io(e) }
}

// ---- Public API -------------------------------------------------------------

/// Read a UEFI variable. Returns (attributes, data) on success.
pub fn read(name: &str, guid: &str) -> Result<(u32, Vec<u8>), UefiVarError> {
    #[cfg(target_os = "linux")]   { linux_impl::read(name, guid) }
    #[cfg(target_os = "windows")] { windows_impl::read(name, guid) }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (name, guid);
        Err(UefiVarError::NotSupported("only Linux and Windows hosts supported".into()))
    }
}

/// Write a UEFI variable. Idempotent: writing the same data twice has no
/// observable effect on the firmware side.
pub fn write(name: &str, guid: &str, attributes: u32, data: &[u8]) -> Result<(), UefiVarError> {
    #[cfg(target_os = "linux")]   { linux_impl::write(name, guid, attributes, data) }
    #[cfg(target_os = "windows")] { windows_impl::write(name, guid, attributes, data) }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (name, guid, attributes, data);
        Err(UefiVarError::NotSupported("only Linux and Windows hosts supported".into()))
    }
}

/// Delete a UEFI variable. Idempotent: removing a non-existent variable is
/// a no-op success.
pub fn delete(name: &str, guid: &str) -> Result<(), UefiVarError> {
    #[cfg(target_os = "linux")]   { linux_impl::delete(name, guid) }
    #[cfg(target_os = "windows")] { windows_impl::delete(name, guid) }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (name, guid);
        Err(UefiVarError::NotSupported("only Linux and Windows hosts supported".into()))
    }
}

/// Probe whether UEFI variable services are accessible at all. Used by the
/// install pipeline to fail early with a clear message rather than blowing
/// up halfway through.
pub fn available() -> bool {
    #[cfg(target_os = "linux")]   { linux_impl::available() }
    #[cfg(target_os = "windows")] { windows_impl::available() }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))] { false }
}

// ---- Linux backend ----------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};

    const EFIVARS_DIR: &str = "/sys/firmware/efi/efivars";

    pub fn available() -> bool {
        std::path::Path::new(EFIVARS_DIR).is_dir()
    }

    fn path_for(name: &str, guid: &str) -> PathBuf {
        // efivarfs filenames are "<Name>-<guid-lowercase>".
        let mut p = PathBuf::from(EFIVARS_DIR);
        p.push(format!("{}-{}", name, guid.to_ascii_lowercase()));
        p
    }

    pub fn read(name: &str, guid: &str) -> Result<(u32, Vec<u8>), UefiVarError> {
        let p = path_for(name, guid);
        let mut f = match fs::File::open(&p) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                return Err(UefiVarError::NotFound(format!("{:?}", p))),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied =>
                return Err(UefiVarError::PermissionDenied(
                    format!("{:?} (need root)", p))),
            Err(e) => return Err(UefiVarError::Io(e)),
        };
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        if buf.len() < 4 {
            return Err(UefiVarError::Other(format!("efivar file too short: {} bytes", buf.len())));
        }
        let attrs = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let data  = buf[4..].to_vec();
        Ok((attrs, data))
    }

    pub fn write(name: &str, guid: &str, attributes: u32, data: &[u8]) -> Result<(), UefiVarError> {
        let p = path_for(name, guid);

        // efivarfs files are usually immutable. Strip the flag if present.
        // We do this by invoking `chattr -i` -- direct ioctl(FS_IOC_SETFLAGS)
        // would also work but pulls in libc bindings.
        let _ = std::process::Command::new("chattr").args(["-i"]).arg(&p).output();

        // Build payload: 4-byte LE attribute header + data.
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(&attributes.to_le_bytes());
        payload.extend_from_slice(data);

        // efivarfs requires a single write() call equal to the full payload.
        // Using OpenOptions::create(true) creates the var if it doesn't exist;
        // truncate(true) replaces it atomically if it does.
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => UefiVarError::PermissionDenied(
                    format!("{:?} (need root)", p)),
                _ => UefiVarError::Io(e),
            })?;

        f.write_all(&payload)?;
        Ok(())
    }

    pub fn delete(name: &str, guid: &str) -> Result<(), UefiVarError> {
        let p = path_for(name, guid);
        let _ = std::process::Command::new("chattr").args(["-i"]).arg(&p).output();
        match fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied =>
                Err(UefiVarError::PermissionDenied(format!("{:?}", p))),
            Err(e) => Err(UefiVarError::Io(e)),
        }
    }
}

// ---- Windows backend --------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;

    // Raw FFI declarations. Avoids pulling the full `windows` crate.
    type BOOL  = i32;
    type DWORD = u32;
    type HANDLE = *mut c_void;
    type LPCWSTR = *const u16;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFirmwareEnvironmentVariableExW(
            lpName: LPCWSTR,
            lpGuid: LPCWSTR,
            pBuffer: *mut c_void,
            nSize: DWORD,
            pdwAttribubutes: *mut DWORD,
        ) -> DWORD;

        fn SetFirmwareEnvironmentVariableExW(
            lpName: LPCWSTR,
            lpGuid: LPCWSTR,
            pValue: *const c_void,
            nSize: DWORD,
            dwAttributes: DWORD,
        ) -> BOOL;

        fn GetLastError() -> DWORD;
        fn GetCurrentProcess() -> HANDLE;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: DWORD,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;

        fn LookupPrivilegeValueW(
            lpSystemName: LPCWSTR,
            lpName: LPCWSTR,
            lpLuid: *mut Luid,
        ) -> BOOL;

        fn AdjustTokenPrivileges(
            TokenHandle: HANDLE,
            DisableAllPrivileges: BOOL,
            NewState: *const TokenPrivileges,
            BufferLength: DWORD,
            PreviousState: *mut TokenPrivileges,
            ReturnLength: *mut DWORD,
        ) -> BOOL;

        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    // Win32 struct field names follow the Microsoft API convention; the
    // #[allow] is required because Rust enforces snake_case by default.
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    #[allow(non_snake_case)]
    struct Luid { LowPart: DWORD, HighPart: i32 }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct LuidAndAttributes { Luid: Luid, Attributes: DWORD }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct TokenPrivileges {
        PrivilegeCount: DWORD,
        Privileges:     [LuidAndAttributes; 1],
    }

    const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
    const TOKEN_QUERY:             DWORD = 0x0008;
    const SE_PRIVILEGE_ENABLED:    DWORD = 0x00000002;
    const SE_SYSTEM_ENVIRONMENT_NAME: &str = "SeSystemEnvironmentPrivilege";

    const ERROR_ENVVAR_NOT_FOUND: DWORD = 203;
    const ERROR_ACCESS_DENIED:    DWORD = 5;
    const ERROR_PRIVILEGE_NOT_HELD: DWORD = 1314;
    const ERROR_INVALID_FUNCTION: DWORD = 1;  // Returned on non-UEFI BIOS-mode systems.

    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0u16)).collect()
    }

    fn braced_guid(guid: &str) -> String {
        let trimmed = guid.trim().trim_start_matches('{').trim_end_matches('}');
        format!("{{{}}}", trimmed)
    }

    /// One-shot privilege grant. Idempotent within the process.
    fn enable_system_environment_privilege() -> Result<(), UefiVarError> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                &mut token) == 0 {
                return Err(UefiVarError::Other(
                    format!("OpenProcessToken failed: GetLastError={}", GetLastError())));
            }
            let priv_name = to_wide_nul(SE_SYSTEM_ENVIRONMENT_NAME);
            let mut luid = Luid::default();
            if LookupPrivilegeValueW(std::ptr::null(),
                                     priv_name.as_ptr(),
                                     &mut luid) == 0 {
                CloseHandle(token);
                return Err(UefiVarError::Other(
                    format!("LookupPrivilegeValueW failed: GetLastError={}", GetLastError())));
            }
            let tp = TokenPrivileges {
                PrivilegeCount: 1,
                Privileges: [LuidAndAttributes { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            let ok = AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
            let err = GetLastError();
            CloseHandle(token);
            if ok == 0 || (err != 0 && err != 0 /* placeholder for ERROR_SUCCESS=0 */) {
                if err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_ACCESS_DENIED {
                    return Err(UefiVarError::PermissionDenied(format!(
                        "AdjustTokenPrivileges denied (GetLastError={}). Run as Administrator.",
                        err)));
                }
            }
            Ok(())
        }
    }

    pub fn available() -> bool {
        // On BIOS-mode (non-UEFI) installs, GetFirmwareEnvironmentVariableExW
        // returns ERROR_INVALID_FUNCTION (1). On UEFI it returns either the
        // variable size or one of the documented error codes.
        let name = to_wide_nul("BootCurrent");
        let guid = to_wide_nul(&braced_guid(super::EFI_GLOBAL_VARIABLE_GUID_LOCAL));
        let mut attrs: DWORD = 0;
        let mut probe = [0u8; 4];
        let bytes = unsafe {
            GetFirmwareEnvironmentVariableExW(
                name.as_ptr(),
                guid.as_ptr(),
                probe.as_mut_ptr() as *mut _,
                probe.len() as DWORD,
                &mut attrs,
            )
        };
        if bytes > 0 { return true; }
        let err = unsafe { GetLastError() };
        // ENVVAR_NOT_FOUND or ACCESS_DENIED still mean UEFI services exist.
        err == ERROR_ENVVAR_NOT_FOUND
            || err == ERROR_ACCESS_DENIED
            || err == ERROR_PRIVILEGE_NOT_HELD
    }

    pub fn read(name: &str, guid: &str) -> Result<(u32, Vec<u8>), UefiVarError> {
        enable_system_environment_privilege()?;

        let wname = to_wide_nul(name);
        let wguid = to_wide_nul(&braced_guid(guid));

        // Two-step: first call sizes the buffer.
        let mut buf = vec![0u8; 4096];
        let mut attrs: DWORD = 0;
        let bytes = unsafe {
            GetFirmwareEnvironmentVariableExW(
                wname.as_ptr(),
                wguid.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                &mut attrs,
            )
        };
        if bytes == 0 {
            let err = unsafe { GetLastError() };
            return match err {
                ERROR_ENVVAR_NOT_FOUND => Err(UefiVarError::NotFound(name.to_string())),
                ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD =>
                    Err(UefiVarError::PermissionDenied(
                        format!("Run as Administrator. GetLastError={}", err))),
                ERROR_INVALID_FUNCTION =>
                    Err(UefiVarError::NotSupported("legacy BIOS boot (no UEFI variables)".into())),
                _ => Err(UefiVarError::Other(format!("GetFirmwareEnvironmentVariableEx: err={}", err))),
            };
        }
        buf.truncate(bytes as usize);
        Ok((attrs, buf))
    }

    pub fn write(name: &str, guid: &str, attributes: u32, data: &[u8]) -> Result<(), UefiVarError> {
        enable_system_environment_privilege()?;
        let wname = to_wide_nul(name);
        let wguid = to_wide_nul(&braced_guid(guid));
        let ok = unsafe {
            SetFirmwareEnvironmentVariableExW(
                wname.as_ptr(),
                wguid.as_ptr(),
                data.as_ptr() as *const _,
                data.len() as DWORD,
                attributes,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return match err {
                ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD =>
                    Err(UefiVarError::PermissionDenied(
                        format!("SetFirmwareEnvironmentVariableEx denied. err={}", err))),
                ERROR_INVALID_FUNCTION =>
                    Err(UefiVarError::NotSupported("legacy BIOS boot (no UEFI variables)".into())),
                _ => Err(UefiVarError::Other(format!("SetFirmwareEnvironmentVariableEx: err={}", err))),
            };
        }
        Ok(())
    }

    pub fn delete(name: &str, guid: &str) -> Result<(), UefiVarError> {
        // On Windows, passing a zero-length value to SetFirmwareEnvironmentVariableEx
        // is the documented way to delete a variable.
        match write(name, guid, 0, &[]) {
            Ok(()) => Ok(()),
            Err(UefiVarError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// Local symbol so the `windows_impl` module above can reference the GUID
// from `boot_entry` without a circular import.
#[cfg(target_os = "windows")]
const EFI_GLOBAL_VARIABLE_GUID_LOCAL: &str = crate::boot_entry::EFI_GLOBAL_VARIABLE_GUID;
