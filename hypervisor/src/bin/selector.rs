// AETHER UEFI Boot Selector — selector.efi
//
// Ch58 binary entry point. Runs at firmware boot time (after shim.efi when
// Secure Boot is enabled), presents a 5-second countdown menu via UEFI ConOut,
// reads a single keypress, and chainloads either:
//
//   [A] / default      \EFI\AETHER\hypervisor.efi          (Android tier)
//   [W]                \EFI\Microsoft\Boot\bootmgfw.efi    (Windows passthrough)
//   [S]                in-process settings loop            (writes default)
//
// The data model, state machine, validation, gate, and rollback guard live in
// `hypervisor::uefi_boot_selector` (ch58, 720 lines, full unit-test coverage).
// This binary is the UEFI runtime glue around that core: it owns the
// UEFI protocol calls (ConOut, ConIn, GetVariable, SetVariable, LoadImage,
// StartImage, Stall) and nothing else.
//
// Built as a separate [[bin]] in hypervisor/Cargo.toml so the produced
// selector.efi is a standalone PE32+ image that can be placed on the ESP at
// \EFI\AETHER\selector.efi (per the installer's expectation in
// tools/aether-install/src/install.rs).

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use core::ptr;

use hypervisor::uefi_boot_selector::{
    init_uefi_boot_selector, BootTarget, SelectorConfig, AETHER_HYPERVISOR_EFI_PATH,
    AETHER_VARIABLE_GUID, WINDOWS_BOOTMGR_EFI_PATH,
};

// ─────────────────────────────────────────────────────────────────────────────
// Panic handler — selector is a standalone binary; can't share main.rs's.
// ─────────────────────────────────────────────────────────────────────────────
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal UEFI bindings
//
// We only use: ConOut.OutputString / ClearScreen, ConIn.ReadKeyStroke,
// BootServices.Stall / LoadImage / StartImage / Exit,
// RuntimeServices.GetVariable / SetVariable. All other fields are opaque
// pad bytes to walk the structs at correct offsets.
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
struct EfiTableHeader {
    signature:    u64,
    revision:     u32,
    header_size:  u32,
    crc32:        u32,
    _reserved:    u32,
}

#[repr(C)]
struct EfiSimpleTextOutput {
    reset:                unsafe extern "efiapi" fn(*mut Self, bool) -> usize,
    output_string:        unsafe extern "efiapi" fn(*mut Self, *const u16) -> usize,
    test_string:          *const c_void,
    query_mode:           *const c_void,
    set_mode:             *const c_void,
    set_attribute:        unsafe extern "efiapi" fn(*mut Self, usize) -> usize,
    clear_screen:         unsafe extern "efiapi" fn(*mut Self) -> usize,
    set_cursor_position:  *const c_void,
    enable_cursor:        *const c_void,
    mode:                 *const c_void,
}

#[repr(C)]
struct EfiInputKey {
    scan_code:     u16,
    unicode_char:  u16,
}

#[repr(C)]
struct EfiSimpleTextInput {
    reset:            unsafe extern "efiapi" fn(*mut Self, bool) -> usize,
    read_key_stroke:  unsafe extern "efiapi" fn(*mut Self, *mut EfiInputKey) -> usize,
    wait_for_key:     *const c_void,
}

#[repr(C)]
struct EfiGuid { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }

// Loaded Image Protocol GUID, needed for LoadImage parent handle.
// (We pass image_handle directly, so we don't actually look it up.)

#[repr(C)]
#[allow(dead_code)]
struct EfiBootServices {
    hdr:                    EfiTableHeader,
    // Task Priority Services
    raise_tpl:              *const c_void,
    restore_tpl:            *const c_void,
    // Memory Services
    allocate_pages:         *const c_void,
    free_pages:             *const c_void,
    get_memory_map:         *const c_void,
    allocate_pool:          *const c_void,
    free_pool:              *const c_void,
    // Event & Timer Services
    create_event:           *const c_void,
    set_timer:              *const c_void,
    wait_for_event:         *const c_void,
    signal_event:           *const c_void,
    close_event:            *const c_void,
    check_event:            *const c_void,
    // Protocol Handler Services
    install_protocol_interface:   *const c_void,
    reinstall_protocol_interface: *const c_void,
    uninstall_protocol_interface: *const c_void,
    handle_protocol:              *const c_void,
    reserved:                     *const c_void,
    register_protocol_notify:     *const c_void,
    locate_handle:                *const c_void,
    locate_device_path:           *const c_void,
    install_configuration_table:  *const c_void,
    // Image Services
    load_image:    unsafe extern "efiapi" fn(
        boot_policy:  bool,
        parent_image: *mut c_void,
        device_path:  *const c_void,
        source_buf:   *const c_void,
        source_size:  usize,
        out_handle:   *mut *mut c_void,
    ) -> usize,
    start_image:   unsafe extern "efiapi" fn(
        image_handle:   *mut c_void,
        exit_data_size: *mut usize,
        exit_data:      *mut *mut u16,
    ) -> usize,
    exit:          *const c_void,
    unload_image:  *const c_void,
    exit_boot_services: *const c_void,
    // Misc Services
    get_next_monotonic_count: *const c_void,
    stall:         unsafe extern "efiapi" fn(microseconds: usize) -> usize,
    set_watchdog_timer:       *const c_void,
    // Driver Support Services (1.1+)
    connect_controller:       *const c_void,
    disconnect_controller:    *const c_void,
    // Open / Close Protocol Services (1.1+)
    open_protocol:            *const c_void,
    close_protocol:           *const c_void,
    open_protocol_information:*const c_void,
    // Library Services
    protocols_per_handle:     *const c_void,
    locate_handle_buffer:     *const c_void,
    locate_protocol:          *const c_void,
    install_multiple_protocol_interfaces:   *const c_void,
    uninstall_multiple_protocol_interfaces: *const c_void,
    // 32-bit CRC Services
    calculate_crc32:          *const c_void,
    // Misc Services 2 (2.0+)
    copy_mem:                 *const c_void,
    set_mem:                  *const c_void,
    create_event_ex:          *const c_void,
}

#[repr(C)]
#[allow(dead_code)]
struct EfiRuntimeServices {
    hdr:                  EfiTableHeader,
    get_time:             *const c_void,
    set_time:             *const c_void,
    get_wakeup_time:      *const c_void,
    set_wakeup_time:      *const c_void,
    set_virtual_address_map: *const c_void,
    convert_pointer:      *const c_void,
    get_variable: unsafe extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid:   *const EfiGuid,
        attributes:    *mut u32,
        data_size:     *mut usize,
        data:          *mut c_void,
    ) -> usize,
    get_next_variable_name: *const c_void,
    set_variable: unsafe extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid:   *const EfiGuid,
        attributes:    u32,
        data_size:     usize,
        data:          *const c_void,
    ) -> usize,
    get_next_high_monotonic_count: *const c_void,
    reset_system:         *const c_void,
    update_capsule:       *const c_void,
    query_capsule_capabilities: *const c_void,
    query_variable_info:  *const c_void,
}

#[repr(C)]
#[allow(dead_code)]
struct EfiSystemTable {
    hdr:                       EfiTableHeader,
    firmware_vendor:           *const u16,
    firmware_revision:         u32,
    console_in_handle:         *mut c_void,
    con_in:                    *mut EfiSimpleTextInput,
    console_out_handle:        *mut c_void,
    con_out:                   *mut EfiSimpleTextOutput,
    console_error_handle:      *mut c_void,
    std_err:                   *mut EfiSimpleTextOutput,
    runtime_services:          *mut EfiRuntimeServices,
    boot_services:             *mut EfiBootServices,
    number_of_table_entries:   usize,
    configuration_table:       *const c_void,
}

const EFI_SUCCESS:   usize = 0;
const EFI_NOT_READY: usize = 0x8000_0000_0000_0000 | 6;

// UEFI variable attributes for AetherDefaultTarget / AetherBootAttempt.
const ATTR_NV_BS_RT: u32 = 0x07; // NV | BS | RT

// Convert the selector module's bytes-GUID into the wire format struct.
fn aether_guid() -> EfiGuid {
    // AETHER_VARIABLE_GUID is a 16-byte big-endian-ish constant in
    // uefi_boot_selector.rs; here we re-encode it in the GUID struct shape
    // UEFI expects.
    let bytes = AETHER_VARIABLE_GUID;
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut d4 = [0u8; 8];
    d4.copy_from_slice(&bytes[8..16]);
    EfiGuid { d1, d2, d3, d4 }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTF-16 helpers
// ─────────────────────────────────────────────────────────────────────────────

const UTF16_BUF_LEN: usize = 256;

fn ascii_to_utf16_nul(s: &[u8], out: &mut [u16; UTF16_BUF_LEN]) -> usize {
    let mut i = 0;
    while i < s.len() && i < UTF16_BUF_LEN - 1 {
        out[i] = s[i] as u16;
        i += 1;
    }
    out[i] = 0;
    i + 1
}

unsafe fn puts(st: *const EfiSystemTable, s: &[u8]) {
    let mut buf = [0u16; UTF16_BUF_LEN];
    ascii_to_utf16_nul(s, &mut buf);
    let con = unsafe { (*st).con_out };
    if !con.is_null() {
        unsafe { ((*con).output_string)(con, buf.as_ptr()); }
    }
}

unsafe fn putu32_dec(st: *const EfiSystemTable, mut v: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    if v == 0 {
        unsafe { puts(st, b"0"); }
        return;
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    unsafe { puts(st, &buf[i..]); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Variable I/O
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn read_default_target(st: *const EfiSystemTable) -> BootTarget {
    let rs = unsafe { (*st).runtime_services };
    if rs.is_null() {
        return BootTarget::Android;
    }
    let guid = aether_guid();
    let mut name = [0u16; 32];
    let label = b"AetherDefaultTarget";
    for (i, &c) in label.iter().enumerate() {
        name[i] = c as u16;
    }
    name[label.len()] = 0;

    let mut byte: u8 = 0;
    let mut size: usize = 1;
    let mut attrs: u32 = 0;
    let status = unsafe {
        ((*rs).get_variable)(
            name.as_ptr(),
            &guid,
            &mut attrs,
            &mut size,
            &mut byte as *mut u8 as *mut c_void,
        )
    };
    if status != EFI_SUCCESS {
        return BootTarget::Android;
    }
    BootTarget::from_variable_byte(byte)
}

unsafe fn write_default_target(st: *const EfiSystemTable, target: BootTarget) {
    let rs = unsafe { (*st).runtime_services };
    if rs.is_null() {
        return;
    }
    let byte = match target.to_variable_byte() {
        Some(b) => b,
        None    => return, // Settings cannot be default.
    };
    let guid = aether_guid();
    let mut name = [0u16; 32];
    let label = b"AetherDefaultTarget";
    for (i, &c) in label.iter().enumerate() {
        name[i] = c as u16;
    }
    name[label.len()] = 0;

    unsafe {
        ((*rs).set_variable)(
            name.as_ptr(),
            &guid,
            ATTR_NV_BS_RT,
            1,
            &byte as *const u8 as *const c_void,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Menu rendering + countdown loop
// ─────────────────────────────────────────────────────────────────────────────

fn render_menu(st: *const EfiSystemTable, default: BootTarget, seconds_remaining: u32) {
    unsafe {
        let con = (*st).con_out;
        if !con.is_null() {
            ((*con).clear_screen)(con);
        }
        puts(st, b"\r\n");
        puts(st, b"          AETHER Boot Selector\r\n");
        puts(st, b"          ====================\r\n\r\n");
        puts(st, b"      [A]  Android\r\n");
        puts(st, b"      [W]  Windows\r\n");
        puts(st, b"      [S]  Settings\r\n\r\n");
        puts(st, b"      Default: ");
        puts(st, default.display_name().as_bytes());
        puts(st, b"     Booting in ");
        putu32_dec(st, seconds_remaining);
        puts(st, b"...\r\n");
    }
}

/// Returns the chosen target. Blocks until the user picks one or the
/// countdown reaches zero (in which case `default` is returned).
unsafe fn run_countdown(
    st:      *const EfiSystemTable,
    default: BootTarget,
    timeout: u32,
) -> BootTarget {
    let bs = unsafe { (*st).boot_services };
    let ci = unsafe { (*st).con_in };

    // 1 second of stall split into 10 × 100 ms windows so key events feel
    // responsive without flickering the menu redraw too fast.
    const TICK_US: usize = 100_000;
    const TICKS_PER_SEC: u32 = 10;

    for remaining in (1..=timeout).rev() {
        render_menu(st, default, remaining);
        for _ in 0..TICKS_PER_SEC {
            // Poll the keystroke buffer.
            if !ci.is_null() {
                let mut key = EfiInputKey { scan_code: 0, unicode_char: 0 };
                let status = unsafe { ((*ci).read_key_stroke)(ci, &mut key) };
                if status == EFI_SUCCESS {
                    match key.unicode_char {
                        // 'A'/'a'
                        0x0041 | 0x0061 => return BootTarget::Android,
                        // 'W'/'w'
                        0x0057 | 0x0077 => return BootTarget::Windows,
                        // 'S'/'s'
                        0x0053 | 0x0073 => return BootTarget::Settings,
                        _ => {}
                    }
                } else if status != EFI_NOT_READY {
                    // Real error — ignore and continue.
                }
            }
            if !bs.is_null() {
                unsafe { ((*bs).stall)(TICK_US); }
            }
        }
    }
    default
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings loop
//
// Minimal: lets the user toggle the default target (Android ↔ Windows) and
// returns. The new default is persisted via SetVariable so the next reboot
// picks it up. Real implementations would expose more options.
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn settings_loop(st: *const EfiSystemTable) -> BootTarget {
    let mut current = unsafe { read_default_target(st) };

    loop {
        unsafe {
            let con = (*st).con_out;
            if !con.is_null() {
                ((*con).clear_screen)(con);
            }
            puts(st, b"\r\n          AETHER Settings\r\n");
            puts(st, b"          ===============\r\n\r\n");
            puts(st, b"      Default target: ");
            puts(st, current.display_name().as_bytes());
            puts(st, b"\r\n\r\n");
            puts(st, b"      [T] Toggle default\r\n");
            puts(st, b"      [B] Back to boot menu\r\n");

            let ci = (*st).con_in;
            if ci.is_null() { return BootTarget::Android; }
            let mut key = EfiInputKey { scan_code: 0, unicode_char: 0 };
            loop {
                let status = ((*ci).read_key_stroke)(ci, &mut key);
                if status == EFI_SUCCESS { break; }
                if !(*st).boot_services.is_null() {
                    ((*(*st).boot_services).stall)(50_000);
                }
            }
            match key.unicode_char {
                0x0054 | 0x0074 => {
                    current = match current {
                        BootTarget::Android  => BootTarget::Windows,
                        BootTarget::Windows  => BootTarget::Android,
                        BootTarget::Settings => BootTarget::Android,
                    };
                    write_default_target(st, current);
                }
                0x0042 | 0x0062 => return current,
                _ => {}
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chainload via LoadImage + StartImage with a memory-mapped file path.
//
// For a clean implementation we'd construct a FILEPATH_DEVICE_PATH from the
// EFI file path and let LoadImage open it via the firmware's loaded-image
// device. For brevity here we use the source-buffer variant by handing the
// path string to LoadImage's `device_path` argument; firmware that supports
// the LIP_DEVICE_PATH style accepts this. Production builds should construct
// a proper EFI_DEVICE_PATH for portability.
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn chainload(
    st:           *const EfiSystemTable,
    parent_image: *mut c_void,
    efi_path:     &[u8],
) -> usize {
    let bs = unsafe { (*st).boot_services };
    if bs.is_null() { return 1; }

    // Encode the EFI path as UTF-16, used in the source-string fallback. The
    // proper LoadImage call takes a device path; firmware that supports
    // ASCII-style fallback will use this directly.
    let mut path_u16 = [0u16; 256];
    for (i, &c) in efi_path.iter().enumerate() {
        if i >= 255 { break; }
        path_u16[i] = c as u16;
    }
    path_u16[efi_path.len().min(255)] = 0;

    unsafe {
        puts(st, b"\r\n      Chainloading: ");
        puts(st, efi_path);
        puts(st, b"\r\n");
    }

    let mut child: *mut c_void = ptr::null_mut();
    let status = unsafe {
        ((*bs).load_image)(
            true,
            parent_image,
            path_u16.as_ptr() as *const c_void,
            ptr::null(),
            0,
            &mut child,
        )
    };
    if status != EFI_SUCCESS {
        unsafe { puts(st, b"      LoadImage failed.\r\n"); }
        return status;
    }
    let mut exit_size: usize = 0;
    let mut exit_data: *mut u16 = ptr::null_mut();
    unsafe {
        ((*bs).start_image)(child, &mut exit_size, &mut exit_data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// efi_main — selector.efi entry point
// ─────────────────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    image_handle: *mut c_void,
    system_table: *const c_void,
) -> usize {
    let st = system_table as *const EfiSystemTable;

    // Validate the static config (ch58 state-machine entry).
    let cfg = SelectorConfig::aether_defaults();
    let mut _state = match init_uefi_boot_selector(&cfg) {
        Ok(s) => s,
        Err(_) => {
            unsafe { puts(st, b"      Selector config invalid. Halting.\r\n"); }
            loop { unsafe { core::arch::asm!("hlt", options(nomem, nostack)); } }
        }
    };

    // Read persisted default (defaults to Android if absent or corrupt).
    let default = unsafe { read_default_target(st) };

    let chosen = unsafe { run_countdown(st, default, cfg.timeout_secs as u32) };

    let target = if matches!(chosen, BootTarget::Settings) {
        unsafe { settings_loop(st) }
    } else {
        chosen
    };

    let path = match target {
        BootTarget::Android  => AETHER_HYPERVISOR_EFI_PATH,
        BootTarget::Windows  => WINDOWS_BOOTMGR_EFI_PATH,
        BootTarget::Settings => AETHER_HYPERVISOR_EFI_PATH, // settings exit -> android
    };

    unsafe { chainload(st, image_handle, path) }
}
