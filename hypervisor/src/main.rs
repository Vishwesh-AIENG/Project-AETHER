#![no_std]
#![no_main]

use core::panic::PanicInfo;

// UEFI entry point — called by UEFI firmware before any OS loads.
// AETHER takes control here and never returns to UEFI.
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    _image: *const core::ffi::c_void,
    _system_table: *const core::ffi::c_void,
) -> usize {
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
