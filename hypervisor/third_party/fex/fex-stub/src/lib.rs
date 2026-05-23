// fex-stub — no-op shims for the 5 FEX FFI symbols the hypervisor links
// when built with `--features fex_linked`.
//
// Every function matches the signature declared in
// hypervisor/src/fex_integration.rs (`extern "C"` block under
// `#[cfg(feature = "fex_linked")]`). They return FexResult codes that
// AETHER's `try_init_fex` interprets as "FEX absent — fall back to
// foundation-gate HLT payload", so the hypervisor still boots and the
// Phase 1–6 wiring all runs end-to-end against a stub.
//
// When the upstream FEX fork strip-down completes, replace this archive
// with the real one — no AETHER-side code changes are required.

#![no_std]

/// Mirrors hypervisor/src/fex_integration.rs::FexResult.
/// MUST stay in sync; this is the wire contract between AETHER and FEX.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FexResult {
    Ok               = 0,
    NotInitialised   = 1,
    BadElf           = 2,
    TranslationFailed= 3,
    DispatcherFault  = 4,
    OutOfCache       = 5,
}

// Opaque pointers FEX would write into; we ignore everything.
type FexHostBindingsPtr = *mut core::ffi::c_void;
type FexJitCachePtr     = *mut core::ffi::c_void;
type FexThreadHandle    = *mut core::ffi::c_void;

/// `fex_init(bindings, jit) -> FexResult`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fex_init(
    _bindings: FexHostBindingsPtr,
    _jit:      FexJitCachePtr,
) -> FexResult {
    FexResult::NotInitialised
}

/// `fex_load_arm64_elf(image_base, image_size) -> FexResult`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fex_load_arm64_elf(
    _image_base: *const u8,
    _image_size: usize,
) -> FexResult {
    FexResult::NotInitialised
}

/// `fex_translate_block(pc, out_host_pa, out_len) -> FexResult`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fex_translate_block(
    _pc:          u64,
    _out_host_pa: *mut u64,
    _out_len:     *mut u32,
) -> FexResult {
    FexResult::NotInitialised
}

/// `fex_dispatch_block(thread, host_pa) -> FexResult`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fex_dispatch_block(
    _thread:  FexThreadHandle,
    _host_pa: u64,
) -> FexResult {
    FexResult::NotInitialised
}

/// `fex_shutdown() -> FexResult`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fex_shutdown() -> FexResult {
    FexResult::Ok
}

// Panic handler — `no_std` requires one. Halt.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
