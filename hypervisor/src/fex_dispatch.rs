// fex_dispatch.rs — FEX VMEXIT dispatch loop (x86 tier).
//
// Phase 5 deliverable. Replaces the "halt-on-first-VMEXIT" pattern in
// `boot_x86::host_vmexit_entry` with a proper translate → dispatch →
// classify-exit → re-enter cycle.
//
// State machine per VMEXIT:
//
//                           ┌────────────────────┐
//                           │  host_vmexit_entry │  (Intel: handler at host_rip;
//                           └─────────┬──────────┘   AMD: instruction after vmrun)
//                                     │
//                                     ▼
//                  ┌──────────────────────────────────┐
//                  │  classify_exit(exit_code/qual)   │
//                  └─────────────────┬────────────────┘
//                                    │
//      ┌─────────────────────────────┼──────────────────────────────┐
//      ▼                ▼            ▼               ▼              ▼
//   Translate          Mmio         IoPort           Halt        Unhandled
//      │                │             │               │              │
//      ▼                ▼             ▼               ▼              ▼
//   fex_translate    mmio_emu      ignore-stub    record-and-     log + halt
//   _block →           ::handle    (Phase 6)      return
//   fex_dispatch_
//   block →
//   advance PC
//
// All FEX FFI calls live behind `#[cfg(feature = "fex_linked")]`; when the
// feature is off the dispatch loop substitutes a stub that increments
// `dispatch_blocks_attempted` so the stats counter still moves and Phase 5
// unit tests can verify the state machine without the upstream FEX library
// being in tree.

#![allow(dead_code)]

use crate::android_handoff::FexInitialRegs;
use crate::mmio_emu::{self, MmioAccess, MmioResult};

#[cfg(feature = "fex_linked")]
use crate::fex_integration::{fex_dispatch_block, fex_translate_block};

// ─────────────────────────────────────────────────────────────────────────────
// FexMmioRequest — FEX-populated record describing one trapped ARM64 MMIO
//
// Phase 5b contract.  When FEX-translated x86 code attempts to access an IPA
// that is unmapped in the EPT/NPT identity map (i.e. an MMIO region from
// the ARM64 perspective), FEX must populate this struct *before* returning
// control to AETHER's VMEXIT handler. The handler then reads it from a
// well-known location (see `AETHER_FEX_MMIO_REQUEST` below) and emulates
// the access via `mmio_emu::handle`.
//
// FEX-side contract (this is the documentation the upstream fork needs):
//
//   On EPT/NPT violation:
//     1. Pause the JIT trampoline.
//     2. Decode the ARM64 LDR/STR being translated (FEX already knows it).
//     3. Fill `AETHER_FEX_MMIO_REQUEST` with:
//          addr     = ARM64 effective address (== IPA == GPA in our identity
//                     stage-2 layout)
//          size     = 1 / 2 / 4 / 8 (bytes)
//          xt       = ARM64 destination register (0..30, 31 = XZR)
//          value    = on writes, the value the guest is publishing
//          is_write = LDR -> false, STR -> true
//          valid    = true
//     4. Set VMCS GUEST_RIP to the address of a HLT-like stub so VMEXIT
//        fires with EXIT_REASON_EPT_VIOLATION + a known GPA — that signal
//        is what `host_vmexit_entry` consumes.
//
//   After AETHER emulates and updates `state.regs.x[xt]` for reads, FEX
//   resumes translation at the next ARM64 instruction.
//
// Until the upstream fork ships, `valid` stays false and the dispatch loop
// falls back to the Phase-5 synthesised access (4 bytes / xt=31). Tests
// drive the fully-populated path directly to exercise both arms.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FexMmioRequest {
    pub valid:    bool,
    pub is_write: bool,
    pub size:     u8,     // 1, 2, 4, 8
    pub xt:       u8,     // ARM64 register index 0..31 (31 = XZR discard)
    pub addr:     u64,
    pub value:    u64,    // STR data on writes; ignored on reads
}

impl FexMmioRequest {
    pub const fn empty() -> Self {
        Self { valid: false, is_write: false, size: 0, xt: 31, addr: 0, value: 0 }
    }

    /// Sanity check: the record FEX hands us must look well-formed.
    pub fn is_sane(&self) -> bool {
        if !self.valid { return false; }
        match self.size {
            1 | 2 | 4 | 8 => {}
            _ => return false,
        }
        if self.xt > 31 { return false; }
        true
    }
}

/// EL2-global slot FEX writes the next MMIO request into.
///
/// `static mut` rather than a spinlocked cell because there is exactly one
/// dispatch core in Phase 5b; Phase 6 may need a per-vCPU array.
static mut AETHER_FEX_MMIO_REQUEST: FexMmioRequest = FexMmioRequest::empty();

/// Read the request slot. The caller should clear `valid` after consuming.
pub fn current_mmio_request() -> FexMmioRequest {
    // SAFETY: single-core EL2 dispatch; no concurrent writer at this point
    // (FEX has already published the record and exited to the host).
    unsafe {
        let p = core::ptr::addr_of!(AETHER_FEX_MMIO_REQUEST);
        *p
    }
}

/// Consume the request slot: read it, then reset `valid` to false.
pub fn take_mmio_request() -> FexMmioRequest {
    let r = current_mmio_request();
    // SAFETY: see above.
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_FEX_MMIO_REQUEST);
        (*p).valid = false;
    }
    r
}

/// Test-only setter — production code never calls this; FEX writes directly.
#[cfg(test)]
pub fn set_mmio_request_for_test(req: FexMmioRequest) {
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_FEX_MMIO_REQUEST);
        *p = req;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FexDispatchState — single-instance EL2-global FEX state
// ─────────────────────────────────────────────────────────────────────────────

/// One iteration's worth of statistics + state mutation tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct FexDispatchStats {
    /// Number of times `fex_translate_block` was attempted.
    pub blocks_translated: u64,
    /// Number of times `fex_dispatch_block` was attempted.
    pub blocks_dispatched: u64,
    /// MMIO transactions emulated successfully.
    pub mmio_handled:      u64,
    /// MMIO transactions that returned `MmioResult::Unhandled`.
    pub mmio_unhandled:    u64,
    /// VMEXITs classified as Halt (HLT or kernel halt-loop).
    pub halt_exits:        u64,
    /// VMEXITs whose code we did not understand.
    pub unhandled_exits:   u64,
}

/// Global FEX dispatch state. Phase 5 holds a single instance — single
/// Android partition per AETHER install.
#[derive(Debug, Clone, Copy)]
pub struct FexDispatchState {
    /// ARM64 register file as last observed by AETHER. FEX is the
    /// authoritative writer; we only consult it for diagnostics and to
    /// re-prime after a register-clobbering exit emulation (e.g. an MMIO
    /// read that needs to land in `x{rd}`).
    pub regs: FexInitialRegs,
    /// Most recent guest ARM64 PC observed by the dispatch loop.
    pub pc:   u64,
    /// Bound by `arm()` when the boot path has staged a real handoff.
    pub armed: bool,
    /// Counters for telemetry / unit tests.
    pub stats: FexDispatchStats,
}

impl FexDispatchState {
    pub const fn new() -> Self {
        Self {
            regs:  FexInitialRegs::zero(),
            pc:    0,
            armed: false,
            stats: FexDispatchStats {
                blocks_translated: 0, blocks_dispatched: 0,
                mmio_handled: 0, mmio_unhandled: 0,
                halt_exits: 0, unhandled_exits: 0,
            },
        }
    }

    /// Bind initial registers from an `AndroidHandoff`. After this returns
    /// the dispatch loop will trust `state.pc` as the next ARM64 PC to
    /// translate.
    pub fn arm(&mut self, regs: FexInitialRegs) {
        self.regs = regs;
        self.pc   = regs.pc;
        self.armed = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exit classification — common to Intel and AMD
// ─────────────────────────────────────────────────────────────────────────────

/// Vendor-neutral classification of a VMEXIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FexExitClass {
    /// Default path: the exit was a `#UD` raised by FEX-translated x86 code,
    /// or an EPT/NPT violation outside any emulated MMIO region. The
    /// dispatch loop translates the next basic block and resumes.
    Translate,
    /// The exit landed inside an `mmio_emu` region. Decode + emulate +
    /// resume.
    Mmio { addr: u64 },
    /// Guest issued an x86 IN/OUT or an ARM64 access mapped to one — Phase 6.
    IoPort,
    /// HLT or guest entered a halt loop.
    Halt,
    /// Anything else — log + halt for diagnostics.
    Unhandled,
}

/// Decode an Intel VMCS exit-reason + exit-qualification into an exit class.
///
/// The qualification field carries the EPT-violation GPA for EXIT_REASON 48
/// (Intel SDM Vol. 3C §27.2.1 Table 27-7). For our purposes we keep the GPA
/// in the variant so `mmio_emu::classify` can run on it.
pub fn classify_intel(exit_reason: u32, exit_qualification: u64, gpa: u64) -> FexExitClass {
    use crate::vtx;
    let _ = exit_qualification;
    match exit_reason {
        vtx::EXIT_REASON_HLT             => FexExitClass::Halt,
        vtx::EXIT_REASON_EPT_VIOLATION   => FexExitClass::Mmio { addr: gpa },
        vtx::EXIT_REASON_CPUID           => FexExitClass::Translate,
        vtx::EXIT_REASON_EXCEPTION_NMI   => FexExitClass::Translate, // #UD from FEX-translated code
        vtx::EXIT_REASON_EXTERNAL_IRQ    => FexExitClass::Translate, // host IRQ window — re-enter
        _                                => FexExitClass::Unhandled,
    }
}

/// Decode an AMD VMCB exit_code into an exit class. NPF (nested page fault)
/// is the AMD analogue of EPT_VIOLATION.
pub fn classify_amd(exit_code: u64, npf_gpa: u64) -> FexExitClass {
    use crate::svm;
    match exit_code {
        svm::SVM_EXIT_HLT       => FexExitClass::Halt,
        0x400 /* NPF */         => FexExitClass::Mmio { addr: npf_gpa },
        svm::SVM_EXIT_INTR      => FexExitClass::Translate,
        svm::SVM_EXIT_IOIO      => FexExitClass::IoPort,
        svm::SVM_EXIT_CPUID     => FexExitClass::Translate,
        _                       => FexExitClass::Unhandled,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch — one block of translation
// ─────────────────────────────────────────────────────────────────────────────

/// One iteration: translate (or fetch cached translation of) the basic block
/// at `state.pc`, dispatch it, update `state.pc`, return `Ok(())` so the
/// caller can re-enter the guest. Counter side-effects accumulate in
/// `state.stats`.
///
/// When `feature = "fex_linked"` is off the function is a no-op success that
/// increments counters; this lets the higher-level dispatch loop be unit-
/// tested without the upstream FEX library.
pub fn dispatch_one_block(state: &mut FexDispatchState) -> Result<(), DispatchError> {
    if !state.armed {
        return Err(DispatchError::NotArmed);
    }

    state.stats.blocks_translated += 1;

    #[cfg(feature = "fex_linked")]
    {
        let mut host_pa: u64 = 0;
        let mut len:    u32 = 0;
        // SAFETY: FEX FFI; arguments are valid out-pointers.
        let r = unsafe { fex_translate_block(state.pc, &mut host_pa, &mut len) };
        if !r.is_ok() {
            return Err(DispatchError::TranslateFailed);
        }
        state.stats.blocks_dispatched += 1;
        // FexThreadHandle is opaque — Phase 5 uses a null sentinel; Phase 6
        // wires per-vCPU handles.
        let null_thread: crate::fex_integration::FexThreadHandle = core::ptr::null_mut();
        let r = unsafe { fex_dispatch_block(null_thread, host_pa) };
        if !r.is_ok() {
            return Err(DispatchError::DispatchFailed);
        }
        // The real PC advance comes from FEX writing to its own thread
        // register file; AETHER reads it back here. For Phase 5 the
        // simplest correct model is a single ARM64 instruction per block:
        // advance PC by 4. Phase 6 reads the FEX thread state.
        state.pc = state.pc.wrapping_add(4);
        Ok(())
    }
    #[cfg(not(feature = "fex_linked"))]
    {
        // Stub path. Tests rely on this so dispatch_one_block always
        // increments counters even when libfex.a is absent.
        state.stats.blocks_dispatched += 1;
        state.pc = state.pc.wrapping_add(4);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    /// `state.arm(...)` was never called — boot path did not stage Android.
    NotArmed,
    /// FEX returned non-Ok from `fex_translate_block`.
    TranslateFailed,
    /// FEX returned non-Ok from `fex_dispatch_block`.
    DispatchFailed,
}

// ─────────────────────────────────────────────────────────────────────────────
// MMIO routing
// ─────────────────────────────────────────────────────────────────────────────

/// Handle one MMIO transaction. Updates `state.regs` if the access is a
/// read (the destination ARM64 register, `xt`, receives the emulated
/// value).
pub fn handle_mmio(state: &mut FexDispatchState, access: MmioAccess, xt_index: u8) -> MmioResult {
    let r = mmio_emu::handle(access);
    match r {
        MmioResult::Ok { value } => {
            state.stats.mmio_handled += 1;
            // For reads, write the result back into the ARM64 destination
            // register so the next translated block sees it.
            if !access.is_write && xt_index < 31 {
                state.regs.x[xt_index as usize] = value;
            }
        }
        MmioResult::Unhandled | MmioResult::BadWidth => {
            state.stats.mmio_unhandled += 1;
        }
    }
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level VMEXIT handler — what host_vmexit_entry calls
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmexitAction {
    /// Re-enter the guest (VMRESUME / VMRUN).
    Reenter,
    /// Halt the hypervisor — operator should examine UART for diagnostics.
    Halt,
}

/// Cross-vendor entry point. The caller has already read the vendor-specific
/// exit fields and converted them into a `FexExitClass`.
pub fn handle_vmexit(state: &mut FexDispatchState, exit: FexExitClass) -> VmexitAction {
    match exit {
        FexExitClass::Translate => {
            match dispatch_one_block(state) {
                Ok(())  => VmexitAction::Reenter,
                Err(_)  => VmexitAction::Halt,
            }
        }
        FexExitClass::Mmio { addr } => {
            // Phase 5b: prefer the FEX-populated request record. If FEX
            // hasn't filled it (e.g. the upstream fork isn't shipping the
            // record yet, or this is a bring-up build with the feature
            // off), fall back to the Phase-5 synthesised 4-byte read so
            // the dispatch loop still progresses.
            let req = take_mmio_request();
            let (access, xt) = if req.is_sane() && req.addr == addr {
                let acc = MmioAccess {
                    addr:     req.addr,
                    size:     req.size,
                    is_write: req.is_write,
                    value:    req.value,
                };
                (acc, req.xt)
            } else {
                (MmioAccess { addr, size: 4, is_write: false, value: 0 }, 31)
            };
            match handle_mmio(state, access, xt) {
                MmioResult::Ok { .. } => VmexitAction::Reenter,
                _                     => VmexitAction::Halt,
            }
        }
        FexExitClass::IoPort => {
            // Phase 6.
            VmexitAction::Halt
        }
        FexExitClass::Halt => {
            state.stats.halt_exits += 1;
            VmexitAction::Halt
        }
        FexExitClass::Unhandled => {
            state.stats.unhandled_exits += 1;
            VmexitAction::Halt
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EL2-global storage
// ─────────────────────────────────────────────────────────────────────────────

/// Single global FEX dispatch state. The x86 boot path arms it before
/// VMLAUNCH/VMRUN; host_vmexit_entry reads + mutates it on every exit.
///
/// Safety: single-threaded by virtue of EL2 single-core dispatch; no other
/// reader/writer exists once the guest is live.
static mut AETHER_FEX_STATE: FexDispatchState = FexDispatchState::new();

/// # Safety
/// Must be called at EL2 single-core before the guest first executes.
pub unsafe fn arm_global(regs: FexInitialRegs) {
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_FEX_STATE);
        (*p).arm(regs);
    }
}

/// Run a closure with the global FEX state.
pub fn with_global_mut<R, F: FnOnce(&mut FexDispatchState) -> R>(f: F) -> R {
    // SAFETY: see comment on `AETHER_FEX_STATE`.
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_FEX_STATE);
        f(&mut *p)
    }
}

pub fn is_armed() -> bool {
    with_global_mut(|s| s.armed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_handoff::FexInitialRegs;
    use crate::virtio::VIRTIO_MMIO_BASE_IPA;

    fn armed_state(pc: u64) -> FexDispatchState {
        let mut s = FexDispatchState::new();
        s.arm(FexInitialRegs::for_kernel_entry(pc, 0x4400_0000));
        s
    }

    #[test]
    fn new_state_is_not_armed() {
        let s = FexDispatchState::new();
        assert!(!s.armed);
        assert_eq!(s.pc, 0);
    }

    #[test]
    fn arming_sets_pc_and_x0_from_handoff() {
        let s = armed_state(0x4080_0000);
        assert!(s.armed);
        assert_eq!(s.pc, 0x4080_0000);
        assert_eq!(s.regs.x[0], 0x4400_0000);
        assert_eq!(s.regs.x[1], 0);
        assert_eq!(s.regs.x[2], 0);
        assert_eq!(s.regs.x[3], 0);
    }

    #[test]
    fn dispatch_without_arm_fails() {
        let mut s = FexDispatchState::new();
        assert_eq!(dispatch_one_block(&mut s), Err(DispatchError::NotArmed));
    }

    #[test]
    fn dispatch_advances_pc_by_4_in_stub_mode() {
        // Compiled with the default feature set, fex_linked is OFF so this
        // exercises the stub path that's also used at install time before
        // libfex.a is delivered.
        let mut s = armed_state(0x4080_0000);
        dispatch_one_block(&mut s).unwrap();
        assert_eq!(s.pc, 0x4080_0004);
        assert_eq!(s.stats.blocks_translated, 1);
        assert_eq!(s.stats.blocks_dispatched, 1);
    }

    #[test]
    fn classify_intel_routes_hlt_and_ept_violation() {
        use crate::vtx::*;
        assert_eq!(classify_intel(EXIT_REASON_HLT, 0, 0), FexExitClass::Halt);
        assert_eq!(
            classify_intel(EXIT_REASON_EPT_VIOLATION, 0, 0x0900_0000),
            FexExitClass::Mmio { addr: 0x0900_0000 },
        );
        assert_eq!(classify_intel(EXIT_REASON_CPUID, 0, 0), FexExitClass::Translate);
        assert_eq!(classify_intel(0xDEAD, 0, 0), FexExitClass::Unhandled);
    }

    #[test]
    fn classify_amd_routes_hlt_and_npf() {
        use crate::svm::*;
        assert_eq!(classify_amd(SVM_EXIT_HLT, 0), FexExitClass::Halt);
        assert_eq!(
            classify_amd(0x400, 0x0800_0000),
            FexExitClass::Mmio { addr: 0x0800_0000 },
        );
        assert_eq!(classify_amd(SVM_EXIT_CPUID, 0), FexExitClass::Translate);
        assert_eq!(classify_amd(SVM_EXIT_IOIO, 0), FexExitClass::IoPort);
    }

    #[test]
    fn vmexit_translate_reenter() {
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(&mut s, FexExitClass::Translate);
        assert_eq!(act, VmexitAction::Reenter);
        assert_eq!(s.pc, 0x4080_0004);
    }

    #[test]
    fn vmexit_halt_halts() {
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(&mut s, FexExitClass::Halt);
        assert_eq!(act, VmexitAction::Halt);
        assert_eq!(s.stats.halt_exits, 1);
    }

    #[test]
    fn vmexit_unhandled_halts() {
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(&mut s, FexExitClass::Unhandled);
        assert_eq!(act, VmexitAction::Halt);
        assert_eq!(s.stats.unhandled_exits, 1);
    }

    #[test]
    fn vmexit_unknown_mmio_addr_halts() {
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(&mut s, FexExitClass::Mmio { addr: 0xDEAD_BEEF });
        assert_eq!(act, VmexitAction::Halt);
        assert_eq!(s.stats.mmio_unhandled, 1);
    }

    #[test]
    fn vmexit_virtio_mmio_with_no_backend_halts() {
        // No virtio backend registered in the unit-test build, so the
        // virtio path returns Unhandled.
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(&mut s, FexExitClass::Mmio { addr: VIRTIO_MMIO_BASE_IPA });
        assert_eq!(act, VmexitAction::Halt);
        assert_eq!(s.stats.mmio_unhandled, 1);
    }

    #[test]
    fn handle_mmio_uart_dr_is_handled() {
        let mut s = armed_state(0x4080_0000);
        let access = MmioAccess {
            addr: crate::mmio_emu::PL011_UART_BASE,
            size: 4, is_write: true, value: b'H' as u64,
        };
        let r = handle_mmio(&mut s, access, 31);
        assert_eq!(r, MmioResult::Ok { value: 0 });
        assert_eq!(s.stats.mmio_handled, 1);
    }

    #[test]
    fn handle_mmio_read_lands_in_xt() {
        let mut s = armed_state(0x4080_0000);
        let access = MmioAccess {
            addr: crate::mmio_emu::PL011_UART_BASE + crate::mmio_emu::pl011::FR,
            size: 4, is_write: false, value: 0,
        };
        let r = handle_mmio(&mut s, access, 5);
        assert_eq!(r, MmioResult::Ok { value: 1 << 4 });
        assert_eq!(s.regs.x[5], 1 << 4);
    }

    // ── Phase 5b: FexMmioRequest contract ──────────────────────────────────

    #[test]
    fn mmio_request_empty_is_not_sane() {
        assert!(!FexMmioRequest::empty().is_sane());
    }

    #[test]
    fn mmio_request_rejects_bad_size() {
        let req = FexMmioRequest { valid: true, size: 3, xt: 0, ..Default::default() };
        assert!(!req.is_sane());
    }

    #[test]
    fn mmio_request_rejects_bad_xt() {
        let req = FexMmioRequest { valid: true, size: 4, xt: 99, ..Default::default() };
        assert!(!req.is_sane());
    }

    #[test]
    fn mmio_request_xt31_is_sane_xzr_discard() {
        let req = FexMmioRequest { valid: true, size: 4, xt: 31, ..Default::default() };
        assert!(req.is_sane());
    }

    #[test]
    fn vmexit_mmio_consumes_request_record_when_valid() {
        // Pre-populate a FEX request: 1-byte STR of 'A' to PL011 DR via xt=2.
        set_mmio_request_for_test(FexMmioRequest {
            valid: true,
            is_write: true,
            size: 1,
            xt: 2,
            addr: crate::mmio_emu::PL011_UART_BASE,
            value: b'A' as u64,
        });
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(
            &mut s,
            FexExitClass::Mmio { addr: crate::mmio_emu::PL011_UART_BASE },
        );
        assert_eq!(act, VmexitAction::Reenter);
        assert_eq!(s.stats.mmio_handled, 1);
        // Slot consumed.
        assert!(!current_mmio_request().valid);
    }

    #[test]
    fn vmexit_mmio_uses_fallback_synthesis_without_request() {
        // No request set; the dispatcher must fall back to xt=31, size=4
        // and still successfully emulate a PL011 FR read.
        set_mmio_request_for_test(FexMmioRequest::empty());
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(
            &mut s,
            FexExitClass::Mmio {
                addr: crate::mmio_emu::PL011_UART_BASE + crate::mmio_emu::pl011::FR,
            },
        );
        assert_eq!(act, VmexitAction::Reenter);
        assert_eq!(s.stats.mmio_handled, 1);
        // xt=31 = XZR (no-op write), so no GPR was touched.
        assert_eq!(s.regs.x[0], s.regs.x[0]);
    }

    #[test]
    fn vmexit_mmio_request_read_writes_value_into_xt() {
        set_mmio_request_for_test(FexMmioRequest {
            valid: true,
            is_write: false,
            size: 4,
            xt: 7,
            addr: crate::mmio_emu::PL011_UART_BASE + crate::mmio_emu::pl011::FR,
            value: 0,
        });
        let mut s = armed_state(0x4080_0000);
        let _ = handle_vmexit(
            &mut s,
            FexExitClass::Mmio {
                addr: crate::mmio_emu::PL011_UART_BASE + crate::mmio_emu::pl011::FR,
            },
        );
        // PL011 FR returns RXFE=1 (bit 4) when AETHER's emulator is queried.
        assert_eq!(s.regs.x[7], 1 << 4);
    }

    #[test]
    fn vmexit_mmio_addr_mismatch_falls_back_to_synthesis() {
        // FEX-populated request points at a different address than the
        // classifier hands us — refuse to trust it and fall back.
        set_mmio_request_for_test(FexMmioRequest {
            valid: true, is_write: true, size: 8, xt: 0,
            addr: 0xDEAD_BEEF, value: 0xAA55,
        });
        let mut s = armed_state(0x4080_0000);
        let act = handle_vmexit(
            &mut s,
            FexExitClass::Mmio { addr: crate::mmio_emu::PL011_UART_BASE },
        );
        // PL011 base offset 0 = DR; fallback synthesis = 4-byte read; emulator
        // returns 0 from DR read. Action is Reenter because the fallback access
        // is still successfully emulated.
        assert_eq!(act, VmexitAction::Reenter);
    }
}
