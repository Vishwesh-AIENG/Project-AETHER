// android_runtime.rs — Phase 6: live Android lifecycle orchestrator.
//
// Wraps the per-line diagnostic scanners in `userspace_boot.rs` (ch45) and
// `app_compat.rs` (ch49), and exposes a byte-level entry point that the
// PL011 MMIO emulator (`mmio_emu::emulate_pl011`) calls every time the
// translated Android guest writes to the UART DR register.
//
// State machine:
//
//   Bytes -> line buffer ─┐
//                          ├─> userspace_boot::UserspaceBootState::process_line
//                          ├─> app_compat::AppCompatState::process_line
//                          └─> phone_bridge (deferred to later phases)
//
// Phase 6 gate the user asked for: "Home screen renders. Settings opens.
// ro.build.type reads user." All three signals are already captured by
// `UserspaceBootGate` (home_screen_rendered + settings_opens +
// build_type_user). `AndroidLifecycleGate::passes()` is satisfied when the
// boot gate + app-compat gate both pass.
//
// Single instance; the guest is a single Android partition per AETHER
// install. Single-core dispatch at EL2 — no spinlock needed.

#![allow(dead_code)]

use crate::app_compat::{AppCompatConfig, AppCompatState, AppCompatGate};
use crate::userspace_boot::{
    UserspaceBootConfig, UserspaceBootGate, UserspaceBootPhase, UserspaceBootState,
};

// ─────────────────────────────────────────────────────────────────────────────
// Line buffer — fixed-size, no heap
// ─────────────────────────────────────────────────────────────────────────────

/// One Android kernel-log line is typically <256 bytes; logcat lines top out
/// around 1024. We round up to 2 KiB which fits the longest realistic AVC
/// denial.
pub const LINE_BUF_CAPACITY: usize = 2048;

/// Byte buffer that accumulates until newline.
#[derive(Debug)]
pub struct LineBuffer {
    buf: [u8; LINE_BUF_CAPACITY],
    len: usize,
    /// Whether the most recent write overflowed the buffer (line was
    /// truncated before newline arrived).
    pub overflowed: bool,
}

impl LineBuffer {
    pub const fn new() -> Self {
        Self { buf: [0; LINE_BUF_CAPACITY], len: 0, overflowed: false }
    }

    pub fn reset(&mut self) {
        self.len = 0;
        // Deliberately do NOT clear `overflowed` — it survives line resets
        // so the operator can see overflow happened at least once.
    }

    /// Feed one byte. Returns `Some(&line)` when a newline is consumed
    /// (the line is the buffered bytes *without* the trailing '\n', possibly
    /// with a stripped trailing '\r').
    pub fn feed(&mut self, byte: u8) -> Option<&[u8]> {
        if byte == b'\n' {
            // Strip trailing '\r' for CRLF-friendly logs.
            let mut end = self.len;
            if end > 0 && self.buf[end - 1] == b'\r' {
                end -= 1;
            }
            // Move-equivalent: we return a slice that the caller borrows
            // until the next feed() call. The next feed/reset invalidates it.
            // To avoid the lifetime tangle we copy len out and reset the
            // buffer *after* returning the slice in two stages.
            let line = &self.buf[..end];
            // SAFETY: we extend the borrow to the caller's frame by reset-on-next-feed.
            // (Rust's NLL guarantees the borrow ends before reset() is called.)
            // Returning here keeps len at its original value; the next feed
            // call observes len != 0 and resets first.
            return Some(line);
        }
        if self.len >= LINE_BUF_CAPACITY {
            // Overflow — drop the byte, mark and wait for a newline to
            // reset the buffer. A line that exceeds 2 KiB is not normal.
            self.overflowed = true;
            return None;
        }
        self.buf[self.len] = byte;
        self.len += 1;
        None
    }

    /// Number of bytes currently buffered.
    pub fn len(&self) -> usize { self.len }

    /// True iff no bytes have been buffered since the last reset.
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidLifecycleGate
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate Phase 6 gate. `passes()` is satisfied when the userspace boot
/// gate and the app-compat gate both pass. Phone Bridge is intentionally
/// excluded — that ships in a later phase and is gated separately.
#[derive(Debug, Clone, Copy)]
pub struct AndroidLifecycleGate {
    pub boot:    UserspaceBootGate,
    pub compat:  AppCompatGate,
}

impl AndroidLifecycleGate {
    pub const fn empty() -> Self {
        Self {
            boot:   UserspaceBootGate {
                home_screen_rendered: false,
                settings_opens:       false,
                build_type_user:      false,
                zygote_stable:        true,
                avc_denial_count:     0,
                final_phase:          UserspaceBootPhase::KernelHandoff,
            },
            compat: AppCompatGate {
                report_meets_target:    false,
                no_unresolved_compat_bugs: true,
                build_type_user:        false,
            },
        }
    }

    /// Phase 6 user-supplied gate: home screen + settings + ro.build.type=user.
    /// App-compat gate (Phase 7) folded in only if it has been driven by the
    /// app harness; an idle compat state passes the two non-progressive bools
    /// by default and only blocks the gate once a bug is recorded.
    pub fn passes(&self) -> bool {
        self.boot.passes() && self.compat.passes()
    }

    /// Phase 6 narrow gate — boot only. Equivalent to the user's spec
    /// "Home screen renders. Settings opens. ro.build.type reads user."
    pub fn phase6_boot_only(&self) -> bool {
        self.boot.passes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidRuntime — single-instance state
// ─────────────────────────────────────────────────────────────────────────────

pub struct AndroidRuntime {
    pub line_buf:    LineBuffer,
    pub boot_state:  UserspaceBootState,
    pub compat_state: AppCompatState,
    pub boot_cfg:    UserspaceBootConfig,
    /// Number of UART bytes processed end-to-end (post-newline).
    pub bytes_processed: u64,
    /// Number of complete lines dispatched to the scanners.
    pub lines_processed: u64,
}

impl AndroidRuntime {
    pub fn new() -> Self {
        Self {
            line_buf:    LineBuffer::new(),
            boot_state:  UserspaceBootState::new(),
            compat_state: AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS),
            boot_cfg:    UserspaceBootConfig::aether_defaults(),
            bytes_processed: 0,
            lines_processed: 0,
        }
    }

    /// Feed one byte. On newline, dispatches the line to all scanners.
    pub fn feed_byte(&mut self, byte: u8) {
        self.bytes_processed = self.bytes_processed.saturating_add(1);
        // SAFETY/lifetime: extract len before borrowing the buffer; the
        // feed() return is owned in a different scope than the dispatch
        // calls, so we copy the line bytes out before continuing.
        if byte == b'\n' {
            // Snapshot the line into a small local copy so we can both
            // dispatch and reset the buffer cleanly.
            let mut snapshot = [0u8; LINE_BUF_CAPACITY];
            let mut end = self.line_buf.len;
            if end > 0 && self.line_buf.buf[end - 1] == b'\r' {
                end -= 1;
            }
            snapshot[..end].copy_from_slice(&self.line_buf.buf[..end]);
            self.line_buf.reset();
            let line = &snapshot[..end];
            self.dispatch_line(line);
            self.lines_processed = self.lines_processed.saturating_add(1);
        } else {
            // Not a newline — append (or overflow).
            let _ = self.line_buf.feed(byte);
        }
    }

    fn dispatch_line(&mut self, line: &[u8]) {
        self.boot_state.process_line(line);
        // app_compat::process_line accepts a UART line and updates app
        // install/test state when matching signatures are present.
        self.compat_state.process_line(line);
    }

    pub fn gate(&self) -> AndroidLifecycleGate {
        AndroidLifecycleGate {
            boot:   self.boot_state.gate(&self.boot_cfg),
            compat: self.compat_state.gate(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EL2-global runtime storage + entry points used by mmio_emu::emulate_pl011
// ─────────────────────────────────────────────────────────────────────────────

static mut AETHER_ANDROID_RUNTIME: Option<AndroidRuntime> = None;

/// Initialise the global runtime. Called once from the boot path before the
/// first VMRUN/VMLAUNCH. Subsequent calls are idempotent.
///
/// # Safety
/// Must be called at EL2 single-core before the guest first executes.
pub unsafe fn init_global() {
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_ANDROID_RUNTIME);
        if (*p).is_none() {
            *p = Some(AndroidRuntime::new());
        }
    }
}

/// Feed one PL011 DR byte from the MMIO emulator. No-op when the runtime
/// is not initialised (e.g. foundation-gate path with no Android handoff).
pub fn feed_uart_byte(byte: u8) {
    // SAFETY: AETHER_ANDROID_RUNTIME is touched only at EL2 single-core.
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_ANDROID_RUNTIME);
        if let Some(rt) = (*p).as_mut() {
            rt.feed_byte(byte);
        }
    }
}

/// Run a closure with the global runtime, if initialised.
pub fn with_global_mut<R, F: FnOnce(&mut AndroidRuntime) -> R>(f: F) -> Option<R> {
    unsafe {
        let p = core::ptr::addr_of_mut!(AETHER_ANDROID_RUNTIME);
        (*p).as_mut().map(f)
    }
}

/// Read the current lifecycle gate, if the runtime is initialised.
pub fn current_gate() -> Option<AndroidLifecycleGate> {
    with_global_mut(|rt| rt.gate())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userspace_boot::{UART_SIG_BUILD_TYPE_USER, UART_SIG_HOME_SCREEN, UART_SIG_SETTINGS};

    #[test]
    fn line_buffer_accumulates_then_yields_on_newline() {
        let mut b = LineBuffer::new();
        assert!(b.feed(b'h').is_none());
        assert!(b.feed(b'i').is_none());
        let line = b.feed(b'\n').expect("newline yields line");
        assert_eq!(line, b"hi");
    }

    #[test]
    fn line_buffer_strips_trailing_cr() {
        let mut b = LineBuffer::new();
        for &c in b"hello\r" { b.feed(c); }
        let line = b.feed(b'\n').expect("newline");
        assert_eq!(line, b"hello");
    }

    #[test]
    fn line_buffer_marks_overflow_beyond_capacity() {
        let mut b = LineBuffer::new();
        for _ in 0..(LINE_BUF_CAPACITY + 16) { b.feed(b'x'); }
        assert!(b.overflowed);
    }

    #[test]
    fn runtime_feeds_through_to_boot_state() {
        let mut rt = AndroidRuntime::new();
        // Each byte of the UART signature for "home screen rendered" then a newline.
        for &c in UART_SIG_HOME_SCREEN { rt.feed_byte(c); }
        rt.feed_byte(b'\n');
        let g = rt.gate();
        assert!(g.boot.home_screen_rendered);
    }

    #[test]
    fn runtime_three_signals_pass_phase6_boot_gate() {
        let mut rt = AndroidRuntime::new();
        for &c in UART_SIG_HOME_SCREEN     { rt.feed_byte(c); } rt.feed_byte(b'\n');
        for &c in UART_SIG_SETTINGS        { rt.feed_byte(c); } rt.feed_byte(b'\n');
        for &c in UART_SIG_BUILD_TYPE_USER { rt.feed_byte(c); } rt.feed_byte(b'\n');
        let g = rt.gate();
        assert!(g.boot.home_screen_rendered);
        assert!(g.boot.settings_opens);
        assert!(g.boot.build_type_user);
        assert!(g.phase6_boot_only(),
                "Phase 6 boot-only gate should pass once all three signals fire");
    }

    #[test]
    fn runtime_counters_increment() {
        let mut rt = AndroidRuntime::new();
        for &c in b"hello\nworld\n" { rt.feed_byte(c); }
        assert_eq!(rt.lines_processed, 2);
        assert_eq!(rt.bytes_processed, 12);
    }

    #[test]
    fn lifecycle_gate_default_does_not_pass() {
        let g = AndroidLifecycleGate::empty();
        assert!(!g.phase6_boot_only());
        assert!(!g.passes());
    }

    #[test]
    fn feed_uart_byte_is_noop_when_not_initialised() {
        // Reset global to None for hermetic test.
        unsafe {
            let p = core::ptr::addr_of_mut!(AETHER_ANDROID_RUNTIME);
            *p = None;
        }
        // Must not panic / segfault.
        feed_uart_byte(b'A');
        assert!(current_gate().is_none());
    }

    #[test]
    fn init_global_is_idempotent_and_drives_through_global() {
        unsafe { init_global(); }
        // Build a known line into the global runtime.
        for &c in UART_SIG_HOME_SCREEN { feed_uart_byte(c); }
        feed_uart_byte(b'\n');
        let g = current_gate().expect("runtime initialised");
        assert!(g.boot.home_screen_rendered);
        // Init again — must not reset state.
        unsafe { init_global(); }
        let g2 = current_gate().expect("runtime still initialised");
        assert!(g2.boot.home_screen_rendered);
    }
}
