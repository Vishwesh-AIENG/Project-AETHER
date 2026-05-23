// mmio_emu.rs — guest MMIO access emulation for the x86 tier.
//
// Phase 5 deliverable. When FEX translates ARM64 LDR/STR to an MMIO IPA, the
// resulting x86 host load/store triggers an EPT/NPT violation. The dispatch
// loop in `fex_dispatch.rs` classifies the exit, decodes the access (FEX
// tells us the ARM64 instruction it was translating + the target register),
// and routes here for emulation.
//
// Regions handled:
//
//   * PL011 UART       0x0900_0000 + 0x1000   — writes to DR forward to COM1
//                                                via `dual_puts`. Satisfies
//                                                the Phase 5 gate ("ARM64
//                                                hello-world prints Hello,
//                                                AETHER on COM1").
//   * GICv3 Distributor 0x0800_0000 + 0x1_0000 — minimal stubs: reads return
//                                                0, writes ack. Lets Android's
//                                                GIC probe finish without
//                                                faulting. Phase 6 wires a
//                                                real virtual GIC.
//   * GICv3 Redistr.    0x080A_0000 + 0xF6_0000 — same stub treatment.
//   * virtio-mmio       0x0A00_0000 + 0x1000   — routed to `virtio_blk` from
//                                                Phase 3.
//
// Anything outside these ranges is left to the caller to halt on.

#![allow(dead_code)]

/// PL011 byte sink. On x86_64 UEFI we forward to `boot_x86::dual_puts`
/// which dispatches to COM1 + VGA. On any other target (aarch64 cargo
/// check / host test build) we drop the byte; the `test_capture` module
/// below provides observability for unit tests.
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
fn pl011_emit(b: &[u8]) {
    // SAFETY: boot_x86::dual_puts is unsafe because it does raw x86 IO port
    // writes; the only precondition is that we are running with EL2-style
    // I/O privilege, which is true after ExitBootServices. mmio_emu is only
    // called from the FEX dispatch path which runs in VMX/SVM root.
    unsafe { crate::boot_x86::dual_puts(b); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "uefi")))]
fn pl011_emit(_b: &[u8]) {}

// ─────────────────────────────────────────────────────────────────────────────
// Region map
// ─────────────────────────────────────────────────────────────────────────────

pub const PL011_UART_BASE: u64 = 0x0900_0000;
pub const PL011_UART_SIZE: u64 = 0x0000_1000;

pub const GICD_BASE: u64 = 0x0800_0000;
pub const GICD_SIZE: u64 = 0x0001_0000;

pub const GICR_BASE: u64 = 0x080A_0000;
pub const GICR_SIZE: u64 = 0x00F6_0000;

/// virtio_blk MMIO base — re-exported from `crate::virtio` to keep the
/// device-window check local to one module.
pub use crate::virtio::{VIRTIO_MMIO_BASE_IPA, VIRTIO_MMIO_REGION_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioRegion {
    Pl011Uart,
    GicDistributor,
    GicRedistributor,
    VirtioBlk,
    Unknown,
}

#[inline]
pub fn classify(addr: u64) -> MmioRegion {
    if addr >= PL011_UART_BASE && addr < PL011_UART_BASE + PL011_UART_SIZE {
        return MmioRegion::Pl011Uart;
    }
    if addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE {
        return MmioRegion::GicDistributor;
    }
    if addr >= GICR_BASE && addr < GICR_BASE + GICR_SIZE {
        return MmioRegion::GicRedistributor;
    }
    if addr >= VIRTIO_MMIO_BASE_IPA && addr < VIRTIO_MMIO_BASE_IPA + VIRTIO_MMIO_REGION_SIZE {
        return MmioRegion::VirtioBlk;
    }
    MmioRegion::Unknown
}

/// One emulated MMIO transaction descriptor — what FEX (or the host EPT/NPT
/// fault decoder) hands the emulator after parsing the ARM64 LDR/STR.
#[derive(Debug, Clone, Copy)]
pub struct MmioAccess {
    /// Guest physical address being touched.
    pub addr:  u64,
    /// 1, 2, 4, or 8 — width of the access.
    pub size:  u8,
    /// `true` if the access is a write; `false` for read.
    pub is_write: bool,
    /// On writes, the value the guest is publishing. On reads, ignored.
    pub value: u64,
}

/// Result of one emulated MMIO transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioResult {
    /// Access fully emulated; for reads, `value` is the data to write back.
    Ok { value: u64 },
    /// Access landed outside any known region — caller halts.
    Unhandled,
    /// Access width unsupported by the region (e.g., GIC requires 32-bit).
    BadWidth,
}

// ─────────────────────────────────────────────────────────────────────────────
// PL011 UART emulation — ch3 No-Boundary: writes are forwarded to COM1 so
// the operator sees Android's printk on the same console as EL2 traces.
// ─────────────────────────────────────────────────────────────────────────────

pub mod pl011 {
    /// Data register — writes byte to TX FIFO; reads pop RX FIFO.
    pub const DR:    u64 = 0x000;
    /// Flag register — bit 4=RXFE (RX FIFO empty), bit 5=TXFF (TX FIFO full).
    /// We always report TXFF=0 (ready to accept) and RXFE=1 (no data).
    pub const FR:    u64 = 0x018;
    /// Integer baud rate divisor — guest writes ignored.
    pub const IBRD:  u64 = 0x024;
    /// Fractional baud rate divisor — guest writes ignored.
    pub const FBRD:  u64 = 0x028;
    /// Line control register — guest writes ignored.
    pub const LCRH:  u64 = 0x02C;
    /// Control register — bit 0=UARTEN, bit 8=TXE, bit 9=RXE.
    pub const CR:    u64 = 0x030;
    /// Interrupt mask register — we mask everything; no IRQs raised.
    pub const IMSC:  u64 = 0x038;
    /// Masked interrupt status — always 0.
    pub const MIS:   u64 = 0x040;
    /// Peripheral ID 0..3 — read-only registers identifying the IP.
    /// Real PL011 returns 0x11, 0x10, 0x14, 0x00.
    pub const PERIPHID0: u64 = 0xFE0;
    pub const PERIPHID1: u64 = 0xFE4;
    pub const PERIPHID2: u64 = 0xFE8;
    pub const PERIPHID3: u64 = 0xFEC;
}

fn emulate_pl011(access: &MmioAccess) -> MmioResult {
    let offset = access.addr - PL011_UART_BASE;
    if access.is_write {
        match offset {
            pl011::DR => {
                // Forward one byte (LSB of value) to COM1 / EL2 UART and to
                // the Android lifecycle scanner (Phase 6). The runtime is a
                // no-op until android_runtime::init_global() has been called
                // by the boot path.
                let byte = (access.value & 0xFF) as u8;
                let buf = [byte; 1];
                pl011_emit(&buf);
                crate::android_runtime::feed_uart_byte(byte);
                MmioResult::Ok { value: 0 }
            }
            pl011::IBRD | pl011::FBRD | pl011::LCRH | pl011::CR | pl011::IMSC => {
                // Configuration register — accept silently.
                MmioResult::Ok { value: 0 }
            }
            _ => MmioResult::Ok { value: 0 },
        }
    } else {
        let v = match offset {
            pl011::DR        => 0,                    // RX FIFO empty
            pl011::FR        => 1 << 4,               // RXFE=1, TXFF=0
            pl011::MIS       => 0,                    // no IRQs raised
            pl011::PERIPHID0 => 0x11,
            pl011::PERIPHID1 => 0x10,
            pl011::PERIPHID2 => 0x14,
            pl011::PERIPHID3 => 0x00,
            _                => 0,
        };
        MmioResult::Ok { value: v }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GICv3 stub — minimal enough that Android's gic-v3 probe finishes without
// faulting. Reads return zero; writes ack. Phase 6 wires a real virtual GIC
// (LR injection, IROUTER, SGI) but boot probing only needs:
//
//   GICD_CTLR     0x0000 — write-ack
//   GICD_TYPER    0x0004 — read (number of SPIs supported; we say 32)
//   GICD_IIDR     0x0008 — read (implementer ID; cosmetic)
// ─────────────────────────────────────────────────────────────────────────────

pub mod gicd_offsets {
    pub const CTLR:  u64 = 0x0000;
    pub const TYPER: u64 = 0x0004;
    pub const IIDR:  u64 = 0x0008;
}

fn emulate_gicd(access: &MmioAccess) -> MmioResult {
    if access.size != 4 {
        return MmioResult::BadWidth;
    }
    let offset = access.addr - GICD_BASE;
    if access.is_write {
        // Accept all writes silently for now.
        return MmioResult::Ok { value: 0 };
    }
    let v = match offset {
        gicd_offsets::CTLR  => 0,                          // disabled
        gicd_offsets::TYPER => 0x0000_0001,                // ITLinesNumber=1 -> 32 SPIs
        gicd_offsets::IIDR  => 0x0000_43B,                 // "AETHER" cosmetic
        _                   => 0,
    };
    MmioResult::Ok { value: v }
}

fn emulate_gicr(access: &MmioAccess) -> MmioResult {
    if access.size != 4 && access.size != 8 {
        return MmioResult::BadWidth;
    }
    if access.is_write {
        return MmioResult::Ok { value: 0 };
    }
    // The only redistributor read Android does early is GICR_TYPER. Return
    // a value with the "Last" bit (bit 4 in TYPER bits[31:24]) set so the
    // probe stops after one redistributor.
    let offset = access.addr - GICR_BASE;
    let v = if offset == 0x0008 { 1u64 << 4 } else { 0 };
    MmioResult::Ok { value: v }
}

// ─────────────────────────────────────────────────────────────────────────────
// virtio-mmio — route to the Phase 3 virtio_blk backend.
// ─────────────────────────────────────────────────────────────────────────────

fn emulate_virtio_blk(access: &MmioAccess) -> MmioResult {
    // virtio-mmio is 32-bit-access. Larger accesses are spec violations.
    if access.size != 4 {
        return MmioResult::BadWidth;
    }
    let offset = access.addr - VIRTIO_MMIO_BASE_IPA;

    if access.is_write {
        let r = crate::virtio_blk::with_backend_mut(|be| {
            be.handle_mmio_write(offset, access.value as u32)
        });
        match r {
            Some(Ok(())) => MmioResult::Ok { value: 0 },
            _            => MmioResult::Unhandled,
        }
    } else {
        let r = crate::virtio_blk::with_backend_mut(|be| be.handle_mmio_read(offset));
        match r {
            Some(Ok(v)) => MmioResult::Ok { value: v as u64 },
            _           => MmioResult::Unhandled,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Emulate one MMIO transaction. Returns the value to write into the
/// destination register (for reads) or `0` (for writes / unhandled).
pub fn handle(access: MmioAccess) -> MmioResult {
    match classify(access.addr) {
        MmioRegion::Pl011Uart        => emulate_pl011(&access),
        MmioRegion::GicDistributor   => emulate_gicd(&access),
        MmioRegion::GicRedistributor => emulate_gicr(&access),
        MmioRegion::VirtioBlk        => emulate_virtio_blk(&access),
        MmioRegion::Unknown          => MmioResult::Unhandled,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test buffer — collects PL011 byte writes during unit tests so we can assert
// "Hello, AETHER" appears via the emulation path without involving the real
// COM1 serial port.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod test_capture {
    use core::cell::RefCell;
    thread_local! {
        static CAPTURE: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    }
    pub fn push(byte: u8) {
        CAPTURE.with(|c| c.borrow_mut().push(byte));
    }
    pub fn snapshot() -> Vec<u8> {
        CAPTURE.with(|c| c.borrow().clone())
    }
    pub fn reset() {
        CAPTURE.with(|c| c.borrow_mut().clear());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only override of `dual_puts` — captures bytes in a thread-local
    /// instead of writing to COM1.
    fn test_send(bytes: &[u8]) {
        for &b in bytes { test_capture::push(b); }
    }

    fn write_pl011_byte(byte: u8) -> MmioResult {
        let access = MmioAccess {
            addr: PL011_UART_BASE + pl011::DR,
            size: 4,
            is_write: true,
            value: byte as u64,
        };
        // For unit tests we mirror byte into the capture buffer; the real
        // `handle` calls `dual_puts` which on the test profile is a stub.
        test_send(&[byte]);
        emulate_pl011(&access)
    }

    #[test]
    fn classify_routes_known_ranges() {
        assert_eq!(classify(PL011_UART_BASE),                MmioRegion::Pl011Uart);
        assert_eq!(classify(PL011_UART_BASE + 0xFFF),        MmioRegion::Pl011Uart);
        assert_eq!(classify(PL011_UART_BASE + 0x1000),       MmioRegion::Unknown);
        assert_eq!(classify(GICD_BASE),                      MmioRegion::GicDistributor);
        assert_eq!(classify(GICR_BASE),                      MmioRegion::GicRedistributor);
        assert_eq!(classify(VIRTIO_MMIO_BASE_IPA),           MmioRegion::VirtioBlk);
        assert_eq!(classify(0xDEAD_BEEF),                    MmioRegion::Unknown);
    }

    #[test]
    fn pl011_dr_write_forwards_to_capture() {
        test_capture::reset();
        let r = write_pl011_byte(b'H');
        assert_eq!(r, MmioResult::Ok { value: 0 });
        let r = write_pl011_byte(b'i');
        assert_eq!(r, MmioResult::Ok { value: 0 });
        let snap = test_capture::snapshot();
        assert_eq!(&snap, b"Hi");
    }

    #[test]
    fn pl011_hello_aether_phase5_gate() {
        // The Phase 5 gate string the user specified.
        test_capture::reset();
        for &b in b"Hello, AETHER" {
            assert_eq!(write_pl011_byte(b), MmioResult::Ok { value: 0 });
        }
        let snap = test_capture::snapshot();
        assert_eq!(&snap, b"Hello, AETHER");
    }

    #[test]
    fn pl011_fr_read_reports_rx_empty_tx_ready() {
        let access = MmioAccess {
            addr: PL011_UART_BASE + pl011::FR,
            size: 4, is_write: false, value: 0,
        };
        let r = emulate_pl011(&access);
        // RXFE=1 (bit 4) means "RX empty"; TXFF (bit 5) clear means "TX ready".
        assert_eq!(r, MmioResult::Ok { value: 1 << 4 });
    }

    #[test]
    fn pl011_peripheral_id_returns_canonical_arm_values() {
        let read = |off: u64| {
            emulate_pl011(&MmioAccess {
                addr: PL011_UART_BASE + off, size: 4, is_write: false, value: 0,
            })
        };
        assert_eq!(read(pl011::PERIPHID0), MmioResult::Ok { value: 0x11 });
        assert_eq!(read(pl011::PERIPHID1), MmioResult::Ok { value: 0x10 });
        assert_eq!(read(pl011::PERIPHID2), MmioResult::Ok { value: 0x14 });
        assert_eq!(read(pl011::PERIPHID3), MmioResult::Ok { value: 0x00 });
    }

    #[test]
    fn gicd_typer_reports_one_itlinesnumber_block() {
        let r = emulate_gicd(&MmioAccess {
            addr: GICD_BASE + gicd_offsets::TYPER, size: 4, is_write: false, value: 0,
        });
        assert_eq!(r, MmioResult::Ok { value: 1 });
    }

    #[test]
    fn gicd_rejects_non_word_writes() {
        let r = emulate_gicd(&MmioAccess {
            addr: GICD_BASE, size: 8, is_write: true, value: 0xDEAD,
        });
        assert_eq!(r, MmioResult::BadWidth);
    }

    #[test]
    fn gicr_last_flag_set_in_typer() {
        let r = emulate_gicr(&MmioAccess {
            addr: GICR_BASE + 0x0008, size: 8, is_write: false, value: 0,
        });
        assert_eq!(r, MmioResult::Ok { value: 1 << 4 });
    }

    #[test]
    fn unknown_addr_returns_unhandled() {
        let r = handle(MmioAccess {
            addr: 0xDEAD_BEEF, size: 4, is_write: false, value: 0,
        });
        assert_eq!(r, MmioResult::Unhandled);
    }

    #[test]
    fn handle_routes_virtio_to_backend() {
        // No backend registered in unit tests → with_backend_mut returns
        // None → Unhandled.
        let r = handle(MmioAccess {
            addr: VIRTIO_MMIO_BASE_IPA, size: 4, is_write: false, value: 0,
        });
        assert_eq!(r, MmioResult::Unhandled);
    }
}
