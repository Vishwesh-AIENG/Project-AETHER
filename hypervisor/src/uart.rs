// PL011 UART driver — debug output for AETHER boot diagnostics
//
// The ARM PL011 is the serial UART that QEMU's `virt` machine exposes at
// 0x0900_0000. Writing a byte to the Data Register (DR) at offset 0x00
// transmits it over the serial line that QEMU maps to the host terminal
// via `-serial stdio`.
//
// This module implements polled (busy-wait) TX only — no RX, no interrupts,
// no DMA. That is sufficient for hypervisor diagnostics: we write a few
// strings at boot time and then hand control to the guest, which drives
// the UART through its own GIC-backed interrupt path.
//
// Reference: PL011 Technical Reference Manual DDI0183 (ARM).
// QEMU virt machine UART0 base address: 0x0900_0000.

/// PL011 UART Data Register offset. Write a byte here to transmit.
/// DDI0183 Section 3.3.1.
const UARTDR: usize = 0x00;

/// PL011 UART Flag Register offset.
/// Bit 5 (TXFF): Transmit FIFO Full — wait when this is set.
/// Bit 7 (TXFE): Transmit FIFO Empty — all bytes sent when this is set.
/// DDI0183 Section 3.3.3.
const UARTFR: usize = 0x18;

/// UARTFR bit 5: Transmit FIFO Full. Busy-wait while set before writing DR.
const UARTFR_TXFF: u32 = 1 << 5;

/// A polled PL011 UART driver anchored to one MMIO base address.
pub struct Uart {
    base: usize,
}

impl Uart {
    /// Construct a UART driver at the given physical base address.
    ///
    /// The caller must ensure the base address is valid MMIO and is mapped
    /// (either identity-mapped through Stage 2 or accessible from EL2 before
    /// Stage 2 is enabled).
    ///
    /// # Safety
    /// `base` must be the physical base address of an accessible PL011 UART.
    pub const unsafe fn new(base: u64) -> Self {
        Self { base: base as usize }
    }

    /// Read the Flag Register.
    #[inline]
    fn read_fr(&self) -> u32 {
        // SAFETY: base is a valid UART MMIO address; volatile read is required
        // for MMIO registers to prevent the compiler from eliding/reordering.
        unsafe { core::ptr::read_volatile((self.base + UARTFR) as *const u32) }
    }

    /// Write one byte to the UART, busy-waiting if the TX FIFO is full.
    ///
    /// # Safety
    /// `self.base` must point to a mapped, accessible PL011 UART.
    pub unsafe fn putc(&self, byte: u8) {
        // Wait until the transmit FIFO has room.
        while self.read_fr() & UARTFR_TXFF != 0 {
            core::hint::spin_loop();
        }
        // Write to UARTDR. The PL011 accepts an 8-bit value in a 32-bit register;
        // only bits [7:0] are used for data — bits [11:8] carry error flags on
        // receive (ignored here).
        unsafe {
            core::ptr::write_volatile(
                (self.base + UARTDR) as *mut u32,
                byte as u32,
            );
        }
    }

    /// Write a UTF-8 string byte-by-byte.
    ///
    /// `\n` is automatically expanded to `\r\n` so output looks correct on
    /// serial terminals that need both a carriage return and a line feed.
    ///
    /// # Safety
    /// Same as `putc`.
    pub unsafe fn puts(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                unsafe { self.putc(b'\r') };
            }
            unsafe { self.putc(byte) };
        }
    }

    /// Write a 64-bit value as `0x<hex>`.
    ///
    /// # Safety
    /// Same as `putc`.
    pub unsafe fn puthex64(&self, v: u64) {
        const DIGITS: &[u8] = b"0123456789abcdef";
        unsafe { self.puts("0x") };
        for shift in (0..16).rev() {
            let nibble = ((v >> (shift * 4)) & 0xF) as usize;
            unsafe { self.putc(DIGITS[nibble]) };
        }
    }

    /// Write a 32-bit value as `0x<hex>`.
    ///
    /// # Safety
    /// Same as `putc`.
    pub unsafe fn puthex32(&self, v: u32) {
        const DIGITS: &[u8] = b"0123456789abcdef";
        unsafe { self.puts("0x") };
        for shift in (0..8).rev() {
            let nibble = ((v >> (shift * 4)) & 0xF) as usize;
            unsafe { self.putc(DIGITS[nibble]) };
        }
    }

    /// Write a decimal usize value.
    ///
    /// # Safety
    /// Same as `putc`.
    pub unsafe fn putdec(&self, mut v: usize) {
        if v == 0 {
            unsafe { self.putc(b'0') };
            return;
        }
        let mut buf = [0u8; 20];
        let mut i = 20usize;
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        for &byte in &buf[i..] {
            unsafe { self.putc(byte) };
        }
    }
}
