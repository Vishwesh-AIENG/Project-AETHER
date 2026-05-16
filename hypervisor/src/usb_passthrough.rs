// ch41: USB Controller and Input Switch — Functional
//
// Implements the hardware pipeline that makes Ch16 (usb.rs) types operate on
// real xHCI silicon. The chapter delivers three functional capabilities:
//
//   1. xHCI Controller Assignment — maps the xHCI BAR into the Android guest's
//      Stage 2 page tables, configures SMMU STEs for DMA isolation, maps the
//      ECAM config-space window, and issues HCRST before handing the controller
//      to the Android USB driver.
//
//   2. Event Ring Interception — AETHER monitors the xHCI Event Ring for
//      Transfer Event TRBs from the integrated keyboard's interrupt endpoint.
//      Each completion carries a pointer to the HID data buffer. AETHER reads
//      the 8-byte HID boot-protocol report, passes it to
//      UsbPartitionState::process_hid_report(), and either forwards or triggers
//      the input switch depending on the result.
//
//   3. Input Switch Execution — when Ctrl+Alt+Tab is detected in the raw HID
//      stream, execute_xhci_input_switch() performs:
//        a. Stop the xHCI controller (clear USBCMD.RS, await USBSTS.HCH=1)
//        b. Issue HCRST (set USBCMD.HCRST=1, await USBCMD.HCRST=0)
//        c. Rewrite the SMMU STE with the new guest's VMID and Stage 2 base
//        d. Transfer ownership in UsbPartitionState
//      The triggering key events are never forwarded to either guest.
//
// Gate: UsbPassthroughGate { keyboard_enumerated: true, input_switch_ready: true }
//   keyboard_enumerated = ≥1 xHCI BAR mapped in Stage 2 + SMMU STE configured
//                         + ECAM window mapped + HCRST completed; Android USB
//                         stack enumerates a HID keyboard on /dev/input/eventN.
//   input_switch_ready  = UsbPartitionState::configure_input_switch() succeeded;
//                         Ctrl+Alt+Tab switches focus without reboot.
//
// xHCI Controller Assignment pipeline (7 steps, assign_xhci_controller()):
//   1. Config validation — ECAM bus range non-empty; ctrl_addr within window.
//   2. BAR scan → Stage 2 — scan_bars on ctrl_addr; identity-map each non-None
//      BAR as DeviceRw (IPA == PA, so the Android xHCI driver can MMIO the regs).
//   3. SMMU STEs — SmmuSte::stage2_only + write_ste per stream_id; mandatory
//      word order: words 1–7 → DSB ISH → word 0 (IHI0070E §3.6).
//   4. ECAM window — identity-map config-space window as DeviceRw so Android can
//      enumerate the USB controller.
//   5. Bus Master Enable — assert BME (Command reg bit 2) on the controller;
//      FLR or firmware reset may have cleared it.
//   6. HCRST — stop controller (USBCMD.RS=0, await USBSTS.HCH=1) then write
//      USBCMD.HCRST=1 and poll USBCMD.HCRST=0 (up to HCRST_POLL_MAX iterations).
//      Clears all TRB ring state and port state to a clean initial state.
//   7. Register in UsbPartitionRegistry — smmu_configured=true, reset_state=Clean.
//
// Input Switch pipeline (execute_xhci_input_switch()):
//   1. Halt xHCI (USBCMD.RS=0, await USBSTS.HCH=1).
//   2. Issue HCRST (USBCMD.HCRST=1, await HCRST=0); abort on timeout.
//   3. Rewrite SMMU STE for the new guest (words 1–7 → DSB → word 0).
//   4. Call UsbPartitionState::execute_switch() — transfers ownership in registry.
//   5. Call registry.mark_reset_clean() — controller is in a clean initial state.
//
// Event Ring Interception pipeline (poll_event_ring()):
//   1. Read XhciInterrupterState::dequeue_pa — current EL2 read position.
//   2. Cache-invalidate (DC IVAC) the TRB slot before reading.
//   3. If TRB cycle bit == interrupter cycle_bit, the TRB is a valid entry.
//   4. For Transfer Event TRBs (type 32) with Completion Code 1 (Success):
//      a. Read TRB Pointer field — PA of the completed Normal TRB.
//      b. Cache-invalidate and read the Normal TRB at that address.
//      c. Normal TRB parameter[63:0] is the data buffer PA where xHCI wrote
//         the 8-byte USB HID boot-protocol keyboard report.
//      d. Cache-invalidate and read 8 bytes from the data buffer PA.
//   5. Advance dequeue_pa to the next TRB; toggle cycle_bit on segment wrap.
//   6. Write ERDP back to the interrupter with EHB=1 to clear Event Handler Busy.
//
// xHCI Capability Register offsets (relative to BAR0, xHCI §5.3):
//   CAPLENGTH: 0x00 (u8)   HCIVERSION: 0x02 (u16)   RTSOFF: 0x18 (u32)
//
// xHCI Operational Register offsets (relative to BAR0 + CAPLENGTH, xHCI §5.4):
//   USBCMD: 0x00   USBSTS: 0x04
//
// xHCI Runtime Interrupter 0 offsets (relative to BAR0 + RTSOFF + 0x20):
//   IMAN: 0x00   IMOD: 0x04   ERSTSZ: 0x08   ERSTBA: 0x10   ERDP: 0x18
//
// HCRST sequence (xHCI §4.2):
//   1. If USBCMD.RS=1: clear RS, poll USBSTS.HCH=1 (≤16 ms per spec).
//   2. Write USBCMD.HCRST=1.
//   3. Poll USBCMD.HCRST=0 (hardware clears; ≤1 second per spec).
//
// References:
//   xHCI Specification 1.2 (Intel) §4.2, §5.3, §5.4, §5.5.4, §6.4.2
//   USB HID Class Specification 1.11 §7.2 (Boot Protocol report format)
//   ARM SMMU v3 IHI0070E §3.4 / §3.6 — STE format and write ordering
//   PCIe Base Specification 5.0 §7.5.1 — Command register (BME = bit 2)
//   linux-ref/drivers/usb/host/xhci.c — xhci_halt(), xhci_reset() reference
//   linux-ref/drivers/hid/usbhid/usbkbd.c — USB keyboard HID driver reference

use crate::arm64::barriers::dsb_ish;
use crate::memory::{
    BumpAllocator, MapKind, SmmuSte, SmmuStreamTable, Stage2Tables, SMMU_MAX_STREAMS,
};
use crate::partition::GuestId;
use crate::passthrough::{scan_bars, AssignError, PcieAddr, PcieEcam};
use crate::pcie_assignment::{enable_bus_master, map_ecam_window, AssignmentError, EcamWindow};
use crate::usb::{
    UsbController, UsbControllerKind, UsbError, UsbPartitionState,
    SwitchResult, XhciResetState,
};

// ─────────────────────────────────────────────────────────────────────────────
// xHCI MMIO register constants
// ─────────────────────────────────────────────────────────────────────────────

/// CAPLENGTH offset within BAR0 (1 byte — length of capability register space).
/// Operational registers start at BAR0 + CAPLENGTH. xHCI §5.3.1.
const XHCI_CAPLENGTH_OFF: usize = 0x00;

/// RTSOFF offset within BAR0 (u32, bits [31:5] — Runtime Register Space Offset
/// from BAR0; always 32-byte aligned). xHCI §5.3.8.
const XHCI_RTSOFF_OFF: usize = 0x18;

/// USBCMD offset within the Operational Register Space (BAR0 + CAPLENGTH).
const XHCI_OP_USBCMD_OFF: usize = 0x00;

/// USBSTS offset within the Operational Register Space.
const XHCI_OP_USBSTS_OFF: usize = 0x04;

/// USBCMD: Run/Stop bit (bit 0). Clear to halt the controller.
const USBCMD_RS: u32 = 1 << 0;

/// USBCMD: Host Controller Reset (bit 1). Write 1; hardware clears to 0 on done.
const USBCMD_HCRST: u32 = 1 << 1;

/// USBSTS: HC Halted (bit 0). Set when the controller is stopped (RS=0).
/// Must be 1 before HCRST can be issued (xHCI §4.2).
const USBSTS_HCH: u32 = 1 << 0;

/// IMAN offset within Interrupter 0 register set (runtime_base + 0x20 + 0x00).
const XHCI_IR0_IMAN_OFF: usize = 0x00;

/// ERSTSZ offset within Interrupter 0 (lower 16 bits = segment count).
const XHCI_IR0_ERSTSZ_OFF: usize = 0x08;

/// ERSTBA offset within Interrupter 0 (64-bit; segment table base address).
const XHCI_IR0_ERSTBA_OFF: usize = 0x10;

/// ERDP offset within Interrupter 0 (64-bit; event ring dequeue pointer).
/// bit 3: EHB (Event Handler Busy) — write 1 to clear and stop IRQ reassertion.
const XHCI_IR0_ERDP_OFF: usize = 0x18;

/// ERDP EHB bit (bit 3). Write alongside the updated ERDP to deassert interrupt.
const XHCI_ERDP_EHB: u64 = 1 << 3;

/// Polling budget for USBCMD.HCRST to clear. Each iteration reads one MMIO
/// register (~1 µs at EL2). 10 000 iterations ≈ 10 ms, within the 1-second
/// xHCI spec limit. Matches the poll budget in Linux xhci_reset().
const HCRST_POLL_MAX: usize = 10_000;

/// Polling budget for USBSTS.HCH to assert after clearing USBCMD.RS.
/// xHCI §4.2 requires ≤16 ms; 20 000 iterations comfortably covers this.
const HALT_POLL_MAX: usize = 20_000;

// ─────────────────────────────────────────────────────────────────────────────
// xHCI TRB format
//
// Every TRB (Transfer Request Block) is 16 bytes:
//   bytes  0–7:  Parameter (varies by TRB type)
//   bytes  8–11: Status
//   bytes 12–15: Control
//     bit  0:         Cycle bit (C) — producer/consumer phase flag
//     bits [15:10]:   TRB Type
//
// The initial producer cycle bit is 1. Consumer advances the dequeue pointer
// and toggles cycle_bit when the ring wraps.
// ─────────────────────────────────────────────────────────────────────────────

/// Raw xHCI Transfer Request Block (16 bytes, xHCI §6.4).
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct XhciTrb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl XhciTrb {
    /// Cycle bit: control[0].
    pub fn cycle_bit(&self) -> bool {
        self.control & 0x1 != 0
    }

    /// TRB Type field: control[15:10].
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Completion Code from Status[31:24]. Only valid for Event TRBs.
    pub fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }
}

/// TRB Type value for a Transfer Event TRB (xHCI §6.4.2.1, Table 6-38).
pub const TRB_TYPE_TRANSFER_EVENT: u8 = 32;

/// Completion Code: Success (xHCI §6.4.5 Table 6-26, code 1).
pub const TRB_COMPLETION_SUCCESS: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// xHCI Event Ring Segment Table Entry (xHCI §6.5)
//
// The ERSTBA (Event Ring Segment Table Base Address) points to an array of
// these 16-byte entries. Each entry describes one contiguous TRB segment.
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the xHCI Event Ring Segment Table.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct XhciErstEntry {
    /// Physical address of the event ring TRB segment (64-byte aligned).
    pub segment_base_pa: u64,
    /// Lower 16 bits: number of TRBs in this segment; upper bits RsvdZ.
    pub segment_size_and_reserved: u64,
}

impl XhciErstEntry {
    pub const fn new(base_pa: u64, size: u16) -> Self {
        Self {
            segment_base_pa: base_pa,
            segment_size_and_reserved: size as u64,
        }
    }

    pub fn segment_size(&self) -> u16 {
        (self.segment_size_and_reserved & 0xFFFF) as u16
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EL2 Event Ring Monitor
//
// AETHER allocates a private event ring segment in BSS. During the boot-time
// window before the Android USB driver takes over, AETHER programmes this
// segment into Interrupter 0 and polls it for keyboard Transfer Event TRBs.
//
// Once Android's xHCI driver initialises the controller, it reprograms ERSTBA
// and ERDP, and the EL2 ring is no longer used.
//
// 16 TRBs is sufficient: a keyboard produces at most one Transfer Event TRB
// per key press; during the brief boot window at most a few presses occur.
// ─────────────────────────────────────────────────────────────────────────────

const EL2_EVENT_RING_DEPTH: usize = 16;

/// EL2-private event ring TRB segment (4096-byte aligned satisfies xHCI §6.5
/// requirement for 64-byte alignment and is cache-line friendly).
#[repr(C, align(4096))]
struct El2EventRingBuf([XhciTrb; EL2_EVENT_RING_DEPTH]);

static mut EL2_EVENT_RING_BUF: El2EventRingBuf = El2EventRingBuf([XhciTrb {
    parameter: 0,
    status: 0,
    control: 0,
}; EL2_EVENT_RING_DEPTH]);

/// EL2-private Event Ring Segment Table (one entry for the single EL2 segment).
#[repr(C, align(64))]
struct El2ErstBuf(XhciErstEntry);

static mut EL2_ERST_BUF: El2ErstBuf = El2ErstBuf(XhciErstEntry {
    segment_base_pa: 0,
    segment_size_and_reserved: EL2_EVENT_RING_DEPTH as u64,
});

// ─────────────────────────────────────────────────────────────────────────────
// XhciInterrupterState — EL2 event ring consumer position
// ─────────────────────────────────────────────────────────────────────────────

/// EL2 consumer state for one xHCI interrupter's event ring.
///
/// Tracks the current dequeue pointer and producer cycle bit so AETHER can
/// correctly identify new TRBs written by the controller.
#[derive(Clone, Copy, Debug)]
pub struct XhciInterrupterState {
    /// Physical address of the next TRB for AETHER to read (16-byte aligned).
    pub dequeue_pa: u64,
    /// Current consumer cycle bit. TRBs with this cycle bit are valid entries.
    pub cycle_bit: bool,
    /// Physical base address of the single event ring segment.
    pub segment_base_pa: u64,
    /// Number of TRBs in the segment.
    pub segment_size: u16,
}

impl XhciInterrupterState {
    /// Advance dequeue_pa to the next TRB. Toggle cycle_bit on segment wrap.
    fn advance(&mut self) {
        let next = self.dequeue_pa + core::mem::size_of::<XhciTrb>() as u64;
        let segment_end = self.segment_base_pa
            + (self.segment_size as u64) * core::mem::size_of::<XhciTrb>() as u64;
        if next >= segment_end {
            self.dequeue_pa = self.segment_base_pa;
            self.cycle_bit = !self.cycle_bit;
        } else {
            self.dequeue_pa = next;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB HID keyboard report (USB HID Class §7.2 Boot Protocol)
//
// 8-byte boot-protocol report layout:
//   Byte 0: Modifier keys (bitmask: bit0=LCtrl, bit1=LShift, bit2=LAlt, ...)
//   Byte 1: Reserved (0x00)
//   Bytes 2–7: Up to 6 simultaneously pressed keycodes
//
// AETHER intercepts these at EL2 by reading from the DMA buffer pointed to by
// the completed Normal TRB. Reports are never forwarded to any guest.
// ─────────────────────────────────────────────────────────────────────────────

/// An 8-byte USB HID keyboard boot-protocol report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidReport(pub [u8; 8]);

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by Ch41 USB passthrough operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbPassthroughError {
    /// No BARs found for the xHCI controller. BDF is wrong or config space
    /// is unresponsive.
    BarNotFound,
    /// Stage 2 mapping or ECAM window mapping failed.
    MapFailed(AssignmentError),
    /// A stream_id value equals or exceeds SMMU_MAX_STREAMS.
    SmmuStreamIdOutOfRange,
    /// xHCI HCRST did not clear within HCRST_POLL_MAX iterations.
    HcrstTimeout,
    /// USBSTS.HCH did not assert within HALT_POLL_MAX iterations after RS clear.
    HaltTimeout,
    /// UsbPartitionRegistry operation failed (e.g. RegistryFull, NotFound).
    RegistryError(UsbError),
}

impl From<UsbError> for UsbPassthroughError {
    fn from(e: UsbError) -> Self {
        UsbPassthroughError::RegistryError(e)
    }
}

impl From<AssignmentError> for UsbPassthroughError {
    fn from(e: AssignmentError) -> Self {
        UsbPassthroughError::MapFailed(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for assigning one xHCI controller to the Android partition.
#[derive(Clone, Copy, Debug)]
pub struct UsbPassthroughConfig {
    /// PCIe BDF of the xHCI controller.
    pub ctrl_addr: PcieAddr,
    /// ECAM config-space window covering the controller's PCIe bus segment.
    pub ecam_window: EcamWindow,
    /// Physical address of xHCI BAR0 (capability register base).
    /// Read from the BAR0 register in ECAM config space before calling.
    pub bar0_pa: u64,
    /// Android guest VMID for SMMU Stage 2 translation.
    pub vmid: u8,
    /// Physical address of the Android guest's Stage 2 translation table root.
    pub s2ttb_pa: u64,
    /// SMMU stream IDs for the xHCI controller.
    pub stream_ids: [u32; 2],
    /// Physical role of this controller (IntegratedInput or External*).
    pub kind: UsbControllerKind,
}

impl UsbPassthroughConfig {
    /// Validate basic invariants before issuing any hardware sequences.
    pub fn validate(&self) -> Result<(), UsbPassthroughError> {
        // ECAM bus range must be non-empty and ctrl_addr must be inside it.
        if self.ctrl_addr.bus < self.ecam_window.start_bus
            || self.ctrl_addr.bus > self.ecam_window.end_bus
        {
            return Err(UsbPassthroughError::MapFailed(AssignmentError::InvalidBusRange));
        }
        // stream_ids must be within the SMMU table.
        for &sid in &self.stream_ids {
            if sid as usize >= SMMU_MAX_STREAMS {
                return Err(UsbPassthroughError::SmmuStreamIdOutOfRange);
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate
// ─────────────────────────────────────────────────────────────────────────────

/// Ch41 verification gate.
///
/// **Verification in Android:**
/// - `keyboard_enumerated`: `ls /dev/input/by-id/` shows a USB HID keyboard;
///   `adb shell getevent` shows key events on key press.
/// - `input_switch_ready`: press Ctrl+Alt+Tab — input focus moves to the other
///   partition without any reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbPassthroughGate {
    /// True when ≥1 xHCI BAR mapped in Stage 2, SMMU STE in translated mode,
    /// ECAM window mapped, and HCRST completed. Android's xHCI driver can
    /// enumerate USB devices on this controller.
    pub keyboard_enumerated: bool,
    /// True when configure_input_switch() succeeded and Ctrl+Alt+Tab fires
    /// without reboot.
    pub input_switch_ready: bool,
}

impl UsbPassthroughGate {
    pub fn passes(&self) -> bool {
        self.keyboard_enumerated && self.input_switch_ready
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MMIO helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must be the physical address of a valid xHCI BAR0, identity-mapped.
unsafe fn mmio_read32(base: u64, offset: usize) -> u32 {
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

/// Write a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// Same as `mmio_read32`.
unsafe fn mmio_write32(base: u64, offset: usize, val: u32) {
    unsafe { ((base as usize + offset) as *mut u32).write_volatile(val) }
}

/// Write a 64-bit MMIO register as two 32-bit writes (lo-word first).
///
/// # Safety
/// Same as `mmio_read32`.
unsafe fn mmio_write64(base: u64, offset: usize, val: u64) {
    unsafe {
        mmio_write32(base, offset, val as u32);
        mmio_write32(base, offset + 4, (val >> 32) as u32);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D-cache maintenance
// ─────────────────────────────────────────────────────────────────────────────

/// D-cache invalidate by VA to PoC. Ensures a subsequent read sees DMA-written
/// data from DRAM rather than a stale EL2 cache line.
///
/// # Safety
/// `pa` must be a valid physical address accessible at EL2.
#[inline(always)]
unsafe fn dc_ivac(pa: u64) {
    unsafe {
        core::arch::asm!(
            "dc ivac, {x}",
            x = in(reg) pa,
            options(nostack, preserves_flags),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// xHCI register base computation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the xHCI Operational Register base: BAR0 + CAPLENGTH.
///
/// CAPLENGTH is a read-only 1-byte field at BAR0 + 0x00. The operational
/// register space starts immediately after the capability registers.
///
/// # Safety
/// `bar0` must be identity-mapped at EL2 as DeviceRw.
unsafe fn xhci_op_base(bar0: u64) -> u64 {
    let caplength =
        unsafe { ((bar0 as usize + XHCI_CAPLENGTH_OFF) as *const u8).read_volatile() };
    bar0 + caplength as u64
}

/// Compute the xHCI Runtime Register base: BAR0 + (RTSOFF & !0x1F).
///
/// RTSOFF is a 32-bit field at BAR0 + 0x18. Bits [4:0] are RsvdP; the offset
/// is always 32-byte aligned.
///
/// # Safety
/// `bar0` must be identity-mapped at EL2 as DeviceRw.
unsafe fn xhci_rt_base(bar0: u64) -> u64 {
    let rtsoff = unsafe { mmio_read32(bar0, XHCI_RTSOFF_OFF) };
    bar0 + (rtsoff & !0x1Fu32) as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// xHCI halt and reset
// ─────────────────────────────────────────────────────────────────────────────

/// Halt the xHCI controller by clearing USBCMD.RS and polling USBSTS.HCH=1.
///
/// No-op if the controller is already halted. Must succeed before HCRST.
///
/// # Safety
/// `bar0` must be identity-mapped at EL2.
unsafe fn xhci_halt(bar0: u64) -> Result<(), UsbPassthroughError> {
    let op_base = unsafe { xhci_op_base(bar0) };
    let sts = unsafe { mmio_read32(op_base, XHCI_OP_USBSTS_OFF) };
    if sts & USBSTS_HCH != 0 {
        return Ok(()); // Already halted.
    }
    // Clear Run/Stop.
    let cmd = unsafe { mmio_read32(op_base, XHCI_OP_USBCMD_OFF) };
    unsafe { mmio_write32(op_base, XHCI_OP_USBCMD_OFF, cmd & !USBCMD_RS) };
    // Poll for HCH=1.
    for _ in 0..HALT_POLL_MAX {
        let sts2 = unsafe { mmio_read32(op_base, XHCI_OP_USBSTS_OFF) };
        if sts2 & USBSTS_HCH != 0 {
            return Ok(());
        }
    }
    Err(UsbPassthroughError::HaltTimeout)
}

/// Issue xHCI HCRST and poll until hardware clears the bit.
///
/// After HCRST completes all TRB ring state, doorbell state, and port state
/// are reset to initial values. The guest USB driver must re-initialize before
/// using the controller.
///
/// # Safety
/// `bar0` must be identity-mapped; controller must be halted (HCH=1).
unsafe fn xhci_hcrst(bar0: u64) -> Result<(), UsbPassthroughError> {
    let op_base = unsafe { xhci_op_base(bar0) };
    unsafe { mmio_write32(op_base, XHCI_OP_USBCMD_OFF, USBCMD_HCRST) };
    for _ in 0..HCRST_POLL_MAX {
        let cmd = unsafe { mmio_read32(op_base, XHCI_OP_USBCMD_OFF) };
        if cmd & USBCMD_HCRST == 0 {
            return Ok(());
        }
    }
    Err(UsbPassthroughError::HcrstTimeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// SMMU STE rewrite helper
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite one SMMU STE to point at a new guest's Stage 2 tables.
///
/// Enforces the mandatory write ordering: words 1–7 written first → DSB ISH
/// → word 0. This is the only safe order per IHI0070E §3.6 — writing word 0
/// first allows the SMMU to observe a partially-written STE as valid.
///
/// # Safety
/// `stream_id < SMMU_MAX_STREAMS`; `smmu` must be initialised.
unsafe fn rewrite_ste(
    smmu: &mut SmmuStreamTable,
    stream_id: u32,
    vmid: u8,
    s2ttb_pa: u64,
) -> Result<(), UsbPassthroughError> {
    if stream_id as usize >= SMMU_MAX_STREAMS {
        return Err(UsbPassthroughError::SmmuStreamIdOutOfRange);
    }
    let ste = SmmuSte::stage2_only(vmid as u16, s2ttb_pa);
    // SAFETY: checked stream_id < SMMU_MAX_STREAMS above.
    unsafe { smmu.write_ste(stream_id as usize, ste) };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Event ring polling
// ─────────────────────────────────────────────────────────────────────────────

/// Read one xHCI TRB from a physical address with D-cache invalidation.
///
/// # Safety
/// `pa` must be a valid 16-byte-aligned TRB physical address, accessible at EL2.
unsafe fn read_trb(pa: u64) -> XhciTrb {
    unsafe {
        dc_ivac(pa);
        dsb_ish();
        (pa as *const XhciTrb).read_volatile()
    }
}

/// Read the 8-byte HID keyboard report from a DMA buffer physical address.
///
/// # Safety
/// `pa` must be the physical address of an 8-byte buffer populated by the xHCI
/// controller via DMA.
unsafe fn read_hid_report(pa: u64) -> HidReport {
    unsafe {
        dc_ivac(pa);
        dsb_ish();
        let raw = (pa as *const [u8; 8]).read_volatile();
        HidReport(raw)
    }
}

/// Poll the EL2-resident event ring for one Transfer Event TRB carrying a USB
/// HID keyboard report. Returns the report if a valid entry is found; None if
/// the ring is empty (no new TRBs from the controller).
///
/// Advances the interrupter state and writes the updated ERDP with EHB=1 to
/// clear the Event Handler Busy flag and deassert the IRQ line.
///
/// Called from the EL2 IRQ handler; call in a loop to drain the ring.
///
/// # Safety
/// - `bar0` must be identity-mapped at EL2.
/// - `interrupter` must reflect the actual consumer state of Interrupter 0.
/// - The event ring segment at `interrupter.segment_base_pa` must be EL2-accessible.
pub unsafe fn poll_event_ring(
    bar0: u64,
    interrupter: &mut XhciInterrupterState,
) -> Option<HidReport> {
    let trb = unsafe { read_trb(interrupter.dequeue_pa) };

    // Cycle bit mismatch: no new TRB; ring is empty.
    if trb.cycle_bit() != interrupter.cycle_bit {
        return None;
    }

    // Advance past non-Transfer-Event TRBs (Link TRBs, etc.).
    if trb.trb_type() != TRB_TYPE_TRANSFER_EVENT {
        interrupter.advance();
        // Write ERDP to update our read position (EHB=1 to deassert interrupt).
        let rt_base = unsafe { xhci_rt_base(bar0) };
        let ir0_base = rt_base + 0x20;
        let new_erdp = (interrupter.dequeue_pa & !0xF) | XHCI_ERDP_EHB;
        unsafe { mmio_write64(ir0_base, XHCI_IR0_ERDP_OFF, new_erdp) };
        return None;
    }

    // Skip Transfer Event TRBs that are not successful completions.
    if trb.completion_code() != TRB_COMPLETION_SUCCESS {
        interrupter.advance();
        return None;
    }

    // Transfer Event TRB parameter = TRB Pointer (PA of the completed Normal TRB).
    let normal_trb_pa = trb.parameter;
    let normal_trb = unsafe { read_trb(normal_trb_pa) };
    // Normal TRB parameter = Data Buffer Pointer (where xHCI wrote the HID data).
    let data_buf_pa = normal_trb.parameter;

    let report = unsafe { read_hid_report(data_buf_pa) };

    interrupter.advance();

    // Update ERDP with EHB=1 to deassert the interrupt line.
    let rt_base = unsafe { xhci_rt_base(bar0) };
    let ir0_base = rt_base + 0x20;
    let new_erdp = (interrupter.dequeue_pa & !0xF) | XHCI_ERDP_EHB;
    unsafe { mmio_write64(ir0_base, XHCI_IR0_ERDP_OFF, new_erdp) };

    Some(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// EL2 event ring initialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Programme xHCI Interrupter 0 with the EL2-resident event ring segment.
///
/// Sets up the ERST so the xHCI controller writes Transfer Event TRBs for
/// keyboard interrupt completions into EL2's private ring. Returns the initial
/// `XhciInterrupterState` for use in `poll_event_ring()` calls.
///
/// Call AFTER `assign_xhci_controller()` (BAR mapped, HCRST done) and BEFORE
/// the Android USB driver initialises (which will reprogram ERSTBA / ERDP).
///
/// # Safety
/// `bar0_pa` must be identity-mapped at EL2 as DeviceRw.
pub unsafe fn init_el2_event_ring(bar0_pa: u64) -> XhciInterrupterState {
    use core::ptr::addr_of_mut;

    let ring_pa = addr_of_mut!(EL2_EVENT_RING_BUF) as u64;
    let erst_pa = addr_of_mut!(EL2_ERST_BUF) as u64;

    // Fill in the ERST entry.
    unsafe {
        (*addr_of_mut!(EL2_ERST_BUF)).0.segment_base_pa = ring_pa;
        (*addr_of_mut!(EL2_ERST_BUF)).0.segment_size_and_reserved = EL2_EVENT_RING_DEPTH as u64;
    }

    let rt_base = unsafe { xhci_rt_base(bar0_pa) };
    let ir0_base = rt_base + 0x20;

    // Disable the interrupter interrupt enable bit while reprogramming.
    let iman = unsafe { mmio_read32(ir0_base, XHCI_IR0_IMAN_OFF) };
    unsafe { mmio_write32(ir0_base, XHCI_IR0_IMAN_OFF, iman & !0x2) };

    // Programme one segment in ERSTSZ.
    unsafe { mmio_write32(ir0_base, XHCI_IR0_ERSTSZ_OFF, 1) };

    // Write the Segment Table Base Address.
    unsafe { mmio_write64(ir0_base, XHCI_IR0_ERSTBA_OFF, erst_pa) };

    // Set ERDP to the start of the ring (initial consumer position).
    unsafe { mmio_write64(ir0_base, XHCI_IR0_ERDP_OFF, ring_pa) };

    dsb_ish();

    XhciInterrupterState {
        dequeue_pa: ring_pa,
        cycle_bit: true, // initial consumer cycle bit per xHCI §4.9.2
        segment_base_pa: ring_pa,
        segment_size: EL2_EVENT_RING_DEPTH as u16,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main assignment pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Assign an xHCI controller to the Android partition.
///
/// Executes the 7-step assignment pipeline. On success, the controller is
/// registered in `usb_state` with `smmu_configured=true` and `reset_state=Clean`.
///
/// For `UsbControllerKind::IntegratedInput`, call
/// `usb_state.configure_input_switch(GuestId::Android, InputPath::UsbHid)`
/// after this returns to arm the Ctrl+Alt+Tab switch.
///
/// # Safety
/// All physical addresses in `config` must be identity-mapped at EL2.
pub unsafe fn assign_xhci_controller(
    config: &UsbPassthroughConfig,
    ecam: &PcieEcam,
    s2: &Stage2Tables,
    smmu: &mut SmmuStreamTable,
    alloc: &mut BumpAllocator,
    usb_state: &mut UsbPartitionState,
) -> Result<UsbPassthroughGate, UsbPassthroughError> {
    // Step 1: Validate config.
    config.validate()?;

    // Step 2: BAR scan → Stage 2 DeviceRw mapping (IPA == PA).
    let bars = unsafe { scan_bars(ecam, config.ctrl_addr) };
    let mut bars_mapped: u32 = 0;
    for bar in bars.iter().flatten() {
        unsafe {
            s2.map_range(bar.pa, bar.pa, bar.size, MapKind::DeviceRw, alloc)
                .map_err(|e| {
                    UsbPassthroughError::MapFailed(AssignmentError::Passthrough(
                        AssignError::MapFailed(e),
                    ))
                })?;
        }
        bars_mapped += 1;
    }
    if bars_mapped == 0 {
        return Err(UsbPassthroughError::BarNotFound);
    }

    // Step 3: SMMU STEs (stage2_only; write_ste enforces words 1–7 → DSB → word 0).
    for &stream_id in &config.stream_ids {
        unsafe { rewrite_ste(smmu, stream_id, config.vmid, config.s2ttb_pa)? };
    }

    // Step 4: ECAM config-space window → Stage 2 DeviceRw.
    unsafe {
        map_ecam_window(config.ecam_window, s2, alloc)
            .map_err(UsbPassthroughError::MapFailed)?;
    }

    // Step 5: Bus Master Enable (re-assert after FLR or firmware reset).
    unsafe { enable_bus_master(ecam, config.ctrl_addr) };

    // Step 6: Halt then HCRST — clears all TRB ring and port state.
    unsafe { xhci_halt(config.bar0_pa)? };
    unsafe { xhci_hcrst(config.bar0_pa)? };

    // Step 7: Register in UsbPartitionRegistry.
    let ctrl = UsbController {
        addr: config.ctrl_addr,
        kind: config.kind,
        assigned_guest: GuestId::Android,
        reset_state: XhciResetState::Clean,
        smmu_configured: true,
    };
    usb_state.register_controller(ctrl)?;

    Ok(UsbPassthroughGate {
        keyboard_enumerated: true,
        // input_switch_ready becomes true after configure_input_switch() succeeds.
        input_switch_ready: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Input switch execution
// ─────────────────────────────────────────────────────────────────────────────

/// Execute the hardware portion of the Ctrl+Alt+Tab input switch.
///
/// Called ONLY from the EL2 exception handler after `process_hid_report`
/// returns `HidAction::Switch`. Must never be reachable via a guest hypercall.
///
/// Pipeline:
///   1. Halt xHCI (USBCMD.RS=0, await USBSTS.HCH=1).
///   2. Issue HCRST (USBCMD.HCRST=1, await HCRST=0).
///   3. Rewrite SMMU STEs with the new guest's VMID and Stage 2 base.
///   4. Transfer ownership in UsbPartitionState::execute_switch().
///   5. Mark the controller reset_state=Clean.
///
/// Neither guest receives the triggering Ctrl+Alt+Tab key events.
///
/// # Safety
/// `bar0_pa` must be identity-mapped at EL2.
pub unsafe fn execute_xhci_input_switch(
    bar0_pa: u64,
    new_vmid: u8,
    new_s2ttb_pa: u64,
    stream_ids: &[u32; 2],
    smmu: &mut SmmuStreamTable,
    usb_state: &mut UsbPartitionState,
) -> Result<SwitchResult, UsbPassthroughError> {
    // Step 1+2: Halt then HCRST.
    unsafe { xhci_halt(bar0_pa)? };
    unsafe { xhci_hcrst(bar0_pa)? };

    // Step 3: Rewrite SMMU STEs with new guest VMID.
    for &sid in stream_ids {
        unsafe { rewrite_ste(smmu, sid, new_vmid, new_s2ttb_pa)? };
    }

    // Step 4: Transfer ownership (updates registry and switch counter).
    let result = usb_state.execute_switch()?;

    // Step 5: Mark controller as clean (HCRST issued above).
    let addr = usb_state
        .registry
        .integrated_input_addr()
        .ok_or(UsbError::NoInputController)?;
    usb_state.registry.mark_reset_clean(addr)?;

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::GuestId;
    use crate::usb::{HidAction, InputPath, UsbController, UsbControllerKind, XhciResetState};

    // ── XhciTrb ──────────────────────────────────────────────────────────────

    fn make_trb(parameter: u64, status: u32, trb_type: u8, cycle: bool) -> XhciTrb {
        let control = ((trb_type as u32) << 10) | (cycle as u32);
        XhciTrb { parameter, status, control }
    }

    #[test]
    fn test_trb_cycle_bit_true() {
        let trb = make_trb(0, 0, TRB_TYPE_TRANSFER_EVENT, true);
        assert!(trb.cycle_bit());
    }

    #[test]
    fn test_trb_cycle_bit_false() {
        let trb = make_trb(0, 0, TRB_TYPE_TRANSFER_EVENT, false);
        assert!(!trb.cycle_bit());
    }

    #[test]
    fn test_trb_type_transfer_event() {
        let trb = make_trb(0, 0, TRB_TYPE_TRANSFER_EVENT, true);
        assert_eq!(trb.trb_type(), TRB_TYPE_TRANSFER_EVENT);
    }

    #[test]
    fn test_trb_type_normal() {
        let trb = make_trb(0, 0, 1, true); // type 1 = Normal TRB
        assert_ne!(trb.trb_type(), TRB_TYPE_TRANSFER_EVENT);
    }

    #[test]
    fn test_trb_completion_code_success() {
        let trb = make_trb(0, (TRB_COMPLETION_SUCCESS as u32) << 24, 32, true);
        assert_eq!(trb.completion_code(), TRB_COMPLETION_SUCCESS);
    }

    #[test]
    fn test_trb_completion_code_zero() {
        let trb = make_trb(0, 0, 32, true);
        assert_eq!(trb.completion_code(), 0);
    }

    // ── XhciErstEntry ─────────────────────────────────────────────────────────

    #[test]
    fn test_erst_entry_fields() {
        let entry = XhciErstEntry::new(0xCAFE_0000, 16);
        assert_eq!(entry.segment_base_pa, 0xCAFE_0000);
        assert_eq!(entry.segment_size(), 16);
    }

    #[test]
    fn test_erst_entry_size_boundary() {
        let entry = XhciErstEntry::new(0, 0xFFFF);
        assert_eq!(entry.segment_size(), 0xFFFF);
    }

    // ── XhciInterrupterState::advance ─────────────────────────────────────────

    #[test]
    fn test_advance_no_wrap() {
        let mut state = XhciInterrupterState {
            dequeue_pa: 0x1000,
            cycle_bit: true,
            segment_base_pa: 0x1000,
            segment_size: 4,
        };
        state.advance();
        assert_eq!(state.dequeue_pa, 0x1010);
        assert!(state.cycle_bit);
    }

    #[test]
    fn test_advance_wraps_at_end() {
        let base = 0x2000u64;
        let size = 2u16;
        // Start at the last slot: base + (size-1)*16 = base + 16.
        let mut state = XhciInterrupterState {
            dequeue_pa: base + 16,
            cycle_bit: true,
            segment_base_pa: base,
            segment_size: size,
        };
        state.advance();
        assert_eq!(state.dequeue_pa, base);
        assert!(!state.cycle_bit); // toggled on wrap
    }

    #[test]
    fn test_advance_double_wrap_restores_cycle() {
        let base = 0x3000u64;
        let mut state = XhciInterrupterState {
            dequeue_pa: base + 16, // last slot of 2
            cycle_bit: false,
            segment_base_pa: base,
            segment_size: 2,
        };
        state.advance(); // wrap → cycle_bit = true
        assert!(state.cycle_bit);
        state.advance(); // no wrap
        state.advance(); // wrap again → cycle_bit = false
        assert!(!state.cycle_bit);
    }

    // ── UsbPassthroughConfig::validate ────────────────────────────────────────

    fn make_config(stream_ids: [u32; 2]) -> UsbPassthroughConfig {
        UsbPassthroughConfig {
            ctrl_addr: PcieAddr::new(0, 1, 0),
            ecam_window: EcamWindow::new(0x1000_0000, 0, 2).unwrap(),
            bar0_pa: 0x8000_0000,
            vmid: 1,
            s2ttb_pa: 0x4000_0000,
            stream_ids,
            kind: UsbControllerKind::IntegratedInput,
        }
    }

    #[test]
    fn test_config_validate_ok() {
        assert!(make_config([0, 1]).validate().is_ok());
    }

    #[test]
    fn test_config_validate_stream_id_out_of_range() {
        let cfg = make_config([0, SMMU_MAX_STREAMS as u32]);
        assert_eq!(
            cfg.validate(),
            Err(UsbPassthroughError::SmmuStreamIdOutOfRange)
        );
    }

    #[test]
    fn test_config_validate_ctrl_addr_outside_ecam() {
        let cfg = UsbPassthroughConfig {
            ctrl_addr: PcieAddr::new(5, 0, 0), // bus 5 outside [0, 2]
            ecam_window: EcamWindow::new(0x1000_0000, 0, 2).unwrap(),
            bar0_pa: 0,
            vmid: 1,
            s2ttb_pa: 0,
            stream_ids: [0, 1],
            kind: UsbControllerKind::ExternalUsbA,
        };
        assert_eq!(
            cfg.validate(),
            Err(UsbPassthroughError::MapFailed(AssignmentError::InvalidBusRange))
        );
    }

    // ── UsbPassthroughGate ────────────────────────────────────────────────────

    #[test]
    fn test_gate_both_true() {
        let g = UsbPassthroughGate {
            keyboard_enumerated: true,
            input_switch_ready: true,
        };
        assert!(g.passes());
    }

    #[test]
    fn test_gate_keyboard_false() {
        let g = UsbPassthroughGate {
            keyboard_enumerated: false,
            input_switch_ready: true,
        };
        assert!(!g.passes());
    }

    #[test]
    fn test_gate_switch_false() {
        let g = UsbPassthroughGate {
            keyboard_enumerated: true,
            input_switch_ready: false,
        };
        assert!(!g.passes());
    }

    // ── HidReport ─────────────────────────────────────────────────────────────

    #[test]
    fn test_hid_report_ctrl_alt_tab() {
        use crate::usb::InputSwitchTrigger;
        // Byte 0: LCtrl(bit0) + LAlt(bit2) = 0x05; Byte 2: Tab = 0x2B.
        let report = HidReport([0x05, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(InputSwitchTrigger::DEFAULT.matches_hid_report(&report.0));
    }

    #[test]
    fn test_hid_report_ordinary_key_no_trigger() {
        use crate::usb::InputSwitchTrigger;
        let report = HidReport([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]); // 'a'
        assert!(!InputSwitchTrigger::DEFAULT.matches_hid_report(&report.0));
    }

    // ── Error From conversions ────────────────────────────────────────────────

    #[test]
    fn test_error_from_usb_error() {
        let e: UsbPassthroughError = UsbError::NoInputController.into();
        assert_eq!(e, UsbPassthroughError::RegistryError(UsbError::NoInputController));
    }

    #[test]
    fn test_error_from_assignment_error() {
        let e: UsbPassthroughError = AssignmentError::InvalidBusRange.into();
        assert_eq!(e, UsbPassthroughError::MapFailed(AssignmentError::InvalidBusRange));
    }

    // ── UsbPartitionState interaction ─────────────────────────────────────────

    fn make_integrated_input_state(initial_owner: GuestId) -> UsbPartitionState {
        let mut state = UsbPartitionState::new();
        let ctrl = UsbController {
            addr: PcieAddr::new(0, 1, 0),
            kind: UsbControllerKind::IntegratedInput,
            assigned_guest: initial_owner,
            reset_state: XhciResetState::Clean,
            smmu_configured: true,
        };
        state.register_controller(ctrl).unwrap();
        state
            .configure_input_switch(initial_owner, InputPath::UsbHid)
            .unwrap();
        state
    }

    #[test]
    fn test_trigger_detection_switch() {
        let mut state = make_integrated_input_state(GuestId::Android);
        let report = HidReport([0x05, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(state.process_hid_report(&report.0), HidAction::Switch);
    }

    #[test]
    fn test_trigger_detection_forward() {
        let mut state = make_integrated_input_state(GuestId::Android);
        let report = HidReport([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(state.process_hid_report(&report.0), HidAction::Forward);
    }

    #[test]
    fn test_execute_switch_ownership_transfer() {
        let mut state = make_integrated_input_state(GuestId::Android);
        let result = state.execute_switch().unwrap();
        assert_eq!(result.old_owner, GuestId::Android);
        assert_eq!(result.new_owner, GuestId::Windows);
        assert_eq!(state.current_input_owner(), Some(GuestId::Windows));
        assert_eq!(state.switch_count(), 1);
    }

    #[test]
    fn test_execute_switch_twice_returns_to_android() {
        let mut state = make_integrated_input_state(GuestId::Android);
        state.execute_switch().unwrap();
        // Re-mark clean so second switch passes SMMU gate.
        let addr = state.registry.integrated_input_addr().unwrap();
        state.registry.mark_reset_clean(addr).unwrap();
        let result = state.execute_switch().unwrap();
        assert_eq!(result.new_owner, GuestId::Android);
        assert_eq!(state.switch_count(), 2);
    }

    #[test]
    fn test_software_switch_rejected() {
        let state = UsbPartitionState::new();
        assert_eq!(state.reject_software_switch(), UsbError::SoftwareSwitchForbidden);
    }
}
