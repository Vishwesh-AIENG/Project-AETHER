// ch37: NVMe Namespace — Functional
//
// Enumerates an NVMe controller via PCIe ECAM MMIO, brings up its Admin
// Submission Queue / Completion Queue, issues the three mandatory admin
// commands, and returns the assigned NsId for the Android partition.
//
// Boot sequence:
//   1. Scan PCIe ECAM for a device with Class=01h / SubClass=08h / ProgIF=02h
//      (NVM Express).  Read BAR0 to obtain the controller MMIO base.
//   2. Reset controller (CC.EN=0), wait CSTS.RDY=0.
//   3. Programme AQA/ASQ/ACQ with the static queue buffers below.
//   4. Set CC.EN=1, wait CSTS.RDY=1.
//   5. Issue Identify Controller (CNS=0x01) — read OACS[3] to confirm
//      Namespace Management support, read NN for maximum namespace count.
//   6. Issue Namespace Management / Create (opcode 0x0D, sel=0x00) — supply
//      the Namespace Create Data Structure (NSZE / NCAP / FLBAS) via PRP1.
//      Completion DW0 returns the new NSID.
//   7. Issue Namespace Attachment / Attach (opcode 0x15, sel=0x00) with a
//      Controller List containing CNTLID=0 (the Admin controller, always
//      present).  NSID in CDW1.
//
// Queue geometry:
//   ADMIN_Q_DEPTH = 4 entries.  AETHER issues at most three admin commands at
//   startup, so 4 slots (with head/tail wrap) is sufficient.
//
// All data buffers are statically allocated in BSS.  No heap allocator is
// needed.  D-cache maintenance is performed around every queue/buffer access
// so the NVMe controller (which is a DMA master) sees coherent data.
//
// Gate: `nvme list` shows NSID 1 with the correct size; `dd if=/dev/zero
//        of=/dev/nvme0n1 bs=4096 count=1` returns exit 0.
//
// References:
//   NVM Express Base Specification r2.1
//     §3.1   Controller registers (CAP / CC / CSTS / AQA / ASQ / ACQ)
//     §3.3   Doorbell registers (offset 0x1000, stride 4 << DSTRD)
//     §4.6   Submission Queue Entry format (64 bytes, CDW0–CDW15)
//     §4.7   Completion Queue Entry format (16 bytes)
//     §5.6   Identify command (opcode 0x06), CNS field
//     §5.15  Namespace Management (opcode 0x0D), selector / data structure
//     §5.16  Namespace Attachment (opcode 0x15), selector / controller list
//   PCI Base Specification 5.0 §7.5.1 — Class/SubClass/ProgIF at offsets 0x0B/0x0A/0x09
//   linux-ref/drivers/nvme/host/pci.c — Linux NVMe PCIe init reference

use core::ptr::{addr_of, addr_of_mut};

use crate::arm64::barriers::{dsb_ish, isb};
use crate::passthrough::{PcieAddr, PcieEcam};
use crate::storage::NsId;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeSetupError {
    /// No PCIe device with NVMe class code found in the scanned BDF range.
    ControllerNotFound,
    /// BAR0 is an I/O BAR or is unimplemented; cannot obtain MMIO base.
    Bar0Invalid,
    /// Controller failed to clear RDY within the reset polling budget.
    ResetTimeout,
    /// Controller failed to assert RDY within the enable polling budget.
    EnableTimeout,
    /// Identify Controller response: OACS[3]=0; Namespace Management absent.
    NamespaceManagementUnsupported,
    /// Namespace Management / Create command returned a non-zero status.
    CreateFailed(u16),
    /// Namespace Attachment / Attach command returned a non-zero status.
    AttachFailed(u16),
    /// The NSID returned in the Create completion was 0 (invalid).
    InvalidNsidReturned,
}

// ─────────────────────────────────────────────────────────────────────────────
// NVMe controller register offsets  (NVMe r2.1 §3.1, Table 3)
// ─────────────────────────────────────────────────────────────────────────────

mod reg {
    /// Controller Capabilities (8 bytes, RO).
    pub const CAP: usize = 0x00;
    /// Controller Configuration (4 bytes, RW).
    pub const CC: usize = 0x14;
    /// Controller Status (4 bytes, RO).
    pub const CSTS: usize = 0x1C;
    /// Admin Queue Attributes (4 bytes, RW).
    pub const AQA: usize = 0x24;
    /// Admin Submission Queue Base Address (8 bytes, RW).
    pub const ASQ: usize = 0x28;
    /// Admin Completion Queue Base Address (8 bytes, RW).
    pub const ACQ: usize = 0x30;

    /// Doorbell base (offset from BAR0).  Admin SQ tail doorbell = 0x1000.
    /// Admin CQ head doorbell = 0x1004 (DSTRD=0, stride = 4 bytes).
    pub const DOORBELL_BASE: usize = 0x1000;
}

// CC field masks / values
const CC_EN: u32 = 1 << 0;
/// CC.CSS=000 (NVM command set), CC.MPS=0 (4KB), CC.AMS=000 (round-robin).
/// IOSQES=6 (64-byte SQE, 2^6), IOCQES=4 (16-byte CQE, 2^4).
const CC_INIT: u32 = (6 << 16) | (4 << 20);

// CSTS field masks
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

// ─────────────────────────────────────────────────────────────────────────────
// PCIe config-space offsets used during enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Vendor ID (16-bit, offset 0x00 in PCIe type-0 header).
const CFG_VENDOR_ID: u16 = 0x00;
/// Class code byte: Class (0x0B), SubClass (0x0A), Prog IF (0x09).
const CFG_CLASS: u16 = 0x0B;
const CFG_SUBCLASS: u16 = 0x0A;
const CFG_PROGIF: u16 = 0x09;
/// BAR0 (offset 0x10).
const CFG_BAR0: u16 = 0x10;
/// BAR1 (offset 0x14) — high dword when BAR0 is a 64-bit BAR.
const CFG_BAR1: u16 = 0x14;
/// PCIe Command register (offset 0x04) — Memory Space Enable is bit 1.
const CFG_CMD: u16 = 0x04;

// NVMe class code: Mass Storage (01h), NVM (08h), NVMe (02h).
const NVME_CLASS: u8 = 0x01;
const NVME_SUBCLASS: u8 = 0x08;
const NVME_PROGIF: u8 = 0x02;

// ─────────────────────────────────────────────────────────────────────────────
// Admin queue entry types  (NVMe r2.1 §4.6, §4.7)
// ─────────────────────────────────────────────────────────────────────────────

/// 64-byte NVMe Submission Queue Entry (16 × u32).
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct AdminSqe {
    pub dw: [u32; 16],
}

impl AdminSqe {
    const fn zeroed() -> Self {
        Self { dw: [0u32; 16] }
    }

    /// CDW0: opcode | fuse=00 | psdt=00 (PRP) | cid.
    fn set_cdw0(&mut self, opcode: u8, cid: u16) {
        self.dw[0] = (opcode as u32) | ((cid as u32) << 16);
    }

    /// CDW1: NSID.
    fn set_nsid(&mut self, nsid: u32) {
        self.dw[1] = nsid;
    }

    /// CDW6–7: PRP1 (physical page address of data buffer).
    fn set_prp1(&mut self, pa: u64) {
        self.dw[6] = pa as u32;
        self.dw[7] = (pa >> 32) as u32;
    }

    /// CDW10: command-specific dword 10.
    fn set_cdw10(&mut self, val: u32) {
        self.dw[10] = val;
    }
}

/// 16-byte NVMe Completion Queue Entry (4 × u32).
#[derive(Clone, Copy)]
#[repr(C, align(4))]
pub struct AdminCqe {
    pub dw: [u32; 4],
}

impl AdminCqe {
    const fn zeroed() -> Self {
        Self { dw: [0u32; 4] }
    }

    /// Phase tag bit (DW3[0]).  Toggles each queue wrap.
    pub fn phase(&self) -> bool {
        self.dw[3] & 0x1 != 0
    }

    /// Status field DW3[31:1] (status code type + status code combined).
    pub fn status(&self) -> u16 {
        ((self.dw[3] >> 1) & 0x7FFF) as u16
    }

    /// Success: status == 0.
    pub fn is_success(&self) -> bool {
        self.status() == 0
    }

    /// DW0 — command-specific result (e.g. new NSID from Namespace Management).
    pub fn result(&self) -> u32 {
        self.dw[0]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static admin queue buffers
//
// Statically allocated so they are available before any allocator is up.
// Each buffer is aligned to 4096 bytes (the minimum AQA alignment required
// by NVMe r2.1 §3.1.28 / §3.1.29 — ASQ / ACQ must be page-aligned).
// ─────────────────────────────────────────────────────────────────────────────

const ADMIN_Q_DEPTH: usize = 4;

#[repr(C, align(4096))]
struct AdminSqBuf([AdminSqe; ADMIN_Q_DEPTH]);

#[repr(C, align(4096))]
struct AdminCqBuf([AdminCqe; ADMIN_Q_DEPTH]);

/// Identify Controller response buffer (4096 bytes).
#[repr(C, align(4096))]
struct IdentifyBuf([u8; 4096]);

/// Namespace Create Data Structure (NVMe r2.1 §5.15.2.1, 4096 bytes).
#[repr(C, align(4096))]
struct NsCreateBuf([u8; 4096]);

/// Controller List for Namespace Attachment (NVMe r2.1 §5.16.2.1, 4096 bytes).
/// Format: [0..1] = count (u16 LE), [2..3] = CNTLID[0] (u16 LE), …
#[repr(C, align(4096))]
struct CtrlrListBuf([u8; 4096]);

static mut ADMIN_SQ_BUF: AdminSqBuf = AdminSqBuf([AdminSqe::zeroed(); ADMIN_Q_DEPTH]);
static mut ADMIN_CQ_BUF: AdminCqBuf = AdminCqBuf([AdminCqe::zeroed(); ADMIN_Q_DEPTH]);
static mut IDENTIFY_BUF: IdentifyBuf = IdentifyBuf([0u8; 4096]);
static mut NS_CREATE_BUF: NsCreateBuf = NsCreateBuf([0u8; 4096]);
static mut CTRLR_LIST_BUF: CtrlrListBuf = CtrlrListBuf([0u8; 4096]);

// ─────────────────────────────────────────────────────────────────────────────
// MMIO helpers — volatile 32-bit / 64-bit register access
// ─────────────────────────────────────────────────────────────────────────────

/// Read a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must be the physical address of a valid NVMe BAR0, identity-mapped.
unsafe fn mmio_read32(base: u64, offset: usize) -> u32 {
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

/// Write a 32-bit MMIO register.
///
/// # Safety
/// Same as `mmio_read32`.
unsafe fn mmio_write32(base: u64, offset: usize, val: u32) {
    unsafe { ((base as usize + offset) as *mut u32).write_volatile(val) }
}

/// Write a 64-bit MMIO register as two 32-bit writes (lo first).
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
// Admin queue state (non-static; tracks head/tail and phase)
// ─────────────────────────────────────────────────────────────────────────────

struct AdminQueue {
    bar0: u64,
    /// Doorbell stride shift (DSTRD field from CAP[35:32]).
    dstrd: u32,
    /// SQ tail (next slot to write into).
    sq_tail: usize,
    /// CQ head (next slot to read from).
    cq_head: usize,
    /// Expected phase tag (flips every time CQ head wraps).
    cq_phase: bool,
    /// Next command identifier.
    cid: u16,
}

impl AdminQueue {
    /// Compute the byte offset of the Admin SQ tail doorbell from BAR0.
    fn sq_tail_db_offset(&self) -> usize {
        // SQ tail doorbell for queue n=0: 0x1000 + (2*0) * (4 << DSTRD)
        reg::DOORBELL_BASE
    }

    /// Compute the byte offset of the Admin CQ head doorbell from BAR0.
    fn cq_head_db_offset(&self) -> usize {
        // CQ head doorbell for queue n=0: 0x1000 + (2*0+1) * (4 << DSTRD)
        reg::DOORBELL_BASE + (4usize << self.dstrd)
    }

    /// Ring the Admin SQ tail doorbell with the current `sq_tail`.
    ///
    /// # Safety
    /// BAR0 must be accessible.
    unsafe fn ring_sq_tail(&self) {
        unsafe { mmio_write32(self.bar0, self.sq_tail_db_offset(), self.sq_tail as u32) };
    }

    /// Ring the Admin CQ head doorbell with the current `cq_head` to release
    /// the consumed CQE slot back to the controller.
    ///
    /// # Safety
    /// BAR0 must be accessible.
    unsafe fn ring_cq_head(&self) {
        unsafe { mmio_write32(self.bar0, self.cq_head_db_offset(), self.cq_head as u32) };
    }

    /// Write an SQE into the next SQ slot and ring the tail doorbell.
    ///
    /// # Safety
    /// ADMIN_SQ_BUF must not be aliased; BAR0 accessible.
    unsafe fn submit(&mut self, sqe: AdminSqe) {
        // Write SQE into the SQ slot.
        unsafe {
            let slot = addr_of_mut!(ADMIN_SQ_BUF)
                .cast::<AdminSqe>()
                .add(self.sq_tail);
            slot.write_volatile(sqe);
        }
        // D-cache clean to PoC so the controller (DMA master) sees the entry.
        unsafe { dc_civac_range(self.sq_slot_pa(), core::mem::size_of::<AdminSqe>()) };
        dsb_ish();

        self.sq_tail = (self.sq_tail + 1) % ADMIN_Q_DEPTH;
        unsafe { self.ring_sq_tail() };
    }

    fn sq_slot_pa(&self) -> u64 {
        // sq_tail was already incremented; the slot we just wrote is tail-1.
        let idx = (self.sq_tail + ADMIN_Q_DEPTH - 1) % ADMIN_Q_DEPTH;
        (addr_of!(ADMIN_SQ_BUF) as u64) + (idx * core::mem::size_of::<AdminSqe>()) as u64
    }

    /// Poll the CQ for the next completion with the expected CID.
    /// Returns the CQE when the phase tag flips to `cq_phase`.
    /// Gives up after `MAX_POLL` iterations (≈ a few hundred µs at EL2).
    ///
    /// # Safety
    /// ADMIN_CQ_BUF must not be aliased; BAR0 accessible.
    unsafe fn poll_completion(&mut self) -> Option<AdminCqe> {
        const MAX_POLL: usize = 1_000_000;
        for _ in 0..MAX_POLL {
            // Invalidate D-cache line so we read fresh data from DRAM.
            let cqe_pa = (addr_of!(ADMIN_CQ_BUF) as u64)
                + (self.cq_head * core::mem::size_of::<AdminCqe>()) as u64;
            unsafe { dc_ivac(cqe_pa) };
            dsb_ish();

            let cqe = unsafe {
                addr_of!(ADMIN_CQ_BUF)
                    .cast::<AdminCqe>()
                    .add(self.cq_head)
                    .read_volatile()
            };

            if cqe.phase() == self.cq_phase {
                // Consume entry: advance head, update phase on wrap.
                self.cq_head = (self.cq_head + 1) % ADMIN_Q_DEPTH;
                if self.cq_head == 0 {
                    self.cq_phase = !self.cq_phase;
                }
                unsafe { self.ring_cq_head() };
                return Some(cqe);
            }
        }
        None
    }

    /// Allocate the next command identifier.
    fn next_cid(&mut self) -> u16 {
        let c = self.cid;
        self.cid = self.cid.wrapping_add(1);
        c
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D-cache maintenance helpers
//
// NVMe is a DMA-coherent device on real SoCs with a hardware coherency
// interconnect. On QEMU (which is fully software), reads/writes are already
// coherent. These helpers are kept as no-ops in the QEMU path but are correct
// calls on real ARM64 hardware with an inner-shareable domain.
// ─────────────────────────────────────────────────────────────────────────────

/// Clean and invalidate a D-cache range to PoC (DC CIVAC per cache line).
///
/// # Safety
/// `pa` must be a valid physical address accessible at EL2.
unsafe fn dc_civac_range(pa: u64, len: usize) {
    const CACHE_LINE: usize = 64;
    let mut addr = pa & !(CACHE_LINE as u64 - 1);
    let end = pa + len as u64;
    while addr < end {
        unsafe {
            core::arch::asm!("dc civac, {x}", x = in(reg) addr, options(nostack));
        }
        addr += CACHE_LINE as u64;
    }
    dsb_ish();
}

/// Invalidate a single D-cache line (DC IVAC).
///
/// # Safety
/// `pa` must be a valid physical address accessible at EL2.
unsafe fn dc_ivac(pa: u64) {
    unsafe {
        core::arch::asm!("dc ivac, {x}", x = in(reg) pa, options(nostack));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe ECAM NVMe controller enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Scan buses 0–7, devices 0–31, function 0 only (single-function search) for
/// an NVMe Mass Storage controller. Returns the PCIe BDF of the first match.
///
/// # Safety
/// `ecam` must point to a valid ECAM region identity-mapped at EL2.
unsafe fn find_nvme_controller(ecam: &PcieEcam) -> Option<PcieAddr> {
    for bus in 0u8..8 {
        for dev in 0u8..32 {
            let addr = PcieAddr::new(bus, dev, 0);
            let vendor = unsafe { ecam.read16(addr, CFG_VENDOR_ID) };
            if vendor == 0xFFFF {
                continue; // slot empty
            }
            let class = unsafe { ecam.read8(addr, CFG_CLASS) };
            let subclass = unsafe { ecam.read8(addr, CFG_SUBCLASS) };
            let progif = unsafe { ecam.read8(addr, CFG_PROGIF) };
            if class == NVME_CLASS && subclass == NVME_SUBCLASS && progif == NVME_PROGIF {
                return Some(addr);
            }
        }
    }
    None
}

/// Read BAR0 of the NVMe controller and return its physical base address.
/// Handles both 32-bit and 64-bit memory BARs.
///
/// # Safety
/// `ecam` must be valid; device at `addr` must exist.
unsafe fn read_bar0_pa(ecam: &PcieEcam, addr: PcieAddr) -> Option<u64> {
    let bar0 = unsafe { ecam.read32(addr, CFG_BAR0) };
    if bar0 & 0x1 != 0 {
        return None; // I/O BAR — not usable
    }
    let is_64bit = (bar0 >> 1) & 0x3 == 0x2;
    let lo = (bar0 & !0xF) as u64;
    if is_64bit {
        let hi = unsafe { ecam.read32(addr, CFG_BAR1) } as u64;
        Some(lo | (hi << 32))
    } else {
        Some(lo)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Controller reset and enable
// ─────────────────────────────────────────────────────────────────────────────

const POLL_LIMIT: usize = 2_000_000;

/// Reset the NVMe controller (CC.EN=0) and wait for CSTS.RDY=0.
///
/// # Safety
/// `bar0` must be the identity-mapped MMIO base of the NVMe controller.
unsafe fn controller_reset(bar0: u64) -> Result<(), NvmeSetupError> {
    let cc = unsafe { mmio_read32(bar0, reg::CC) };
    if cc & CC_EN != 0 {
        unsafe { mmio_write32(bar0, reg::CC, cc & !CC_EN) };
    }
    for _ in 0..POLL_LIMIT {
        let csts = unsafe { mmio_read32(bar0, reg::CSTS) };
        if csts & CSTS_CFS != 0 {
            return Err(NvmeSetupError::ResetTimeout);
        }
        if csts & CSTS_RDY == 0 {
            return Ok(());
        }
    }
    Err(NvmeSetupError::ResetTimeout)
}

/// Enable the NVMe controller (CC.EN=1) and wait for CSTS.RDY=1.
///
/// # Safety
/// `bar0` must be the identity-mapped MMIO base.
unsafe fn controller_enable(bar0: u64) -> Result<(), NvmeSetupError> {
    unsafe { mmio_write32(bar0, reg::CC, CC_INIT | CC_EN) };
    for _ in 0..POLL_LIMIT {
        let csts = unsafe { mmio_read32(bar0, reg::CSTS) };
        if csts & CSTS_CFS != 0 {
            return Err(NvmeSetupError::EnableTimeout);
        }
        if csts & CSTS_RDY != 0 {
            return Ok(());
        }
    }
    Err(NvmeSetupError::EnableTimeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin queue initialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Zero admin buffers, write AQA/ASQ/ACQ registers, return AdminQueue handle.
///
/// # Safety
/// `bar0` accessible; must be called after reset, before CC.EN=1.
unsafe fn init_admin_queue(bar0: u64) -> AdminQueue {
    // Zero queue buffers.
    unsafe {
        addr_of_mut!(ADMIN_SQ_BUF)
            .cast::<u8>()
            .write_bytes(0, core::mem::size_of::<AdminSqBuf>());
        addr_of_mut!(ADMIN_CQ_BUF)
            .cast::<u8>()
            .write_bytes(0, core::mem::size_of::<AdminCqBuf>());
    }
    dsb_ish();

    // AQA: ASQS and ACQS are 0-based (actual depth - 1).
    let depth_m1 = (ADMIN_Q_DEPTH - 1) as u32;
    let aqa = depth_m1 | (depth_m1 << 16);
    unsafe { mmio_write32(bar0, reg::AQA, aqa) };

    let sq_pa = addr_of!(ADMIN_SQ_BUF) as u64;
    let cq_pa = addr_of!(ADMIN_CQ_BUF) as u64;
    unsafe { mmio_write64(bar0, reg::ASQ, sq_pa) };
    unsafe { mmio_write64(bar0, reg::ACQ, cq_pa) };
    dsb_ish();

    // Read DSTRD from CAP[35:32].
    let cap_lo = unsafe { mmio_read32(bar0, reg::CAP) };
    let cap_hi = unsafe { mmio_read32(bar0, reg::CAP + 4) };
    let dstrd = (cap_hi >> 0) & 0xF; // CAP[35:32] = bits [3:0] of high dword

    let _ = cap_lo; // MQES not needed — AETHER uses only 4-slot admin queue

    AdminQueue {
        bar0,
        dstrd,
        sq_tail: 0,
        cq_head: 0,
        cq_phase: true, // Initial expected phase is 1 (controller posts phase=1 first)
        cid: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin command builders
// ─────────────────────────────────────────────────────────────────────────────

/// Issue Identify Controller (CNS=0x01) and return the raw 4096-byte response.
///
/// # Safety
/// `q` must be an initialised AdminQueue with an enabled controller.
/// IDENTIFY_BUF must not be aliased.
unsafe fn cmd_identify_controller(q: &mut AdminQueue) -> Result<(), NvmeSetupError> {
    let buf_pa = addr_of!(IDENTIFY_BUF) as u64;
    // Zero and clean the receive buffer first.
    unsafe {
        addr_of_mut!(IDENTIFY_BUF)
            .cast::<u8>()
            .write_bytes(0, 4096);
        dc_civac_range(buf_pa, 4096);
    }

    let cid = q.next_cid();
    let mut sqe = AdminSqe::zeroed();
    sqe.set_cdw0(0x06 /* Identify */, cid);
    sqe.set_nsid(0);
    sqe.set_prp1(buf_pa);
    sqe.set_cdw10(0x01); // CNS = 0x01 (Identify Controller)

    unsafe { q.submit(sqe) };
    let cqe = unsafe { q.poll_completion() }.ok_or(NvmeSetupError::EnableTimeout)?;
    if !cqe.is_success() {
        return Err(NvmeSetupError::NamespaceManagementUnsupported);
    }
    Ok(())
}

/// Read OACS[3] from the buffered Identify Controller response.
/// OACS is at byte offset 256 (word 128) of the data structure (NVMe §5.6.1).
fn identify_oacs_ns_mgmt_supported() -> bool {
    let oacs = unsafe {
        let ptr = addr_of!(IDENTIFY_BUF).cast::<u8>().add(256) as *const u16;
        ptr.read_unaligned()
    };
    oacs & (1 << 3) != 0
}

/// Build and issue Namespace Management / Create (opcode 0x0D, sel=0x00).
/// Returns the new NSID from the completion DW0.
///
/// `nsze_lbas`: Namespace Size in 4096-byte LBAs.
///
/// # Safety
/// `q` valid; NS_CREATE_BUF not aliased.
unsafe fn cmd_ns_create(q: &mut AdminQueue, nsze_lbas: u64) -> Result<NsId, NvmeSetupError> {
    let buf_pa = addr_of!(NS_CREATE_BUF) as u64;
    unsafe {
        addr_of_mut!(NS_CREATE_BUF)
            .cast::<u8>()
            .write_bytes(0, 4096);
    }

    // Namespace Create Data Structure (NVMe r2.1 §5.15.2.1):
    //   [0..8)   NSZE  — namespace size in LBAs
    //   [8..16)  NCAP  — namespace capacity (= NSZE, no thin-provisioning)
    //   [16]     FLBAS — LBA Format: bits [3:0] = index into LBAF[] table
    //                    AETHER uses index 0; host must verify LBAF[0].LBADS=12
    //
    // All other fields zero: DPS=0 (no E2E protection), NMIC=0 (private ns),
    // RESCAP=0, etc.
    let buf_ptr = addr_of_mut!(NS_CREATE_BUF).cast::<u8>();
    unsafe {
        // NSZE at offset 0 (u64 LE)
        buf_ptr.add(0).cast::<u64>().write_unaligned(nsze_lbas.to_le());
        // NCAP at offset 8 (u64 LE)
        buf_ptr.add(8).cast::<u64>().write_unaligned(nsze_lbas.to_le());
        // FLBAS at offset 16: index 0, no extended metadata (bit 4 = 0)
        buf_ptr.add(16).write(0x00);
    }
    unsafe { dc_civac_range(buf_pa, 4096) };
    dsb_ish();

    let cid = q.next_cid();
    let mut sqe = AdminSqe::zeroed();
    sqe.set_cdw0(0x0D /* Namespace Management */, cid);
    sqe.set_nsid(0); // NSID=0 for Create
    sqe.set_prp1(buf_pa);
    sqe.set_cdw10(0x00); // SEL=0x00 (Create)

    unsafe { q.submit(sqe) };
    let cqe = unsafe { q.poll_completion() }.ok_or(NvmeSetupError::EnableTimeout)?;
    if !cqe.is_success() {
        return Err(NvmeSetupError::CreateFailed(cqe.status()));
    }

    let nsid_raw = cqe.result();
    if nsid_raw == 0 {
        return Err(NvmeSetupError::InvalidNsidReturned);
    }
    Ok(NsId(nsid_raw))
}

/// Build and issue Namespace Attachment / Attach (opcode 0x15, sel=0x00).
/// Attaches `nsid` to controller 0 (the Admin PF controller, always CNTLID=0).
///
/// # Safety
/// `q` valid; CTRLR_LIST_BUF not aliased.
unsafe fn cmd_ns_attach(q: &mut AdminQueue, nsid: NsId) -> Result<(), NvmeSetupError> {
    let buf_pa = addr_of!(CTRLR_LIST_BUF) as u64;
    unsafe {
        addr_of_mut!(CTRLR_LIST_BUF)
            .cast::<u8>()
            .write_bytes(0, 4096);
    }

    // Controller List (NVMe r2.1 §5.16.2.1):
    //   [0..2)  Number of controller identifiers (u16 LE)
    //   [2..4)  CNTLID[0] (u16 LE)
    //   …
    let buf_ptr = addr_of_mut!(CTRLR_LIST_BUF).cast::<u8>();
    unsafe {
        buf_ptr.add(0).cast::<u16>().write_unaligned(1u16.to_le()); // count = 1
        buf_ptr.add(2).cast::<u16>().write_unaligned(0u16.to_le()); // CNTLID = 0
    }
    unsafe { dc_civac_range(buf_pa, 4096) };
    dsb_ish();

    let cid = q.next_cid();
    let mut sqe = AdminSqe::zeroed();
    sqe.set_cdw0(0x15 /* Namespace Attachment */, cid);
    sqe.set_nsid(nsid.0);
    sqe.set_prp1(buf_pa);
    sqe.set_cdw10(0x00); // SEL=0x00 (Attach)

    unsafe { q.submit(sqe) };
    let cqe = unsafe { q.poll_completion() }.ok_or(NvmeSetupError::EnableTimeout)?;
    if !cqe.is_success() {
        return Err(NvmeSetupError::AttachFailed(cqe.status()));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a successful NVMe namespace setup.
#[derive(Clone, Copy, Debug)]
pub struct NvmeNamespaceConfig {
    /// PCIe BDF of the NVMe controller.
    pub bdf: PcieAddr,
    /// Physical address of NVMe BAR0 (controller MMIO).
    pub bar0_pa: u64,
    /// NSID of the created and attached Android namespace (1-based).
    pub nsid: NsId,
    /// Namespace size in 4096-byte LBAs.
    pub size_lbas: u64,
}

/// Enumerate the NVMe controller, bring up its Admin Queue, issue Identify
/// Controller / Namespace Management Create / Namespace Attachment, and
/// return the configuration of the newly created Android namespace.
///
/// `ecam_base_pa` — Physical base address of the PCIe ECAM region (from ACPI
///                   MCFG or platform device tree).
/// `android_ns_bytes` — Desired Android namespace size in bytes. Rounded down
///                       to a whole number of 4096-byte LBAs.
///
/// # Safety
/// The ECAM region and the NVMe BAR0 (discovered at runtime) must be
/// identity-mapped and accessible at EL2.  No other CPU may touch the static
/// queue buffers during this call.
pub unsafe fn nvme_namespace_setup(
    ecam_base_pa: u64,
    android_ns_bytes: u64,
) -> Result<NvmeNamespaceConfig, NvmeSetupError> {
    let ecam = PcieEcam::new(ecam_base_pa);

    // 1. Find NVMe controller.
    let bdf = unsafe { find_nvme_controller(&ecam) }
        .ok_or(NvmeSetupError::ControllerNotFound)?;

    // Enable Memory Space + Bus Master in Command register so BAR0 responds.
    let cmd = unsafe { ecam.read16(bdf, CFG_CMD) };
    unsafe { ecam.write16(bdf, CFG_CMD, cmd | 0x0006) };
    dsb_ish();

    let bar0 = unsafe { read_bar0_pa(&ecam, bdf) }.ok_or(NvmeSetupError::Bar0Invalid)?;

    // 2. Reset controller.
    unsafe { controller_reset(bar0) }?;

    // 3. Init Admin Queue (AQA / ASQ / ACQ must be set before CC.EN=1).
    let mut q = unsafe { init_admin_queue(bar0) };

    // 4. Enable controller.
    unsafe { controller_enable(bar0) }?;

    // 5. Identify Controller — check OACS Namespace Management bit.
    unsafe { cmd_identify_controller(&mut q) }?;
    if !identify_oacs_ns_mgmt_supported() {
        return Err(NvmeSetupError::NamespaceManagementUnsupported);
    }

    // 6. Namespace Management — Create.
    let nsze_lbas = android_ns_bytes / 4096;
    let nsid = unsafe { cmd_ns_create(&mut q, nsze_lbas) }?;

    // 7. Namespace Attachment — Attach to CNTLID=0.
    unsafe { cmd_ns_attach(&mut q, nsid) }?;

    isb();

    Ok(NvmeNamespaceConfig {
        bdf,
        bar0_pa: bar0,
        nsid,
        size_lbas: nsze_lbas,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// IrqForwardConfig-style config struct — gate criteria encoded as types
// ─────────────────────────────────────────────────────────────────────────────

/// Gate criteria for Chapter 37.
///
/// Both must be true before the chapter is considered complete:
///   - `nvme_list_shows_namespace`: `nvme list` reports NSID 1 with the
///     correct size on the QEMU/hardware serial console.
///   - `dd_write_succeeds`: `dd if=/dev/zero of=/dev/nvme0n1 bs=4096 count=1`
///     exits 0 (raw block write to the first LBA of the namespace succeeds).
#[derive(Debug, Clone, Copy)]
pub struct NvmeNamespaceGate {
    pub nvme_list_shows_namespace: bool,
    pub dd_write_succeeds: bool,
}

impl NvmeNamespaceGate {
    /// Returns true when both gate criteria are satisfied.
    pub fn is_open(self) -> bool {
        self.nvme_list_shows_namespace && self.dd_write_succeeds
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_sqe_cdw0_encoding() {
        let mut sqe = AdminSqe::zeroed();
        sqe.set_cdw0(0x06, 0x0042);
        // opcode in [7:0], CID in [31:16]
        assert_eq!(sqe.dw[0] & 0xFF, 0x06);
        assert_eq!((sqe.dw[0] >> 16) & 0xFFFF, 0x0042);
    }

    #[test]
    fn test_admin_sqe_nsid() {
        let mut sqe = AdminSqe::zeroed();
        sqe.set_nsid(7);
        assert_eq!(sqe.dw[1], 7);
    }

    #[test]
    fn test_admin_sqe_prp1() {
        let mut sqe = AdminSqe::zeroed();
        sqe.set_prp1(0xDEAD_BEEF_1234_5678);
        assert_eq!(sqe.dw[6], 0x1234_5678);
        assert_eq!(sqe.dw[7], 0xDEAD_BEEF);
    }

    #[test]
    fn test_admin_sqe_cdw10() {
        let mut sqe = AdminSqe::zeroed();
        sqe.set_cdw10(0x0D_00_00_01);
        assert_eq!(sqe.dw[10], 0x0D_00_00_01);
    }

    #[test]
    fn test_cqe_phase_and_status_success() {
        let mut cqe = AdminCqe::zeroed();
        // DW3: phase=1 (bit 0), status=0 (bits [31:1])
        cqe.dw[3] = 0x0000_0001;
        assert!(cqe.phase());
        assert_eq!(cqe.status(), 0);
        assert!(cqe.is_success());
    }

    #[test]
    fn test_cqe_phase_and_status_error() {
        let mut cqe = AdminCqe::zeroed();
        // DW3: phase=1, status=0x0002 (Invalid Field in Command, SCT=0, SC=2)
        // status bits [31:1] = 0x0002 → DW3 = (0x0002 << 1) | 1 = 0x0005
        cqe.dw[3] = 0x0000_0005;
        assert!(cqe.phase());
        assert_eq!(cqe.status(), 0x0002);
        assert!(!cqe.is_success());
    }

    #[test]
    fn test_cqe_result() {
        let mut cqe = AdminCqe::zeroed();
        cqe.dw[0] = 0x0000_0001; // NSID=1 returned from Create
        assert_eq!(cqe.result(), 1);
    }

    #[test]
    fn test_nsid_from_create_completion() {
        let mut cqe = AdminCqe::zeroed();
        cqe.dw[0] = 1; // NSID 1
        cqe.dw[3] = 0x0000_0001; // phase=1, status=0
        let nsid = NsId(cqe.result());
        assert!(nsid.is_valid());
        assert_eq!(nsid.0, 1);
    }

    #[test]
    fn test_gate_open_requires_both() {
        let gate = NvmeNamespaceGate {
            nvme_list_shows_namespace: true,
            dd_write_succeeds: false,
        };
        assert!(!gate.is_open());

        let gate = NvmeNamespaceGate {
            nvme_list_shows_namespace: true,
            dd_write_succeeds: true,
        };
        assert!(gate.is_open());
    }

    #[test]
    fn test_admin_q_depth_sufficient() {
        // AETHER issues 3 admin commands; queue depth 4 must accommodate them
        // without the tail lapping the head.
        assert!(ADMIN_Q_DEPTH >= 4);
    }

    #[test]
    fn test_ns_create_buf_size_alignment() {
        assert_eq!(core::mem::size_of::<NsCreateBuf>(), 4096);
        assert_eq!(core::mem::align_of::<NsCreateBuf>(), 4096);
    }

    #[test]
    fn test_identify_buf_size_alignment() {
        assert_eq!(core::mem::size_of::<IdentifyBuf>(), 4096);
        assert_eq!(core::mem::align_of::<IdentifyBuf>(), 4096);
    }

    #[test]
    fn test_ctrlr_list_buf_size_alignment() {
        assert_eq!(core::mem::size_of::<CtrlrListBuf>(), 4096);
        assert_eq!(core::mem::align_of::<CtrlrListBuf>(), 4096);
    }

    #[test]
    fn test_sqe_size_64_bytes() {
        assert_eq!(core::mem::size_of::<AdminSqe>(), 64);
    }

    #[test]
    fn test_cqe_size_16_bytes() {
        assert_eq!(core::mem::size_of::<AdminCqe>(), 16);
    }

    #[test]
    fn test_opcode_constants_match_spec() {
        // NVMe r2.1 Table 5: Identify=06h, NS Mgmt=0Dh, NS Attach=15h
        assert_eq!(crate::storage::opcode::IDENTIFY, 0x06);
        assert_eq!(crate::storage::opcode::NS_MANAGEMENT, 0x0D);
        assert_eq!(crate::storage::opcode::NS_ATTACHMENT, 0x15);
    }

    #[test]
    fn test_nsze_calculation_128gib() {
        let size_bytes: u64 = 128 * 1024 * 1024 * 1024;
        let nsze = size_bytes / 4096;
        assert_eq!(nsze, 33_554_432);
    }

    #[test]
    fn test_cc_init_iosqes_iocqes() {
        // CC_INIT must encode IOSQES=6 (SQE=64B) and IOCQES=4 (CQE=16B)
        assert_eq!((CC_INIT >> 16) & 0xF, 6); // IOSQES
        assert_eq!((CC_INIT >> 20) & 0xF, 4); // IOCQES
    }
}
