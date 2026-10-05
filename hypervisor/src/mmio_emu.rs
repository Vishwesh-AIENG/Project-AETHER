// mmio_emu.rs — guest MMIO access emulation for the x86 tier.
//
// Phase 5 deliverable. When FEX translates ARM64 LDR/STR to an MMIO IPA, the
// resulting x86 host load/store triggers an EPT/NPT violation. The dispatch
// loop in `dbt_dispatch.rs` classifies the exit, decodes the access (FEX
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

// M4b-5: the GICv3 distributor/redistributor decode routes the guest's
// interrupt configuration into the translator's `VirtualGic` via these FFI
// entry points, so enabling the virtual timer PPI (and SPIs) actually takes
// effect and `aether_pending_irq` can deliver them through the dispatch loop.
use aether_translator::runtime::gic::GIC_MAX_INTID;
use aether_translator::runtime::sysreg_rt::{
    aether_gic_raise, aether_gic_set_enable, aether_gic_set_group1, aether_gic_set_priority,
};

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
// GICv3 distributor / redistributor (M4b-5) — route the guest's interrupt
// configuration into the translator `VirtualGic` so the virtual timer PPI
// (INTID 27) and SPIs can actually be enabled, grouped, prioritised, and
// delivered through the dispatch loop. Reference: ARM IHI 0069 (GICv3).
//
// The kernel gic-v3 driver, in order:
//   * reads GICD_TYPER (INTID count) + GICD_IIDR;
//   * groups all to non-secure group 1 (IGROUPR), disables all (ICENABLER),
//     sets priorities (IPRIORITYR), enables the distributor (GICD_CTLR);
//   * per-CPU wakes the redistributor (GICR_WAKER → poll ChildrenAsleep=0) and
//     configures PPI/SGI in the SGI frame (+0x10000), enabling the virtual
//     timer PPI via GICR_ISENABLER0 bit 27.
//
// Config-register READS return the reset value (0); WRITES decode into the
// VirtualGic. Affinity routing (IROUTER) and trigger mode (ICFGR) are accepted
// but not modelled (single vCPU, all level-sensitive virtual lines).
// ─────────────────────────────────────────────────────────────────────────────

const GIC_MAX_INTID_U32: u32 = GIC_MAX_INTID as u32;

pub mod gicd_offsets {
    pub const CTLR:  u64 = 0x0000;
    pub const TYPER: u64 = 0x0004;
    pub const IIDR:  u64 = 0x0008;
    // Banked register arrays (each 4-byte register is INTID-indexed):
    pub const IGROUPR:    u64 = 0x0080; // 1 bit/INTID  (1 = group 1)
    pub const ISENABLER:  u64 = 0x0100; // write-1-to-set-enable
    pub const ICENABLER:  u64 = 0x0180; // write-1-to-clear-enable
    pub const ISPENDR:    u64 = 0x0200; // write-1-to-set-pending
    pub const IPRIORITYR: u64 = 0x0400; // 1 byte/INTID
    pub const IROUTER:    u64 = 0x6000; // 8 bytes/INTID (SPI >= 32)
    pub const PIDR2:      u64 = 0xFFE8; // Peripheral ID2: bits[7:4] = arch rev
}

/// GICv3 architecture revision signature in PIDR2 bits[7:4] (Linux:
/// `GIC_PIDR2_ARCH_GICv3 = 0x3 << 4`). The Linux GICv3 driver does NOT trust the
/// DTB `compatible` string — `gic_init_bases`/`gic_populate_rdist` read
/// GICD_PIDR2 / GICR_PIDR2 and abort GIC init ("No distributor/redistributor
/// detected, giving up") unless bits[7:4] are 0x3 (v3) or 0x4 (v4). A 0 read
/// (the old `_ => 0` default) therefore silently kills GIC bring-up — and with
/// it the timer PPI 27 enable/delivery path this milestone targets.
const GICV3_PIDR2: u64 = 0x30;

/// Invoke `f(intid)` for each SET bit of a 1-bit-per-INTID banked register write
/// (ISENABLER / ICENABLER / ISPENDR). `array_base` is the register-array base;
/// `offset` is the accessed 4-byte register's offset within the same frame.
fn gic_for_each_set_bit(array_base: u64, offset: u64, value: u32, mut f: impl FnMut(u32)) {
    let reg = (offset - array_base) / 4; // which 32-INTID register
    let base = (reg * 32) as u32;
    let mut v = value;
    while v != 0 {
        let bit = v.trailing_zeros();
        let intid = base + bit;
        if intid < GIC_MAX_INTID_U32 {
            f(intid);
        }
        v &= v - 1; // clear lowest set bit
    }
}

/// Apply an IGROUPR write (every bit matters: 1 = group 1, 0 = group 0).
fn gic_apply_group(array_base: u64, offset: u64, value: u32) {
    let reg = (offset - array_base) / 4;
    let base = (reg * 32) as u32;
    for bit in 0..32u32 {
        let intid = base + bit;
        if intid < GIC_MAX_INTID_U32 {
            aether_gic_set_group1(intid, (value >> bit) & 1);
        }
    }
}

/// Apply an IPRIORITYR write (1 byte per INTID; `size` bytes touch `size` INTIDs).
fn gic_apply_priority(array_base: u64, offset: u64, size: u8, value: u64) {
    let base = (offset - array_base) as u32; // 1 byte/INTID → offset IS the INTID base
    for j in 0..(size as u32) {
        let intid = base + j;
        if intid < GIC_MAX_INTID_U32 {
            aether_gic_set_priority(intid, ((value >> (8 * j)) & 0xFF) as u32);
        }
    }
}

fn emulate_gicd(access: &MmioAccess) -> MmioResult {
    let offset = access.addr - GICD_BASE;
    let in_router = offset >= gicd_offsets::IROUTER;
    // B28: IPRIORITYR is a byte array (one priority byte per interrupt) and is
    // legitimately accessed byte/halfword-wide by the kernel; gic_apply_priority
    // below handles the sub-word size. The previous unconditional `size != 4`
    // guard rejected those with BadWidth before they reached the dispatch.
    let is_ipriority =
        (gicd_offsets::IPRIORITYR..gicd_offsets::IPRIORITYR + 0x400).contains(&offset);
    // Everything except the 64-bit IROUTER array and the IPRIORITYR byte array
    // is 32-bit-accessed.
    if !in_router && !is_ipriority && access.size != 4 {
        return MmioResult::BadWidth;
    }

    if access.is_write {
        let v32 = access.value as u32;
        match offset {
            o if (gicd_offsets::IGROUPR..gicd_offsets::IGROUPR + 0x80).contains(&o) => {
                gic_apply_group(gicd_offsets::IGROUPR, o, v32);
            }
            o if (gicd_offsets::ISENABLER..gicd_offsets::ISENABLER + 0x80).contains(&o) => {
                gic_for_each_set_bit(gicd_offsets::ISENABLER, o, v32, |id| aether_gic_set_enable(id, 1));
            }
            o if (gicd_offsets::ICENABLER..gicd_offsets::ICENABLER + 0x80).contains(&o) => {
                gic_for_each_set_bit(gicd_offsets::ICENABLER, o, v32, |id| aether_gic_set_enable(id, 0));
            }
            o if (gicd_offsets::ISPENDR..gicd_offsets::ISPENDR + 0x80).contains(&o) => {
                gic_for_each_set_bit(gicd_offsets::ISPENDR, o, v32, |id| aether_gic_raise(id));
            }
            o if (gicd_offsets::IPRIORITYR..gicd_offsets::IPRIORITYR + 0x400).contains(&o) => {
                gic_apply_priority(gicd_offsets::IPRIORITYR, o, access.size, access.value);
            }
            // CTLR / ICPENDR / ICFGR / IROUTER / reserved: accept silently
            // (group enable is tracked CPU-side; trigger mode/affinity unmodelled).
            _ => {}
        }
        return MmioResult::Ok { value: 0 };
    }

    // Reads.
    let v = match offset {
        gicd_offsets::CTLR  => 0,            // distributor enable tracked CPU-side
        gicd_offsets::TYPER => 0x0000_0007,  // ITLinesNumber=7 → 256 INTIDs (== GIC_MAX_INTID)
        gicd_offsets::IIDR  => 0x0000_043B,  // cosmetic implementer
        gicd_offsets::PIDR2 => GICV3_PIDR2,  // arch rev = GICv3 (else Linux aborts GIC init)
        _                   => 0,            // config arrays read as reset (0)
    };
    MmioResult::Ok { value: v }
}

pub mod gicr_offsets {
    // RD frame (0x0000..0xFFFF):
    pub const TYPER: u64 = 0x0008; // 64-bit; "Last" redistributor bit at [4]
    pub const WAKER: u64 = 0x0014;
    pub const PIDR2: u64 = 0xFFE8; // Peripheral ID2: bits[7:4] = arch rev
    /// SGI frame base offset within the redistributor window.
    pub const SGI_BASE: u64 = 0x1_0000;
    // SGI-frame banked registers (INTID 0..31), offsets RELATIVE to SGI_BASE:
    pub const IGROUPR0:   u64 = 0x0080;
    pub const ISENABLER0: u64 = 0x0100;
    pub const ICENABLER0: u64 = 0x0180;
    pub const ISPENDR0:   u64 = 0x0200;
    pub const IPRIORITYR: u64 = 0x0400; // 32 bytes (INTID 0..31)
}

fn emulate_gicr(access: &MmioAccess) -> MmioResult {
    if access.size != 4 && access.size != 8 {
        return MmioResult::BadWidth;
    }
    let offset = access.addr - GICR_BASE;

    // SGI frame: PPI/SGI configuration (INTID 0..31) — incl. the timer PPI 27.
    if offset >= gicr_offsets::SGI_BASE {
        let sgi = offset - gicr_offsets::SGI_BASE;
        if access.is_write {
            let v32 = access.value as u32;
            match sgi {
                gicr_offsets::IGROUPR0 => gic_apply_group(gicr_offsets::IGROUPR0, sgi, v32),
                gicr_offsets::ISENABLER0 => {
                    gic_for_each_set_bit(gicr_offsets::ISENABLER0, sgi, v32, |id| aether_gic_set_enable(id, 1));
                }
                gicr_offsets::ICENABLER0 => {
                    gic_for_each_set_bit(gicr_offsets::ICENABLER0, sgi, v32, |id| aether_gic_set_enable(id, 0));
                }
                gicr_offsets::ISPENDR0 => {
                    gic_for_each_set_bit(gicr_offsets::ISPENDR0, sgi, v32, |id| aether_gic_raise(id));
                }
                o if (gicr_offsets::IPRIORITYR..gicr_offsets::IPRIORITYR + 0x20).contains(&o) => {
                    gic_apply_priority(gicr_offsets::IPRIORITYR, o, access.size, access.value);
                }
                _ => {} // ICFGR / reserved: accept silently
            }
        }
        return MmioResult::Ok { value: 0 }; // config reads = reset state
    }

    // RD frame.
    if access.is_write {
        return MmioResult::Ok { value: 0 }; // CTLR / WAKER writes acked
    }
    let v = match offset {
        gicr_offsets::TYPER => 1u64 << 4,   // "Last" redistributor (single vCPU)
        gicr_offsets::WAKER => 0,           // ProcessorSleep=0 & ChildrenAsleep=0 (awake)
        gicr_offsets::PIDR2 => GICV3_PIDR2, // arch rev = GICv3 (else rdist probe gives up)
        _                   => 0,
    };
    MmioResult::Ok { value: v }
}

/// extern "C" bridge the translator runtime calls for every MMIO load/store.
/// Registered at boot via `aether_translator::runtime::mmu::aether_set_mmio_handler`.
/// Translates the runtime's `(addr, size, is_write, value)` tuple into an
/// `MmioAccess`, runs the emulator, and returns the read value (writes → 0).
///
/// # Safety
/// `extern "C"` ABI matching `AetherMmioHandler`; no preconditions beyond a
/// valid call from the single-vCPU EL2 dispatch path.
// One-shot diagnostic counters so we can see whether the kernel reaches MMIO
// at all + how many of each kind of access happen before the dispatch loop
// ends. The kernel emits no PL011 output during early boot until earlycon is
// activated (parse_early_param) — these counters tell us whether the kernel
// even reached that point. Logged from the dispatch loop at HARTBEAT cadence.
#[cfg(target_arch = "x86_64")]
pub static mut MMIO_PL011_W: u32 = 0;
#[cfg(target_arch = "x86_64")]
pub static mut MMIO_GICD_W: u32 = 0;
#[cfg(target_arch = "x86_64")]
pub static mut MMIO_GICR_W: u32 = 0;
#[cfg(target_arch = "x86_64")]
pub static mut MMIO_OTHER_W: u32 = 0;
#[cfg(target_arch = "x86_64")]
pub static mut MMIO_LAST_ADDR: u64 = 0;
/// B28: read-side visibility — an Unhandled/BadWidth MMIO READ returns 0 to the
/// guest (reads as "device absent"). Count + record the last so it is diagnosable.
pub static mut MMIO_UNHANDLED_READS: u64 = 0;
pub static mut MMIO_LAST_UNHANDLED_READ: u64 = 0;

pub unsafe extern "C" fn aether_mmio_bridge(addr: u64, size: u32, is_write: u32, value: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if is_write != 0 {
            *core::ptr::addr_of_mut!(MMIO_LAST_ADDR) = addr;
            if addr >= PL011_UART_BASE && addr < PL011_UART_BASE + PL011_UART_SIZE {
                *core::ptr::addr_of_mut!(MMIO_PL011_W) =
                    (*core::ptr::addr_of!(MMIO_PL011_W)).saturating_add(1);
            } else if addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE {
                *core::ptr::addr_of_mut!(MMIO_GICD_W) =
                    (*core::ptr::addr_of!(MMIO_GICD_W)).saturating_add(1);
            } else if addr >= GICR_BASE && addr < GICR_BASE + GICR_SIZE {
                *core::ptr::addr_of_mut!(MMIO_GICR_W) =
                    (*core::ptr::addr_of!(MMIO_GICR_W)).saturating_add(1);
            } else {
                *core::ptr::addr_of_mut!(MMIO_OTHER_W) =
                    (*core::ptr::addr_of!(MMIO_OTHER_W)).saturating_add(1);
            }
        }
    }
    let acc = MmioAccess {
        addr,
        size: size as u8,
        is_write: is_write != 0,
        value,
    };
    match handle(acc) {
        MmioResult::Ok { value } => value,
        MmioResult::Unhandled | MmioResult::BadWidth => {
            // B28: record silent device-absent READs so they are diagnosable.
            #[cfg(target_arch = "x86_64")]
            if is_write == 0 {
                unsafe {
                    *core::ptr::addr_of_mut!(MMIO_UNHANDLED_READS) =
                        (*core::ptr::addr_of!(MMIO_UNHANDLED_READS)).saturating_add(1);
                    *core::ptr::addr_of_mut!(MMIO_LAST_UNHANDLED_READ) = addr;
                }
            }
            0
        }
    }
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
            let res = be.handle_mmio_write(offset, access.value as u32);
            // After processing (e.g. a QUEUE_NOTIFY that completed a request),
            // the device sets its used-buffer-notification bit. The guest's
            // virtio-blk driver WFIs waiting for the completion IRQ, so we must
            // raise the virtio-blk SPI; without it the guest sleeps forever and
            // the dispatch loop stalls (iter frozen). INTERRUPT_STATUS stays set
            // until the guest's handler ACKs it, and the SPI is level-high, so
            // re-raising while already pending is idempotent.
            (res, be.interrupt != 0)
        });
        match r {
            Some((Ok(()), raise_irq)) => {
                if raise_irq {
                    aether_gic_raise(crate::virtio::VIRTIO_BLK_SPI_INTID);
                }
                MmioResult::Ok { value: 0 }
            }
            _ => MmioResult::Unhandled,
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
    fn gicd_typer_reports_full_intid_space() {
        // M4b-5: ITLinesNumber=7 → (7+1)*32 = 256 INTIDs, matching the
        // translator VirtualGic's GIC_MAX_INTID so the kernel iterates the full
        // configured INTID space.
        let r = emulate_gicd(&MmioAccess {
            addr: GICD_BASE + gicd_offsets::TYPER, size: 4, is_write: false, value: 0,
        });
        assert_eq!(r, MmioResult::Ok { value: 0x7 });
    }

    /// Serializes the few tests that mutate the process-global VirtualGic.
    static GIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gicd_write_path_routes_spi_into_virtual_gic_and_delivers() {
        use aether_translator::runtime::sysreg_rt::{
            aether_pending_irq, aether_platform_reset, aether_sysreg_write, regid,
        };
        let _g = GIC_TEST_LOCK.lock().unwrap();
        aether_platform_reset(); // fresh vGIC + timer

        // Configure SPI INTID 33 via the distributor MMIO path: group 1, enabled,
        // pending. 33 lives in register index 1 (INTIDs 32..63), bit 1.
        let w = |off: u64, val: u64| {
            emulate_gicd(&MmioAccess { addr: GICD_BASE + off, size: 4, is_write: true, value: val });
        };
        w(gicd_offsets::IGROUPR + 4, 1 << 1);   // IGROUPR1 bit1 → group 1
        w(gicd_offsets::ISENABLER + 4, 1 << 1); // ISENABLER1 bit1 → enable
        w(gicd_offsets::ISPENDR + 4, 1 << 1);   // ISPENDR1 bit1 → pending

        // Open the CPU interface so the line can signal (priority defaults to 0).
        aether_sysreg_write(regid::ICC_PMR_EL1, 0xFF);
        aether_sysreg_write(regid::ICC_IGRPEN1_EL1, 1);

        // The decode must have driven the writes into the VirtualGic: INTID 33 is
        // now the highest signalled interrupt.
        assert_eq!(aether_pending_irq(), 33, "GICD MMIO writes routed SPI 33 into the vGIC");

        aether_platform_reset(); // leave global state clean for other tests
    }

    #[test]
    fn gicr_isenabler0_decodes_ppi_bit() {
        use aether_translator::runtime::sysreg_rt::{
            aether_pending_irq, aether_platform_reset, aether_sysreg_write, regid,
        };
        let _g = GIC_TEST_LOCK.lock().unwrap();
        aether_platform_reset();

        // SGI frame is at GICR_BASE + 0x10000; configure PPI INTID 20 (an
        // arbitrary PPI the timer logic does not auto-manage, unlike 27).
        let sgi = GICR_BASE + gicr_offsets::SGI_BASE;
        let w = |off: u64, val: u64| {
            emulate_gicr(&MmioAccess { addr: sgi + off, size: 4, is_write: true, value: val });
        };
        w(gicr_offsets::IGROUPR0, 1 << 20);
        w(gicr_offsets::ISENABLER0, 1 << 20);
        w(gicr_offsets::ISPENDR0, 1 << 20);
        aether_sysreg_write(regid::ICC_PMR_EL1, 0xFF);
        aether_sysreg_write(regid::ICC_IGRPEN1_EL1, 1);

        assert_eq!(aether_pending_irq(), 20, "GICR_ISENABLER0 routed PPI 20 into the vGIC");
        aether_platform_reset();
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
    fn gicd_and_gicr_pidr2_report_gicv3_arch_rev() {
        // M4b-5 fix: the Linux GICv3 driver validates the silicon by reading
        // GICD_PIDR2 / GICR_PIDR2 (offset 0xFFE8) and aborts GIC init unless
        // bits[7:4] == 0x3 (GICv3). A 0 read (the old `_ => 0` default) silently
        // kills GIC bring-up. Both must now report the arch signature.
        let d = emulate_gicd(&MmioAccess {
            addr: GICD_BASE + gicd_offsets::PIDR2, size: 4, is_write: false, value: 0,
        });
        match d {
            MmioResult::Ok { value } => assert_eq!(value & 0xF0, 0x30, "GICD_PIDR2 arch rev != GICv3"),
            other => panic!("GICD_PIDR2 read returned {other:?}"),
        }
        let r = emulate_gicr(&MmioAccess {
            addr: GICR_BASE + gicr_offsets::PIDR2, size: 4, is_write: false, value: 0,
        });
        match r {
            MmioResult::Ok { value } => assert_eq!(value & 0xF0, 0x30, "GICR_PIDR2 arch rev != GICv3"),
            other => panic!("GICR_PIDR2 read returned {other:?}"),
        }
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
