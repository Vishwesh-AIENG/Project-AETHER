//! Phase 3 — host-side virtio-blk-pci driver (x86_64 / q35).
//!
//! AETHER runs in VMX-root and drives the QEMU `virtio-blk-pci` disks that back
//! the AOSP partition images (system/vendor/product/userdata). It enumerates the
//! modern (virtio 1.0+) devices via the q35 ECAM window, brings each queue up,
//! and serves block reads ON DEMAND. The guest never sees these PCI devices — it
//! sees the AETHER virtio-MMIO block model in `virtio_blk.rs`, whose read source
//! calls [`read`] here. So this is purely a host backend; no guest-visible state.
//!
//! Read-only: system/vendor/product are `ro`; userdata is `rw` but late-mounted,
//! so the bring-up path only needs reads. Writes can be added with a second
//! descriptor type (VIRTIO_BLK_T_OUT) later.
//!
//! Memory model: the split virtqueue rings + the DMA bounce buffer live in this
//! module's BSS. In VMX-root the identity map makes `addr_of!(STATIC) as u64` the
//! PHYSICAL address QEMU's device DMA targets, so no allocator / translation is
//! needed. Single-vCPU, synchronous (post each request, busy-poll `used.idx`).
#![allow(dead_code)]

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

/// q35 ECAM (MMCONFIG) base — QEMU's PCIEXBAR default. config(bus,dev,fn,off) =
/// ECAM_BASE + (bus<<20)+(dev<<15)+(fn<<12)+off.
const ECAM_BASE: u64 = 0xB000_0000;
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Modern virtio-blk PCI device id (transitional 0x1001 is rejected — we require
/// disable-legacy=on so the device is 0x1042 with the modern capability layout).
const VIRTIO_BLK_DEVID_MODERN: u16 = 0x1042;

/// virtio PCI capability cfg_type values (virtio v1.1 §4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// device_status bits (virtio v1.1 §2.1).
const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;

/// VIRTIO_F_VERSION_1 (feature bit 32) — mandatory for the modern transport.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// virtio-blk request types (virtio v1.1 §5.2.6).
const VIRTIO_BLK_T_IN: u32 = 0;

/// virtqueue descriptor flags.
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const SECTOR: u64 = 512;
/// Queue size — small; we post one request at a time and poll. 8 descriptors is
/// plenty for a 3-descriptor read chain.
const QSZ: usize = 8;
/// Per-disk DMA bounce buffer (sectors served per virtio-pci request). 256 KiB =
/// 512 sectors; larger guest reads loop over this.
const BOUNCE_SECTORS: u32 = 512;
const BOUNCE_BYTES: usize = (BOUNCE_SECTORS as usize) * (SECTOR as usize);

/// Max AOSP image disks (system/vendor/product/userdata).
pub const MAX_DISKS: usize = 4;

// ── split virtqueue (modern, separate desc/avail/used) ───────────────────────
#[repr(C, align(16))]
struct VqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}
#[repr(C, align(2))]
struct VqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QSZ],
    used_event: u16,
}
#[repr(C, align(4))]
struct VqUsedElem {
    id: u32,
    len: u32,
}
#[repr(C, align(4))]
struct VqUsed {
    flags: u16,
    idx: u16,
    ring: [VqUsedElem; QSZ],
    avail_event: u16,
}

/// virtio-blk request header (16 bytes, virtio v1.1 §5.2.6.1).
#[repr(C)]
struct BlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

/// Per-disk ring + buffers. One static instance per disk index.
#[repr(C, align(4096))]
struct DiskRings {
    desc: [VqDesc; QSZ],
    avail: VqAvail,
    used: VqUsed,
    header: BlkReqHeader,
    status: u8,
    _pad: [u8; 7],
    data: [u8; BOUNCE_BYTES],
}

impl DiskRings {
    const fn zeroed() -> Self {
        // SAFETY-free const init.
        DiskRings {
            desc: [const {
                VqDesc { addr: 0, len: 0, flags: 0, next: 0 }
            }; QSZ],
            avail: VqAvail { flags: 0, idx: 0, ring: [0; QSZ], used_event: 0 },
            used: VqUsed {
                flags: 0,
                idx: 0,
                ring: [const { VqUsedElem { id: 0, len: 0 } }; QSZ],
                avail_event: 0,
            },
            header: BlkReqHeader { type_: 0, reserved: 0, sector: 0 },
            status: 0xFF,
            _pad: [0; 7],
            data: [0; BOUNCE_BYTES],
        }
    }
}

/// Discovered per-disk MMIO pointers + state.
#[derive(Clone, Copy)]
struct DiskDev {
    present: bool,
    common_cfg_pa: u64,
    notify_base_pa: u64,
    notify_off_mult: u32,
    device_cfg_pa: u64,
    capacity_sectors: u64,
    avail_shadow: u16, // our local copy of avail.idx
    used_shadow: u16,  // last seen used.idx
}

impl DiskDev {
    const fn empty() -> Self {
        DiskDev {
            present: false,
            common_cfg_pa: 0,
            notify_base_pa: 0,
            notify_off_mult: 0,
            device_cfg_pa: 0,
            capacity_sectors: 0,
            avail_shadow: 0,
            used_shadow: 0,
        }
    }
}

// One ring block + one device record per disk. EL2/VMX-root private, single-vCPU.
static mut RINGS: [DiskRings; MAX_DISKS] = [const { DiskRings::zeroed() }; MAX_DISKS];
static mut DEVS: [DiskDev; MAX_DISKS] = [DiskDev::empty(); MAX_DISKS];
static mut NDISKS: usize = 0;

// ── Legacy CF8/CFC config-space accessors ────────────────────────────────────
// More robust than guessing the q35 MMCONFIG (PCIEXBAR) base: the I/O-port
// mechanism is always present on bus 0 and reaches QEMU directly from VMX-root
// (port I/O is not intercepted in root mode). Everything we need (vendor/device,
// the virtio capability list, BARs) lives in the first 256 config bytes.
#[inline]
unsafe fn outl(port: u16, val: u32) {
    // SAFETY: caller guarantees `port` is a valid I/O port; word write to it.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val,
                         options(nomem, nostack, preserves_flags));
    }
}
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: caller guarantees `port` is a valid I/O port; word read from it.
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") port,
                         options(nomem, nostack, preserves_flags));
    }
    val
}
#[inline]
fn cfg_sel(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}
#[inline]
fn cfg_r32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    // SAFETY: CF8/CFC PCI config mechanism; VMX-root port I/O hits QEMU.
    unsafe {
        outl(0xCF8, cfg_sel(bus, dev, func, off));
        inl(0xCFC)
    }
}
#[inline]
fn cfg_r16(bus: u8, dev: u8, func: u8, off: u16) -> u16 {
    let d = cfg_r32(bus, dev, func, off & !3);
    ((d >> (((off & 2) as u32) * 8)) & 0xFFFF) as u16
}
#[inline]
fn cfg_r8(bus: u8, dev: u8, func: u8, off: u16) -> u8 {
    let d = cfg_r32(bus, dev, func, off & !3);
    ((d >> (((off & 3) as u32) * 8)) & 0xFF) as u8
}
#[inline]
fn cfg_w32(bus: u8, dev: u8, func: u8, off: u16, v: u32) {
    // SAFETY: as cfg_r32.
    unsafe {
        outl(0xCF8, cfg_sel(bus, dev, func, off));
        outl(0xCFC, v);
    }
}
#[inline]
fn cfg_w16(bus: u8, dev: u8, func: u8, off: u16, v: u16) {
    // Read-modify-write the containing dword.
    let d = cfg_r32(bus, dev, func, off & !3);
    let sh = ((off & 2) as u32) * 8;
    let nd = (d & !(0xFFFFu32 << sh)) | ((v as u32) << sh);
    cfg_w32(bus, dev, func, off & !3, nd);
}

/// Diagnostic: (vendor, device) of bus0/dev/func0, for the boot-time scan dump.
pub fn probe_vendor_dev(dev: u8) -> u32 {
    cfg_r32(0, dev, 0, 0x00)
}

// ── common_cfg field MMIO (virtio v1.1 §4.1.4.3) ─────────────────────────────
mod common {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0C;
    pub const DEVICE_STATUS: u64 = 0x14; // u8
    pub const QUEUE_SELECT: u64 = 0x16; // u16
    pub const QUEUE_SIZE: u64 = 0x18; // u16
    pub const QUEUE_ENABLE: u64 = 0x1C; // u16
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1E; // u16
    pub const QUEUE_DESC: u64 = 0x20; // u64
    pub const QUEUE_DRIVER: u64 = 0x28; // u64
    pub const QUEUE_DEVICE: u64 = 0x30; // u64
}
#[inline]
fn cc_r8(base: u64, off: u64) -> u8 {
    unsafe { read_volatile((base + off) as *const u8) }
}
#[inline]
fn cc_w8(base: u64, off: u64, v: u8) {
    unsafe { write_volatile((base + off) as *mut u8, v) }
}
#[inline]
fn cc_r16(base: u64, off: u64) -> u16 {
    unsafe { read_volatile((base + off) as *const u16) }
}
#[inline]
fn cc_w16(base: u64, off: u64, v: u16) {
    unsafe { write_volatile((base + off) as *mut u16, v) }
}
#[inline]
fn cc_r32(base: u64, off: u64) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}
#[inline]
fn cc_w32(base: u64, off: u64, v: u32) {
    unsafe { write_volatile((base + off) as *mut u32, v) }
}
#[inline]
fn cc_w64(base: u64, off: u64, v: u64) {
    unsafe {
        write_volatile((base + off) as *mut u32, v as u32);
        write_volatile((base + off + 4) as *mut u32, (v >> 32) as u32);
    }
}

/// Read a 64-bit (or 32-bit) BAR's MMIO base from config space `bar_idx`.
fn read_bar(bus: u8, dev: u8, func: u8, bar_idx: u8) -> u64 {
    let off = 0x10 + (bar_idx as u16) * 4;
    let lo = cfg_r32(bus, dev, func, off);
    // memory BAR; bits [2:1]=10 => 64-bit
    let is64 = (lo & 0b110) == 0b100;
    let base_lo = (lo & 0xFFFF_FFF0) as u64;
    if is64 {
        let hi = cfg_r32(bus, dev, func, off + 4) as u64;
        (hi << 32) | base_lo
    } else {
        base_lo
    }
}

/// Enumerate the q35 root bus for modern virtio-blk devices and bring each up.
/// Returns the number of disks initialised (also stored in `NDISKS`). Idempotent
/// enough for a single boot-time call.
pub fn init() -> usize {
    let mut n = 0usize;
    let mut dev: u8 = 0;
    while dev < 32 && n < MAX_DISKS {
        let vendor = cfg_r16(0, dev, 0, 0x00);
        if vendor == 0xFFFF {
            dev += 1;
            continue;
        }
        let devid = cfg_r16(0, dev, 0, 0x02);
        if vendor == VIRTIO_VENDOR && devid == VIRTIO_BLK_DEVID_MODERN {
            if bring_up(dev, n) {
                n += 1;
            }
        }
        dev += 1;
    }
    unsafe {
        *addr_of_mut!(NDISKS) = n;
    }
    n
}

/// Number of disks successfully brought up.
pub fn disk_count() -> usize {
    unsafe { *addr_of!(NDISKS) }
}

/// Capacity (in 512-byte sectors) of disk `idx`, or 0 if absent.
pub fn capacity_sectors(idx: usize) -> u64 {
    if idx >= MAX_DISKS {
        return 0;
    }
    unsafe { (*addr_of!(DEVS))[idx].capacity_sectors }
}

/// Debug: discovered addresses for disk `idx` —
/// [common_cfg_pa, notify_base_pa, device_cfg_pa, notify_off_mult, desc_pa, capacity_sectors].
/// `desc_pa` is the PA we handed the device for queue 0's descriptor ring; if the
/// device DMAs there but we read the rings at a different address, the mismatch is
/// visible by comparing this against where reads land.
pub fn debug_addrs(idx: usize) -> [u64; 6] {
    if idx >= MAX_DISKS {
        return [0; 6];
    }
    // SAFETY: EL2-private single-vCPU read of the device record + ring base.
    unsafe {
        let d = (*addr_of!(DEVS))[idx];
        let desc_pa = addr_of!((*addr_of!(RINGS))[idx].desc) as u64;
        [
            d.common_cfg_pa,
            d.notify_base_pa,
            d.device_cfg_pa,
            d.notify_off_mult as u64,
            desc_pa,
            d.capacity_sectors,
        ]
    }
}

/// Bring a single virtio-blk-pci device up: enable bus-master, parse caps, reset,
/// negotiate features, set up queue 0, DRIVER_OK. Returns true on success.
fn bring_up(pci_dev: u8, idx: usize) -> bool {
    // 1. Enable Memory Space + Bus Master in the PCI Command register.
    let cmd = cfg_r16(0, pci_dev, 0, 0x04);
    cfg_w16(0, pci_dev, 0, 0x04, cmd | 0x0006);

    // 2. Walk the capability list for the virtio structure caps.
    let mut common_pa = 0u64;
    let mut notify_pa = 0u64;
    let mut notify_mult = 0u32;
    let mut device_pa = 0u64;
    let status = cfg_r16(0, pci_dev, 0, 0x06);
    if (status & 0x10) == 0 {
        return false; // no capability list
    }
    let mut cap = (cfg_r8(0, pci_dev, 0, 0x34) & 0xFC) as u16;
    let mut guard = 0;
    while cap != 0 && guard < 48 {
        guard += 1;
        let cap_id = cfg_r8(0, pci_dev, 0, cap);
        let next = cfg_r8(0, pci_dev, 0, cap + 1) as u16;
        if cap_id == 0x09 {
            // vendor-specific = virtio cap: cfg_type@3, bar@4, offset@8, length@12
            let cfg_type = cfg_r8(0, pci_dev, 0, cap + 3);
            let bar = cfg_r8(0, pci_dev, 0, cap + 4);
            let offset = cfg_r32(0, pci_dev, 0, cap + 8) as u64;
            let bar_base = read_bar(0, pci_dev, 0, bar);
            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => common_pa = bar_base + offset,
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_pa = bar_base + offset;
                    notify_mult = cfg_r32(0, pci_dev, 0, cap + 16); // notify_off_multiplier
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => device_pa = bar_base + offset,
                _ => {}
            }
        }
        cap = next & 0xFFFF;
        cap &= 0xFC;
    }
    if common_pa == 0 || notify_pa == 0 || device_pa == 0 {
        return false;
    }

    // 3. Reset + ACK + DRIVER.
    cc_w8(common_pa, common::DEVICE_STATUS, 0);
    // (spec: read back 0 to confirm reset; QEMU completes synchronously)
    let _ = cc_r8(common_pa, common::DEVICE_STATUS);
    cc_w8(common_pa, common::DEVICE_STATUS, STATUS_ACK);
    cc_w8(common_pa, common::DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

    // 4. Feature negotiation — accept ONLY VIRTIO_F_VERSION_1 (read-only blk needs
    //    no blk feature bits; leaving them off keeps the request format basic).
    cc_w32(common_pa, common::DEVICE_FEATURE_SELECT, 1); // feature bits 32..63
    let feat_hi = cc_r32(common_pa, common::DEVICE_FEATURE);
    if (feat_hi & 1) == 0 {
        // device doesn't offer VERSION_1 — unusable in modern mode.
        cc_w8(common_pa, common::DEVICE_STATUS, STATUS_FAILED);
        return false;
    }
    cc_w32(common_pa, common::DRIVER_FEATURE_SELECT, 0);
    cc_w32(common_pa, common::DRIVER_FEATURE, 0);
    cc_w32(common_pa, common::DRIVER_FEATURE_SELECT, 1);
    cc_w32(common_pa, common::DRIVER_FEATURE, (VIRTIO_F_VERSION_1 >> 32) as u32);
    cc_w8(common_pa, common::DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (cc_r8(common_pa, common::DEVICE_STATUS) & STATUS_FEATURES_OK) == 0 {
        cc_w8(common_pa, common::DEVICE_STATUS, STATUS_FAILED);
        return false;
    }

    // 5. Capacity from device_cfg (virtio_blk_config.capacity @ offset 0, u64).
    let cap_lo = unsafe { read_volatile(device_pa as *const u32) } as u64;
    let cap_hi = unsafe { read_volatile((device_pa + 4) as *const u32) } as u64;
    let capacity = (cap_hi << 32) | cap_lo;

    // 6. Queue 0 setup. Point the device at our static rings (their PA == VA).
    let rings = unsafe { &mut (*addr_of_mut!(RINGS))[idx] };
    let desc_pa = addr_of!(rings.desc) as u64;
    let avail_pa = addr_of!(rings.avail) as u64;
    let used_pa = addr_of!(rings.used) as u64;
    cc_w16(common_pa, common::QUEUE_SELECT, 0);
    // honour the device's max queue size but cap at our ring length.
    let qmax = cc_r16(common_pa, common::QUEUE_SIZE);
    let qsize = if qmax == 0 || qmax as usize > QSZ { QSZ as u16 } else { qmax };
    cc_w16(common_pa, common::QUEUE_SIZE, qsize);
    let notify_off = cc_r16(common_pa, common::QUEUE_NOTIFY_OFF);
    cc_w64(common_pa, common::QUEUE_DESC, desc_pa);
    cc_w64(common_pa, common::QUEUE_DRIVER, avail_pa);
    cc_w64(common_pa, common::QUEUE_DEVICE, used_pa);
    cc_w16(common_pa, common::QUEUE_ENABLE, 1);

    // 7. DRIVER_OK.
    cc_w8(
        common_pa,
        common::DEVICE_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );

    let d = unsafe { &mut (*addr_of_mut!(DEVS))[idx] };
    d.present = true;
    d.common_cfg_pa = common_pa;
    d.notify_base_pa = notify_pa + (notify_off as u64) * (notify_mult as u64);
    d.notify_off_mult = notify_mult;
    d.device_cfg_pa = device_pa;
    d.capacity_sectors = capacity;
    d.avail_shadow = 0;
    d.used_shadow = 0;
    true
}

/// Read `count` 512-byte sectors starting at `lba` from disk `idx` into `dst`
/// (a host buffer of `count*512` bytes). Returns true on full success. Loops over
/// the bounce buffer for large requests. Synchronous (busy-polls `used.idx`).
pub fn read(idx: usize, lba: u64, count: u32, dst: *mut u8) -> bool {
    if idx >= MAX_DISKS {
        return false;
    }
    let present = unsafe { (*addr_of!(DEVS))[idx].present };
    if !present {
        return false;
    }
    let mut done = 0u32;
    while done < count {
        let chunk = core::cmp::min(count - done, BOUNCE_SECTORS);
        let data_pa = {
            let rings = unsafe { &(*addr_of!(RINGS))[idx] };
            addr_of!(rings.data) as u64
        };
        if !read_chunk(idx, lba + done as u64, chunk, data_pa) {
            return false;
        }
        // copy bounce -> dst
        let rings = unsafe { &(*addr_of!(RINGS))[idx] };
        let src = addr_of!(rings.data) as *const u8;
        let n = (chunk as usize) * (SECTOR as usize);
        // SAFETY: bounce holds `n` valid bytes; dst has room for the full request.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.add((done as usize) * (SECTOR as usize)), n);
        }
        done += chunk;
    }
    true
}

/// Maximum sectors per descriptor for the direct-DMA path. 2048 sectors = 1 MiB
/// per virtio request — bypasses the bounce buffer entirely, so the only ceiling
/// is QEMU's per-request segment size (1 MiB is comfortably within it).
const READ_TO_MAX_SECTORS: u32 = 2048;

/// Direct-DMA read: QEMU DMAs `count` 512-byte sectors starting at `lba` from
/// disk `idx` straight into the physical region at `dst_pa` (which MUST be
/// `count*512` contiguous bytes), bypassing the bounce buffer. Used for the
/// one-time PMEM image load — no AETHER-side memcpy. Returns true on full
/// success. Synchronous (busy-polls `used.idx`).
pub fn read_to(idx: usize, lba: u64, count: u32, dst_pa: u64) -> bool {
    if idx >= MAX_DISKS {
        return false;
    }
    let present = unsafe { (*addr_of!(DEVS))[idx].present };
    if !present {
        return false;
    }
    let mut done = 0u32;
    while done < count {
        let chunk = core::cmp::min(count - done, READ_TO_MAX_SECTORS);
        let pa = dst_pa + (done as u64) * SECTOR;
        if !read_chunk(idx, lba + done as u64, chunk, pa) {
            return false;
        }
        done += chunk;
    }
    true
}

/// Issue ONE read request of `chunk` sectors and poll for completion. The data
/// payload is DMA'd to `dma_pa` (the bounce buffer for `read`, or the caller's
/// destination PA for `read_to`).
fn read_chunk(idx: usize, lba: u64, chunk: u32, dma_pa: u64) -> bool {
    let d = unsafe { &mut (*addr_of_mut!(DEVS))[idx] };
    let rings = unsafe { &mut (*addr_of_mut!(RINGS))[idx] };

    // Fill the request header + status.
    rings.header.type_ = VIRTIO_BLK_T_IN;
    rings.header.reserved = 0;
    rings.header.sector = lba;
    rings.status = 0xFF;

    let hdr_pa = addr_of!(rings.header) as u64;
    let stat_pa = addr_of!(rings.status) as u64;

    // 3-descriptor chain: [0] hdr (RO) -> [1] data (WO) -> [2] status (WO).
    rings.desc[0] = VqDesc { addr: hdr_pa, len: 16, flags: VRING_DESC_F_NEXT, next: 1 };
    rings.desc[1] = VqDesc {
        addr: dma_pa,
        len: chunk * (SECTOR as u32),
        flags: VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
        next: 2,
    };
    rings.desc[2] = VqDesc { addr: stat_pa, len: 1, flags: VRING_DESC_F_WRITE, next: 0 };

    // Publish head index 0 in avail.ring at the current avail position.
    let slot = (d.avail_shadow as usize) % QSZ;
    rings.avail.ring[slot] = 0;
    // Ensure descriptor + ring writes are visible before bumping idx (fence).
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    d.avail_shadow = d.avail_shadow.wrapping_add(1);
    // SAFETY: avail.idx is device-visible; write it volatile after the fence.
    unsafe {
        write_volatile(addr_of_mut!(rings.avail.idx), d.avail_shadow);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Notify queue 0.
    unsafe {
        write_volatile(d.notify_base_pa as *mut u16, 0);
    }

    // Poll used.idx for completion (bounded spin).
    let mut spins: u64 = 0;
    loop {
        let used_idx = unsafe { read_volatile(addr_of!(rings.used.idx)) };
        if used_idx != d.used_shadow {
            d.used_shadow = used_idx;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            return rings.status == 0;
        }
        spins += 1;
        if spins > 20_000_000 {
            return false; // device stuck (used.idx never advanced)
        }
        core::hint::spin_loop();
    }
}
