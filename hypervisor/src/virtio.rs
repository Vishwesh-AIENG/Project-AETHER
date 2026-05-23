// virtio.rs — virtio-mmio transport common types.
//
// Phase 3 introduces a paravirtual virtio-mmio block device so AETHER can
// mediate every block read the Android guest issues. This module holds the
// transport-level pieces shared by any virtio device behind virtio-mmio:
//
//   * MMIO register offsets and magic constants (virtio v1.1 §4.2.2).
//   * The Split Virtqueue layout (descriptor table + avail ring + used ring)
//     per virtio v1.1 §2.6.
//   * `VirtioQueue` — a descriptor-chain walker that traverses the avail
//     ring and follows `next` indices, validating each descriptor against
//     the configured queue size.
//
// All ring memory accesses go through the Stage 2 translation in EL2 — the
// guest publishes IPAs into the queue base registers, and the hypervisor
// must translate them to host PAs before dereferencing. The actual S2
// translation hooks live in `virtio_blk.rs::handle_mmio_access`; this
// module exposes only pure data layouts and the chain walker, both of
// which are exercised by unit tests without any S2 dependency.
//
// References:
//   * virtio v1.1 specification, OASIS, 2019
//     §4.2.2 (MMIO transport), §2.6 (Split Virtqueue), §2.4 (Features)
//   * QEMU virt machine memory map (matches `VIRTIO_MMIO_BASE_IPA` below)

#![allow(dead_code)]

// ─────────────────────────────────────────────────────────────────────────────
// MMIO base and constants
// ─────────────────────────────────────────────────────────────────────────────

/// IPA at which the AETHER virtio-mmio device is exposed to the guest.
///
/// Matches QEMU's virt-machine first virtio-mmio slot. Reusing this IPA
/// means the guest DTB looks identical to what QEMU emits for virtio-blk,
/// which means stock GKI virtio_mmio bindings bind without surgery.
pub const VIRTIO_MMIO_BASE_IPA: u64 = 0x0A00_0000;

/// Size of a single virtio-mmio device window. Spec mandates 0x200 minimum;
/// QEMU and Linux both use 0x200. We expose 0x1000 (one 4 KiB page) so the
/// Stage 2 mapping is page-aligned, which simplifies trap configuration.
pub const VIRTIO_MMIO_REGION_SIZE: u64 = 0x1000;

/// `MagicValue` register contents — ASCII "virt" little-endian.
/// virtio v1.1 §4.2.2.1: drivers MUST check this before doing anything else.
pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// Modern virtio-mmio transport version. Legacy was 1; we implement only 2.
pub const VIRTIO_MMIO_VERSION: u32 = 2;

/// Vendor ID — opaque, drivers ignore. "AETH" little-endian for diagnostics.
pub const VIRTIO_MMIO_VENDOR_ID: u32 = 0x4854_4541;

/// SPI INTID delivered when a request completes (matches QEMU virt slot 0).
/// 3-cell GICv3 DT spec: `<GIC_SPI=0  intid-32  IRQ_TYPE_EDGE_RISING=1>`.
pub const VIRTIO_BLK_SPI_INTID: u32 = 32 + 16;

// ─────────────────────────────────────────────────────────────────────────────
// MMIO register offsets (virtio v1.1 §4.2.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Register offsets within the per-device MMIO window.
///
/// Every offset is verified against virtio v1.1 §4.2.2 Table 4.1.
pub mod regs {
    pub const MAGIC_VALUE:        u64 = 0x000;
    pub const VERSION:            u64 = 0x004;
    pub const DEVICE_ID:          u64 = 0x008;
    pub const VENDOR_ID:          u64 = 0x00C;
    pub const DEVICE_FEATURES:    u64 = 0x010;
    pub const DEVICE_FEATURES_SEL:u64 = 0x014;
    pub const DRIVER_FEATURES:    u64 = 0x020;
    pub const DRIVER_FEATURES_SEL:u64 = 0x024;
    pub const QUEUE_SEL:          u64 = 0x030;
    pub const QUEUE_NUM_MAX:      u64 = 0x034;
    pub const QUEUE_NUM:          u64 = 0x038;
    pub const QUEUE_READY:        u64 = 0x044;
    pub const QUEUE_NOTIFY:       u64 = 0x050;
    pub const INTERRUPT_STATUS:   u64 = 0x060;
    pub const INTERRUPT_ACK:      u64 = 0x064;
    pub const STATUS:             u64 = 0x070;
    pub const QUEUE_DESC_LOW:     u64 = 0x080;
    pub const QUEUE_DESC_HIGH:    u64 = 0x084;
    pub const QUEUE_DRIVER_LOW:   u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH:  u64 = 0x094;
    pub const QUEUE_DEVICE_LOW:   u64 = 0x0A0;
    pub const QUEUE_DEVICE_HIGH:  u64 = 0x0A4;
    pub const CONFIG_GEN:         u64 = 0x0FC;
    pub const CONFIG:             u64 = 0x100;
}

// ─────────────────────────────────────────────────────────────────────────────
// Device status bits (virtio v1.1 §2.1)
// ─────────────────────────────────────────────────────────────────────────────

pub mod status {
    pub const ACKNOWLEDGE: u32 = 1 << 0;
    pub const DRIVER:      u32 = 1 << 1;
    pub const DRIVER_OK:   u32 = 1 << 2;
    pub const FEATURES_OK: u32 = 1 << 3;
    pub const NEEDS_RESET: u32 = 1 << 6;
    pub const FAILED:      u32 = 1 << 7;
}

// ─────────────────────────────────────────────────────────────────────────────
// Common virtio feature bits (virtio v1.1 §6)
// ─────────────────────────────────────────────────────────────────────────────

/// `VIRTIO_F_VERSION_1` — the modern transport bit. The device MUST advertise
/// it and the driver MUST accept it; otherwise feature negotiation fails.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// `VIRTIO_F_ACCESS_PLATFORM` — driver respects platform memory access
/// boundaries (Stage 2 / IOMMU). AETHER REQUIRES this so that the queue
/// IPAs in QueueDesc/Driver/Device are honoured as guest-physical and run
/// through Stage 2 translation, not punched straight to host PA.
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;

// ─────────────────────────────────────────────────────────────────────────────
// Split Virtqueue layout (virtio v1.1 §2.6)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum queue size we advertise via QUEUE_NUM_MAX. Power of two per spec.
/// 64 is plenty for boot-time block I/O and keeps the static allocator sane.
pub const VIRTIO_QUEUE_NUM_MAX: u16 = 64;

/// Descriptor flags (virtio v1.1 §2.6.5).
pub mod desc_flags {
    /// The buffer continues into the next descriptor (`next` is valid).
    pub const NEXT:     u16 = 1 << 0;
    /// Device write-only buffer (vs. driver write-only / read-only by device).
    pub const WRITE:    u16 = 1 << 1;
    /// Descriptor is an indirect table; ignored — we reject in walker.
    pub const INDIRECT: u16 = 1 << 2;
}

/// One entry in the descriptor table (virtio v1.1 §2.6.5).
///
/// 16 bytes, little-endian, packed:
///   addr   : u64  — guest-physical address (IPA in our Stage 2 world)
///   len    : u32  — length in bytes
///   flags  : u16  — see `desc_flags`
///   next   : u16  — index into the descriptor table if `NEXT` is set
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtqueueDesc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

impl VirtqueueDesc {
    pub const SIZE_BYTES: usize = 16;

    pub const fn empty() -> Self {
        Self { addr: 0, len: 0, flags: 0, next: 0 }
    }

    /// Decode 16 bytes (little-endian) into a descriptor.
    pub fn from_le_bytes(b: &[u8; 16]) -> Self {
        Self {
            addr:  u64::from_le_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]),
            len:   u32::from_le_bytes([b[8],b[9],b[10],b[11]]),
            flags: u16::from_le_bytes([b[12],b[13]]),
            next:  u16::from_le_bytes([b[14],b[15]]),
        }
    }

    pub fn has_next(self)        -> bool { self.flags & desc_flags::NEXT != 0 }
    pub fn is_device_write(self) -> bool { self.flags & desc_flags::WRITE != 0 }
    pub fn is_indirect(self)     -> bool { self.flags & desc_flags::INDIRECT != 0 }
}

/// One element in the used ring (virtio v1.1 §2.6.8).
/// `id` is the head-of-chain descriptor index just consumed.
/// `len` is the number of bytes the device wrote into device-writable
/// portions of the chain.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VirtqueueUsedElem {
    pub id:  u32,
    pub len: u32,
}

impl VirtqueueUsedElem {
    pub const SIZE_BYTES: usize = 8;

    pub fn to_le_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.id.to_le_bytes());
        out[4..8].copy_from_slice(&self.len.to_le_bytes());
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtioQueue — per-queue driver-published state held by the device backend
// ─────────────────────────────────────────────────────────────────────────────

/// Per-queue state held by the device backend.
///
/// IPAs in `desc_ipa` / `avail_ipa` / `used_ipa` are written by the guest
/// through the QUEUE_DESC_LOW/HIGH (etc.) MMIO writes. The backend reads them
/// out, runs them through Stage 2 translation, and walks descriptor chains.
#[derive(Debug, Clone, Copy)]
pub struct VirtioQueue {
    pub size:      u16,      // last value written to QUEUE_NUM
    pub ready:     bool,     // last value written to QUEUE_READY
    pub desc_ipa:  u64,      // QUEUE_DESC_LOW + (QUEUE_DESC_HIGH << 32)
    pub avail_ipa: u64,
    pub used_ipa:  u64,

    /// Last avail ring index the backend has seen. Compared against the
    /// fresh `idx` field of the avail ring on every pop attempt.
    pub last_avail_idx: u16,

    /// Next slot to write into the used ring. Mirrors the `idx` field we
    /// publish back to the driver.
    pub used_idx: u16,
}

impl VirtioQueue {
    pub const fn new() -> Self {
        Self {
            size: 0, ready: false,
            desc_ipa: 0, avail_ipa: 0, used_ipa: 0,
            last_avail_idx: 0, used_idx: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Descriptor-chain walker
// ─────────────────────────────────────────────────────────────────────────────

/// One element of a walked descriptor chain.
///
/// `addr` is the **guest IPA** the descriptor referenced. The backend's
/// memory accessors run this through Stage 2 before reading or writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSegment {
    pub addr:           u64,
    pub len:            u32,
    pub is_device_write:bool,
}

/// Maximum descriptors followed in a single chain. virtio caps at queue size;
/// for safety we further cap at this constant so an adversarial guest cannot
/// loop the walker indefinitely with a self-referential ring.
pub const MAX_CHAIN_LEN: usize = 16;

/// A walked descriptor chain — head index plus an array of (addr,len) segments.
///
/// virtio convention for virtio-blk:
///   chain[0]                = device-readable request header (16 B)
///   chain[1..n-1]           = data buffer(s) — readable for OUT, writable for IN
///   chain[n-1]              = device-writable 1-byte status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorChain {
    pub head: u16,
    pub segments: [ChainSegment; MAX_CHAIN_LEN],
    pub seg_count: usize,
}

impl DescriptorChain {
    pub const fn empty() -> Self {
        Self {
            head: 0,
            segments: [ChainSegment { addr: 0, len: 0, is_device_write: false };
                MAX_CHAIN_LEN],
            seg_count: 0,
        }
    }

    pub fn segments(&self) -> &[ChainSegment] {
        &self.segments[..self.seg_count]
    }

    /// Total bytes the device may write to (sum of `len` over device-writable
    /// segments). Used to bound block reads.
    pub fn device_writable_bytes(&self) -> u64 {
        self.segments()
            .iter()
            .filter(|s| s.is_device_write)
            .map(|s| s.len as u64)
            .sum()
    }
}

/// Errors that can arise while walking a descriptor chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// `head` is out of range for the configured queue size.
    HeadOutOfRange,
    /// A `next` index is out of range.
    NextOutOfRange,
    /// The chain exceeded MAX_CHAIN_LEN — guest constructed a loop or
    /// pathological chain. Refuse and return.
    ChainTooLong,
    /// An INDIRECT descriptor was encountered; AETHER does not implement
    /// indirect descriptors in Phase 3 (and never plans to — adds complexity
    /// without buying anything for boot-time block I/O).
    IndirectRejected,
}

/// Walk a descriptor chain starting at `head`.
///
/// `read_desc` is a closure that returns one `VirtqueueDesc` given its index,
/// or `None` if the index is out of range. Splitting it out lets the unit
/// tests substitute a pure in-memory table; the real backend wires it to a
/// Stage 2 translator + 16-byte memory read.
pub fn walk_chain<F>(
    head: u16,
    queue_size: u16,
    mut read_desc: F,
) -> Result<DescriptorChain, ChainError>
where
    F: FnMut(u16) -> Option<VirtqueueDesc>,
{
    if head >= queue_size {
        return Err(ChainError::HeadOutOfRange);
    }
    let mut chain = DescriptorChain::empty();
    chain.head = head;

    let mut cur = head;
    for _ in 0..MAX_CHAIN_LEN {
        let d = read_desc(cur).ok_or(ChainError::NextOutOfRange)?;
        if d.is_indirect() {
            return Err(ChainError::IndirectRejected);
        }
        chain.segments[chain.seg_count] = ChainSegment {
            addr:            d.addr,
            len:             d.len,
            is_device_write: d.is_device_write(),
        };
        chain.seg_count += 1;
        if !d.has_next() {
            return Ok(chain);
        }
        if d.next >= queue_size {
            return Err(ChainError::NextOutOfRange);
        }
        cur = d.next;
    }
    Err(ChainError::ChainTooLong)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value_is_ascii_virt() {
        // "virt" little-endian = 't','r','i','v' reversed = 0x74726976.
        assert_eq!(VIRTIO_MMIO_MAGIC, 0x7472_6976);
        assert_eq!(VIRTIO_MMIO_MAGIC.to_le_bytes(), *b"virt");
    }

    #[test]
    fn region_size_is_one_page() {
        assert_eq!(VIRTIO_MMIO_REGION_SIZE, 0x1000);
    }

    #[test]
    fn desc_from_le_bytes_round_trip() {
        let bytes: [u8; 16] = [
            0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,  // addr
            0x00,0x10,0x00,0x00,                       // len = 0x1000
            0x03,0x00,                                 // flags = NEXT|WRITE
            0x05,0x00,                                 // next  = 5
        ];
        let d = VirtqueueDesc::from_le_bytes(&bytes);
        assert_eq!(d.addr, 0xBEBA_FECA_EFBE_ADDE);
        assert_eq!(d.len,  0x1000);
        assert!(d.has_next());
        assert!(d.is_device_write());
        assert!(!d.is_indirect());
        assert_eq!(d.next, 5);
    }

    fn make_table() -> [VirtqueueDesc; 4] {
        [
            // 0: request header (read-only by device, 16 B)
            VirtqueueDesc { addr: 0x4000_0000, len: 16, flags: desc_flags::NEXT,                 next: 1 },
            // 1: data buffer (device-writable, 512 B)
            VirtqueueDesc { addr: 0x4000_2000, len: 512, flags: desc_flags::NEXT | desc_flags::WRITE, next: 2 },
            // 2: status byte (device-writable, 1 B)
            VirtqueueDesc { addr: 0x4000_4000, len: 1, flags: desc_flags::WRITE, next: 0 },
            // 3: unused
            VirtqueueDesc::empty(),
        ]
    }

    #[test]
    fn walker_follows_chain_of_three() {
        let tab = make_table();
        let chain = walk_chain(0, 4, |i| tab.get(i as usize).copied()).unwrap();
        assert_eq!(chain.seg_count, 3);
        assert_eq!(chain.head, 0);
        assert_eq!(chain.segments[0].addr, 0x4000_0000);
        assert!(!chain.segments[0].is_device_write);
        assert!(chain.segments[1].is_device_write);
        assert!(chain.segments[2].is_device_write);
        assert_eq!(chain.device_writable_bytes(), 512 + 1);
    }

    #[test]
    fn walker_rejects_head_out_of_range() {
        let tab = make_table();
        assert_eq!(
            walk_chain(99, 4, |i| tab.get(i as usize).copied()),
            Err(ChainError::HeadOutOfRange)
        );
    }

    #[test]
    fn walker_rejects_indirect() {
        let mut tab = make_table();
        tab[0].flags = desc_flags::INDIRECT;
        assert_eq!(
            walk_chain(0, 4, |i| tab.get(i as usize).copied()),
            Err(ChainError::IndirectRejected)
        );
    }

    #[test]
    fn walker_rejects_loop() {
        // A 2-element ring that points back at 0 — would be infinite.
        let tab = [
            VirtqueueDesc { addr: 0, len: 8, flags: desc_flags::NEXT, next: 1 },
            VirtqueueDesc { addr: 0, len: 8, flags: desc_flags::NEXT, next: 0 },
        ];
        assert_eq!(
            walk_chain(0, 2, |i| tab.get(i as usize).copied()),
            Err(ChainError::ChainTooLong)
        );
    }

    #[test]
    fn walker_rejects_next_out_of_range() {
        let mut tab = make_table();
        tab[0].next = 99; // out of range for queue_size = 4
        assert_eq!(
            walk_chain(0, 4, |i| tab.get(i as usize).copied()),
            Err(ChainError::NextOutOfRange)
        );
    }

    #[test]
    fn used_elem_to_le_bytes() {
        let u = VirtqueueUsedElem { id: 0x1234_5678, len: 0xABCD };
        let b = u.to_le_bytes();
        assert_eq!(b, [0x78,0x56,0x34,0x12, 0xCD,0xAB,0x00,0x00]);
    }

    #[test]
    fn status_bits_distinct_and_monotonic_through_negotiation() {
        // Expected progression: ACKNOWLEDGE -> DRIVER -> FEATURES_OK -> DRIVER_OK.
        let mut s = 0u32;
        s |= status::ACKNOWLEDGE; assert_eq!(s, 0b0000_0001);
        s |= status::DRIVER;      assert_eq!(s, 0b0000_0011);
        s |= status::FEATURES_OK; assert_eq!(s, 0b0000_1011);
        s |= status::DRIVER_OK;   assert_eq!(s, 0b0000_1111);
        // FAILED is not set in the happy path.
        assert_eq!(s & status::FAILED, 0);
    }
}
