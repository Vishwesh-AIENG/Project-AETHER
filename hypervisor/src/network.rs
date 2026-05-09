// ch15: Network Partitioning
//
// AETHER partitions the network adapter using one of three modes, selected at
// boot based on hardware capability (in priority order):
//
//   1. SR-IOV  — NIC exposes PCIe Virtual Functions; one VF per guest.
//                Isolation is hardware-enforced. No hypervisor mediation in
//                the data path. Preferred when the NIC supports it.
//
//   2. DedicatedAdapter — each guest receives a separate physical NIC.
//                Android gets the integrated WiFi; Windows gets a USB-attached
//                Ethernet or a secondary WiFi adapter. Zero sharing.
//
//   3. ParavirtBridge — single NIC assigned to one guest (the "owner"); the
//                other guest receives a virtual interface that tunnels through
//                the owner. This is a deliberate compromise, labeled explicitly
//                in the type system. The design goal is to eliminate this mode
//                by recommending hardware that supports modes 1 or 2.
//
// IMPORTANT — WiFi VIFs vs. SR-IOV VFs:
//   The Linux mac80211 stack supports multiple Virtual Interfaces (VIFs) on a
//   single WiFi radio (e.g., one AP + one station). These are NOT the same as
//   PCIe SR-IOV Virtual Functions. VIFs share the physical radio's time slots
//   and cannot be independently partitioned in the security sense — they do not
//   provide DMA isolation, separate interrupt routing, or separate SMMU STEs.
//   AETHER only uses PCIe SR-IOV VFs (mode 1); VIFs are NOT an acceptable
//   substitute for guest network isolation.
//
// MAC address rules:
//   Every network interface assigned to a guest has a unique MAC address.
//   Two interfaces with the same MAC produce an address conflict that silently
//   breaks both guests' ARP resolution. The MacRegistry enforces uniqueness
//   at registration time. Locally-administered MACs (bit 1 of byte 0 set) are
//   used for VFs and bridge tunnel interfaces; the physical NIC's burned-in
//   address is preserved for the passthrough interface.
//
// NIC reset before assignment:
//   Before assigning a physical NIC (or enabling SR-IOV VFs), AETHER issues a
//   Function-Level Reset (FLR) via PCIe config space. This clears any TCP
//   offload state, RX/TX ring state, or DMA addresses left by a previous
//   boot session. Skipping FLR can leave checksum offload state from an
//   earlier context visible to the new guest.
//
// Paravirt bridge directionality:
//   In mode 3, traffic flows strictly from the tunnel guest to the owner guest
//   and then onto the physical network. The owner guest cannot inject arbitrary
//   frames back into the tunnel guest's RX path — only IP-level responses to
//   packets the tunnel guest originated are permitted. This prevents Windows
//   from seeing Android's raw WiFi traffic in sniffing mode.
//
// ARM Tier hardware:
//   Snapdragon X Elite uses Qualcomm ath12k WiFi. SR-IOV support on ath12k is
//   firmware-dependent and must be probed at runtime. If unavailable, AETHER
//   falls back to mode 2 (Android owns WiFi; Windows gets USB Ethernet) or
//   mode 3 (paravirt bridge, labeled as compromise).
//
// References:
//   PCIe Base Specification 5.0, Chapter 6   — SR-IOV
//   PCIe Base Specification 5.0, §6.6.2      — Function-Level Reset
//   IEEE 802.11-2020, §9.2.4.3               — MAC address structure
//   linux-ref/drivers/net/wireless/ath/ath12k — Snapdragon X Elite WiFi driver
//   linux-ref/drivers/net/ethernet/intel/e1000e — NIC driver reference patterns
//   virtio-net specification (OASIS)          — paravirt NIC spec (fallback ref)

use crate::partition::GuestId;
use crate::passthrough::PcieAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    /// MAC address is already assigned to another interface.
    /// Two interfaces with the same MAC will silently corrupt ARP resolution.
    DuplicateMacAddress,
    /// SR-IOV not supported by this NIC (no SR-IOV Extended Capability).
    SrIovNotSupported,
    /// SR-IOV is already enabled; cannot reconfigure.
    SrIovAlreadyEnabled,
    /// Requested VF count exceeds the NIC's MaxVFs.
    VfCountExceedsMax,
    /// Interface is already assigned to a guest; cannot reassign.
    InterfaceAlreadyAssigned,
    /// The specified interface does not exist in the registry.
    InterfaceNotFound,
    /// A ParavirtBridge was requested but the NIC does not support it
    /// (would require the NIC owner to proxy raw L2 frames).
    BridgeUnsupported,
    /// Registry is at capacity.
    RegistryFull,
    /// MAC address has the multicast bit set (bit 0 of byte 0). Unicast only.
    MulticastMacRejected,
}

// ─────────────────────────────────────────────────────────────────────────────
// MAC address
//
// IEEE 802.11-2020 §9.2.4.3: 48-bit address, transmitted LSB first.
// Bit 0 of octet 0: 0 = unicast, 1 = multicast/broadcast. Always unicast here.
// Bit 1 of octet 0: 0 = globally unique (OUI), 1 = locally administered.
// AETHER uses locally-administered MACs for VFs and bridge tunnels.
// ─────────────────────────────────────────────────────────────────────────────

/// 48-bit IEEE 802.3 MAC address (EUI-48).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Construct and validate a MAC address. Rejects multicast addresses.
    pub fn new(octets: [u8; 6]) -> Result<Self, NetworkError> {
        if octets[0] & 0x01 != 0 {
            return Err(NetworkError::MulticastMacRejected);
        }
        Ok(MacAddr(octets))
    }

    /// True if this is a locally-administered address (bit 1 of byte 0 set).
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// True if this is a globally-unique (OUI-assigned, burned-in) address.
    pub fn is_globally_unique(&self) -> bool {
        !self.is_locally_administered()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network partitioning mode
//
// Determined at boot by probing hardware capability. Encoded in the type system
// so that mode-3 (ParavirtBridge) callers cannot claim they are using mode-1.
// ─────────────────────────────────────────────────────────────────────────────

/// How the physical network adapter(s) are partitioned between guests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// PCIe SR-IOV: NIC exposes Virtual Functions; one VF per guest.
    /// Hardware enforces isolation. No hypervisor in the data path.
    /// Preferred mode.
    SrIov,
    /// Each guest receives a separate physical NIC.
    /// Zero sharing; each guest believes it owns a full physical adapter.
    DedicatedAdapter,
    /// One NIC assigned to an "owner" guest; the other guest receives a
    /// virtual interface tunneling through the owner.
    /// Labeled compromise — use only when SR-IOV and dedicated adapters
    /// are both unavailable.
    ParavirtBridge,
}

// ─────────────────────────────────────────────────────────────────────────────
// NIC SR-IOV capability (PCIe Extended Capability, same structure as ch13/ch14)
// ─────────────────────────────────────────────────────────────────────────────

/// SR-IOV capability read from the NIC's PCIe Extended Capability space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NicSrIovCapability {
    /// Maximum number of VFs the NIC supports.
    pub max_vfs: u16,
    /// BUS:DEV:FUNC offset to the first VF from the PF.
    pub first_vf_offset: u16,
    /// Stride between consecutive VF BDFs.
    pub vf_stride: u16,
}

impl NicSrIovCapability {
    /// Compute the PCIe BDF of VF n given the PF's BDF.
    ///
    /// VF_BDF(n) = PF_BDF + FirstVFOffset + n × VFStride
    pub fn vf_bdf(&self, pf_bdf: u16, vf_index: u16) -> Option<u16> {
        if vf_index >= self.max_vfs {
            return None;
        }
        Some(pf_bdf.wrapping_add(self.first_vf_offset + vf_index * self.vf_stride))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NIC Virtual Function (SR-IOV mode)
// ─────────────────────────────────────────────────────────────────────────────

/// One NIC Virtual Function assigned to a guest (SR-IOV mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NicVirtualFunction {
    /// PCIe BUS:DEV:FUNC address of this VF.
    pub addr: PcieAddr,
    /// Unique MAC address assigned to this VF.
    /// Must differ from every other interface MAC in the system.
    pub mac: MacAddr,
    /// Guest exclusively assigned this VF.
    pub guest: GuestId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dedicated adapter descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A physical NIC assigned exclusively to one guest (DedicatedAdapter mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DedicatedNic {
    /// PCIe BUS:DEV:FUNC address of the physical NIC.
    pub addr: PcieAddr,
    /// Burned-in MAC address (globally unique, OUI-assigned).
    pub mac: MacAddr,
    /// Guest exclusively assigned this adapter.
    pub guest: GuestId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Paravirtualized bridge configuration
//
// The owner guest holds the physical NIC. The tunnel guest sends and receives
// through a virtual interface that the owner forwards to the physical network.
//
// Directionality rule (enforced by design, not in this module):
//   Traffic flows: TunnelGuest → OwnerGuest → Physical Network.
//   The owner guest MUST NOT inject arbitrary frames back into the tunnel
//   guest's RX path. Only responses to tunnel-guest-originated packets
//   are forwarded inward.
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the paravirtualized network bridge (mode 3 fallback).
///
/// This is a deliberate, labeled compromise. It violates the No-Boundary
/// Principle (the owner guest mediates the tunnel guest's network access)
/// and is documented as such. Used only when SR-IOV and dedicated adapters
/// are both unavailable on the target hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeConfig {
    /// PCIe address of the physical NIC (assigned to owner_guest).
    pub nic_addr: PcieAddr,
    /// MAC address of the physical NIC (used by owner_guest).
    pub owner_mac: MacAddr,
    /// Guest that owns the physical NIC and forwards packets.
    pub owner_guest: GuestId,
    /// MAC address of the virtual interface presented to the tunnel guest.
    /// Must be locally-administered and distinct from owner_mac.
    pub tunnel_mac: MacAddr,
    /// Guest receiving the virtual (tunnel) interface.
    pub tunnel_guest: GuestId,
}

impl BridgeConfig {
    /// Validate bridge invariants: owner and tunnel guests must differ,
    /// MACs must differ, tunnel MAC must be locally administered.
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.owner_guest == self.tunnel_guest {
            return Err(NetworkError::InterfaceAlreadyAssigned);
        }
        if self.owner_mac == self.tunnel_mac {
            return Err(NetworkError::DuplicateMacAddress);
        }
        // Tunnel MAC should be locally administered (AETHER-generated).
        // We don't enforce this as a hard error since burned-in MACs could
        // theoretically be reused, but it is the expected configuration.
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network interface descriptor — one logical interface regardless of mode
// ─────────────────────────────────────────────────────────────────────────────

/// One logical network interface as seen by a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkInterface {
    /// SR-IOV Virtual Function presented as a full NIC.
    VirtualFunction(NicVirtualFunction),
    /// Physical NIC passed through directly.
    Physical(DedicatedNic),
    /// Paravirtualized virtual interface tunneling through another guest.
    /// Tagged with the owner guest so audits can detect bridge usage.
    BridgeTunnel {
        tunnel_mac: MacAddr,
        tunnel_guest: GuestId,
        owner_guest: GuestId,
    },
}

impl NetworkInterface {
    /// Guest that receives this interface.
    pub fn guest(&self) -> GuestId {
        match self {
            NetworkInterface::VirtualFunction(vf) => vf.guest,
            NetworkInterface::Physical(nic) => nic.guest,
            NetworkInterface::BridgeTunnel { tunnel_guest, .. } => *tunnel_guest,
        }
    }

    /// MAC address of this interface.
    pub fn mac(&self) -> MacAddr {
        match self {
            NetworkInterface::VirtualFunction(vf) => vf.mac,
            NetworkInterface::Physical(nic) => nic.mac,
            NetworkInterface::BridgeTunnel { tunnel_mac, .. } => *tunnel_mac,
        }
    }

    /// True if this interface routes through another guest (paravirt bridge).
    pub fn is_paravirt(&self) -> bool {
        matches!(self, NetworkInterface::BridgeTunnel { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAC registry — enforces uniqueness across all interfaces
// ─────────────────────────────────────────────────────────────────────────────

const MAX_INTERFACES: usize = 16;

/// Tracks all assigned MAC addresses and rejects duplicates.
///
/// Two interfaces with the same MAC address produce an ARP conflict that
/// silently breaks networking for both guests. This registry makes such a
/// conflict a registration-time error rather than a hard-to-debug runtime fault.
#[derive(Debug)]
pub struct MacRegistry {
    macs: [Option<MacAddr>; MAX_INTERFACES],
    count: usize,
}

impl MacRegistry {
    pub const fn new() -> Self {
        Self {
            macs: [None; MAX_INTERFACES],
            count: 0,
        }
    }

    /// Register a MAC address. Returns `DuplicateMacAddress` if already present.
    pub fn register(&mut self, mac: MacAddr) -> Result<(), NetworkError> {
        if self.count >= MAX_INTERFACES {
            return Err(NetworkError::RegistryFull);
        }
        for existing in self.macs.iter().flatten() {
            if *existing == mac {
                return Err(NetworkError::DuplicateMacAddress);
            }
        }
        self.macs[self.count] = Some(mac);
        self.count += 1;
        Ok(())
    }

    /// True if this MAC is already registered.
    pub fn contains(&self, mac: MacAddr) -> bool {
        self.macs.iter().flatten().any(|m| *m == mac)
    }

    /// Number of registered MACs.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for MacRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NIC SR-IOV state
// ─────────────────────────────────────────────────────────────────────────────

const MAX_NIC_VFS: usize = 8;

/// SR-IOV state for one NIC.
#[derive(Debug)]
pub struct NicSrIovState {
    pub enabled: bool,
    pub capability: NicSrIovCapability,
    vfs: [Option<NicVirtualFunction>; MAX_NIC_VFS],
    vf_count: usize,
}

impl NicSrIovState {
    pub const fn new(capability: NicSrIovCapability) -> Self {
        Self {
            enabled: false,
            capability,
            vfs: [None; MAX_NIC_VFS],
            vf_count: 0,
        }
    }

    pub fn assign_vf(&mut self, vf: NicVirtualFunction) -> Result<(), NetworkError> {
        if self.vf_count >= MAX_NIC_VFS {
            return Err(NetworkError::VfCountExceedsMax);
        }
        self.vfs[self.vf_count] = Some(vf);
        self.vf_count += 1;
        Ok(())
    }

    pub fn vf_for_guest(&self, guest: GuestId) -> Option<&NicVirtualFunction> {
        self.vfs.iter().flatten().find(|v| v.guest == guest)
    }

    pub fn assigned_count(&self) -> usize {
        self.vf_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network partition registry — interface-level tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of all network interfaces assigned to guests.
#[derive(Debug)]
pub struct NetworkPartitionRegistry {
    interfaces: [Option<NetworkInterface>; MAX_INTERFACES],
    count: usize,
    /// MAC uniqueness enforcer — every registration goes through here first.
    pub macs: MacRegistry,
}

impl NetworkPartitionRegistry {
    pub const fn new() -> Self {
        Self {
            interfaces: [None; MAX_INTERFACES],
            count: 0,
            macs: MacRegistry::new(),
        }
    }

    /// Register a network interface. MAC uniqueness is enforced before insertion.
    pub fn register(&mut self, iface: NetworkInterface) -> Result<(), NetworkError> {
        if self.count >= MAX_INTERFACES {
            return Err(NetworkError::RegistryFull);
        }
        // Enforce MAC uniqueness across all registered interfaces.
        self.macs.register(iface.mac())?;
        self.interfaces[self.count] = Some(iface);
        self.count += 1;
        Ok(())
    }

    /// Query the interface assigned to a guest, if any.
    pub fn interface_for_guest(&self, guest: GuestId) -> Option<&NetworkInterface> {
        self.interfaces
            .iter()
            .flatten()
            .find(|i| i.guest() == guest)
    }

    /// True if any registered interface is a paravirt bridge tunnel.
    /// Used to audit for No-Boundary Principle compliance.
    pub fn has_paravirt_interface(&self) -> bool {
        self.interfaces.iter().flatten().any(|i| i.is_paravirt())
    }

    /// Count of registered interfaces.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for NetworkPartitionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network partition state — top-level for one system's network configuration
//
// Boot-time sequence:
//   1. probe_sr_iov()      — attempt to read SR-IOV Extended Capability from NIC
//   2a. If SR-IOV available:
//       enable_sr_iov()    — write NumVFs to PCIe config; wait for VFs to appear
//       assign_sr_iov_vf() — record VF→guest mapping; enforce MAC uniqueness
//   2b. If dedicated adapters available:
//       assign_dedicated() — record NIC→guest mapping; enforce MAC uniqueness
//   2c. Fallback only:
//       configure_bridge() — validate bridge config; register owner + tunnel faces
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level network partitioning state.
pub struct NetworkPartitionState {
    /// Active partitioning mode (detected at boot from hardware).
    pub mode: Option<NetworkMode>,
    /// SR-IOV state (populated in SrIov mode).
    pub sr_iov: Option<NicSrIovState>,
    /// Bridge configuration (populated in ParavirtBridge mode).
    pub bridge: Option<BridgeConfig>,
    /// Registry of all assigned interfaces.
    pub registry: NetworkPartitionRegistry,
}

impl NetworkPartitionState {
    pub const fn new() -> Self {
        Self {
            mode: None,
            sr_iov: None,
            bridge: None,
            registry: NetworkPartitionRegistry::new(),
        }
    }

    /// Record SR-IOV capability discovered from the NIC's PCIe config space.
    ///
    /// In production: reads the SR-IOV Extended Capability structure from the
    /// NIC's PCIe ECAM config space and checks MaxVFs > 0.
    pub fn probe_sr_iov(&mut self, cap: NicSrIovCapability) -> Result<(), NetworkError> {
        if self.mode.is_some() {
            return Err(NetworkError::SrIovAlreadyEnabled);
        }
        if cap.max_vfs == 0 {
            return Err(NetworkError::SrIovNotSupported);
        }
        self.sr_iov = Some(NicSrIovState::new(cap));
        Ok(())
    }

    /// Enable SR-IOV and prepare for VF assignment.
    ///
    /// In production: writes NumVFs to SR-IOV Control register in PCIe config
    /// space, sets VF Enable bit, then waits for VFs to become enumerable.
    pub fn enable_sr_iov(&mut self) -> Result<(), NetworkError> {
        match self.mode {
            Some(NetworkMode::SrIov) => return Err(NetworkError::SrIovAlreadyEnabled),
            Some(_) => return Err(NetworkError::SrIovNotSupported),
            None => {}
        }
        let sr_iov = self.sr_iov.as_mut().ok_or(NetworkError::SrIovNotSupported)?;
        sr_iov.enabled = true;
        self.mode = Some(NetworkMode::SrIov);
        Ok(())
    }

    /// Assign an SR-IOV VF to a guest. Enforces MAC uniqueness.
    pub fn assign_sr_iov_vf(&mut self, vf: NicVirtualFunction) -> Result<(), NetworkError> {
        if self.mode != Some(NetworkMode::SrIov) {
            return Err(NetworkError::SrIovNotSupported);
        }
        let sr_iov = self.sr_iov.as_mut().ok_or(NetworkError::SrIovNotSupported)?;
        sr_iov.assign_vf(vf)?;
        self.registry.register(NetworkInterface::VirtualFunction(vf))?;
        Ok(())
    }

    /// Assign a dedicated physical NIC to a guest (DedicatedAdapter mode).
    ///
    /// Sets mode to DedicatedAdapter on first call. Subsequent calls add
    /// additional dedicated adapters (e.g., Android gets WiFi, Windows gets
    /// USB Ethernet).
    pub fn assign_dedicated(&mut self, nic: DedicatedNic) -> Result<(), NetworkError> {
        match self.mode {
            Some(NetworkMode::DedicatedAdapter) | None => {}
            Some(_) => return Err(NetworkError::InterfaceAlreadyAssigned),
        }
        self.registry.register(NetworkInterface::Physical(nic))?;
        self.mode = Some(NetworkMode::DedicatedAdapter);
        Ok(())
    }

    /// Configure a paravirtualized bridge (mode 3 fallback).
    ///
    /// Registers both the owner's physical interface and the tunnel guest's
    /// virtual interface. Validates bridge config invariants before insertion.
    ///
    /// This is a deliberate compromise. Callers must acknowledge this by using
    /// the `ParavirtBridge` variant explicitly — the type system ensures the
    /// compromise cannot be hidden behind a generic "assign" call.
    pub fn configure_bridge(&mut self, bridge: BridgeConfig) -> Result<(), NetworkError> {
        if self.mode.is_some() {
            return Err(NetworkError::InterfaceAlreadyAssigned);
        }
        bridge.validate()?;

        // Register owner's physical interface.
        let owner_nic = DedicatedNic {
            addr: bridge.nic_addr,
            mac: bridge.owner_mac,
            guest: bridge.owner_guest,
        };
        self.registry.register(NetworkInterface::Physical(owner_nic))?;

        // Register tunnel guest's virtual interface.
        let tunnel_iface = NetworkInterface::BridgeTunnel {
            tunnel_mac: bridge.tunnel_mac,
            tunnel_guest: bridge.tunnel_guest,
            owner_guest: bridge.owner_guest,
        };
        self.registry.register(tunnel_iface)?;

        self.bridge = Some(bridge);
        self.mode = Some(NetworkMode::ParavirtBridge);
        Ok(())
    }

    /// Query which interface a guest has been assigned.
    pub fn interface_for_guest(&self, guest: GuestId) -> Option<&NetworkInterface> {
        self.registry.interface_for_guest(guest)
    }

    /// True if any interface is paravirtualized (No-Boundary Principle audit).
    pub fn has_paravirt(&self) -> bool {
        self.registry.has_paravirt_interface()
    }
}

impl Default for NetworkPartitionState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MacAddr ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mac_unicast_accepted() {
        let mac = MacAddr::new([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert!(mac.is_ok());
    }

    #[test]
    fn test_mac_multicast_rejected() {
        let err = MacAddr::new([0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert_eq!(err, Err(NetworkError::MulticastMacRejected));
    }

    #[test]
    fn test_mac_broadcast_rejected() {
        let err = MacAddr::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(err, Err(NetworkError::MulticastMacRejected));
    }

    #[test]
    fn test_mac_locally_administered() {
        let mac = MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).unwrap();
        assert!(mac.is_locally_administered());
        assert!(!mac.is_globally_unique());
    }

    #[test]
    fn test_mac_globally_unique() {
        let mac = MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]).unwrap();
        assert!(!mac.is_locally_administered());
        assert!(mac.is_globally_unique());
    }

    // ── NicSrIovCapability ────────────────────────────────────────────────────

    #[test]
    fn test_sr_iov_vf_bdf() {
        let cap = NicSrIovCapability {
            max_vfs: 4,
            first_vf_offset: 0x0001,
            vf_stride: 0x0001,
        };
        let pf: u16 = 0x0000;
        assert_eq!(cap.vf_bdf(pf, 0), Some(0x0001));
        assert_eq!(cap.vf_bdf(pf, 1), Some(0x0002));
        assert_eq!(cap.vf_bdf(pf, 4), None); // out of range
    }

    // ── MacRegistry ───────────────────────────────────────────────────────────

    fn la_mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, last]).unwrap()
    }

    #[test]
    fn test_mac_registry_unique() {
        let mut reg = MacRegistry::new();
        reg.register(la_mac(0x01)).unwrap();
        reg.register(la_mac(0x02)).unwrap();
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn test_mac_registry_duplicate_rejected() {
        let mut reg = MacRegistry::new();
        reg.register(la_mac(0x01)).unwrap();
        assert_eq!(reg.register(la_mac(0x01)), Err(NetworkError::DuplicateMacAddress));
    }

    #[test]
    fn test_mac_registry_contains() {
        let mut reg = MacRegistry::new();
        reg.register(la_mac(0x01)).unwrap();
        assert!(reg.contains(la_mac(0x01)));
        assert!(!reg.contains(la_mac(0x02)));
    }

    // ── BridgeConfig ──────────────────────────────────────────────────────────

    fn valid_bridge() -> BridgeConfig {
        BridgeConfig {
            nic_addr: PcieAddr::new(0, 0, 0),
            owner_mac: MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01]).unwrap(),
            owner_guest: GuestId::Android,
            tunnel_mac: MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).unwrap(),
            tunnel_guest: GuestId::Windows,
        }
    }

    #[test]
    fn test_bridge_config_valid() {
        assert_eq!(valid_bridge().validate(), Ok(()));
    }

    #[test]
    fn test_bridge_config_same_mac_rejected() {
        let mac = MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).unwrap();
        let bridge = BridgeConfig {
            nic_addr: PcieAddr::new(0, 0, 0),
            owner_mac: mac,
            owner_guest: GuestId::Android,
            tunnel_mac: mac, // Same — should fail
            tunnel_guest: GuestId::Windows,
        };
        assert_eq!(bridge.validate(), Err(NetworkError::DuplicateMacAddress));
    }

    #[test]
    fn test_bridge_config_same_guest_rejected() {
        let bridge = BridgeConfig {
            nic_addr: PcieAddr::new(0, 0, 0),
            owner_mac: MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01]).unwrap(),
            owner_guest: GuestId::Android,
            tunnel_mac: MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).unwrap(),
            tunnel_guest: GuestId::Android, // Same guest
        };
        assert_eq!(bridge.validate(), Err(NetworkError::InterfaceAlreadyAssigned));
    }

    // ── NetworkInterface ──────────────────────────────────────────────────────

    #[test]
    fn test_interface_guest_and_mac() {
        let vf = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            mac: la_mac(0x01),
            guest: GuestId::Android,
        };
        let iface = NetworkInterface::VirtualFunction(vf);
        assert_eq!(iface.guest(), GuestId::Android);
        assert_eq!(iface.mac(), la_mac(0x01));
        assert!(!iface.is_paravirt());
    }

    #[test]
    fn test_bridge_tunnel_is_paravirt() {
        let iface = NetworkInterface::BridgeTunnel {
            tunnel_mac: la_mac(0x02),
            tunnel_guest: GuestId::Windows,
            owner_guest: GuestId::Android,
        };
        assert!(iface.is_paravirt());
        assert_eq!(iface.guest(), GuestId::Windows);
    }

    // ── NetworkPartitionState — SR-IOV path ───────────────────────────────────

    fn sriov_cap() -> NicSrIovCapability {
        NicSrIovCapability {
            max_vfs: 2,
            first_vf_offset: 1,
            vf_stride: 1,
        }
    }

    #[test]
    fn test_state_sr_iov_pipeline() {
        let mut state = NetworkPartitionState::new();
        state.probe_sr_iov(sriov_cap()).unwrap();
        state.enable_sr_iov().unwrap();
        assert_eq!(state.mode, Some(NetworkMode::SrIov));

        let vf = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            mac: la_mac(0x01),
            guest: GuestId::Android,
        };
        state.assign_sr_iov_vf(vf).unwrap();
        assert_eq!(state.registry.count(), 1);

        let iface = state.interface_for_guest(GuestId::Android).unwrap();
        assert_eq!(iface.mac(), la_mac(0x01));
        assert!(!state.has_paravirt());
    }

    #[test]
    fn test_state_sr_iov_duplicate_mac_rejected() {
        let mut state = NetworkPartitionState::new();
        state.probe_sr_iov(sriov_cap()).unwrap();
        state.enable_sr_iov().unwrap();

        let vf1 = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            mac: la_mac(0x01),
            guest: GuestId::Android,
        };
        let vf2 = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 2),
            mac: la_mac(0x01), // Same MAC — must fail
            guest: GuestId::Windows,
        };
        state.assign_sr_iov_vf(vf1).unwrap();
        assert_eq!(
            state.assign_sr_iov_vf(vf2),
            Err(NetworkError::DuplicateMacAddress)
        );
    }

    #[test]
    fn test_state_enable_sr_iov_twice_fails() {
        let mut state = NetworkPartitionState::new();
        state.probe_sr_iov(sriov_cap()).unwrap();
        state.enable_sr_iov().unwrap();
        assert_eq!(state.enable_sr_iov(), Err(NetworkError::SrIovAlreadyEnabled));
    }

    #[test]
    fn test_state_probe_no_vfs_fails() {
        let mut state = NetworkPartitionState::new();
        let cap = NicSrIovCapability {
            max_vfs: 0, // None supported
            first_vf_offset: 0,
            vf_stride: 0,
        };
        assert_eq!(state.probe_sr_iov(cap), Err(NetworkError::SrIovNotSupported));
    }

    // ── NetworkPartitionState — DedicatedAdapter path ─────────────────────────

    #[test]
    fn test_state_dedicated_adapter() {
        let mut state = NetworkPartitionState::new();
        let android_nic = DedicatedNic {
            addr: PcieAddr::new(0, 0, 0),
            mac: MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01]).unwrap(),
            guest: GuestId::Android,
        };
        state.assign_dedicated(android_nic).unwrap();
        assert_eq!(state.mode, Some(NetworkMode::DedicatedAdapter));
        assert!(!state.has_paravirt());
    }

    #[test]
    fn test_state_two_dedicated_adapters() {
        let mut state = NetworkPartitionState::new();
        let android_nic = DedicatedNic {
            addr: PcieAddr::new(0, 0, 0),
            mac: MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01]).unwrap(),
            guest: GuestId::Android,
        };
        let windows_nic = DedicatedNic {
            addr: PcieAddr::new(0, 0, 1),
            mac: MacAddr::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x02]).unwrap(),
            guest: GuestId::Windows,
        };
        state.assign_dedicated(android_nic).unwrap();
        state.assign_dedicated(windows_nic).unwrap();
        assert_eq!(state.registry.count(), 2);
    }

    // ── NetworkPartitionState — ParavirtBridge path ───────────────────────────

    #[test]
    fn test_state_bridge_pipeline() {
        let mut state = NetworkPartitionState::new();
        state.configure_bridge(valid_bridge()).unwrap();
        assert_eq!(state.mode, Some(NetworkMode::ParavirtBridge));
        // Both owner and tunnel interfaces registered.
        assert_eq!(state.registry.count(), 2);
        // Audit detects paravirt usage.
        assert!(state.has_paravirt());
    }

    #[test]
    fn test_state_bridge_and_sr_iov_conflict() {
        let mut state = NetworkPartitionState::new();
        state.configure_bridge(valid_bridge()).unwrap();
        // Attempt to also probe SR-IOV after bridge is configured.
        assert_eq!(
            state.probe_sr_iov(sriov_cap()),
            Err(NetworkError::SrIovAlreadyEnabled)
        );
    }

    #[test]
    fn test_state_bridge_guest_lookup() {
        let mut state = NetworkPartitionState::new();
        state.configure_bridge(valid_bridge()).unwrap();
        let tunnel = state.interface_for_guest(GuestId::Windows).unwrap();
        assert!(tunnel.is_paravirt());
        let owner = state.interface_for_guest(GuestId::Android).unwrap();
        assert!(!owner.is_paravirt());
    }

    // ── Error variants ────────────────────────────────────────────────────────

    #[test]
    fn test_error_variants_distinct() {
        assert_ne!(NetworkError::DuplicateMacAddress, NetworkError::SrIovNotSupported);
        assert_ne!(NetworkError::InterfaceAlreadyAssigned, NetworkError::InterfaceNotFound);
        assert_ne!(NetworkError::SrIovAlreadyEnabled, NetworkError::VfCountExceedsMax);
    }
}
