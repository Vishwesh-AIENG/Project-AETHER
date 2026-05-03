// ch02: Why AETHER Exists
//
// Every existing Android-on-PC product (BlueStacks, LDPlayer, Waydroid, etc.)
// makes compromises that produce detectable seams. Anti-cheat systems, banking
// apps, and DRM detect these seams by looking for places where the Android
// environment behaves differently from real hardware.
//
// This module classifies every known fingerprint source and maps each one to
// AETHER's strategy for eliminating it. The enum variants are the architecture:
// if a new device or subsystem doesn't fit into `Strategy::Passthrough` or
// `Strategy::PhysicsAccurateSimulation`, the design is wrong.
//
// Reference: README.md — Chapter 2, "Why AETHER Exists"

/// A category of detectable seam produced by every other Android-on-PC solution.
///
/// Each variant represents a specific architectural compromise that creates a
/// point where Android behavior differs from real hardware. Naming them
/// explicitly ensures no future implementation accidentally reintroduces one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintSource {
    /// Shared file system between Windows and Android partitions.
    /// Enables drag-and-drop convenience but produces distinct timing and
    /// path behavior not present on real Android storage.
    SharedFilesystem,

    /// Android GPU commands routed through the host OS's graphics driver.
    /// Produces timing characteristics, error codes, and capability reports
    /// that don't match any real GPU implementation.
    ProxiedGraphics,

    /// Android network stack tunnelled through Windows's network stack.
    /// Produces MTU, latency, and routing behavior inconsistent with a
    /// dedicated radio interface.
    SharedNetworkStack,

    /// Sensors simulated with simple noise generators rather than physical models.
    /// Real MEMS sensors have thermal drift, calibration signatures, and
    /// integration characteristics that trivial simulation omits.
    ImpreciseSensorModels,

    /// Device identifiers (IMEI, serial, hardware IDs) that are synthetic or
    /// generic in a recognizable way — empty strings, all-zeros, or values
    /// from a known virtual-device namespace.
    GenericIdentifiers,

    /// Virtual device register reads return values with timing not matching
    /// real hardware — too fast, too uniform, or quantized to host timer
    /// resolution rather than device hardware timing.
    ParavirtualDeviceTiming,
}

/// AETHER's architectural response to each `FingerprintSource`.
///
/// Every device or subsystem in AETHER maps to exactly one of these two
/// strategies. There is no third option. Any proposal that requires a third
/// strategy (e.g., "proxy through Windows for now") is rejected — it would
/// reintroduce the fingerprint the strategy was designed to eliminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The physical hardware device is assigned exclusively to one guest.
    ///
    /// The guest's driver talks directly to real hardware registers with zero
    /// hypervisor involvement in the data path. Timing, capability reports,
    /// and error behavior match the real device exactly because it IS the
    /// real device.
    ///
    /// Preferred for: GPU (SR-IOV VF), NVMe (namespace), WiFi (SR-IOV VF),
    /// USB controllers, PCIe devices.
    Passthrough,

    /// The hypervisor provides a software simulation with physics-accurate models.
    ///
    /// Used only for hardware that does not physically exist on a laptop
    /// (cellular modem, gyroscope, magnetometer, proximity sensor). The
    /// simulation must match the specific noise characteristics, timing, and
    /// response format of named real-world devices — not a generic model.
    ///
    /// Examples:
    /// - Accelerometer: Gaussian noise parameters matching Bosch BMI160
    /// - Gyroscope: random-walk drift matching InvenSense MPU6500
    /// - Modem: AT command timing matching Qualcomm baseband
    ///
    /// This strategy is a cost, not a feature. Every use of it is a potential
    /// fingerprint that must be continuously validated against real devices.
    PhysicsAccurateSimulation,
}

/// Maps each known fingerprint source to the strategy AETHER uses to eliminate it.
///
/// This table is the contractual expression of Chapter 2's argument: AETHER
/// exists because it refuses every compromise that every other solution made.
/// If a fingerprint source ever maps to something other than one of the two
/// valid strategies, the architecture has drifted.
pub const FINGERPRINT_STRATEGIES: &[(FingerprintSource, Strategy)] = &[
    (FingerprintSource::SharedFilesystem,        Strategy::Passthrough),
    (FingerprintSource::ProxiedGraphics,          Strategy::Passthrough),
    (FingerprintSource::SharedNetworkStack,       Strategy::Passthrough),
    (FingerprintSource::ImpreciseSensorModels,    Strategy::PhysicsAccurateSimulation),
    (FingerprintSource::GenericIdentifiers,       Strategy::PhysicsAccurateSimulation),
    (FingerprintSource::ParavirtualDeviceTiming,  Strategy::Passthrough),
];
