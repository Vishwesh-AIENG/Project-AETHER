// ch64: HVC Paravirt ABI
//
// Formalises the AETHER hypervisor-call vendor range as a typed ABI.
// Function IDs are stable across hypervisor versions; new functions are
// added by allocating the next unused ID. Versioning happens at the
// ABI level — the guest passes its built-against ABI version in x0 of
// `GET_VERSION`, and the hypervisor refuses cross-version calls.
//
// ── Function IDs (vendor range, SMCCC) ────────────────────────────────────────
//
//   ARM64 (HVC instruction, vendor range 0x8600_0001..0x86FF_FFFF):
//     0x8600_0001  GetVersion       (x0)             -> (status, abi_version)
//     0x8600_0002  BridgeModeGet    (x0)             -> (status, mode_byte)
//     0x8600_0003  BridgeModeSet    (x0, x1=mode)    -> (status)
//     0x8600_0004  SensorRead       (x0, x1=which)   -> (status, x_bits, y_bits, z_bits)
//     0x8600_0005  UpdateStage      (x0, x1=slot)    -> (status)  -- stub
//     0x8600_0006  DiagLogRead      (x0, x1=offset)  -> (status, bytes_read, …)
//
//   x86_64 (VMMCALL/VMCALL, same numeric IDs in RAX, args in RBX/RCX/RDX).
//
// ── Versioning Rule ──────────────────────────────────────────────────────────
//
//   AETHER_ABI_VERSION_MAJOR is bumped on every backwards-incompatible
//   change (id reused, semantics changed). _MINOR is bumped on additive
//   changes. Guests pass the major they were built against; hypervisor
//   compares its own major; mismatch returns AbiVersionMismatch.

pub const AETHER_HVC_VENDOR_BASE: u64 = 0x8600_0000;
pub const AETHER_ABI_VERSION_MAJOR: u32 = 1;
pub const AETHER_ABI_VERSION_MINOR: u32 = 0;

/// Concrete function-ID enum. The discriminant is the SMCCC function ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AetherHvcFn {
    GetVersion    = 0x8600_0001,
    BridgeModeGet = 0x8600_0002,
    BridgeModeSet = 0x8600_0003,
    SensorRead    = 0x8600_0004,
    UpdateStage   = 0x8600_0005,
    DiagLogRead   = 0x8600_0006,
}

impl AetherHvcFn {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x8600_0001 => Some(AetherHvcFn::GetVersion),
            0x8600_0002 => Some(AetherHvcFn::BridgeModeGet),
            0x8600_0003 => Some(AetherHvcFn::BridgeModeSet),
            0x8600_0004 => Some(AetherHvcFn::SensorRead),
            0x8600_0005 => Some(AetherHvcFn::UpdateStage),
            0x8600_0006 => Some(AetherHvcFn::DiagLogRead),
            _ => None,
        }
    }

    pub fn id(self) -> u64 { self as u64 }
}

/// SMCCC-conformant status codes. Negative on the wire (sign-extended
/// to u64); positive values are reserved for function-specific success
/// data in the same register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AetherHvcStatus {
    Success                = 0,
    NotSupported           = -1,
    InvalidParameter       = -2,
    Denied                 = -3,
    AbiVersionMismatch     = -4,
    InternalError          = -5,
}

impl AetherHvcStatus {
    pub fn to_u64(self) -> u64 {
        // SMCCC: status in x0/RAX, negative codes are 64-bit sign-extended.
        let n: i64 = self as i32 as i64;
        n as u64
    }
}

/// Which sensor SensorRead returns. Matches ch47's HvcSensorId values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HvcSensorId {
    Accelerometer = 0,
    Gyroscope     = 1,
    Magnetometer  = 2,
    Proximity     = 3,
}

impl HvcSensorId {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(HvcSensorId::Accelerometer),
            1 => Some(HvcSensorId::Gyroscope),
            2 => Some(HvcSensorId::Magnetometer),
            3 => Some(HvcSensorId::Proximity),
            _ => None,
        }
    }
}

/// 4-register return for SensorRead. Other functions use simpler returns
/// (status only, or status + value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorReadRet {
    pub status: AetherHvcStatus,
    pub x_bits: u32,  // f32::to_bits()
    pub y_bits: u32,
    pub z_bits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvcAbiError {
    UnknownFunctionId,
    InvalidSensorId,
    VersionMajorMismatch,
    InvalidBridgeMode,
    SlotOutOfRange,
}

/// Compare a guest-supplied ABI major against the hypervisor's.
pub fn check_abi_compat(guest_major: u32) -> Result<(), HvcAbiError> {
    if guest_major != AETHER_ABI_VERSION_MAJOR {
        return Err(HvcAbiError::VersionMajorMismatch);
    }
    Ok(())
}

/// Dispatch shape — pure function, no globals. Tests exercise this; the
/// real hypervisor wires it into the VMEXIT (x86) and exception (ARM)
/// handlers with vCPU register access.
pub fn dispatch_function(
    f: AetherHvcFn,
    arg1: u64,
    arg2: u64,
) -> (AetherHvcStatus, [u64; 3]) {
    match f {
        AetherHvcFn::GetVersion => {
            // arg1 = guest major (ignored at function level — caller does
            // their own version check via check_abi_compat before invoke);
            // return current major | minor.
            let _ = arg1; let _ = arg2;
            let major = AETHER_ABI_VERSION_MAJOR as u64;
            let minor = AETHER_ABI_VERSION_MINOR as u64;
            (AetherHvcStatus::Success, [major, minor, 0])
        }
        AetherHvcFn::BridgeModeGet => {
            let _ = arg1; let _ = arg2;
            // Stub: defaults to OFF (0). Real impl reads from configuration_app.
            (AetherHvcStatus::Success, [0, 0, 0])
        }
        AetherHvcFn::BridgeModeSet => {
            // arg1 = 0 OFF / 1 ON. Anything else rejected.
            if arg1 > 1 {
                return (AetherHvcStatus::InvalidParameter, [0; 3]);
            }
            (AetherHvcStatus::Success, [0; 3])
        }
        AetherHvcFn::SensorRead => {
            let which = match HvcSensorId::from_u8(arg1 as u8) {
                Some(s) => s,
                None => return (AetherHvcStatus::InvalidParameter, [0; 3]),
            };
            let _ = which;
            // Stub: zero acceleration on all axes. Real impl pulls
            // VirtualSensorSuite output through the paravirt module.
            (AetherHvcStatus::Success, [
                0.0f32.to_bits() as u64,
                0.0f32.to_bits() as u64,
                0.0f32.to_bits() as u64,
            ])
        }
        AetherHvcFn::UpdateStage => {
            // arg1 = target slot byte. Anything outside {0,1} rejected.
            if arg1 > 1 {
                return (AetherHvcStatus::InvalidParameter, [0; 3]);
            }
            (AetherHvcStatus::Success, [0; 3])
        }
        AetherHvcFn::DiagLogRead => {
            // arg1 = byte offset into the diagnostic ring buffer. Stub:
            // always returns 0 bytes.
            let _ = arg1; let _ = arg2;
            (AetherHvcStatus::Success, [0, 0, 0])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_id_roundtrip() {
        let all = [
            AetherHvcFn::GetVersion,    AetherHvcFn::BridgeModeGet,
            AetherHvcFn::BridgeModeSet, AetherHvcFn::SensorRead,
            AetherHvcFn::UpdateStage,   AetherHvcFn::DiagLogRead,
        ];
        for f in all {
            assert_eq!(AetherHvcFn::from_id(f.id()), Some(f));
        }
    }

    #[test]
    fn fn_ids_are_in_vendor_range() {
        let all = [
            AetherHvcFn::GetVersion,    AetherHvcFn::BridgeModeGet,
            AetherHvcFn::BridgeModeSet, AetherHvcFn::SensorRead,
            AetherHvcFn::UpdateStage,   AetherHvcFn::DiagLogRead,
        ];
        for f in all {
            assert!(f.id() >= AETHER_HVC_VENDOR_BASE);
            assert!(f.id() <  AETHER_HVC_VENDOR_BASE + 0x0100_0000);
        }
    }

    #[test]
    fn from_id_rejects_unknown() {
        assert!(AetherHvcFn::from_id(0x8600_0000).is_none());
        assert!(AetherHvcFn::from_id(0x8600_FFFF).is_none());
        assert!(AetherHvcFn::from_id(0).is_none());
    }

    #[test]
    fn status_to_u64_sign_extends() {
        let s = AetherHvcStatus::InvalidParameter; // -2
        let n = s.to_u64();
        assert_eq!(n, 0xFFFF_FFFF_FFFF_FFFEu64);
    }

    #[test]
    fn sensor_id_roundtrip() {
        for s in [
            HvcSensorId::Accelerometer, HvcSensorId::Gyroscope,
            HvcSensorId::Magnetometer,  HvcSensorId::Proximity,
        ] {
            assert_eq!(HvcSensorId::from_u8(s as u8), Some(s));
        }
        assert!(HvcSensorId::from_u8(4).is_none());
    }

    #[test]
    fn version_check() {
        assert!(check_abi_compat(AETHER_ABI_VERSION_MAJOR).is_ok());
        assert_eq!(
            check_abi_compat(AETHER_ABI_VERSION_MAJOR + 1),
            Err(HvcAbiError::VersionMajorMismatch)
        );
    }

    #[test]
    fn dispatch_get_version_returns_current() {
        let (s, r) = dispatch_function(AetherHvcFn::GetVersion, 0, 0);
        assert_eq!(s, AetherHvcStatus::Success);
        assert_eq!(r[0], AETHER_ABI_VERSION_MAJOR as u64);
        assert_eq!(r[1], AETHER_ABI_VERSION_MINOR as u64);
    }

    #[test]
    fn dispatch_bridge_set_rejects_out_of_range() {
        let (s, _) = dispatch_function(AetherHvcFn::BridgeModeSet, 2, 0);
        assert_eq!(s, AetherHvcStatus::InvalidParameter);
        let (s, _) = dispatch_function(AetherHvcFn::BridgeModeSet, 1, 0);
        assert_eq!(s, AetherHvcStatus::Success);
    }

    #[test]
    fn dispatch_sensor_read_rejects_invalid_id() {
        let (s, _) = dispatch_function(AetherHvcFn::SensorRead, 99, 0);
        assert_eq!(s, AetherHvcStatus::InvalidParameter);
    }

    #[test]
    fn dispatch_update_stage_rejects_out_of_range_slot() {
        let (s, _) = dispatch_function(AetherHvcFn::UpdateStage, 2, 0);
        assert_eq!(s, AetherHvcStatus::InvalidParameter);
    }
}
