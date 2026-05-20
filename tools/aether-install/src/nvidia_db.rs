// nvidia_db.rs -- NVIDIA consumer GPU reset bug device-ID table.
//
// The "NVIDIA reset bug" is the well-known issue where a consumer GeForce GPU
// passed through to a VM/guest cannot be cleanly reset back to the host on
// teardown. After the guest releases the device, BIOS-level power cycle is
// required to return the card to a usable state -- a warm reboot is not
// sufficient.
//
// Mitigations existed (vendor-reset kernel module on Linux) but the bug is
// hardware/microcode-level on affected silicon. From AETHER's perspective the
// user just needs a heads-up: if you assign this card to Android via full
// passthrough, switching back to Windows may require power-off rather than
// just reboot.
//
// Affected families (broad strokes):
//   Turing      (RTX 20-series, GTX 16-series)  -- widespread
//   Ampere      (RTX 30-series)                 -- widespread on most boards
//   Ada Lovelace (RTX 40-series)                -- largely fixed
//
// Source: vendor-reset project + community testing. We list a conservative
// subset of device IDs; presence in the table = "warn", absence != "safe".
// (Absence just means we don't know enough to flag it; we still warn that
// passthrough has reset risk in general for NVIDIA consumer cards.)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetBugSeverity {
    /// Definitively affected on most motherboards. Warn loudly.
    Affected,
    /// Inconsistent reports; treat as affected.
    LikelyAffected,
    /// Generally fixed; light note only.
    LikelyFixed,
}

#[derive(Debug, Clone, Copy)]
pub struct NvidiaResetBugEntry {
    pub device_id: u16,
    pub name:      &'static str,
    pub severity:  ResetBugSeverity,
}

#[allow(dead_code)] // exported for callers that want to detect NVIDIA at the vendor-id level
pub const NVIDIA_VENDOR_ID: u16 = 0x10DE;

/// Conservative list of NVIDIA consumer-GPU device IDs known to exhibit the
/// reset bug. Quadro / Tesla / A-series cards are NOT listed here -- they
/// support proper FLR and don't need the warning.
pub const NVIDIA_RESET_BUG_TABLE: &[NvidiaResetBugEntry] = &[
    // ---- Turing (RTX 20xx, GTX 16xx) -------------------------------------
    NvidiaResetBugEntry { device_id: 0x1E02, name: "RTX 2080 Ti",        severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1E04, name: "RTX 2080 Ti (Rev A)",severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1E07, name: "RTX 2080 Ti",        severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1E82, name: "RTX 2080",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1E84, name: "RTX 2070 SUPER",     severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1F02, name: "RTX 2070",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1F07, name: "RTX 2070",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1F08, name: "RTX 2060 SUPER",     severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x1F82, name: "GTX 1650",           severity: ResetBugSeverity::LikelyAffected },
    NvidiaResetBugEntry { device_id: 0x2182, name: "GTX 1660 Ti",        severity: ResetBugSeverity::LikelyAffected },
    NvidiaResetBugEntry { device_id: 0x2184, name: "GTX 1660",           severity: ResetBugSeverity::LikelyAffected },

    // ---- Ampere (RTX 30xx) ------------------------------------------------
    NvidiaResetBugEntry { device_id: 0x2204, name: "RTX 3090",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2206, name: "RTX 3080",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2208, name: "RTX 3080 Ti",        severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2216, name: "RTX 3080 (LHR)",     severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2484, name: "RTX 3070",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2486, name: "RTX 3060 Ti",        severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2503, name: "RTX 3060",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2504, name: "RTX 3060",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2507, name: "RTX 3050",           severity: ResetBugSeverity::Affected },
    NvidiaResetBugEntry { device_id: 0x2520, name: "RTX 3060 Mobile",    severity: ResetBugSeverity::Affected },

    // ---- Ada Lovelace (RTX 40xx) -- largely fixed -----------------------
    NvidiaResetBugEntry { device_id: 0x2684, name: "RTX 4090",           severity: ResetBugSeverity::LikelyFixed },
    NvidiaResetBugEntry { device_id: 0x2702, name: "RTX 4080",           severity: ResetBugSeverity::LikelyFixed },
    NvidiaResetBugEntry { device_id: 0x2704, name: "RTX 4080",           severity: ResetBugSeverity::LikelyFixed },
    NvidiaResetBugEntry { device_id: 0x2782, name: "RTX 4070 Ti",        severity: ResetBugSeverity::LikelyFixed },
    NvidiaResetBugEntry { device_id: 0x2786, name: "RTX 4070",           severity: ResetBugSeverity::LikelyFixed },
];

/// Look up a device ID in the reset-bug table. Returns None if the device is
/// not listed (which means "we don't know" -- emit a generic warning).
pub fn lookup(device_id: u16) -> Option<&'static NvidiaResetBugEntry> {
    NVIDIA_RESET_BUG_TABLE.iter().find(|e| e.device_id == device_id)
}

/// Returns true if the device ID looks like an NVIDIA *consumer* card. Quadro,
/// Tesla, and A-series device IDs are filtered out here. Heuristic: the upper
/// nibble of the device ID. NVIDIA reserves ranges 0x1Exx-0x1Fxx (Turing),
/// 0x21xx (TU11x), 0x22xx-0x25xx (Ampere consumer), 0x26xx-0x27xx (Ada
/// consumer). Professional cards live mostly in 0x1Bxx (Quadro RTX), 0x20xx
/// (A100), 0x2330 (H100), etc.
pub fn is_consumer_device_id(device_id: u16) -> bool {
    let hi = device_id >> 8;
    matches!(hi,
        0x1E | 0x1F |       // Turing consumer
        0x21 |              // TU116/TU117 consumer
        0x22 | 0x23 | 0x24 | 0x25 |  // Ampere consumer
        0x26 | 0x27 | 0x28   // Ada consumer
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_rtx_3060() {
        let e = lookup(0x2504).expect("RTX 3060 should be listed");
        assert_eq!(e.severity, ResetBugSeverity::Affected);
        assert!(e.name.contains("3060"));
    }

    #[test]
    fn finds_rtx_4090() {
        let e = lookup(0x2684).expect("RTX 4090 should be listed");
        assert_eq!(e.severity, ResetBugSeverity::LikelyFixed);
    }

    #[test]
    fn unknown_device_returns_none() {
        assert!(lookup(0xFFFF).is_none());
    }

    #[test]
    fn consumer_id_heuristic() {
        assert!( is_consumer_device_id(0x2504));   // RTX 3060
        assert!( is_consumer_device_id(0x2684));   // RTX 4090
        assert!(!is_consumer_device_id(0x1BB6));   // Quadro RTX 5000
        assert!(!is_consumer_device_id(0x20B0));   // A100
    }
}
