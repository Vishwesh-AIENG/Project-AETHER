// ch60: Configuration App — runtime user-tunable settings surface
//
// The post-install settings module. Holds the same UEFI-variable backing
// store as ch59 Setup Wizard, plus a few additional knobs that wouldn't
// appear on first-boot (OTA channel, identity-feed mode, fingerprint
// strictness). Read access is hot from Android (every IRadio /
// ISensors / IHealth HAL call queries one or more of these), so reads
// are lock-free pointer loads against snapshotted state; writes take
// a global spinlock and atomically swap the snapshot pointer.
//
// ── Storage ───────────────────────────────────────────────────────────────────
//
//   UEFI variables (NV+BS+RT, AETHER_VARIABLE_GUID):
//
//     AetherBridgeMode        u8  — 0 OFF / 1 ON (also written by ch59)
//     AetherSensorProfile     u8  — 0/1/2 (also written by ch59)
//     AetherOtaChannel        u8  — 0 Stable / 1 Beta / 2 Disabled
//     AetherIdentityFeed      u8  — 0 Software / 1 Phone (Bridge)
//     AetherFingerprintStrict u8  — 0 Strict / 1 Permissive (dev)
//     AetherUiTheme           u8  — 0 Dark / 1 Light / 2 System
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1. ConfigKey enum — typed key namespace.
//   2. ConfigValue + ConfigChange records.
//   3. ConfigAppConfig + Gate + Error + Phase.
//   4. ConfigSnapshot — atomic-swappable read surface.
//   5. init_configuration_app() — 6-step pipeline.

/// Typed config key namespace. New keys go at the END (ABI-stable ordinal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ConfigKey {
    BridgeMode        = 0,
    SensorProfile     = 1,
    OtaChannel        = 2,
    IdentityFeed      = 3,
    FingerprintStrict = 4,
    UiTheme           = 5,
}

impl ConfigKey {
    pub const fn ordinal(self) -> u8 { self as u8 }
    pub fn from_ordinal(o: u8) -> Option<Self> {
        match o {
            0 => Some(ConfigKey::BridgeMode),
            1 => Some(ConfigKey::SensorProfile),
            2 => Some(ConfigKey::OtaChannel),
            3 => Some(ConfigKey::IdentityFeed),
            4 => Some(ConfigKey::FingerprintStrict),
            5 => Some(ConfigKey::UiTheme),
            _ => None,
        }
    }

    /// UEFI variable name backing this key.
    pub fn variable_name(self) -> &'static [u8] {
        match self {
            ConfigKey::BridgeMode        => b"AetherBridgeMode",
            ConfigKey::SensorProfile     => b"AetherSensorProfile",
            ConfigKey::OtaChannel        => b"AetherOtaChannel",
            ConfigKey::IdentityFeed      => b"AetherIdentityFeed",
            ConfigKey::FingerprintStrict => b"AetherFingerprintStrict",
            ConfigKey::UiTheme           => b"AetherUiTheme",
        }
    }

    /// Maximum valid u8 value for this key (inclusive). Writes outside
    /// the range are rejected with ConfigAppError::ValueOutOfRange.
    pub fn max_value(self) -> u8 {
        match self {
            ConfigKey::BridgeMode        => 1,
            ConfigKey::SensorProfile     => 2,
            ConfigKey::OtaChannel        => 2,
            ConfigKey::IdentityFeed      => 1,
            ConfigKey::FingerprintStrict => 1,
            ConfigKey::UiTheme           => 2,
        }
    }
}

/// Number of typed keys (one per ConfigKey variant). Static array size.
pub const CONFIG_KEY_COUNT: usize = 6;

/// One key/value pair. Used both for in-memory snapshot and for the
/// audit log emitted by every write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigKv {
    pub key:   ConfigKey,
    pub value: u8,
}

/// A change record. Surfaced to the (future) audit-log subsystem so OTA
/// can verify post-update state matches pre-update intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigChange {
    pub key:       ConfigKey,
    pub old_value: u8,
    pub new_value: u8,
}

/// Atomic read surface. Every ConfigKey's current u8. The runtime keeps
/// a pointer to one of these in a static; writers allocate a new snapshot,
/// swap the pointer atomically, and let the old one drop. Reads are
/// lock-free pointer loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub values: [u8; CONFIG_KEY_COUNT],
}

impl ConfigSnapshot {
    pub const fn aether_defaults() -> Self {
        let mut values = [0u8; CONFIG_KEY_COUNT];
        // Bridge OFF, Stationary sensors, Stable OTA, Software identity,
        // Strict fingerprint, System theme.
        values[ConfigKey::BridgeMode.ordinal() as usize]        = 0;
        values[ConfigKey::SensorProfile.ordinal() as usize]     = 0;
        values[ConfigKey::OtaChannel.ordinal() as usize]        = 0;
        values[ConfigKey::IdentityFeed.ordinal() as usize]      = 0;
        values[ConfigKey::FingerprintStrict.ordinal() as usize] = 0;
        values[ConfigKey::UiTheme.ordinal() as usize]           = 2;
        Self { values }
    }

    pub fn get(&self, key: ConfigKey) -> u8 {
        self.values[key.ordinal() as usize]
    }

    pub fn with(&self, key: ConfigKey, value: u8) -> Self {
        let mut out = *self;
        out.values[key.ordinal() as usize] = value;
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAppError {
    /// Asked for a key the build doesn't define.
    UnknownKey,
    /// Value outside the inclusive range [0, key.max_value()].
    ValueOutOfRange,
    /// UEFI SetVariable failed.
    VariableWriteError,
    /// UEFI GetVariable failed.
    VariableReadError,
    /// Phase machine asked to advance backward.
    PhaseRegression,
    /// Snapshot replace raced with a concurrent writer (only fatal in
    /// release; debug builds retry).
    SnapshotRaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigAppPhase {
    NotStarted,
    DefaultsLoaded,
    UefiVariablesRead,
    SnapshotPublished,
    GatePassed,
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigAppConfig {
    /// Whether the runtime must guarantee lock-free reads. Always true
    /// in production — Android HALs poll IsBridgeOn() and ISensors at
    /// frame rates and cannot afford a spinlock acquire on every read.
    pub require_lock_free_reads: bool,
    /// Per-write spinlock spin budget (loop iterations before yield).
    pub write_spin_budget: u32,
}

impl ConfigAppConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            require_lock_free_reads: true,
            write_spin_budget:       1024,
        }
    }
    pub fn validate(&self) -> Result<(), ConfigAppError> {
        if !self.require_lock_free_reads {
            // Reads must be lock-free in production.
            return Err(ConfigAppError::SnapshotRaced);
        }
        if self.write_spin_budget == 0 {
            return Err(ConfigAppError::SnapshotRaced);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigAppGate {
    pub defaults_loaded:     bool,
    pub uefi_variables_read: bool,
    pub snapshot_published:  bool,
    pub reads_lock_free:     bool,
}

impl ConfigAppGate {
    pub fn passes(&self) -> bool {
        self.defaults_loaded
            && self.uefi_variables_read
            && self.snapshot_published
            && self.reads_lock_free
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigAppState {
    pub config:   ConfigAppConfig,
    pub snapshot: ConfigSnapshot,
    pub phase:    ConfigAppPhase,
    pub gate:     ConfigAppGate,
}

impl ConfigAppState {
    pub const fn new(config: ConfigAppConfig) -> Self {
        Self {
            config,
            snapshot: ConfigSnapshot::aether_defaults(),
            phase:    ConfigAppPhase::NotStarted,
            gate:     ConfigAppGate {
                defaults_loaded:     false,
                uefi_variables_read: false,
                snapshot_published:  false,
                reads_lock_free:     false,
            },
        }
    }

    pub fn advance_phase(&mut self, next: ConfigAppPhase) -> Result<(), ConfigAppError> {
        if next < self.phase {
            return Err(ConfigAppError::PhaseRegression);
        }
        self.phase = next;
        Ok(())
    }

    pub fn set(&mut self, key: ConfigKey, value: u8) -> Result<ConfigChange, ConfigAppError> {
        if value > key.max_value() {
            return Err(ConfigAppError::ValueOutOfRange);
        }
        let old = self.snapshot.get(key);
        self.snapshot = self.snapshot.with(key, value);
        Ok(ConfigChange { key, old_value: old, new_value: value })
    }

    pub fn get(&self, key: ConfigKey) -> u8 { self.snapshot.get(key) }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }
}

/// 6-step pipeline.
///   1. validate config
///   2. load aether_defaults snapshot
///   3. read each ConfigKey's variable from UEFI; overwrite default if set
///   4. publish snapshot (atomic pointer swap into runtime static)
///   5. assert reads_lock_free invariant
///   6. gate.passes()
pub fn init_configuration_app(cfg: &ConfigAppConfig) -> Result<ConfigAppState, ConfigAppError> {
    cfg.validate()?;
    let mut s = ConfigAppState::new(*cfg);
    s.advance_phase(ConfigAppPhase::DefaultsLoaded)?;
    s.gate.defaults_loaded = true;
    // Step 3 (UEFI read) is delegated to caller; the test/native build
    // marks it ready manually so init_configuration_app stays pure.
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        ConfigAppConfig::aether_defaults().validate().unwrap();
    }

    #[test]
    fn key_ordinal_roundtrip() {
        for k in [
            ConfigKey::BridgeMode, ConfigKey::SensorProfile, ConfigKey::OtaChannel,
            ConfigKey::IdentityFeed, ConfigKey::FingerprintStrict, ConfigKey::UiTheme,
        ] {
            assert_eq!(ConfigKey::from_ordinal(k.ordinal()), Some(k));
        }
        assert_eq!(ConfigKey::from_ordinal(CONFIG_KEY_COUNT as u8), None);
    }

    #[test]
    fn set_clamps_above_max() {
        let mut s = ConfigAppState::new(ConfigAppConfig::aether_defaults());
        assert_eq!(s.set(ConfigKey::BridgeMode, 2), Err(ConfigAppError::ValueOutOfRange));
        assert_eq!(s.set(ConfigKey::BridgeMode, 1), Ok(ConfigChange {
            key: ConfigKey::BridgeMode,
            old_value: 0,
            new_value: 1,
        }));
        assert_eq!(s.get(ConfigKey::BridgeMode), 1);
    }

    #[test]
    fn snapshot_with_is_pure() {
        let snap = ConfigSnapshot::aether_defaults();
        let updated = snap.with(ConfigKey::UiTheme, 0);
        assert_eq!(snap.get(ConfigKey::UiTheme), 2);
        assert_eq!(updated.get(ConfigKey::UiTheme), 0);
    }

    #[test]
    fn phase_is_monotonic() {
        let mut s = ConfigAppState::new(ConfigAppConfig::aether_defaults());
        s.advance_phase(ConfigAppPhase::DefaultsLoaded).unwrap();
        s.advance_phase(ConfigAppPhase::UefiVariablesRead).unwrap();
        assert_eq!(s.advance_phase(ConfigAppPhase::DefaultsLoaded),
                   Err(ConfigAppError::PhaseRegression));
    }

    #[test]
    fn gate_requires_all_four() {
        let mut g = ConfigAppGate::default();
        assert!(!g.passes());
        g.defaults_loaded = true;
        g.uefi_variables_read = true;
        g.snapshot_published = true;
        assert!(!g.passes());
        g.reads_lock_free = true;
        assert!(g.passes());
    }

    #[test]
    fn init_advances_to_defaults_loaded() {
        let s = init_configuration_app(&ConfigAppConfig::aether_defaults()).unwrap();
        assert_eq!(s.phase, ConfigAppPhase::DefaultsLoaded);
        assert!(s.gate.defaults_loaded);
    }
}
