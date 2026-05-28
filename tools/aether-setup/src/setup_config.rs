// setup_config.rs — the JSON contract between this GUI installer and the
// hypervisor's ch59 setup wizard.
//
// At Confirm time the installer writes a setup-config.json into the AETHER
// config partition (alongside hypervisor.efi / selector.efi). On first boot,
// the ch59 wizard reads this file, populates its WizardSelections, writes
// the matching UEFI variables, and skips straight to SetupComplete — the
// user never sees the EL2-side wizard if they completed this one.
//
// Format is intentionally simple JSON so it can be inspected with any text
// editor and edited by an OEM imaging tool that doesn't link Rust serde.

use serde::{Deserialize, Serialize};

/// Filename written into the AETHER ESP root.
pub const SETUP_CONFIG_FILENAME: &str = "setup-config.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BridgeModeDefault { Off, On }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorProfile { Stationary, InHand, Driving }

/// The five fields the hypervisor ch59 wizard captures, plus a schema
/// version so a future format change doesn't silently misread an old file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConfig {
    /// Schema version. Bump on incompatible changes; ch59 rejects unknown.
    pub schema_version: u32,
    /// Short language code: "en", "hi", "ja", "zh-CN", etc.
    pub language: String,
    /// Keyboard layout: "qwerty", "azerty", "dvorak", etc.
    pub keyboard_layout: String,
    /// IANA time zone: "Asia/Kolkata", "America/New_York", etc.
    pub timezone: String,
    /// Whether Phone Bridge starts ON by default (ch48).
    pub bridge_mode: BridgeModeDefault,
    /// Virtual sensor noise profile (ch12 + ch47).
    pub sensor_profile: SensorProfile,
}

impl SetupConfig {
    pub const CURRENT_SCHEMA: u32 = 1;

    /// Reasonable defaults — match the ch59 LANGUAGE_OPTIONS / KEYBOARD_
    /// LAYOUT_OPTIONS first entries.
    pub fn defaults() -> Self {
        Self {
            schema_version: Self::CURRENT_SCHEMA,
            language: "en".to_string(),
            keyboard_layout: "qwerty".to_string(),
            timezone: "UTC".to_string(),
            bridge_mode: BridgeModeDefault::Off,
            sensor_profile: SensorProfile::Stationary,
        }
    }

    /// Pretty-printed JSON. Pretty because this file is meant to be
    /// human-inspectable on the ESP.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .expect("SetupConfig serialization must not fail")
    }
}

// Tightly mirror ch59's LANGUAGE_OPTIONS / KEYBOARD_LAYOUT_OPTIONS /
// REGION_OPTIONS so the GUI can never offer a choice the hypervisor will
// reject. Keep these in sync with hypervisor/src/setup_wizard.rs.
pub const LANGUAGES:  &[(&str, &str)] = &[
    ("en", "English"),
    ("hi", "हिन्दी (Hindi)"),
    ("ta", "தமிழ் (Tamil)"),
    ("te", "తెలుగు (Telugu)"),
    ("ja", "日本語 (Japanese)"),
    ("fr", "Français"),
    ("de", "Deutsch"),
    ("es", "Español"),
    ("pt", "Português"),
    ("zh-CN", "中文 (简体)"),
];

pub const KEYBOARDS: &[&str] =
    &["qwerty", "qwertz", "azerty", "dvorak", "colemak"];

pub const TIMEZONES: &[&str] = &[
    "UTC",
    "Asia/Kolkata",
    "Asia/Tokyo",
    "Europe/Berlin",
    "Europe/London",
    "America/New_York",
    "America/Los_Angeles",
];
