// ch63: AETHER Manager Android App
//
// The Android-side companion app. Lives at /system/priv-app/AetherManager
// on the device, talks to the hypervisor via the ch64 HVC paravirt ABI,
// surfaces the four user-facing controls:
//
//   1. Bridge Mode toggle (calls AetherHvcFn::BridgeModeSet)
//   2. Sensor profile (Stationary / InHand / Driving) — re-seeds the
//      virtual IMU noise model on the hypervisor side
//   3. Identity feed source (Software / Phone) — when Phone is selected
//      the modem returns the tethered handset's IMEI/IMSI/MAC instead of
//      the generated values
//   4. OTA controls (check, download, install, rollback)
//
// This module is the *specification* of the app's runtime contract: what
// permissions it needs, what selinux contexts it gets, what the package
// signature must be. The actual Java/Kt source lives under
// packages/apps/AetherManager/ in the AOSP tree and is consumed by the
// build_system chapter (ch27).
//
// ── Package Metadata ──────────────────────────────────────────────────────────
//
//   Package name        com.aether.manager
//   Install path        /system/priv-app/AetherManager
//   minSdkVersion       33 (AOSP 13 — for the BridgeMode permission API)
//   targetSdkVersion    34 (AOSP 14 — matches ch42 lunch target)
//   Signature           AETHER_PLATFORM_SIGNATURE (signing key controlled
//                       by ch57 Secure Boot; reused for /system/priv-app
//                       so the app shares platform UID)
//
// ── Required permissions (declared in AndroidManifest.xml) ────────────────────
//
//   android.permission.AETHER_BRIDGE_CONTROL
//   android.permission.AETHER_SENSOR_PROFILE
//   android.permission.AETHER_IDENTITY_FEED
//   android.permission.AETHER_OTA_CONTROL
//
//   All four are aether-only signature-level permissions defined by
//   frameworks/base/etc/permissions/aether.xml. Third-party apps cannot
//   request them. The Manager app is the unique grantee.
//
// ── SELinux contexts ──────────────────────────────────────────────────────────
//
//   Process domain:     aether_manager
//   App data:           u:object_r:aether_manager_data_file:s0
//   The aether_manager domain is allowed:
//     - hvc invocations into the AETHER vendor range (binder shim)
//     - read /sys/aether/* (ch12 paravirt diagnostics)
//     - write /data/aether/manager/* (its own data dir)
//   Forbidden:
//     - direct /dev/aether/* access (must go through the HVC ABI)
//     - any network operation (No-Boundary Principle)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AetherManagerError {
    /// Package signature did not match AETHER_PLATFORM_SIGNATURE.
    SignatureMismatch,
    /// minSdkVersion or targetSdkVersion outside the allowed range.
    InvalidSdkVersion,
    /// Manifest declares a third-party-grantable permission.
    DisallowedPermission,
    /// SELinux policy doesn't grant the aether_manager domain HVC access.
    SelinuxMissingHvcRule,
    /// SELinux policy DOES grant network — violates No-Boundary Principle.
    SelinuxNetworkLeak,
    /// Phase regression.
    PhaseRegression,
    /// Install path is not /system/priv-app/AetherManager.
    WrongInstallPath,
    /// Package name mismatch.
    WrongPackageName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AetherManagerPhase {
    NotStarted,
    ManifestParsed,
    SignatureVerified,
    PermissionsValidated,
    SelinuxValidated,
    Installed,
    GatePassed,
}

#[derive(Debug, Clone, Copy)]
pub struct AetherManagerConfig {
    /// Required package name (compared exactly).
    pub package_name:   &'static [u8],
    /// Required install path.
    pub install_path:   &'static [u8],
    /// Allowed minSdk range (inclusive).
    pub min_sdk_min:    u32,
    pub min_sdk_max:    u32,
    /// Allowed targetSdk range (inclusive).
    pub target_sdk_min: u32,
    pub target_sdk_max: u32,
    /// Permissions the manifest is allowed (and required) to declare.
    pub required_permissions: &'static [&'static [u8]],
    /// The 4 AETHER vendor signature permissions — these are the ONLY
    /// AETHER permissions the manifest may declare.
    pub allowed_aether_permissions: &'static [&'static [u8]],
}

impl AetherManagerConfig {
    pub const fn aether_defaults() -> Self {
        Self {
            package_name: b"com.aether.manager",
            install_path: b"/system/priv-app/AetherManager",
            min_sdk_min: 33, min_sdk_max: 33,
            target_sdk_min: 34, target_sdk_max: 34,
            required_permissions: &[
                b"android.permission.AETHER_BRIDGE_CONTROL",
                b"android.permission.AETHER_SENSOR_PROFILE",
                b"android.permission.AETHER_IDENTITY_FEED",
                b"android.permission.AETHER_OTA_CONTROL",
            ],
            allowed_aether_permissions: &[
                b"android.permission.AETHER_BRIDGE_CONTROL",
                b"android.permission.AETHER_SENSOR_PROFILE",
                b"android.permission.AETHER_IDENTITY_FEED",
                b"android.permission.AETHER_OTA_CONTROL",
            ],
        }
    }

    pub fn validate(&self) -> Result<(), AetherManagerError> {
        if self.package_name.is_empty() {
            return Err(AetherManagerError::WrongPackageName);
        }
        if self.install_path.is_empty() {
            return Err(AetherManagerError::WrongInstallPath);
        }
        if self.min_sdk_min > self.min_sdk_max || self.target_sdk_min > self.target_sdk_max {
            return Err(AetherManagerError::InvalidSdkVersion);
        }
        if self.required_permissions.is_empty() {
            return Err(AetherManagerError::DisallowedPermission);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AetherManagerGate {
    pub package_name_correct:      bool,
    pub install_path_correct:      bool,
    pub signature_matches:         bool,
    pub permissions_within_subset: bool,
    pub selinux_hvc_allowed:       bool,
    pub selinux_no_network:        bool,
}

impl AetherManagerGate {
    pub fn passes(&self) -> bool {
        self.package_name_correct
            && self.install_path_correct
            && self.signature_matches
            && self.permissions_within_subset
            && self.selinux_hvc_allowed
            && self.selinux_no_network
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AetherManagerState {
    pub config: AetherManagerConfig,
    pub phase:  AetherManagerPhase,
    pub gate:   AetherManagerGate,
}

impl AetherManagerState {
    pub const fn new(config: AetherManagerConfig) -> Self {
        Self {
            config,
            phase: AetherManagerPhase::NotStarted,
            gate:  AetherManagerGate {
                package_name_correct:      false,
                install_path_correct:      false,
                signature_matches:         false,
                permissions_within_subset: false,
                selinux_hvc_allowed:       false,
                selinux_no_network:        false,
            },
        }
    }

    pub fn advance_phase(&mut self, next: AetherManagerPhase) -> Result<(), AetherManagerError> {
        if next < self.phase {
            return Err(AetherManagerError::PhaseRegression);
        }
        self.phase = next;
        Ok(())
    }

    /// Validate a parsed manifest against the config. Each field that
    /// matches sets the corresponding gate flag; mismatches return
    /// the appropriate error.
    pub fn check_manifest(
        &mut self,
        package_name: &[u8],
        install_path: &[u8],
        min_sdk: u32,
        target_sdk: u32,
        permissions: &[&[u8]],
    ) -> Result<(), AetherManagerError> {
        if package_name != self.config.package_name {
            return Err(AetherManagerError::WrongPackageName);
        }
        self.gate.package_name_correct = true;
        if install_path != self.config.install_path {
            return Err(AetherManagerError::WrongInstallPath);
        }
        self.gate.install_path_correct = true;
        if min_sdk < self.config.min_sdk_min || min_sdk > self.config.min_sdk_max {
            return Err(AetherManagerError::InvalidSdkVersion);
        }
        if target_sdk < self.config.target_sdk_min || target_sdk > self.config.target_sdk_max {
            return Err(AetherManagerError::InvalidSdkVersion);
        }
        // Every declared permission must be in allowed_aether_permissions
        // (no leaking of third-party permissions; this is a closed set).
        for perm in permissions {
            // android.* non-AETHER perms are allowed if not in the AETHER
            // namespace; but anything starting with AETHER_ must be one
            // of the allowed_aether_permissions.
            if perm.starts_with(b"android.permission.AETHER_") {
                let mut found = false;
                for allowed in self.config.allowed_aether_permissions {
                    if perm == allowed {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(AetherManagerError::DisallowedPermission);
                }
            }
        }
        self.gate.permissions_within_subset = true;
        self.advance_phase(AetherManagerPhase::ManifestParsed)
    }

    pub fn mark_signature_verified(&mut self) -> Result<(), AetherManagerError> {
        self.gate.signature_matches = true;
        self.advance_phase(AetherManagerPhase::SignatureVerified)
    }

    pub fn mark_selinux_validated(
        &mut self,
        hvc_rule_present: bool,
        network_rule_present: bool,
    ) -> Result<(), AetherManagerError> {
        if !hvc_rule_present {
            return Err(AetherManagerError::SelinuxMissingHvcRule);
        }
        if network_rule_present {
            return Err(AetherManagerError::SelinuxNetworkLeak);
        }
        self.gate.selinux_hvc_allowed = true;
        self.gate.selinux_no_network  = true;
        self.advance_phase(AetherManagerPhase::SelinuxValidated)
    }

    pub fn is_gate_passed(&self) -> bool { self.gate.passes() }
}

pub fn init_aether_manager(cfg: &AetherManagerConfig) -> Result<AetherManagerState, AetherManagerError> {
    cfg.validate()?;
    Ok(AetherManagerState::new(*cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms_ok() -> [&'static [u8]; 4] {
        [
            b"android.permission.AETHER_BRIDGE_CONTROL",
            b"android.permission.AETHER_SENSOR_PROFILE",
            b"android.permission.AETHER_IDENTITY_FEED",
            b"android.permission.AETHER_OTA_CONTROL",
        ]
    }

    #[test]
    fn defaults_validate() {
        AetherManagerConfig::aether_defaults().validate().unwrap();
    }

    #[test]
    fn check_manifest_accepts_aether_defaults() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        s.check_manifest(
            b"com.aether.manager",
            b"/system/priv-app/AetherManager",
            33, 34,
            &perms_ok(),
        ).unwrap();
        assert!(s.gate.package_name_correct);
        assert!(s.gate.install_path_correct);
        assert!(s.gate.permissions_within_subset);
    }

    #[test]
    fn check_manifest_rejects_wrong_package() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.check_manifest(
                b"com.other.manager",
                b"/system/priv-app/AetherManager",
                33, 34,
                &perms_ok(),
            ),
            Err(AetherManagerError::WrongPackageName)
        );
    }

    #[test]
    fn check_manifest_rejects_wrong_install_path() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.check_manifest(
                b"com.aether.manager",
                b"/data/app/com.aether.manager",
                33, 34,
                &perms_ok(),
            ),
            Err(AetherManagerError::WrongInstallPath)
        );
    }

    #[test]
    fn check_manifest_rejects_unknown_aether_perm() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        let bad: [&[u8]; 1] = [b"android.permission.AETHER_ROOT_SHELL"];
        assert_eq!(
            s.check_manifest(
                b"com.aether.manager",
                b"/system/priv-app/AetherManager",
                33, 34,
                &bad,
            ),
            Err(AetherManagerError::DisallowedPermission)
        );
    }

    #[test]
    fn check_manifest_accepts_non_aether_perm() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        // Non-AETHER perms pass through (Java app might still need
        // INTERNET-like perms — though our app explicitly doesn't).
        let mut combined = perms_ok().to_vec();
        combined.push(b"android.permission.WAKE_LOCK");
        s.check_manifest(
            b"com.aether.manager",
            b"/system/priv-app/AetherManager",
            33, 34,
            &combined,
        ).unwrap();
    }

    #[test]
    fn check_manifest_rejects_wrong_sdk() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.check_manifest(
                b"com.aether.manager",
                b"/system/priv-app/AetherManager",
                32, 34,
                &perms_ok(),
            ),
            Err(AetherManagerError::InvalidSdkVersion)
        );
    }

    #[test]
    fn selinux_validation_rejects_missing_hvc() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.mark_selinux_validated(false, false),
            Err(AetherManagerError::SelinuxMissingHvcRule)
        );
    }

    #[test]
    fn selinux_validation_rejects_network_leak() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        assert_eq!(
            s.mark_selinux_validated(true, true),
            Err(AetherManagerError::SelinuxNetworkLeak)
        );
    }

    #[test]
    fn full_gate_walks_to_pass() {
        let mut s = init_aether_manager(&AetherManagerConfig::aether_defaults()).unwrap();
        s.check_manifest(
            b"com.aether.manager",
            b"/system/priv-app/AetherManager",
            33, 34,
            &perms_ok(),
        ).unwrap();
        s.mark_signature_verified().unwrap();
        s.mark_selinux_validated(true, false).unwrap();
        assert!(s.is_gate_passed());
    }
}
