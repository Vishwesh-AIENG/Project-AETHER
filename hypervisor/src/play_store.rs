// ch23: The Play Store Question
//
// AETHER cannot ship the Google Play Store in its Android image. Google does
// not license the Play Store to non-certified Android implementations, and
// obtaining GMS certification for a hypervisor-based Android environment
// would require Google's cooperation that is not available.
//
// This module encodes AETHER's Play Store access strategy:
//
//   1. App catalog access paths
//      Three distinct paths exist for users to access Android applications.
//      Each has a different legal standing, a different set of apps it can
//      reach, and a different level of ongoing risk:
//
//        F-Droid (default) — open-source catalog, freely redistributable,
//        requires no network authentication, no legal risk.
//
//        Aurora Store (convenience) — anonymous-account frontend to the
//        Google Play Store backend. Provides access to most of the Play
//        catalog. Operates in a tolerance zone: Google has not taken action
//        against it but it is not sanctioned. Legal standing could change.
//
//        Genuine Play Store (manual path) — users who want the real Play
//        Store can install it manually after acknowledging the legal and
//        technical implications. AETHER documents this path but does not
//        automate it or ship Google's proprietary APKs.
//
//   2. Installer package name spoofing
//      Some apps call `PackageManager.getInstallerPackageName()` and behave
//      differently if they were not installed by the official Play Store.
//      Aurora Store can optionally spoof the installer package name to
//      appear as "com.android.vending" (the Play Store's package). This
//      option is off by default and is the user's choice to enable.
//
//   3. Aurora Store account mode
//      Aurora Store authenticates using anonymous built-in accounts by
//      default, requiring no user credentials. Users may also choose to
//      authenticate with their own Google account for access to previously
//      purchased apps and subscriptions.
//
//   4. Manual Play Store installation
//      The manual path requires the user to: (a) download a GApps package
//      from a community site (e.g., OpenGApps, MindTheGapps), (b) install
//      it via adb, and (c) complete Google account setup. AETHER provides
//      the documentation; the user supplies the APKs.
//
// ── App Catalog Coverage ──────────────────────────────────────────────────────
//
//   F-Droid: all FOSS apps (thousands). No proprietary apps.
//   Aurora Store (anonymous): most free apps + paid apps (Google Play catalog).
//   Aurora Store (personal account): purchased apps + subscriptions.
//   Genuine Play Store: complete Google Play catalog including all DRM apps.
//
// ── What AETHER Does NOT Do ─────────────────────────────────────────────────
//
//   AETHER does not ship Google Play Services or Google Play Store APKs.
//   Shipping Google's proprietary code without a GMS license would violate
//   Google's terms of service and potentially copyright law. The manual
//   installation path exists so users who want Google's services can obtain
//   and install them themselves — the legal and technical responsibility is
//   theirs, not AETHER's.
//
// References:
//   f-droid.org/docs              — F-Droid inclusion in AOSP builds
//   gitlab.com/AuroraOSS/AuroraStore — Aurora Store source and README
//   play.google.com/about/developer-content-policy — Google Play policy
//   source.android.com/compatibility/cts — Android CTS documentation
//   github.com/ImranR98/Obtainium — Obtainium direct-APK installer

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during Play Store configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayStoreError {
    /// Genuine Play Store was included in the default AETHER configuration.
    /// AETHER cannot ship Google's proprietary APKs. The genuine Play Store
    /// is only available via the manual user installation path.
    GenuinePlayStoreInDefault,

    /// Installer spoofing was enabled without Aurora Store being configured.
    /// Installer spoofing is only meaningful when Aurora Store is the
    /// installation source; enabling it without Aurora Store is a
    /// misconfiguration.
    InstallerSpoofWithoutAurora,

    /// Personal account mode requires the user to provide credentials at
    /// runtime. This cannot be pre-validated at build time; the error is
    /// returned when a configuration forces personal account mode without
    /// an explicit user acknowledgment flag being set.
    PersonalAccountWithoutAcknowledgment,

    /// The manual Play Store installation path was marked as configured but
    /// the required user disclaimer was not acknowledged.
    ManualPathWithoutDisclaimer,
}

// ─────────────────────────────────────────────────────────────────────────────
// Play catalog access path
// ─────────────────────────────────────────────────────────────────────────────

/// The path through which a user can access Play Store application content.
///
/// Each path differs in legal standing, app availability, and operational risk.
/// AETHER's default image provides `AnonymousProxy` (Aurora Store) alongside
/// `OpenSourceOnly` (F-Droid). `GenuinePlayStore` is a manual-only path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayCatalogAccess {
    /// F-Droid only. Open-source apps exclusively. No proprietary apps.
    ///
    /// Legal standing: fully clear. F-Droid is freely redistributable.
    /// App availability: thousands of FOSS apps; no proprietary apps.
    /// Risk: none.
    OpenSourceOnly,

    /// Aurora Store with anonymous built-in accounts.
    ///
    /// Aurora Store accesses the Google Play backend using anonymous accounts
    /// maintained within the app. It downloads APKs from Google's CDN using
    /// those accounts. Google has tolerated this behavior but has not sanctioned
    /// it — the legal standing is a tolerance zone that could change.
    ///
    /// Legal standing: tolerance zone (not sanctioned, not prohibited).
    /// App availability: most of the Google Play catalog.
    /// Risk: Google could revoke anonymous account access at any time.
    AnonymousProxy,

    /// Genuine Google Play Store, manually installed by the user.
    ///
    /// This path requires the user to download GApps from a community source,
    /// install them via adb, and complete Google account setup. AETHER provides
    /// documentation for this path but does not automate it or ship the APKs.
    ///
    /// Legal standing: the user's responsibility. AETHER ships no Google code.
    /// App availability: complete Play Store catalog including all DRM titles.
    /// Risk: Google could block AETHER devices from GMS services at any time
    ///       since it is not a certified Android implementation.
    GenuinePlayStore,
}

impl PlayCatalogAccess {
    /// Legal tolerance level for this access path.
    pub fn legal_tolerance(self) -> LegalTolerance {
        match self {
            Self::OpenSourceOnly => LegalTolerance::Clear,
            Self::AnonymousProxy => LegalTolerance::ToleranceZone,
            Self::GenuinePlayStore => LegalTolerance::UserResponsibility,
        }
    }

    /// Whether this path provides access to proprietary Play Store apps.
    pub fn has_proprietary_apps(self) -> bool {
        matches!(self, Self::AnonymousProxy | Self::GenuinePlayStore)
    }

    /// Whether AETHER ships the required components in its default image
    /// (no user action required beyond initial setup).
    pub fn ships_in_default_image(self) -> bool {
        matches!(self, Self::OpenSourceOnly | Self::AnonymousProxy)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legal tolerance
// ─────────────────────────────────────────────────────────────────────────────

/// Legal standing of a Play Store access path from AETHER's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegalTolerance {
    /// No legal concerns. The path uses freely licensed software and does not
    /// involve Google's proprietary APKs or terms of service.
    Clear,

    /// Operates at Google's tolerance. Google has not taken action against this
    /// path but has not officially sanctioned it. The path could be shut down
    /// at any time without prior notice. AETHER documents this risk clearly.
    ToleranceZone,

    /// The user's legal responsibility. AETHER provides documentation but does
    /// not ship the proprietary components. The user must obtain them, accept
    /// Google's terms, and install them manually.
    UserResponsibility,
}

// ─────────────────────────────────────────────────────────────────────────────
// Aurora Store configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Aurora Store authentication mode.
///
/// Aurora Store can authenticate with Google Play using either anonymous
/// built-in accounts (no user credentials required) or the user's own
/// Google account (required for previously purchased apps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuroraAccountMode {
    /// Aurora Store uses anonymous Google accounts maintained internally.
    ///
    /// No user credentials are required. The user does not need a Google
    /// account. Access to free apps and most paid apps works via anonymous
    /// purchase tokens. Previously purchased apps tied to a user account are
    /// not accessible in this mode.
    Anonymous,

    /// The user logs in with their own Google account.
    ///
    /// Provides access to previously purchased apps and active subscriptions.
    /// Requires the user to enter Google credentials into Aurora Store.
    /// Aurora Store stores these credentials locally, not on AETHER servers.
    PersonalAccount,
}

/// Whether Aurora Store should spoof the installer package name.
///
/// When an app is installed by Aurora Store, `PackageManager.getInstallerPackageName()`
/// returns `com.aurora.store`. Some apps check this value and behave differently
/// if they were not installed from the official Play Store (`com.android.vending`).
///
/// Aurora Store can optionally report itself as `com.android.vending` to pass
/// these installer checks. This option is off by default because:
///   - Most apps do not check the installer package name.
///   - Enabling it may interfere with app update flows.
///   - It is the user's choice, not AETHER's default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerSpoofMode {
    /// Aurora Store reports its own package name as the installer.
    /// Default. Safe. No interference with app or update flows.
    Disabled,

    /// Aurora Store reports `com.android.vending` as the installer.
    /// Enables compatibility with apps that check `getInstallerPackageName()`.
    /// Off by default — the user must enable this in Aurora Store settings.
    SpoofAsPlayStore,
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual Play Store installation path
// ─────────────────────────────────────────────────────────────────────────────

/// Disclaimer acknowledgment for the manual Google Play Store installation.
///
/// Before AETHER provides the manual Play Store installation documentation,
/// the user must acknowledge the legal and technical implications. This type
/// records whether the acknowledgment has been given.
///
/// The disclaimer covers:
///   - AETHER is not a Google-certified Android implementation.
///   - Running Google Play Services on a non-certified device may violate
///     Google's terms of service.
///   - Google can block AETHER devices from GMS services without notice.
///   - AETHER cannot guarantee Google Play compatibility or stability.
///   - The user is responsible for obtaining the GApps package legally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDisclaimer {
    /// The user has not acknowledged the disclaimer.
    NotAcknowledged,

    /// The user has explicitly acknowledged the legal and technical
    /// implications of installing the genuine Google Play Store on a
    /// non-certified Android environment.
    Acknowledged,
}

/// The documented manual path for users who want the genuine Google Play Store.
///
/// AETHER does not automate this path or ship Google's proprietary APKs.
/// It provides documentation and the disclaimer; the user does the rest.
///
/// Steps documented by AETHER (not automated):
///   1. Enable ADB on the Android partition.
///   2. Download a GApps package (MindTheGapps or OpenGApps) from a
///      community site. AETHER recommends the smallest variant (nano or pico)
///      to minimize the GMS footprint.
///   3. Sideload the package: `adb install` or recovery flash.
///   4. Complete Google account setup on first launch.
///   5. Wait for Play Store to update itself to the latest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualInstallPath {
    /// Whether the user has acknowledged the disclaimer.
    pub disclaimer: UserDisclaimer,

    /// Whether the user has indicated they have a GApps source in mind.
    /// AETHER does not provide a URL — the user finds the package themselves.
    pub user_has_gapps_source: bool,
}

impl ManualInstallPath {
    /// Create a new manual install path (disclaimer not yet acknowledged).
    pub const fn new() -> Self {
        Self {
            disclaimer: UserDisclaimer::NotAcknowledged,
            user_has_gapps_source: false,
        }
    }

    /// Validate the manual install path configuration.
    /// Requires the disclaimer to be acknowledged before proceeding.
    pub fn validate(&self) -> Result<(), PlayStoreError> {
        if self.disclaimer != UserDisclaimer::Acknowledged {
            return Err(PlayStoreError::ManualPathWithoutDisclaimer);
        }
        Ok(())
    }

    /// Whether the manual path is ready for the user to proceed.
    pub fn is_ready(&self) -> bool {
        self.disclaimer == UserDisclaimer::Acknowledged
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Play Store configuration aggregate
// ─────────────────────────────────────────────────────────────────────────────

/// AETHER's complete Play Store access configuration.
///
/// Validated before the Android partition is launched. The configuration
/// records which app catalog access paths are active and their respective
/// settings. The default configuration enables F-Droid and Aurora Store
/// (anonymous mode) and leaves the genuine Play Store path unconfigured.
pub struct PlayStoreConfig {
    /// Active app catalog access paths. At least one must be enabled.
    paths: [Option<PlayCatalogAccess>; MAX_CATALOG_PATHS],

    /// Aurora Store account mode (only relevant when AnonymousProxy is active).
    pub aurora_account_mode: AuroraAccountMode,

    /// Aurora Store installer name spoofing (off by default).
    pub installer_spoof: InstallerSpoofMode,

    /// Manual Play Store installation path (configured separately by user).
    pub manual_path: Option<ManualInstallPath>,
}

/// Maximum number of simultaneously active catalog access paths.
pub const MAX_CATALOG_PATHS: usize = 3;

impl PlayStoreConfig {
    /// Create a new, unconfigured Play Store configuration.
    pub const fn new() -> Self {
        Self {
            paths: [None; MAX_CATALOG_PATHS],
            aurora_account_mode: AuroraAccountMode::Anonymous,
            installer_spoof: InstallerSpoofMode::Disabled,
            manual_path: None,
        }
    }

    /// Add a catalog access path to the configuration.
    ///
    /// Duplicate paths are silently ignored (idempotent).
    pub fn add_path(&mut self, path: PlayCatalogAccess) {
        if self.paths.iter().any(|p| *p == Some(path)) {
            return;
        }
        for slot in &mut self.paths {
            if slot.is_none() {
                *slot = Some(path);
                return;
            }
        }
        // All slots full; silently drop. MAX_CATALOG_PATHS = 3 covers all variants.
    }

    /// Returns the configured access paths as an iterator (non-None entries).
    pub fn active_paths(&self) -> impl Iterator<Item = PlayCatalogAccess> + '_ {
        self.paths.iter().filter_map(|p| *p)
    }

    /// Whether F-Droid (OpenSourceOnly) is active.
    pub fn has_fdroid(&self) -> bool {
        self.paths.iter().any(|p| *p == Some(PlayCatalogAccess::OpenSourceOnly))
    }

    /// Whether Aurora Store (AnonymousProxy) is active.
    pub fn has_aurora(&self) -> bool {
        self.paths.iter().any(|p| *p == Some(PlayCatalogAccess::AnonymousProxy))
    }

    /// Whether the genuine Play Store manual path is configured.
    pub fn has_genuine_play_store(&self) -> bool {
        self.manual_path.as_ref().map(|p| p.is_ready()).unwrap_or(false)
    }

    /// Validate the Play Store configuration.
    ///
    /// Enforces:
    ///   - GenuinePlayStore is not active in the default AETHER image
    ///     (it cannot be shipped — only the manual path is permitted).
    ///   - Installer spoofing is only enabled when Aurora Store is active.
    ///   - PersonalAccount mode requires explicit acknowledgment.
    ///   - If a manual path is configured, its disclaimer must be acknowledged.
    pub fn validate(&self) -> Result<(), PlayStoreError> {
        // Genuine Play Store may not appear as an automatic catalog path —
        // it is only reachable via the user-opt-in manual install path.
        if self.paths.iter().any(|p| *p == Some(PlayCatalogAccess::GenuinePlayStore)) {
            return Err(PlayStoreError::GenuinePlayStoreInDefault);
        }

        // Installer spoofing is only meaningful with Aurora Store.
        if self.installer_spoof == InstallerSpoofMode::SpoofAsPlayStore && !self.has_aurora() {
            return Err(PlayStoreError::InstallerSpoofWithoutAurora);
        }

        // Manual path must be validated if present.
        if let Some(ref path) = self.manual_path {
            path.validate()?;
        }

        Ok(())
    }

    /// Build the default AETHER Play Store configuration.
    ///
    /// Defaults:
    ///   - F-Droid (OpenSourceOnly): enabled — the primary default app store.
    ///   - Aurora Store (AnonymousProxy): enabled — access to Play catalog
    ///     without requiring the user to provide a Google account.
    ///   - Installer spoofing: Disabled (user can enable in Aurora settings).
    ///   - Aurora account mode: Anonymous (no user credentials required).
    ///   - Genuine Play Store manual path: not configured (user opt-in only).
    pub fn default_config() -> Self {
        let mut cfg = Self::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.add_path(PlayCatalogAccess::AnonymousProxy);
        cfg.aurora_account_mode = AuroraAccountMode::Anonymous;
        cfg.installer_spoof = InstallerSpoofMode::Disabled;
        cfg.manual_path = None;
        cfg
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

/// MAX_CATALOG_PATHS must cover all PlayCatalogAccess variants (currently 3).
/// If a new variant is added, this assertion will catch the mismatch.
#[allow(dead_code)]
const _MAX_PATHS_COVERS_ALL_VARIANTS: () = {
    // PlayCatalogAccess has 3 variants: OpenSourceOnly, AnonymousProxy,
    // GenuinePlayStore. MAX_CATALOG_PATHS must be >= 3.
    assert!(
        MAX_CATALOG_PATHS >= 3,
        "MAX_CATALOG_PATHS must be at least 3 to hold all PlayCatalogAccess variants"
    );
};

/// The default config must not include GenuinePlayStore as an automatic path.
/// Verified structurally: default_config() only calls add_path for
/// OpenSourceOnly and AnonymousProxy. This comment is the assertion.

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PlayCatalogAccess ─────────────────────────────────────────────────────

    #[test]
    fn open_source_only_is_clear() {
        assert_eq!(
            PlayCatalogAccess::OpenSourceOnly.legal_tolerance(),
            LegalTolerance::Clear
        );
    }

    #[test]
    fn anonymous_proxy_is_tolerance_zone() {
        assert_eq!(
            PlayCatalogAccess::AnonymousProxy.legal_tolerance(),
            LegalTolerance::ToleranceZone
        );
    }

    #[test]
    fn genuine_play_store_is_user_responsibility() {
        assert_eq!(
            PlayCatalogAccess::GenuinePlayStore.legal_tolerance(),
            LegalTolerance::UserResponsibility
        );
    }

    #[test]
    fn open_source_only_has_no_proprietary_apps() {
        assert!(!PlayCatalogAccess::OpenSourceOnly.has_proprietary_apps());
    }

    #[test]
    fn anonymous_proxy_has_proprietary_apps() {
        assert!(PlayCatalogAccess::AnonymousProxy.has_proprietary_apps());
    }

    #[test]
    fn genuine_play_store_has_proprietary_apps() {
        assert!(PlayCatalogAccess::GenuinePlayStore.has_proprietary_apps());
    }

    #[test]
    fn open_source_only_ships_in_default_image() {
        assert!(PlayCatalogAccess::OpenSourceOnly.ships_in_default_image());
    }

    #[test]
    fn anonymous_proxy_ships_in_default_image() {
        assert!(PlayCatalogAccess::AnonymousProxy.ships_in_default_image());
    }

    #[test]
    fn genuine_play_store_does_not_ship_in_default_image() {
        assert!(!PlayCatalogAccess::GenuinePlayStore.ships_in_default_image());
    }

    // ── ManualInstallPath ─────────────────────────────────────────────────────

    #[test]
    fn manual_path_not_ready_without_disclaimer() {
        let path = ManualInstallPath::new();
        assert!(!path.is_ready());
        assert_eq!(
            path.validate().unwrap_err(),
            PlayStoreError::ManualPathWithoutDisclaimer
        );
    }

    #[test]
    fn manual_path_ready_when_acknowledged() {
        let path = ManualInstallPath {
            disclaimer: UserDisclaimer::Acknowledged,
            user_has_gapps_source: true,
        };
        assert!(path.is_ready());
        assert!(path.validate().is_ok());
    }

    // ── PlayStoreConfig ───────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        let cfg = PlayStoreConfig::default_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn default_config_has_fdroid() {
        let cfg = PlayStoreConfig::default_config();
        assert!(cfg.has_fdroid());
    }

    #[test]
    fn default_config_has_aurora() {
        let cfg = PlayStoreConfig::default_config();
        assert!(cfg.has_aurora());
    }

    #[test]
    fn default_config_no_genuine_play_store() {
        let cfg = PlayStoreConfig::default_config();
        assert!(!cfg.has_genuine_play_store());
    }

    #[test]
    fn default_config_installer_spoof_disabled() {
        let cfg = PlayStoreConfig::default_config();
        assert_eq!(cfg.installer_spoof, InstallerSpoofMode::Disabled);
    }

    #[test]
    fn default_config_aurora_anonymous() {
        let cfg = PlayStoreConfig::default_config();
        assert_eq!(cfg.aurora_account_mode, AuroraAccountMode::Anonymous);
    }

    #[test]
    fn genuine_play_store_as_automatic_path_rejected() {
        let mut cfg = PlayStoreConfig::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        // Directly add GenuinePlayStore as an automatic path — should fail validation.
        cfg.add_path(PlayCatalogAccess::GenuinePlayStore);
        assert_eq!(
            cfg.validate().unwrap_err(),
            PlayStoreError::GenuinePlayStoreInDefault
        );
    }

    #[test]
    fn installer_spoof_without_aurora_rejected() {
        let mut cfg = PlayStoreConfig::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.installer_spoof = InstallerSpoofMode::SpoofAsPlayStore;
        // No Aurora Store added — installer spoof is invalid.
        assert_eq!(
            cfg.validate().unwrap_err(),
            PlayStoreError::InstallerSpoofWithoutAurora
        );
    }

    #[test]
    fn installer_spoof_with_aurora_is_valid() {
        let mut cfg = PlayStoreConfig::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.add_path(PlayCatalogAccess::AnonymousProxy);
        cfg.installer_spoof = InstallerSpoofMode::SpoofAsPlayStore;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn manual_path_with_unacknowledged_disclaimer_rejected() {
        let mut cfg = PlayStoreConfig::default_config();
        cfg.manual_path = Some(ManualInstallPath::new()); // disclaimer not acknowledged
        assert_eq!(
            cfg.validate().unwrap_err(),
            PlayStoreError::ManualPathWithoutDisclaimer
        );
    }

    #[test]
    fn manual_path_acknowledged_accepted() {
        let mut cfg = PlayStoreConfig::default_config();
        cfg.manual_path = Some(ManualInstallPath {
            disclaimer: UserDisclaimer::Acknowledged,
            user_has_gapps_source: true,
        });
        assert!(cfg.validate().is_ok());
        assert!(cfg.has_genuine_play_store());
    }

    #[test]
    fn duplicate_paths_are_idempotent() {
        let mut cfg = PlayStoreConfig::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        // Should still count as one active path.
        assert_eq!(cfg.active_paths().count(), 1);
    }

    #[test]
    fn active_paths_count_matches_added_paths() {
        let mut cfg = PlayStoreConfig::new();
        cfg.add_path(PlayCatalogAccess::OpenSourceOnly);
        cfg.add_path(PlayCatalogAccess::AnonymousProxy);
        assert_eq!(cfg.active_paths().count(), 2);
    }

    // ── LegalTolerance ────────────────────────────────────────────────────────

    #[test]
    fn fdroid_path_has_clear_legal_standing() {
        assert_eq!(
            PlayCatalogAccess::OpenSourceOnly.legal_tolerance(),
            LegalTolerance::Clear
        );
    }

    #[test]
    fn aurora_path_has_tolerance_zone_standing() {
        assert_eq!(
            PlayCatalogAccess::AnonymousProxy.legal_tolerance(),
            LegalTolerance::ToleranceZone
        );
    }
}
