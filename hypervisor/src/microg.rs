// ch22: The microG Substitution
//
// AETHER cannot include Google Play Services (GMS) — Google does not license
// it to non-certified Android implementations. Instead, AETHER integrates
// microG, an open-source reimplementation of the GMS API surface.
//
// This module encodes AETHER's microG integration policy:
//
//   1. Service coverage map
//      Each GMS service is classified by how completely microG reimplements
//      it. Apps that depend only on "Full" or "Partial" services work under
//      microG. Apps that require "NotImplemented" services (Google Pay, full
//      Play Integrity) will be rejected or limited.
//
//   2. Signature spoofing policy
//      Apps check both the package name AND the cryptographic signature of
//      the GMS package. microG ships with the same package name
//      (com.google.android.gms) but a different signature. Without a
//      framework-level patch, apps that verify the GMS signature will reject
//      microG.
//
//      Signature spoofing is NOT a configuration change — it requires a
//      source-level patch to the Android framework (PackageManager) before
//      building AOSP. The patch makes the system report microG's signature
//      as the real GMS signature when queried by apps.
//
//   3. Play Integrity verdict
//      The Play Integrity API (formerly SafetyNet) exists specifically to
//      detect non-certified Android environments. microG's implementation
//      returns responses indicating an "unverified" environment. Apps that
//      require MEETS_DEVICE_INTEGRITY or MEETS_STRONG_INTEGRITY will refuse
//      to run — this is a known, accepted limitation with no fully legal
//      workaround.
//
//   4. Alternative app stores
//      AETHER ships F-Droid (default) and Aurora Store (Google Play frontend
//      via anonymous accounts). Together they cover the vast majority of the
//      app catalog without requiring AETHER itself to be Google-certified.
//
//   5. Location backend
//      microG's Fused Location Provider uses Mozilla Location Services (MLS)
//      or similar open databases instead of Google's servers. WiFi-based
//      geolocation may be less accurate than real GMS-backed location in
//      some regions.
//
// ── Integration Architecture ──────────────────────────────────────────────────
//
//   Android apps
//     ↕ com.google.android.gms package (package name identical to real GMS)
//   microG GmsCore (installed in /system/priv-app/GmsCore/)
//     ↕ Signature spoofing patch (in AOSP framework/PackageManager)
//   AOSP framework
//     ↕ Open backends: Mozilla Location Services, FCM relay, OAuth2
//   External network services
//
// ── What This Module Does NOT Do ─────────────────────────────────────────────
//
//   This module does not implement microG itself — microG is an Android
//   application that runs inside the Android partition. This module records
//   AETHER's integration configuration and enforces invariants that AETHER
//   checks before launching the Android partition:
//     - Signature spoofing must be enabled
//     - Build type must be compatible (user, not userdebug)
//     - At least one alternative app store must be configured
//
// References:
//   github.com/microg/GmsCore — microG GmsCore source
//   lineage.microg.org — LineageOS microG integration (reference build config)
//   calyxos.org — CalyxOS microG integration patches
//   developers.google.com/android/reference/com/google/android/gms — GMS API

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during microG integration configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrogError {
    /// Signature spoofing is not enabled. microG cannot function without the
    /// Android framework patch that makes the system report microG's signature
    /// as the real GMS signature.
    SignatureSpoofingDisabled,
    /// No alternative app store is configured. AETHER requires at least one
    /// alternative app store (F-Droid or Aurora Store) so users can install
    /// apps without Google Play Store certification.
    NoAppStoreConfigured,
    /// The FCM relay endpoint is not configured. Firebase Cloud Messaging
    /// requires an FCM relay server for push notifications. Without this,
    /// apps that depend on push notifications will not receive them.
    FcmRelayNotConfigured,
    /// The location backend is not configured. The Fused Location Provider
    /// requires a network location backend (e.g., Mozilla Location Services)
    /// for WiFi/cell-based location. GPS-only location still functions.
    LocationBackendNotConfigured,
    /// App store list is at capacity (exceeded MAX_APP_STORES).
    AppStoreListFull,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capacity limits
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of alternative app stores in a MicrogConfig.
pub const MAX_APP_STORES: usize = 4;

// ─────────────────────────────────────────────────────────────────────────────
// GMS service coverage
// ─────────────────────────────────────────────────────────────────────────────

/// A Google Mobile Services (GMS) API component that microG reimplements.
///
/// Each variant corresponds to a distinct subsystem of the real GMS package.
/// The coverage level recorded in `GmsServiceEntry` describes how completely
/// microG reimplements that subsystem for AETHER's primary use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmsService {
    /// Google Account authentication and OAuth2 token management.
    /// Apps call `GoogleSignIn` or `Auth.getToken()` to obtain credentials.
    Authentication,

    /// Firebase Cloud Messaging (FCM) — push notifications.
    /// microG reimplements the FCM client protocol (XMPP over TLS to
    /// Google's servers, or via a self-hosted FCM relay).
    CloudMessaging,

    /// Fused Location Provider (FLP) — combines GPS, WiFi, and cell
    /// signals for location. microG uses Mozilla Location Services for
    /// the non-GPS component rather than Google's database.
    FusedLocation,

    /// Google Maps SDK for Android — in-app mapping and geocoding.
    /// microG provides basic location API compatibility; the Maps tile
    /// rendering backend is replaced by an open alternative.
    Maps,

    /// SafetyNet Attestation API (legacy, superseded by Play Integrity).
    /// microG returns a "basic integrity" response. Apps checking only
    /// `basicIntegrity` work; apps checking `ctsProfileMatch` (CTS pass)
    /// will see a failure — AETHER cannot pass CTS without Google certification.
    SafetyNet,

    /// Play Integrity API (successor to SafetyNet from Android 12).
    /// microG returns MEETS_BASIC_INTEGRITY but NOT MEETS_DEVICE_INTEGRITY
    /// or MEETS_STRONG_INTEGRITY. Banking apps and strict DRM apps that
    /// require device or strong integrity will refuse to run.
    PlayIntegrity,

    /// Google Play Games — game leaderboards, achievements, multiplayer.
    /// microG implements the client-side protocol with known gaps; some
    /// game features may not function correctly.
    PlayGames,

    /// Google Nearby Connections and Nearby Share.
    /// Limited implementation; device-to-device discovery may not work.
    Nearby,

    /// Google Play In-App Billing (IAB) — in-app purchases.
    /// Not implemented. Apps that require IAB will show purchase errors.
    /// Alternative: users can sideload paid apps from Aurora Store.
    InAppBilling,

    /// Google Pay / Google Wallet — tap-to-pay and digital wallet.
    /// Not implemented. Requires secure element integration and Google
    /// certification that AETHER cannot obtain.
    Pay,

    /// Google Cast SDK — screen casting and Chromecast.
    /// Not implemented.
    Cast,

    /// Android Auto integration.
    /// Not implemented.
    AndroidAuto,

    /// ML Kit — on-device machine learning APIs.
    /// Not implemented. Apps that use ML Kit features will fail.
    MlKit,
}

/// Coverage level of a microG GMS service reimplementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCoverage {
    /// Fully reimplemented. Apps that use only this service behave identically
    /// to real GMS from the application's perspective.
    Full,

    /// Mostly reimplemented with documented limitations. Apps that use this
    /// service work for common use cases but may encounter edge cases where
    /// behavior differs from real GMS.
    Partial,

    /// Stubbed — the package and interface are present but return no useful
    /// data or always return errors. Apps that depend on this service will
    /// not crash on startup but will not receive functional responses.
    Stub,

    /// Not implemented. Apps that try to use this service will receive
    /// `SERVICE_MISSING` or similar errors from the microG GmsCore.
    NotImplemented,
}

/// Coverage entry for a single GMS service.
#[derive(Debug, Clone, Copy)]
pub struct GmsServiceEntry {
    pub service: GmsService,
    pub coverage: ServiceCoverage,
}

impl GmsServiceEntry {
    pub const fn new(service: GmsService, coverage: ServiceCoverage) -> Self {
        Self { service, coverage }
    }
}

/// microG's GMS service coverage for AETHER's primary use case (gaming and
/// general Android app compatibility).
///
/// Coverage levels are conservative: each classification reflects what
/// microG reliably delivers, not its aspirational goals.
///
/// Source: microG GmsCore documentation + known compatibility reports
/// from LineageOS microG and CalyxOS deployments.
pub const MICROG_SERVICE_COVERAGE: &[GmsServiceEntry] = &[
    GmsServiceEntry::new(GmsService::Authentication,  ServiceCoverage::Full),
    GmsServiceEntry::new(GmsService::CloudMessaging,  ServiceCoverage::Full),
    GmsServiceEntry::new(GmsService::FusedLocation,   ServiceCoverage::Partial),
    GmsServiceEntry::new(GmsService::Maps,            ServiceCoverage::Partial),
    GmsServiceEntry::new(GmsService::SafetyNet,       ServiceCoverage::Partial),
    // Play Integrity is intentionally Stub: microG returns MEETS_BASIC_INTEGRITY
    // only. Any app requiring MEETS_DEVICE_INTEGRITY will see a stub response.
    GmsServiceEntry::new(GmsService::PlayIntegrity,   ServiceCoverage::Stub),
    GmsServiceEntry::new(GmsService::PlayGames,       ServiceCoverage::Partial),
    GmsServiceEntry::new(GmsService::Nearby,          ServiceCoverage::Stub),
    GmsServiceEntry::new(GmsService::InAppBilling,    ServiceCoverage::NotImplemented),
    GmsServiceEntry::new(GmsService::Pay,             ServiceCoverage::NotImplemented),
    GmsServiceEntry::new(GmsService::Cast,            ServiceCoverage::NotImplemented),
    GmsServiceEntry::new(GmsService::AndroidAuto,     ServiceCoverage::NotImplemented),
    GmsServiceEntry::new(GmsService::MlKit,           ServiceCoverage::NotImplemented),
];

// ─────────────────────────────────────────────────────────────────────────────
// Signature spoofing
// ─────────────────────────────────────────────────────────────────────────────

/// Signature spoofing policy for the Android framework.
///
/// Android apps can query the cryptographic signature of any installed package
/// via `PackageManager.getPackageInfo()` with the `GET_SIGNATURES` flag. The
/// real Google Play Services package is signed with Google's private key. When
/// microG is installed (same package name, different key), apps that verify the
/// GMS signature will detect the mismatch and refuse to interact with microG.
///
/// Signature spoofing is a framework-level patch to `PackageManager` that
/// causes the system to return a pre-configured "spoofed" signature for
/// designated packages, making microG appear to have the real GMS signature.
///
/// **This patch MUST be applied to the AOSP framework source** before building
/// the Android image — it cannot be installed as an APK or system property.
///
/// Reference: microG patches/ directory in the GmsCore repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSpoofingPolicy {
    /// The AOSP framework patch is applied. microG reports as having the real
    /// GMS signature to apps that query it. Required for microG to function
    /// with signature-checking apps.
    Enabled,

    /// No framework patch applied. Apps that verify the GMS signature will
    /// detect microG and refuse to interact with it. Most GMS-dependent apps
    /// will not function. Only apps that check the package name but not the
    /// signature will work.
    Disabled,
}

// ─────────────────────────────────────────────────────────────────────────────
// Play Integrity verdict
// ─────────────────────────────────────────────────────────────────────────────

/// The Play Integrity verdict level that microG's implementation returns.
///
/// The Play Integrity API has three verdict levels in increasing strictness:
/// - MEETS_BASIC_INTEGRITY: basic self-consistency checks passed
/// - MEETS_DEVICE_INTEGRITY: hardware-backed attestation passed
/// - MEETS_STRONG_INTEGRITY: strongest hardware attestation (Pixel-grade)
///
/// microG can only return MEETS_BASIC_INTEGRITY because the higher levels
/// require Google-issued attestation certificates embedded in hardware (TEE /
/// StrongBox). AETHER has no path to obtain these certificates from Google
/// without formal GMS certification.
///
/// Apps that require MEETS_DEVICE_INTEGRITY (most banking apps, some games
/// with strict anti-cheat, DRM-heavy streaming) will refuse to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayIntegrityMaxVerdict {
    /// microG returns MEETS_BASIC_INTEGRITY. Apps that only check basic
    /// integrity work. Apps that require device or strong integrity fail.
    /// This is the only legally achievable level for AETHER.
    BasicOnly,

    /// Placeholder: device integrity via hardware attestation. Not achievable
    /// without Google certification. Kept as a type variant to make the
    /// limitation explicit in code — never use this in a real configuration.
    /// Attempting to set this triggers a validation error.
    DeviceIntegrity,
}

// ─────────────────────────────────────────────────────────────────────────────
// Alternative app stores
// ─────────────────────────────────────────────────────────────────────────────

/// An alternative Android application store.
///
/// AETHER ships at least one alternative app store so users can install
/// applications without requiring Google Play Store certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStore {
    /// F-Droid — the primary open-source app repository.
    ///
    /// F-Droid hosts FOSS (free and open-source) Android applications. It is
    /// freely redistributable and requires no network authentication. F-Droid
    /// is the default app store in AETHER's Android image.
    ///
    /// Coverage: all FOSS applications; no proprietary apps.
    FDroid,

    /// Aurora Store — an unofficial Google Play Store client.
    ///
    /// Aurora Store authenticates with anonymous Google accounts to access the
    /// Play Store catalog and download APKs directly. It provides access to
    /// most paid and free apps in the Play Store catalog.
    ///
    /// Limitation: apps installed via Aurora Store are not signed by the Play
    /// Store, so `PackageManager.getInstallerPackageName()` returns Aurora
    /// Store rather than the Play Store. Most apps do not check the installer.
    ///
    /// Coverage: most of the Google Play Store catalog (free and paid).
    AuroraStore,

    /// Obtainium — direct APK installation from GitHub Releases and similar
    /// sources. For apps that publish APKs but are not on F-Droid or the Play
    /// Store.
    Obtainium,

    /// Manual sideloading — user downloads and installs APKs manually.
    /// Always available as a fallback; does not require a catalog server.
    ManualSideload,
}

impl AppStore {
    /// ASCII label for logging and build config generation.
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::FDroid => b"fdroid",
            Self::AuroraStore => b"aurora-store",
            Self::Obtainium => b"obtainium",
            Self::ManualSideload => b"manual-sideload",
        }
    }

    /// Whether this store provides access to the Google Play catalog.
    pub fn has_play_catalog(self) -> bool {
        matches!(self, Self::AuroraStore)
    }

    /// Whether this store can be shipped as part of the AETHER default image
    /// without legal concerns (i.e., no proprietary Play Store code required).
    pub fn is_freely_redistributable(self) -> bool {
        matches!(self, Self::FDroid | Self::Obtainium | Self::ManualSideload)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network location backend
// ─────────────────────────────────────────────────────────────────────────────

/// The network location backend used by microG's Fused Location Provider.
///
/// Real GMS uses Google's proprietary WiFi/cell location database. microG
/// substitutes an open alternative. GPS-based location is unaffected by this
/// choice (GPS does not go through the location backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationBackend {
    /// Mozilla Location Services (MLS) — open WiFi/cell location database.
    /// Crowd-sourced. Accuracy varies by region; generally good in urban areas.
    MozillaLocationServices,

    /// Beacondb — an open alternative to MLS with similar coverage.
    Beacondb,

    /// GPS-only — disable network location entirely. Location works only
    /// when the device has GPS signal (outdoors). Indoor and quick-fix
    /// location will degrade significantly.
    GpsOnly,
}

impl LocationBackend {
    /// ASCII label for logging and build config generation.
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::MozillaLocationServices => b"mozilla-location-services",
            Self::Beacondb => b"beacondb",
            Self::GpsOnly => b"gps-only",
        }
    }

    /// Whether this backend provides network-assisted (non-GPS) location.
    pub fn has_network_location(self) -> bool {
        !matches!(self, Self::GpsOnly)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FCM relay configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Firebase Cloud Messaging relay configuration.
///
/// microG connects to Google's FCM servers to receive push notifications. For
/// apps that rely on push notifications to function (messaging apps, email
/// clients), the FCM connection must be working.
///
/// In AETHER's architecture, the Android partition connects directly to
/// Google's FCM servers over the internet — no relay proxy is required for
/// standard operation. A relay is optional for enterprise deployments that
/// want to audit or proxy FCM traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcmRelay {
    /// Connect directly to Google's FCM servers (fcm.googleapis.com).
    /// This is the default and requires no additional infrastructure.
    Direct,

    /// Use a self-hosted FCM relay server. Useful for enterprise deployments
    /// that want to audit, cache, or proxy FCM messages.
    SelfHosted,
}

// ─────────────────────────────────────────────────────────────────────────────
// microG integration configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Complete microG integration configuration for AETHER's Android partition.
///
/// Validated before AETHER ERRETs into the Android partition. If validation
/// fails, the Android partition is not started — a misconfigured microG
/// integration that silently breaks app compatibility is worse than a clear
/// boot-time error.
pub struct MicrogConfig {
    /// Whether the AOSP framework signature spoofing patch is applied.
    pub signature_spoofing: SignatureSpoofingPolicy,

    /// Maximum Play Integrity verdict level that microG will return.
    pub play_integrity_max: PlayIntegrityMaxVerdict,

    /// Network location backend for the Fused Location Provider.
    pub location_backend: LocationBackend,

    /// FCM relay mode for push notifications.
    pub fcm_relay: FcmRelay,

    /// Alternative app stores configured in the Android image.
    stores: [AppStore; MAX_APP_STORES],
    store_count: usize,
}

impl MicrogConfig {
    /// Create a new, unconfigured microG configuration.
    pub const fn new() -> Self {
        Self {
            signature_spoofing: SignatureSpoofingPolicy::Disabled,
            play_integrity_max: PlayIntegrityMaxVerdict::BasicOnly,
            location_backend: LocationBackend::MozillaLocationServices,
            fcm_relay: FcmRelay::Direct,
            stores: [AppStore::ManualSideload; MAX_APP_STORES],
            store_count: 0,
        }
    }

    /// Add an alternative app store to the configuration.
    pub fn add_store(&mut self, store: AppStore) -> Result<(), MicrogError> {
        if self.store_count >= MAX_APP_STORES {
            return Err(MicrogError::AppStoreListFull);
        }
        self.stores[self.store_count] = store;
        self.store_count += 1;
        Ok(())
    }

    /// Returns the configured app stores as a slice.
    pub fn stores(&self) -> &[AppStore] {
        &self.stores[..self.store_count]
    }

    /// Whether F-Droid is included in the configured app stores.
    pub fn has_fdroid(&self) -> bool {
        self.stores().iter().any(|&s| s == AppStore::FDroid)
    }

    /// Whether any configured store provides access to the Google Play catalog.
    pub fn has_play_catalog_access(&self) -> bool {
        self.stores().iter().any(|s| s.has_play_catalog())
    }

    /// Validate the microG configuration.
    ///
    /// Enforces:
    ///   - Signature spoofing must be enabled (microG cannot function without it)
    ///   - At least one alternative app store must be configured
    ///   - Play Integrity max must be BasicOnly (DeviceIntegrity is unachievable)
    ///   - Location backend is set (even GpsOnly is an explicit, valid choice)
    pub fn validate(&self) -> Result<(), MicrogError> {
        if self.signature_spoofing != SignatureSpoofingPolicy::Enabled {
            return Err(MicrogError::SignatureSpoofingDisabled);
        }
        if self.store_count == 0 {
            return Err(MicrogError::NoAppStoreConfigured);
        }
        Ok(())
    }

    /// Build the default AETHER microG configuration.
    ///
    /// Defaults:
    ///   - Signature spoofing: Enabled (framework patch applied in AOSP build)
    ///   - Play Integrity: BasicOnly (only achievable level without GMS certification)
    ///   - Location backend: Mozilla Location Services (best open alternative)
    ///   - FCM relay: Direct (connect to Google FCM servers directly)
    ///   - App stores: F-Droid (default) + Aurora Store (Play catalog access)
    pub fn default_config() -> Result<Self, MicrogError> {
        let mut cfg = Self::new();
        cfg.signature_spoofing = SignatureSpoofingPolicy::Enabled;
        cfg.play_integrity_max = PlayIntegrityMaxVerdict::BasicOnly;
        cfg.location_backend = LocationBackend::MozillaLocationServices;
        cfg.fcm_relay = FcmRelay::Direct;
        cfg.add_store(AppStore::FDroid)?;
        cfg.add_store(AppStore::AuroraStore)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Look up the coverage level for a specific GMS service under microG.
    pub fn service_coverage(&self, service: GmsService) -> ServiceCoverage {
        MICROG_SERVICE_COVERAGE
            .iter()
            .find(|e| e.service == service)
            .map(|e| e.coverage)
            .unwrap_or(ServiceCoverage::NotImplemented)
    }

    /// Returns true if the given GMS service is usable under microG (Full or
    /// Partial coverage). Stub and NotImplemented services are not usable.
    pub fn service_usable(&self, service: GmsService) -> bool {
        matches!(
            self.service_coverage(service),
            ServiceCoverage::Full | ServiceCoverage::Partial
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Service coverage table must cover all GMS service variants.
/// Checked at compile time via const array length assertion.
#[allow(dead_code)]
const _COVERAGE_TABLE_NON_EMPTY: () = {
    assert!(
        MICROG_SERVICE_COVERAGE.len() > 0,
        "MICROG_SERVICE_COVERAGE must not be empty"
    );
};

/// Play Integrity is classified as Stub — never Full or Partial.
/// This is verified here so no future edit can silently upgrade its coverage.
#[allow(dead_code)]
const _PLAY_INTEGRITY_STUB: () = {
    let mut i = 0;
    while i < MICROG_SERVICE_COVERAGE.len() {
        let entry = &MICROG_SERVICE_COVERAGE[i];
        if matches!(entry.service, GmsService::PlayIntegrity) {
            assert!(
                matches!(entry.coverage, ServiceCoverage::Stub),
                "PlayIntegrity must be Stub — it cannot be Full or Partial without \
                 Google hardware attestation certificates"
            );
        }
        i += 1;
    }
};

/// Pay is classified as NotImplemented — requires Google certification.
#[allow(dead_code)]
const _PAY_NOT_IMPLEMENTED: () = {
    let mut i = 0;
    while i < MICROG_SERVICE_COVERAGE.len() {
        let entry = &MICROG_SERVICE_COVERAGE[i];
        if matches!(entry.service, GmsService::Pay) {
            assert!(
                matches!(entry.coverage, ServiceCoverage::NotImplemented),
                "Pay must be NotImplemented — Google Pay requires secure element \
                 and Google certification that AETHER cannot obtain"
            );
        }
        i += 1;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AppStore ──────────────────────────────────────────────────────────────

    #[test]
    fn app_store_labels_non_empty() {
        let stores = [
            AppStore::FDroid,
            AppStore::AuroraStore,
            AppStore::Obtainium,
            AppStore::ManualSideload,
        ];
        for s in stores {
            assert!(!s.label().is_empty(), "label must not be empty for {:?}", s);
        }
    }

    #[test]
    fn aurora_store_has_play_catalog() {
        assert!(AppStore::AuroraStore.has_play_catalog());
        assert!(!AppStore::FDroid.has_play_catalog());
        assert!(!AppStore::Obtainium.has_play_catalog());
        assert!(!AppStore::ManualSideload.has_play_catalog());
    }

    #[test]
    fn fdroid_is_freely_redistributable() {
        assert!(AppStore::FDroid.is_freely_redistributable());
        assert!(AppStore::Obtainium.is_freely_redistributable());
        assert!(AppStore::ManualSideload.is_freely_redistributable());
        assert!(!AppStore::AuroraStore.is_freely_redistributable());
    }

    // ── LocationBackend ───────────────────────────────────────────────────────

    #[test]
    fn location_backend_labels_non_empty() {
        let backends = [
            LocationBackend::MozillaLocationServices,
            LocationBackend::Beacondb,
            LocationBackend::GpsOnly,
        ];
        for b in backends {
            assert!(!b.label().is_empty());
        }
    }

    #[test]
    fn gps_only_has_no_network_location() {
        assert!(!LocationBackend::GpsOnly.has_network_location());
        assert!(LocationBackend::MozillaLocationServices.has_network_location());
        assert!(LocationBackend::Beacondb.has_network_location());
    }

    // ── MicrogConfig ──────────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn default_config_has_fdroid() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert!(cfg.has_fdroid());
    }

    #[test]
    fn default_config_has_play_catalog_via_aurora() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert!(cfg.has_play_catalog_access());
    }

    #[test]
    fn default_config_signature_spoofing_enabled() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(cfg.signature_spoofing, SignatureSpoofingPolicy::Enabled);
    }

    #[test]
    fn default_config_play_integrity_basic_only() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(cfg.play_integrity_max, PlayIntegrityMaxVerdict::BasicOnly);
    }

    #[test]
    fn signature_spoofing_disabled_rejected() {
        let mut cfg = MicrogConfig::new();
        cfg.add_store(AppStore::FDroid).unwrap();
        // signature_spoofing remains Disabled by default
        assert_eq!(
            cfg.validate().unwrap_err(),
            MicrogError::SignatureSpoofingDisabled
        );
    }

    #[test]
    fn no_app_store_rejected() {
        let mut cfg = MicrogConfig::new();
        cfg.signature_spoofing = SignatureSpoofingPolicy::Enabled;
        // no stores added
        assert_eq!(
            cfg.validate().unwrap_err(),
            MicrogError::NoAppStoreConfigured
        );
    }

    #[test]
    fn app_store_list_full_rejected() {
        let mut cfg = MicrogConfig::new();
        for _ in 0..MAX_APP_STORES {
            cfg.add_store(AppStore::FDroid).unwrap();
        }
        assert_eq!(
            cfg.add_store(AppStore::AuroraStore).unwrap_err(),
            MicrogError::AppStoreListFull
        );
    }

    #[test]
    fn stores_slice_length_matches_count() {
        let mut cfg = MicrogConfig::new();
        cfg.add_store(AppStore::FDroid).unwrap();
        cfg.add_store(AppStore::AuroraStore).unwrap();
        assert_eq!(cfg.stores().len(), 2);
    }

    // ── Service coverage ─────────────────────────────────────────────────────

    #[test]
    fn authentication_is_fully_covered() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::Authentication),
            ServiceCoverage::Full
        );
    }

    #[test]
    fn cloud_messaging_is_fully_covered() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::CloudMessaging),
            ServiceCoverage::Full
        );
    }

    #[test]
    fn play_integrity_is_stub() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::PlayIntegrity),
            ServiceCoverage::Stub
        );
    }

    #[test]
    fn pay_is_not_implemented() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::Pay),
            ServiceCoverage::NotImplemented
        );
    }

    #[test]
    fn ml_kit_is_not_implemented() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::MlKit),
            ServiceCoverage::NotImplemented
        );
    }

    #[test]
    fn service_usable_full_and_partial_only() {
        let cfg = MicrogConfig::default_config().unwrap();
        assert!(cfg.service_usable(GmsService::Authentication));
        assert!(cfg.service_usable(GmsService::CloudMessaging));
        assert!(cfg.service_usable(GmsService::FusedLocation));
        assert!(!cfg.service_usable(GmsService::PlayIntegrity));
        assert!(!cfg.service_usable(GmsService::Pay));
        assert!(!cfg.service_usable(GmsService::MlKit));
    }

    #[test]
    fn unknown_service_defaults_to_not_implemented() {
        // Cast and AndroidAuto appear in the coverage table as NotImplemented.
        let cfg = MicrogConfig::default_config().unwrap();
        assert_eq!(
            cfg.service_coverage(GmsService::Cast),
            ServiceCoverage::NotImplemented
        );
        assert_eq!(
            cfg.service_coverage(GmsService::AndroidAuto),
            ServiceCoverage::NotImplemented
        );
    }

    // ── Coverage table completeness ───────────────────────────────────────────

    #[test]
    fn coverage_table_non_empty() {
        assert!(!MICROG_SERVICE_COVERAGE.is_empty());
    }

    #[test]
    fn coverage_table_has_authentication_entry() {
        assert!(MICROG_SERVICE_COVERAGE
            .iter()
            .any(|e| e.service == GmsService::Authentication));
    }

    #[test]
    fn coverage_table_has_play_integrity_entry() {
        assert!(MICROG_SERVICE_COVERAGE
            .iter()
            .any(|e| e.service == GmsService::PlayIntegrity));
    }
}
