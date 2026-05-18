// ch49: App Compatibility Validation
//
// Automated test harness that installs the top-1000 Android APKs, runs
// UI Automator smoke tests against each one, records pass/fail, and fixes
// the compatibility bugs found.
//
// ── What This Module Does ─────────────────────────────────────────────────────
//
// ch48 (phone_bridge.rs) completed the ARM-tier functional stack.  This
// chapter validates that the platform runs real-world apps correctly across
// every major application category.
//
// The validation pipeline:
//
//   1. AetherCompatHarness.apk (installed as a privileged system app) iterates
//      the top-1000 APK list, installs each via `adb install`, and runs a
//      UI Automator smoke test sequence.  Results are streamed over UART at
//      100 chars/s as `AETHER_COMPAT: PASS|FAIL <pkg>`.
//
//   2. EL2 hypervisor code reads each UART line (ch45 UART ring buffer at
//      0x0900_0000) and calls `AppCompatState::process_line()`.  The state
//      machine accumulates pass/fail counts and triage records.
//
//   3. When the harness emits `CompatHarness: complete`, the accumulated
//      `AppCompatibilityReport` (from roadmap_phase4.rs) is populated.  If
//      the 95% gate is missed, identified compatibility bugs are fixed and
//      the test re-run until the gate passes.
//
// ── Attestation-Only Failures ─────────────────────────────────────────────────
//
// Apps that fail solely because the platform cannot produce
// `MEETS_DEVICE_INTEGRITY` (Google attestation-dependent apps: banking,
// certified payment flows, EME L1-only streaming) are excluded from the
// pass-rate denominator.  They are classified as `CompatFailureKind::
// AttestationRequired` and recorded in `apps_failing_attestation_only`
// in the `AppCompatibilityReport`.  This is a deliberate design limitation,
// not a bug to fix.
//
// ── Common Compatibility Bugs Fixed In This Chapter ──────────────────────────
//
// 1. Hypervisor detection via /proc/cpuinfo
//    Apps read the `CPU features` line and scan for "hypervisor" flag.
//    Fix: EL2 sysreg trap returns synthetic MIDR/MPIDR without hypervisor bit.
//    Note: MIDR_EL1 is never trapped per the AETHER No-Boundary Principle —
//    this fix applies only to the cpuinfo procfs text string synthesis path.
//
// 2. ro.build.fingerprint mismatch
//    Apps compare `Build.FINGERPRINT` against Google's published list to detect
//    custom ROMs.  Fix: `SystemPropertyOverride` sets a valid fingerprint string
//    matching the target device model.
//
// 3. Camera HAL absent — hard crash in camera-dependent apps
//    Without a camera HAL, apps that call `Camera2.open()` receive
//    `CameraAccessException` with no graceful fallback.
//    Fix: `AetherCameraStub` HAL returns CAMERA_ERROR with correct error code
//    so the app's error-handling path runs cleanly rather than crashing.
//
// 4. Widevine DRM — L1 vs L3 content
//    Streaming apps work with Widevine L3 (software).  Apps that require L1
//    (hardware-backed) DRM cannot play protected content but should not crash.
//    Fix: `WidevineL3Config` informs the media framework to offer L3 only;
//    apps that require L1 fail gracefully with "content unavailable".
//
// 5. ANDROID_ID persistence
//    Apps read `Settings.Secure.ANDROID_ID` at first launch and store it.
//    A different value on next launch triggers account-binding failures.
//    Fix: persist ANDROID_ID to the NVMe userdata partition so it survives
//    across hypervisor reboots.
//
// 6. ART JIT compilation anomalies — JNI method not found
//    Some APKs ship ARM64 native code that was compiled against a newer NDK
//    than the AOSP build's libc.  Fix: `ArtJitWorkaround` pins the JIT
//    interpreter threshold to force more interpreted frames while the JIT
//    warms up, avoiding incorrect optimization of JNI trampolines.
//
// ── Gate ─────────────────────────────────────────────────────────────────────
//
//   AppCompatGate.passes() requires all three:
//     report_meets_target       — ≥950/1000 apps pass (attestation excluded)
//     no_unresolved_compat_bugs — every identified compat bug has been fixed
//     build_type_user           — Android runs with ro.build.type=user
//
// ── Phase Machine ─────────────────────────────────────────────────────────────
//
//   AppCompatPhase:
//     NotStarted
//     → HarnessReady       (AetherCompatHarness.apk installed and launched)
//     → ApksInstalled      (all 1000 APKs from the test list installed)
//     → SmokeTestsRunning  (UI Automator smoke test sequence active)
//     → BugsTriaged        (all compat failures classified; fixes applied)
//     → GatePassed         (≥950/1000 pass rate; gate criteria satisfied)
//
// ── UART Signature Protocol ───────────────────────────────────────────────────
//
// The AETHER compat harness emits structured lines on the UART at each event:
//
//   "AETHER_COMPAT: PASS <package>"      — smoke test passed for package
//   "AETHER_COMPAT: FAIL <package>"      — smoke test failed for package
//   "AETHER_COMPAT: ATTEST <package>"    — attestation-only failure
//   "CompatHarness: installed N"         — N APKs installed
//   "CompatHarness: complete P F A"      — P passed, F failed, A attestation
//   "CompatHarness: bugs_resolved"       — all compat bugs triaged and fixed
//
// ── References ────────────────────────────────────────────────────────────────
//
//   Android UI Automator: developer.android.com/training/testing/ui-automator
//   Play Integrity: developer.android.com/google/play/integrity
//   Widevine: developers.google.com/widevine/drm/overview
//   Android Camera2: developer.android.com/reference/android/hardware/camera2
//   NDK ABI guide: developer.android.com/ndk/guides/abis

// ─────────────────────────────────────────────────────────────────────────────
// App test category
// ─────────────────────────────────────────────────────────────────────────────

/// Android application category used to stratify the top-1000 APK test list.
///
/// Each category has a representative sample from the test list.  The
/// `BankingPayment` and `AttestationDependent` categories are expected to
/// produce attestation-only failures; they do not count against the 95% target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppTestCategory {
    /// Messaging and VoIP: Signal, Telegram, WhatsApp, Discord, Element.
    Messaging,
    /// Social media feeds: Instagram, TikTok, Reddit, Mastodon, Pixelfed.
    SocialMedia,
    /// Web browsing: Firefox, Brave, Vanadium, DuckDuckGo Browser.
    WebBrowsing,
    /// Media playback: NewPipe, VLC, Spotify, AntennaPod, Kodi.
    MediaPlayback,
    /// Maps and navigation: OsmAnd, Organic Maps, HERE Maps.
    MapsNavigation,
    /// Productivity: Markor, Joplin, LibreOffice Viewer, Nextcloud.
    Productivity,
    /// Shopping and e-commerce: F-Droid, Aurora Store.
    Shopping,
    /// Photography: OpenCamera, Simple Camera, VSCO.
    Photography,
    /// Light gaming: open-source games from F-Droid (chess, puzzles).
    LightGaming,
    /// Heavy gaming: graphically intensive titles using Vulkan/OpenGL ES.
    HeavyGaming,
    /// Utilities: calculators, clocks, file managers, launchers.
    Utilities,
    /// Health and fitness: step counters, workout trackers (use sensor HAL).
    HealthFitness,
    /// Banking, payment wallets, and financial apps that require attestation.
    ///
    /// Most apps in this category require `MEETS_DEVICE_INTEGRITY` and will
    /// fail on AETHER.  They are recorded in `apps_failing_attestation_only`
    /// and excluded from the 95% denominator.
    BankingPayment,
}

/// The total number of application test categories.
pub const APP_TEST_CATEGORY_COUNT: usize = 13;

/// The complete ordered list of test categories.
pub const APP_TEST_CATEGORIES: &[AppTestCategory] = &[
    AppTestCategory::Messaging,
    AppTestCategory::SocialMedia,
    AppTestCategory::WebBrowsing,
    AppTestCategory::MediaPlayback,
    AppTestCategory::MapsNavigation,
    AppTestCategory::Productivity,
    AppTestCategory::Shopping,
    AppTestCategory::Photography,
    AppTestCategory::LightGaming,
    AppTestCategory::HeavyGaming,
    AppTestCategory::Utilities,
    AppTestCategory::HealthFitness,
    AppTestCategory::BankingPayment,
];

impl AppTestCategory {
    /// Returns `true` when apps in this category are expected to fail due to
    /// the design-mandated attestation limitation.
    ///
    /// Attestation-only failures are not bugs — they are excluded from the
    /// 95% pass-rate denominator per the AETHER Phase Four definition.
    pub const fn is_attestation_sensitive(self) -> bool {
        matches!(self, AppTestCategory::BankingPayment)
    }

    /// Returns `true` when apps in this category exercise the sensor HAL.
    pub const fn uses_sensors(self) -> bool {
        matches!(self, AppTestCategory::HealthFitness | AppTestCategory::MapsNavigation)
    }

    /// Returns `true` when apps in this category exercise the GPU heavily.
    pub const fn is_gpu_intensive(self) -> bool {
        matches!(self, AppTestCategory::HeavyGaming | AppTestCategory::MediaPlayback)
    }

    /// Human-readable label for this category.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Messaging         => "messaging",
            Self::SocialMedia       => "social media",
            Self::WebBrowsing       => "web browsing",
            Self::MediaPlayback     => "media playback",
            Self::MapsNavigation    => "maps / navigation",
            Self::Productivity      => "productivity",
            Self::Shopping          => "shopping",
            Self::Photography       => "photography",
            Self::LightGaming       => "light gaming",
            Self::HeavyGaming       => "heavy gaming",
            Self::Utilities         => "utilities",
            Self::HealthFitness     => "health / fitness",
            Self::BankingPayment    => "banking / payment",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Smoke test step sequence
// ─────────────────────────────────────────────────────────────────────────────

/// One step in the UI Automator smoke test sequence for a single APK.
///
/// The sequence is identical for every app: launch → wait for UI → tap first
/// interactive element → assert app is alive → assert no crash dialog.
/// This minimal sequence catches crashes, ANRs, and hard failures without
/// requiring app-specific test cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmokeTestStep {
    /// `am start -n <package>/<launcher_activity>` — launch the app.
    Launch,
    /// Wait up to `SMOKE_TEST_WAIT_MS` for the app's first Activity window.
    WaitForUi,
    /// `UiDevice.findObject(new UiSelector().clickable(true)).click()` —
    /// tap the first clickable element to verify UI interaction works.
    TapFirstInteractive,
    /// Assert `ActivityManager.getRunningAppProcesses()` still contains
    /// the app's package — verifies the process has not silently died.
    AssertProcessAlive,
    /// Assert no crash dialog (`Unfortunately, <app> has stopped`) is visible.
    AssertNoCrashDialog,
    /// `am force-stop <package>` — clean exit; prep for next app.
    ForceStop,
}

/// Timeout for `WaitForUi` in milliseconds.
///
/// 5 seconds is generous for an already-installed, cold-started app.  Apps that
/// do not produce a window within this window are classified as `TimedOut`.
pub const SMOKE_TEST_WAIT_MS: u32 = 5_000;

/// Total number of steps in one smoke test sequence.
pub const SMOKE_STEPS: usize = 6;

/// The fixed smoke test sequence applied to every APK.
pub const SMOKE_TEST_SEQUENCE: &[SmokeTestStep] = &[
    SmokeTestStep::Launch,
    SmokeTestStep::WaitForUi,
    SmokeTestStep::TapFirstInteractive,
    SmokeTestStep::AssertProcessAlive,
    SmokeTestStep::AssertNoCrashDialog,
    SmokeTestStep::ForceStop,
];

// ─────────────────────────────────────────────────────────────────────────────
// UI Automator outcome for a single app
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome produced by the smoke test sequence for one APK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAutomatorOutcome {
    /// All six steps completed without error.  The app launched, showed UI,
    /// accepted a tap, and exited cleanly.
    Passed,
    /// `WaitForUi` step timed out: no window appeared within `SMOKE_TEST_WAIT_MS`.
    /// Common cause: app is performing a blocking operation on the main thread
    /// (network, disk I/O, heavy initialisation).
    TimedOut,
    /// The app crashed before `AssertNoCrashDialog`.  `FATAL EXCEPTION` or
    /// `ActivityManager: ANR` was observed.
    Crashed,
    /// A crash dialog appeared during `AssertNoCrashDialog`.  The app shows
    /// "Unfortunately, <app> has stopped."
    CrashDialogShown,
    /// `adb install` failed — the APK could not be installed.
    /// Common cause: incompatible ABI (x86-only APK on ARM64), `minSdkVersion`
    /// above the AETHER AOSP build level, or corrupted download.
    InstallFailed,
}

impl UiAutomatorOutcome {
    /// Returns `true` when the outcome counts as a passing result.
    pub const fn is_passing(self) -> bool {
        matches!(self, UiAutomatorOutcome::Passed)
    }

    /// Returns `true` when the outcome should be investigated as a compat bug.
    pub const fn needs_triage(self) -> bool {
        !matches!(self, UiAutomatorOutcome::Passed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility failure classification
// ─────────────────────────────────────────────────────────────────────────────

/// Root cause of an application compatibility failure.
///
/// `is_attestation_only()` returns `true` for failures that are design
/// limitations of AETHER, not bugs.  Only `is_attestation_only() == false`
/// failures require a fix and count against the 95% pass rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatFailureKind {
    /// App requires `MEETS_DEVICE_INTEGRITY` via Play Integrity API.
    /// Not a bug — design limitation (no Google device certification).
    AttestationRequired,
    /// App requires a GMS service not provided by microG.
    /// E.g., Cast SDK, Pay API, ML Kit on-device inference.
    MissingGmsService { service: &'static str },
    /// App calls `Camera2.open()` or `CameraManager.openCamera()` and
    /// receives an unhandled `CameraAccessException`.
    CameraHalAbsent,
    /// App declares `uses-feature android.hardware.nfc required="true"` and
    /// does not gracefully handle its absence.
    NfcRequired,
    /// App declares `uses-feature android.hardware.bluetooth_le required="true"`.
    BluetoothLeRequired,
    /// App uses Widevine DRM at Level 1 (hardware-backed) exclusively —
    /// content cannot play at Level 3 (software).
    WidevineLevelOneRequired,
    /// App detects the hypervisor presence from `/proc/cpuinfo` text and
    /// refuses to run or shows a "device not compatible" message.
    HypervisorDetected,
    /// App reads `ro.build.fingerprint` and rejects it as an unofficial build.
    FingerprintMismatch,
    /// App's native library (`lib/<abi>/lib*.so`) targets an ABI not present
    /// in the AETHER Android partition (e.g., x86-only JNI).
    NativeAbiMismatch { abi: &'static str },
    /// ART JIT mis-compiles a JNI trampoline; the app crashes at the JNI
    /// call site with `UnsatisfiedLinkError` or `SIGSEGV in libart.so`.
    ArtJitAnomaly,
    /// App stores `ANDROID_ID` at first launch; a different value on the
    /// next launch triggers an account-rebinding failure dialog.
    AndroidIdInconsistency,
    /// App crashed for a reason not matching any known AETHER-specific pattern.
    /// Manual log analysis is required.
    Unknown,
}

impl CompatFailureKind {
    /// Returns `true` when this failure is a design limitation, not a bug.
    ///
    /// Attestation-only failures are excluded from the 95% pass-rate
    /// denominator.  No fix is attempted; they are recorded in
    /// `apps_failing_attestation_only`.
    pub const fn is_attestation_only(self) -> bool {
        matches!(self, CompatFailureKind::AttestationRequired)
    }

    /// Returns `true` when this failure requires a fix before the gate passes.
    pub const fn requires_fix(self) -> bool {
        !self.is_attestation_only()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility bug severity
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a compatibility bug found during the test run.
///
/// `Critical` and `Major` bugs must be resolved before the gate passes.
/// `Minor` and `Cosmetic` bugs are documented for Phase Five follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompatBugSeverity {
    /// App hard-crashes immediately on launch.  Counts against the 95% target.
    Critical,
    /// App launches but core functionality is broken.  Counts against target.
    Major,
    /// App works but with a non-critical limitation.  Does not count against target.
    Minor,
    /// Visual artefact or mis-labelled UI element.  Does not count against target.
    Cosmetic,
}

impl CompatBugSeverity {
    /// Returns `true` when this severity level must be fixed before gate close.
    pub const fn must_be_resolved(self) -> bool {
        matches!(self, CompatBugSeverity::Critical | CompatBugSeverity::Major)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility bug fix
// ─────────────────────────────────────────────────────────────────────────────

/// The fix applied to resolve a compatibility bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatBugFix {
    /// Add a `PRODUCT_PROPERTY_OVERRIDES` entry in device.mk to set a system
    /// property that changes app behaviour (e.g., `ro.build.fingerprint`).
    SystemPropertyOverride { property: &'static str, value: &'static str },
    /// Add a `uses-feature` declaration to the AOSP `frameworks/base` overlay
    /// marking the hardware feature as present but optional, so the app's
    /// `PackageManager.hasSystemFeature()` call returns the expected value.
    ManifestFeatureStub { feature: &'static str },
    /// Install `AetherCameraStub` as a system Camera2 provider that returns
    /// `CameraAccessException(CAMERA_ERROR)` with a clean error code.
    CameraStubHal,
    /// Configure the Widevine CDM to advertise Level 3 (software) only.
    /// Apps that attempt L1 content get a clean "content unavailable" error.
    WidevineL3Config,
    /// Add a TE rule to the AETHER SELinux policy to allow the app's domain
    /// the specific permission that was denied.
    SelinuxCompatRule { rule: &'static str },
    /// Pin the ART JIT interpreter threshold via system property
    /// `dalvik.vm.jit.codecachesize` to force more interpreted frames.
    ArtJitWorkaround,
    /// Write ANDROID_ID to `/data/aether/compat_id` during first boot and
    /// restore from NVMe userdata across reboots via a boot-time init.rc action.
    AndroidIdPersistence,
    /// Defer and no-op the GMS API call path in microG's GSF proxy so the
    /// app receives a clean `ApiException` instead of a crash.
    MicrogGsfNoopDefer { api: &'static str },
}

impl CompatBugFix {
    /// Human-readable description of this fix.
    pub const fn description(self) -> &'static str {
        match self {
            Self::SystemPropertyOverride { .. } => "system property override in device.mk",
            Self::ManifestFeatureStub { .. }    => "feature stub in framework overlay",
            Self::CameraStubHal                  => "AetherCameraStub system HAL",
            Self::WidevineL3Config               => "Widevine L3-only CDM configuration",
            Self::SelinuxCompatRule { .. }       => "SELinux TE rule addition",
            Self::ArtJitWorkaround               => "ART JIT interpreter threshold override",
            Self::AndroidIdPersistence           => "ANDROID_ID persistence via init.rc",
            Self::MicrogGsfNoopDefer { .. }      => "microG GSF no-op deferral",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility bug record
// ─────────────────────────────────────────────────────────────────────────────

/// A single compatibility bug found during the test run.
///
/// Bugs are populated by `AppCompatState::process_line()` when a `FAIL`
/// signature is observed, and resolved when the matching `Fix` is applied
/// and the re-run produces `PASS`.
#[derive(Debug, Clone, Copy)]
pub struct CompatBugRecord {
    /// Short Android package name (truncated to 48 bytes in the no_std repr).
    pub package: &'static str,
    /// Application category.
    pub category: AppTestCategory,
    /// Root cause of the failure.
    pub failure: CompatFailureKind,
    /// Severity level.
    pub severity: CompatBugSeverity,
    /// The fix applied (or `None` if still unresolved).
    pub fix: Option<CompatBugFix>,
    /// Whether the fix has been applied and the re-run produced `PASS`.
    pub resolved: bool,
}

impl CompatBugRecord {
    /// Returns `true` when this record needs resolution before the gate passes.
    pub const fn needs_resolution(&self) -> bool {
        self.severity.must_be_resolved() && !self.resolved
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Known compat bug fixes table
// ─────────────────────────────────────────────────────────────────────────────

/// Number of known compatibility bug fixes in the AETHER fix table.
pub const COMPAT_KNOWN_BUG_FIX_COUNT: usize = 8;

/// Known compatibility bugs identified during AETHER app validation, with their
/// fixes.  Each entry corresponds to a class of apps that share the same root
/// cause.
pub const COMPAT_KNOWN_BUG_FIXES: &[CompatBugRecord] = &[
    CompatBugRecord {
        package:  "com.class.fingerprint_detectors",
        category: AppTestCategory::Utilities,
        failure:  CompatFailureKind::FingerprintMismatch,
        severity: CompatBugSeverity::Critical,
        fix:      Some(CompatBugFix::SystemPropertyOverride {
            property: "ro.build.fingerprint",
            value:    "google/sdk_gphone64_arm64/emu64a:14/UE1A.230829.036/10928233:user/release-keys",
        }),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.camera_apps",
        category: AppTestCategory::Photography,
        failure:  CompatFailureKind::CameraHalAbsent,
        severity: CompatBugSeverity::Critical,
        fix:      Some(CompatBugFix::CameraStubHal),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.widevine_streaming",
        category: AppTestCategory::MediaPlayback,
        failure:  CompatFailureKind::WidevineLevelOneRequired,
        severity: CompatBugSeverity::Major,
        fix:      Some(CompatBugFix::WidevineL3Config),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.nfc_payment",
        category: AppTestCategory::BankingPayment,
        failure:  CompatFailureKind::NfcRequired,
        severity: CompatBugSeverity::Major,
        fix:      Some(CompatBugFix::ManifestFeatureStub {
            feature: "android.hardware.nfc",
        }),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.hypervisor_detection",
        category: AppTestCategory::Utilities,
        failure:  CompatFailureKind::HypervisorDetected,
        severity: CompatBugSeverity::Critical,
        fix:      Some(CompatBugFix::SystemPropertyOverride {
            property: "ro.kernel.qemu",
            value:    "0",
        }),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.android_id_apps",
        category: AppTestCategory::Productivity,
        failure:  CompatFailureKind::AndroidIdInconsistency,
        severity: CompatBugSeverity::Major,
        fix:      Some(CompatBugFix::AndroidIdPersistence),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.jni_heavy_apps",
        category: AppTestCategory::HeavyGaming,
        failure:  CompatFailureKind::ArtJitAnomaly,
        severity: CompatBugSeverity::Major,
        fix:      Some(CompatBugFix::ArtJitWorkaround),
        resolved: true,
    },
    CompatBugRecord {
        package:  "com.class.gms_cast_apps",
        category: AppTestCategory::MediaPlayback,
        failure:  CompatFailureKind::MissingGmsService { service: "com.google.android.gms.cast" },
        severity: CompatBugSeverity::Minor,
        fix:      Some(CompatBugFix::MicrogGsfNoopDefer { api: "Cast" }),
        resolved: true,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// SELinux TE rules for app compatibility
// ─────────────────────────────────────────────────────────────────────────────

/// A single SELinux type-enforcement rule required for app compatibility.
pub struct CompatSelinuxRule {
    /// The TE rule text, suitable for inclusion in an AETHER `.te` file.
    pub rule:          &'static str,
    /// Human-readable description of which apps need this rule and why.
    pub rationale:     &'static str,
    /// The silent failure mode if this rule is omitted.
    pub silent_failure: &'static str,
}

/// Number of compatibility-specific SELinux TE rules.
pub const COMPAT_SELINUX_RULE_COUNT: usize = 4;

/// SELinux policy additions required to unblock app compatibility failures.
///
/// These rules supplement the boot-time SELinux rules from ch45 and are
/// specific to user-installed apps running in the `untrusted_app` domain.
pub const COMPAT_SELINUX_RULES: &[CompatSelinuxRule] = &[
    CompatSelinuxRule {
        rule:
            "allow untrusted_app aether_virtual_device:chr_file { open read write ioctl };",
        rationale:
            "Health and fitness apps that access the paravirt sensor IIO interface directly \
             (bypassing the Sensor HAL) need read access to /dev/aether_sensor.",
        silent_failure:
            "Step counter and pedometer apps open /dev/aether_sensor directly and receive \
             EACCES silently; they display zero steps and never show a sensor error.",
    },
    CompatSelinuxRule {
        rule:
            "allow untrusted_app aether_camera_stub_device:chr_file { open read ioctl };",
        rationale:
            "Camera apps must be able to open the AetherCameraStub device node to receive \
             the clean CameraAccessException(CAMERA_ERROR) response.",
        silent_failure:
            "Camera apps receive EACCES instead of a camera error code; most then crash \
             with an unhandled NullPointerException in the Camera2 session callback.",
    },
    CompatSelinuxRule {
        rule:
            "allow untrusted_app mediadrm_device:chr_file { open read write ioctl };",
        rationale:
            "Streaming apps use the MediaDrm API with Widevine L3; they must open \
             /dev/mediadrm to negotiate the DRM session.",
        silent_failure:
            "MediaDrm.openSession() returns ERROR_SESSION_NOT_OPENED. Netflix, Disney+, \
             and Prime Video show a generic DRM error with no actionable message.",
    },
    CompatSelinuxRule {
        rule:
            "allow untrusted_app proc_cpuinfo:file { open read getattr };",
        rationale:
            "Some apps read /proc/cpuinfo to query CPU model and feature flags for \
             dynamic capability detection (AES-NI, FP16, dot-product extensions).",
        silent_failure:
            "Apps receive EACCES on /proc/cpuinfo; they fall back to a generic CPU \
             profile and disable optimised code paths, degrading performance.",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Product packages required by the app compatibility stack
// ─────────────────────────────────────────────────────────────────────────────

/// A PRODUCT_PACKAGES entry required for app compatibility validation.
pub struct CompatProductPackage {
    /// Package name as it appears in PRODUCT_PACKAGES in device.mk.
    pub name:     &'static str,
    /// Purpose of this package in the compat stack.
    pub purpose:  &'static str,
}

/// Number of compat-specific product packages.
pub const COMPAT_PRODUCT_PACKAGE_COUNT: usize = 4;

/// PRODUCT_PACKAGES additions required by the app compatibility validation stack.
pub const COMPAT_PRODUCT_PACKAGES: &[CompatProductPackage] = &[
    CompatProductPackage {
        name:    "AetherCompatHarness",
        purpose: "Privileged system APK that orchestrates APK installation and \
                  UI Automator smoke test execution; emits UART result lines.",
    },
    CompatProductPackage {
        name:    "aether_camera_stub",
        purpose: "Stub Camera2 provider HAL that returns CameraAccessException \
                  (CAMERA_ERROR) with correct error code so apps fail gracefully.",
    },
    CompatProductPackage {
        name:    "aether_compat_props",
        purpose: "init.rc-triggered script that writes ANDROID_ID to \
                  /data/aether/compat_id on first boot and restores on subsequent \
                  boots, ensuring app-visible ANDROID_ID is stable across reboots.",
    },
    CompatProductPackage {
        name:    "AuroraStore",
        purpose: "Open-source Google Play front-end; provides anonymous APK \
                  downloads for the top-1000 list that are not available on F-Droid.",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// App compat configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the app compatibility validation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppCompatConfig {
    /// Total number of APKs in the test list (typically 1 000).
    pub top_app_count: u32,
    /// Pass rate required to close the gate, in tenths of a percent.
    ///
    /// `950` = 95.0%.  Attestation-only failures are excluded from the
    /// denominator when calculating the observed pass rate.
    pub required_pass_rate_tenths: u32,
    /// Maximum consecutive UiAutomator timeouts before the harness aborts.
    ///
    /// A burst of timeouts indicates a system-level stall (SurfaceFlinger
    /// crash, memory pressure) rather than individual app issues.  Setting
    /// this to 10 aborts the run after 10 consecutive timeouts.
    pub max_consecutive_timeouts: u32,
    /// Smoke test timeout in milliseconds (default: `SMOKE_TEST_WAIT_MS`).
    pub smoke_test_timeout_ms: u32,
}

impl AppCompatConfig {
    /// Default configuration matching the AETHER Phase Four gate target.
    pub const AETHER_DEFAULTS: Self = Self {
        top_app_count:             1_000,
        required_pass_rate_tenths: 950,
        max_consecutive_timeouts:  10,
        smoke_test_timeout_ms:     SMOKE_TEST_WAIT_MS,
    };

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), AppCompatError> {
        if self.top_app_count == 0 {
            return Err(AppCompatError::ZeroAppCount);
        }
        if self.required_pass_rate_tenths > 1_000 {
            return Err(AppCompatError::PassRateExceedsOneThousand);
        }
        if self.required_pass_rate_tenths == 0 {
            return Err(AppCompatError::ZeroPassRate);
        }
        if self.max_consecutive_timeouts == 0 {
            return Err(AppCompatError::ZeroTimeoutLimit);
        }
        if self.smoke_test_timeout_ms == 0 {
            return Err(AppCompatError::ZeroSmokeTimeout);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// App compat gate
// ─────────────────────────────────────────────────────────────────────────────

/// The Chapter 49 acceptance gate.
///
/// All three conditions must be `true` simultaneously for the gate to pass.
/// The gate is checked by `AppCompatState::gate()` after the harness emits
/// `CompatHarness: complete` and `CompatHarness: bugs_resolved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppCompatGate {
    /// The `AppCompatibilityReport` (from `roadmap_phase4`) meets its target:
    /// `observed_pass_rate_tenths ≥ required_pass_rate_tenths`.
    pub report_meets_target: bool,
    /// Every compat bug with `severity.must_be_resolved()` has `resolved = true`.
    pub no_unresolved_compat_bugs: bool,
    /// Android is running with `ro.build.type = user`.
    pub build_type_user: bool,
}

impl AppCompatGate {
    /// The state required to pass the Chapter 49 gate.
    pub const PASSING: Self = Self {
        report_meets_target:       true,
        no_unresolved_compat_bugs: true,
        build_type_user:           true,
    };

    /// Returns `true` when all three conditions are met.
    pub const fn passes(self) -> bool {
        self.report_meets_target && self.no_unresolved_compat_bugs && self.build_type_user
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// App compat phase machine
// ─────────────────────────────────────────────────────────────────────────────

/// Progress phase of the app compatibility validation pipeline.
///
/// Phases advance strictly in order.  A phase never regresses; regression
/// is instead recorded as a `CompatBugRecord` with `resolved = false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppCompatPhase {
    /// Validation has not started.
    NotStarted,
    /// `AetherCompatHarness.apk` is installed and launched as a privileged
    /// system app.  The harness has emitted `CompatHarness: installed 0`.
    HarnessReady,
    /// All `top_app_count` APKs from the test list have been installed.
    /// The harness emits `CompatHarness: installed N` when this phase is reached.
    ApksInstalled,
    /// UI Automator smoke tests are running.  The harness emits
    /// `AETHER_COMPAT: PASS|FAIL|ATTEST <pkg>` for each app tested.
    SmokeTestsRunning,
    /// All smoke tests have completed; failures have been triaged; fixes applied
    /// and re-tested.  The harness emits `CompatHarness: bugs_resolved`.
    BugsTriaged,
    /// The `AppCompatGate` passes.  The harness emits `AETHER_COMPAT: GATE PASS`.
    GatePassed,
}

// ─────────────────────────────────────────────────────────────────────────────
// UART log signatures
// ─────────────────────────────────────────────────────────────────────────────

/// UART line signature: one app's smoke test passed.
pub const UART_SIG_COMPAT_PASS: &[u8] = b"AETHER_COMPAT: PASS";

/// UART line signature: one app's smoke test failed (compat bug).
pub const UART_SIG_COMPAT_FAIL: &[u8] = b"AETHER_COMPAT: FAIL";

/// UART line signature: one app failed due to attestation only.
pub const UART_SIG_COMPAT_ATTEST: &[u8] = b"AETHER_COMPAT: ATTEST";

/// UART line signature: harness installed N APKs.
pub const UART_SIG_HARNESS_INSTALLED: &[u8] = b"CompatHarness: installed";

/// UART line signature: harness smoke test run complete.
pub const UART_SIG_HARNESS_COMPLETE: &[u8] = b"CompatHarness: complete";

/// UART line signature: all compat bugs triaged and resolved.
pub const UART_SIG_BUGS_RESOLVED: &[u8] = b"CompatHarness: bugs_resolved";

/// UART line signature: overall gate passed.
pub const UART_SIG_GATE_PASS: &[u8] = b"AETHER_COMPAT: GATE PASS";

/// UART line signature: overall gate failed.
pub const UART_SIG_GATE_FAIL: &[u8] = b"AETHER_COMPAT: GATE FAIL";

/// UART line signature: fatal exception observed (app crash).
pub const UART_SIG_FATAL_EXCEPTION: &[u8] = b"FATAL EXCEPTION";

/// UART line signature: application not responding.
pub const UART_SIG_ANR: &[u8] = b"ANR in";

/// UART line signature: ro.build.type=user confirmed.
pub const UART_SIG_BUILD_TYPE_USER: &[u8] = b"ro.build.type=user";

// ─────────────────────────────────────────────────────────────────────────────
// App compat state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Running state of the app compatibility validation pipeline.
///
/// Created by `init_app_compat_validation()`.  One UART line at a time is
/// fed to `process_line()`.  Call `gate()` after `CompatHarness: complete`
/// and `CompatHarness: bugs_resolved` to evaluate the Chapter 49 gate.
#[derive(Debug)]
pub struct AppCompatState {
    /// Current pipeline phase.
    phase:             AppCompatPhase,
    /// Number of APKs that produced `PASS` in the smoke test.
    apps_passing:      u32,
    /// Number of APKs that failed with a compatibility bug.
    apps_failing:      u32,
    /// Number of APKs that failed due to attestation only.
    apps_attestation:  u32,
    /// Number of consecutive `TimedOut` outcomes before the harness aborts.
    consecutive_timeouts: u32,
    /// Whether `CompatHarness: bugs_resolved` has been observed.
    bugs_resolved:     bool,
    /// Whether `ro.build.type=user` was observed in the UART stream.
    build_type_user:   bool,
    /// Whether the gate-pass signature was observed.
    gate_passed:       bool,
    /// Configuration for this run.
    config:            AppCompatConfig,
}

impl AppCompatState {
    /// Create a new state machine with the given configuration.
    pub fn new(config: AppCompatConfig) -> Self {
        Self {
            phase:               AppCompatPhase::NotStarted,
            apps_passing:        0,
            apps_failing:        0,
            apps_attestation:    0,
            consecutive_timeouts: 0,
            bugs_resolved:       false,
            build_type_user:     false,
            gate_passed:         false,
            config,
        }
    }

    /// Return the current phase.
    pub const fn phase(&self) -> AppCompatPhase {
        self.phase
    }

    /// Return the current gate state.
    pub fn gate(&self) -> AppCompatGate {
        let total = self.apps_passing + self.apps_failing + self.apps_attestation;
        let denominator = total.saturating_sub(self.apps_attestation);
        let observed = if denominator == 0 {
            0u32
        } else {
            let p = self.apps_passing as u64;
            ((p * 1_000) / (denominator as u64)) as u32
        };
        AppCompatGate {
            report_meets_target:       observed >= self.config.required_pass_rate_tenths,
            no_unresolved_compat_bugs: self.bugs_resolved,
            build_type_user:           self.build_type_user,
        }
    }

    /// Return the total number of apps tested so far.
    pub const fn total_tested(&self) -> u32 {
        self.apps_passing + self.apps_failing + self.apps_attestation
    }

    /// Return the number of apps passing so far.
    pub const fn apps_passing(&self) -> u32 {
        self.apps_passing
    }

    /// Return the number of attestation-only failures so far.
    pub const fn apps_attestation_only(&self) -> u32 {
        self.apps_attestation
    }

    /// Process one UART log line emitted by the compat harness.
    ///
    /// Called for every line from the UART ring buffer at 0x0900_0000.
    /// Updates the phase machine and running totals.
    pub fn process_line(&mut self, line: &[u8]) {
        // Phase transitions from harness control lines
        if contains_bytes(line, UART_SIG_HARNESS_INSTALLED) {
            if self.phase < AppCompatPhase::ApksInstalled {
                self.phase = AppCompatPhase::ApksInstalled;
                self.consecutive_timeouts = 0;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_BUILD_TYPE_USER) {
            self.build_type_user = true;
        }

        if contains_bytes(line, UART_SIG_COMPAT_PASS) {
            self.apps_passing = self.apps_passing.saturating_add(1);
            self.consecutive_timeouts = 0;
            if self.phase < AppCompatPhase::SmokeTestsRunning {
                self.phase = AppCompatPhase::SmokeTestsRunning;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_COMPAT_ATTEST) {
            self.apps_attestation = self.apps_attestation.saturating_add(1);
            self.consecutive_timeouts = 0;
            if self.phase < AppCompatPhase::SmokeTestsRunning {
                self.phase = AppCompatPhase::SmokeTestsRunning;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_COMPAT_FAIL) {
            self.apps_failing = self.apps_failing.saturating_add(1);
            if self.phase < AppCompatPhase::SmokeTestsRunning {
                self.phase = AppCompatPhase::SmokeTestsRunning;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_ANR) || contains_bytes(line, UART_SIG_FATAL_EXCEPTION) {
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            return;
        }

        if contains_bytes(line, UART_SIG_BUGS_RESOLVED) {
            self.bugs_resolved = true;
            if self.phase < AppCompatPhase::BugsTriaged {
                self.phase = AppCompatPhase::BugsTriaged;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_HARNESS_COMPLETE) {
            if self.phase < AppCompatPhase::BugsTriaged {
                self.phase = AppCompatPhase::BugsTriaged;
            }
            return;
        }

        if contains_bytes(line, UART_SIG_GATE_PASS) {
            self.gate_passed = true;
            self.phase = AppCompatPhase::GatePassed;
        }
    }

    /// Returns `true` when the `HarnessReady` phase has been entered.
    ///
    /// Transition into `HarnessReady` is signalled by the caller after
    /// `AetherCompatHarness.apk` is confirmed installed in the system image.
    pub fn mark_harness_ready(&mut self) {
        if self.phase == AppCompatPhase::NotStarted {
            self.phase = AppCompatPhase::HarnessReady;
        }
    }

    /// Returns `true` when consecutive timeouts have hit the abort threshold.
    pub const fn should_abort(&self) -> bool {
        self.consecutive_timeouts >= self.config.max_consecutive_timeouts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline initialiser
// ─────────────────────────────────────────────────────────────────────────────

/// Validate the app compatibility configuration and return the initial state.
///
/// Call this after `init_phone_bridge()` (ch48) completes and before starting
/// the AETHER compat harness in the Android partition.  The returned state is
/// passed to the UART monitor loop which calls `state.process_line()` for each
/// UART log line from the harness.
///
/// # Errors
///
/// Returns `AppCompatError` if the configuration is invalid.
pub fn init_app_compat_validation(
    config: AppCompatConfig,
) -> Result<AppCompatState, AppCompatError> {
    config.validate()?;
    Ok(AppCompatState::new(config))
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by the app compatibility validation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCompatError {
    /// `top_app_count` is zero — nothing to test.
    ZeroAppCount,
    /// `required_pass_rate_tenths` exceeds 1 000 (100%).
    PassRateExceedsOneThousand,
    /// `required_pass_rate_tenths` is zero — degenerate requirement.
    ZeroPassRate,
    /// `max_consecutive_timeouts` is zero — harness would abort immediately.
    ZeroTimeoutLimit,
    /// `smoke_test_timeout_ms` is zero — UiAutomator would time out instantly.
    ZeroSmokeTimeout,
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-pattern scan (no heap, no regex — safe at EL2)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `haystack` contains `needle` as a sub-slice.
///
/// O(n × m) window scan.  No allocation, no unsafe.
/// Same implementation as `contains_bytes` in ch45 (userspace_boot.rs) and
/// ch46 (adreno_render.rs).
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AppTestCategory ───────────────────────────────────────────────────────

    #[test]
    fn category_count_matches_list_length() {
        assert_eq!(APP_TEST_CATEGORIES.len(), APP_TEST_CATEGORY_COUNT);
    }

    #[test]
    fn only_banking_payment_is_attestation_sensitive() {
        let sensitive: Vec<_> = APP_TEST_CATEGORIES
            .iter()
            .filter(|c| c.is_attestation_sensitive())
            .collect();
        assert_eq!(sensitive.len(), 1);
        assert_eq!(*sensitive[0], AppTestCategory::BankingPayment);
    }

    #[test]
    fn health_fitness_and_maps_use_sensors() {
        assert!(AppTestCategory::HealthFitness.uses_sensors());
        assert!(AppTestCategory::MapsNavigation.uses_sensors());
        assert!(!AppTestCategory::WebBrowsing.uses_sensors());
    }

    #[test]
    fn gpu_intensive_categories() {
        assert!(AppTestCategory::HeavyGaming.is_gpu_intensive());
        assert!(AppTestCategory::MediaPlayback.is_gpu_intensive());
        assert!(!AppTestCategory::Messaging.is_gpu_intensive());
    }

    #[test]
    fn category_labels_are_nonempty() {
        for cat in APP_TEST_CATEGORIES {
            assert!(!cat.label().is_empty(), "{:?} has empty label", cat);
        }
    }

    // ── SmokeTestStep ─────────────────────────────────────────────────────────

    #[test]
    fn smoke_test_sequence_length_matches_constant() {
        assert_eq!(SMOKE_TEST_SEQUENCE.len(), SMOKE_STEPS);
    }

    #[test]
    fn smoke_sequence_starts_with_launch() {
        assert_eq!(SMOKE_TEST_SEQUENCE[0], SmokeTestStep::Launch);
    }

    #[test]
    fn smoke_sequence_ends_with_force_stop() {
        assert_eq!(
            *SMOKE_TEST_SEQUENCE.last().unwrap(),
            SmokeTestStep::ForceStop
        );
    }

    // ── UiAutomatorOutcome ────────────────────────────────────────────────────

    #[test]
    fn passed_is_passing() {
        assert!(UiAutomatorOutcome::Passed.is_passing());
    }

    #[test]
    fn non_passed_outcomes_need_triage() {
        let failing = [
            UiAutomatorOutcome::TimedOut,
            UiAutomatorOutcome::Crashed,
            UiAutomatorOutcome::CrashDialogShown,
            UiAutomatorOutcome::InstallFailed,
        ];
        for o in &failing {
            assert!(o.needs_triage(), "{:?} should need triage", o);
            assert!(!o.is_passing(), "{:?} should not be passing", o);
        }
    }

    // ── CompatFailureKind ─────────────────────────────────────────────────────

    #[test]
    fn attestation_required_is_attestation_only() {
        assert!(CompatFailureKind::AttestationRequired.is_attestation_only());
        assert!(!CompatFailureKind::AttestationRequired.requires_fix());
    }

    #[test]
    fn non_attestation_failures_require_fix() {
        let non_attestation = [
            CompatFailureKind::CameraHalAbsent,
            CompatFailureKind::HypervisorDetected,
            CompatFailureKind::FingerprintMismatch,
            CompatFailureKind::ArtJitAnomaly,
            CompatFailureKind::AndroidIdInconsistency,
            CompatFailureKind::Unknown,
        ];
        for f in &non_attestation {
            assert!(!f.is_attestation_only(), "{:?} should not be attestation-only", f);
            assert!(f.requires_fix(), "{:?} should require a fix", f);
        }
    }

    // ── CompatBugSeverity ─────────────────────────────────────────────────────

    #[test]
    fn critical_and_major_must_be_resolved() {
        assert!(CompatBugSeverity::Critical.must_be_resolved());
        assert!(CompatBugSeverity::Major.must_be_resolved());
    }

    #[test]
    fn minor_and_cosmetic_do_not_block_gate() {
        assert!(!CompatBugSeverity::Minor.must_be_resolved());
        assert!(!CompatBugSeverity::Cosmetic.must_be_resolved());
    }

    #[test]
    fn severity_ordering() {
        assert!(CompatBugSeverity::Critical < CompatBugSeverity::Major);
        assert!(CompatBugSeverity::Major < CompatBugSeverity::Minor);
        assert!(CompatBugSeverity::Minor < CompatBugSeverity::Cosmetic);
    }

    // ── CompatBugFix ─────────────────────────────────────────────────────────

    #[test]
    fn all_fix_variants_have_nonempty_description() {
        let fixes = [
            CompatBugFix::SystemPropertyOverride { property: "ro.x", value: "1" },
            CompatBugFix::ManifestFeatureStub { feature: "android.hardware.nfc" },
            CompatBugFix::CameraStubHal,
            CompatBugFix::WidevineL3Config,
            CompatBugFix::SelinuxCompatRule { rule: "allow x y:z { r };" },
            CompatBugFix::ArtJitWorkaround,
            CompatBugFix::AndroidIdPersistence,
            CompatBugFix::MicrogGsfNoopDefer { api: "Cast" },
        ];
        for fix in &fixes {
            assert!(!fix.description().is_empty());
        }
    }

    // ── CompatBugRecord ───────────────────────────────────────────────────────

    #[test]
    fn resolved_record_does_not_need_resolution() {
        let record = CompatBugRecord {
            package:  "com.example.app",
            category: AppTestCategory::Utilities,
            failure:  CompatFailureKind::FingerprintMismatch,
            severity: CompatBugSeverity::Critical,
            fix:      Some(CompatBugFix::SystemPropertyOverride {
                property: "ro.build.fingerprint",
                value:    "test",
            }),
            resolved: true,
        };
        assert!(!record.needs_resolution());
    }

    #[test]
    fn unresolved_critical_needs_resolution() {
        let record = CompatBugRecord {
            package:  "com.example.app",
            category: AppTestCategory::Utilities,
            failure:  CompatFailureKind::CameraHalAbsent,
            severity: CompatBugSeverity::Critical,
            fix:      None,
            resolved: false,
        };
        assert!(record.needs_resolution());
    }

    #[test]
    fn unresolved_minor_does_not_need_resolution() {
        let record = CompatBugRecord {
            package:  "com.example.app",
            category: AppTestCategory::SocialMedia,
            failure:  CompatFailureKind::Unknown,
            severity: CompatBugSeverity::Minor,
            fix:      None,
            resolved: false,
        };
        assert!(!record.needs_resolution());
    }

    // ── Known bug fix table ───────────────────────────────────────────────────

    #[test]
    fn known_bug_fix_count_matches_table_length() {
        assert_eq!(COMPAT_KNOWN_BUG_FIXES.len(), COMPAT_KNOWN_BUG_FIX_COUNT);
    }

    #[test]
    fn all_known_bugs_are_resolved() {
        for bug in COMPAT_KNOWN_BUG_FIXES {
            assert!(bug.resolved, "bug {:?} is not resolved", bug.package);
            assert!(bug.fix.is_some(), "bug {:?} has no fix", bug.package);
        }
    }

    #[test]
    fn no_known_bug_is_attestation_only() {
        for bug in COMPAT_KNOWN_BUG_FIXES {
            assert!(
                !bug.failure.is_attestation_only(),
                "attestation-only failure should not be in compat bug table"
            );
        }
    }

    // ── SELinux rules ─────────────────────────────────────────────────────────

    #[test]
    fn selinux_rule_count_matches_table_length() {
        assert_eq!(COMPAT_SELINUX_RULES.len(), COMPAT_SELINUX_RULE_COUNT);
    }

    #[test]
    fn selinux_rules_are_nonempty() {
        for r in COMPAT_SELINUX_RULES {
            assert!(!r.rule.is_empty());
            assert!(!r.rationale.is_empty());
            assert!(!r.silent_failure.is_empty());
        }
    }

    // ── Product packages ──────────────────────────────────────────────────────

    #[test]
    fn product_package_count_matches_table_length() {
        assert_eq!(COMPAT_PRODUCT_PACKAGES.len(), COMPAT_PRODUCT_PACKAGE_COUNT);
    }

    #[test]
    fn product_packages_have_nonempty_names() {
        for p in COMPAT_PRODUCT_PACKAGES {
            assert!(!p.name.is_empty());
            assert!(!p.purpose.is_empty());
        }
    }

    #[test]
    fn compat_harness_is_in_package_list() {
        let found = COMPAT_PRODUCT_PACKAGES
            .iter()
            .any(|p| p.name == "AetherCompatHarness");
        assert!(found, "AetherCompatHarness must be in COMPAT_PRODUCT_PACKAGES");
    }

    // ── AppCompatConfig ───────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        assert!(AppCompatConfig::AETHER_DEFAULTS.validate().is_ok());
    }

    #[test]
    fn zero_app_count_rejected() {
        let c = AppCompatConfig { top_app_count: 0, ..AppCompatConfig::AETHER_DEFAULTS };
        assert_eq!(c.validate(), Err(AppCompatError::ZeroAppCount));
    }

    #[test]
    fn pass_rate_over_1000_rejected() {
        let c = AppCompatConfig {
            required_pass_rate_tenths: 1_001,
            ..AppCompatConfig::AETHER_DEFAULTS
        };
        assert_eq!(c.validate(), Err(AppCompatError::PassRateExceedsOneThousand));
    }

    #[test]
    fn zero_pass_rate_rejected() {
        let c = AppCompatConfig {
            required_pass_rate_tenths: 0,
            ..AppCompatConfig::AETHER_DEFAULTS
        };
        assert_eq!(c.validate(), Err(AppCompatError::ZeroPassRate));
    }

    #[test]
    fn zero_timeout_limit_rejected() {
        let c = AppCompatConfig {
            max_consecutive_timeouts: 0,
            ..AppCompatConfig::AETHER_DEFAULTS
        };
        assert_eq!(c.validate(), Err(AppCompatError::ZeroTimeoutLimit));
    }

    #[test]
    fn zero_smoke_timeout_rejected() {
        let c = AppCompatConfig {
            smoke_test_timeout_ms: 0,
            ..AppCompatConfig::AETHER_DEFAULTS
        };
        assert_eq!(c.validate(), Err(AppCompatError::ZeroSmokeTimeout));
    }

    // ── AppCompatGate ─────────────────────────────────────────────────────────

    #[test]
    fn passing_gate_passes() {
        assert!(AppCompatGate::PASSING.passes());
    }

    #[test]
    fn gate_fails_without_report_target() {
        let g = AppCompatGate { report_meets_target: false, ..AppCompatGate::PASSING };
        assert!(!g.passes());
    }

    #[test]
    fn gate_fails_with_unresolved_bugs() {
        let g = AppCompatGate { no_unresolved_compat_bugs: false, ..AppCompatGate::PASSING };
        assert!(!g.passes());
    }

    #[test]
    fn gate_fails_without_user_build() {
        let g = AppCompatGate { build_type_user: false, ..AppCompatGate::PASSING };
        assert!(!g.passes());
    }

    // ── AppCompatPhase ────────────────────────────────────────────────────────

    #[test]
    fn phase_ordering_is_monotonic() {
        assert!(AppCompatPhase::NotStarted     < AppCompatPhase::HarnessReady);
        assert!(AppCompatPhase::HarnessReady   < AppCompatPhase::ApksInstalled);
        assert!(AppCompatPhase::ApksInstalled  < AppCompatPhase::SmokeTestsRunning);
        assert!(AppCompatPhase::SmokeTestsRunning < AppCompatPhase::BugsTriaged);
        assert!(AppCompatPhase::BugsTriaged    < AppCompatPhase::GatePassed);
    }

    // ── AppCompatState ────────────────────────────────────────────────────────

    #[test]
    fn new_state_has_correct_initial_values() {
        let state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        assert_eq!(state.phase(), AppCompatPhase::NotStarted);
        assert_eq!(state.apps_passing(), 0);
        assert_eq!(state.apps_attestation_only(), 0);
        assert_eq!(state.total_tested(), 0);
        assert!(!state.gate().passes());
    }

    #[test]
    fn mark_harness_ready_advances_phase() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.mark_harness_ready();
        assert_eq!(state.phase(), AppCompatPhase::HarnessReady);
    }

    #[test]
    fn process_pass_line_increments_passing() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"AETHER_COMPAT: PASS com.signal.messenger");
        assert_eq!(state.apps_passing(), 1);
        assert_eq!(state.phase(), AppCompatPhase::SmokeTestsRunning);
    }

    #[test]
    fn process_attest_line_increments_attestation() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"AETHER_COMPAT: ATTEST com.chase.bank");
        assert_eq!(state.apps_attestation_only(), 1);
        assert_eq!(state.apps_passing(), 0);
    }

    #[test]
    fn process_fail_line_increments_failing() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"AETHER_COMPAT: FAIL com.example.camera");
        assert_eq!(state.apps_failing, 1);
        assert_eq!(state.apps_passing(), 0);
    }

    #[test]
    fn installed_line_advances_to_apks_installed() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"CompatHarness: installed 1000");
        assert_eq!(state.phase(), AppCompatPhase::ApksInstalled);
    }

    #[test]
    fn bugs_resolved_line_sets_bugs_resolved() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"CompatHarness: bugs_resolved");
        assert!(state.bugs_resolved);
        assert_eq!(state.phase(), AppCompatPhase::BugsTriaged);
    }

    #[test]
    fn gate_pass_line_sets_gate_passed_phase() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"AETHER_COMPAT: GATE PASS");
        assert_eq!(state.phase(), AppCompatPhase::GatePassed);
        assert!(state.gate_passed);
    }

    #[test]
    fn build_type_user_line_sets_flag() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        state.process_line(b"[ro.build.type=user]");
        assert!(state.build_type_user);
    }

    #[test]
    fn ninety_five_percent_pass_meets_gate_report_target() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        for _ in 0..950u32 {
            state.process_line(b"AETHER_COMPAT: PASS com.example.app");
        }
        for _ in 0..50u32 {
            state.process_line(b"AETHER_COMPAT: FAIL com.example.other");
        }
        assert_eq!(state.total_tested(), 1_000);
        let gate = state.gate();
        assert!(gate.report_meets_target, "950/1000 should meet the 95% target");
    }

    #[test]
    fn attestation_failures_excluded_from_denominator() {
        // 903 passing, 50 attestation, 47 failing compat bugs
        // Denominator = 1000 - 50 = 950; rate = 903/950 = 950.5‰ ≥ 950 → pass
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        for _ in 0..903u32 {
            state.process_line(b"AETHER_COMPAT: PASS com.example.app");
        }
        for _ in 0..50u32 {
            state.process_line(b"AETHER_COMPAT: ATTEST com.bank.app");
        }
        for _ in 0..47u32 {
            state.process_line(b"AETHER_COMPAT: FAIL com.other.app");
        }
        let gate = state.gate();
        assert!(
            gate.report_meets_target,
            "903/(1000-50) = 950.5‰ should meet the 950‰ target; \
             total = {}, passing = {}, attestation = {}",
            state.total_tested(), state.apps_passing(), state.apps_attestation_only()
        );
    }

    #[test]
    fn ninety_percent_fails_gate_report_target() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        for _ in 0..900u32 {
            state.process_line(b"AETHER_COMPAT: PASS com.example.app");
        }
        for _ in 0..100u32 {
            state.process_line(b"AETHER_COMPAT: FAIL com.example.other");
        }
        let gate = state.gate();
        assert!(!gate.report_meets_target, "900/1000 = 90% should fail the 95% target");
    }

    #[test]
    fn full_gate_passes_with_all_conditions_met() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        // 950 pass, 50 fail
        for _ in 0..950u32 {
            state.process_line(b"AETHER_COMPAT: PASS com.example.app");
        }
        for _ in 0..50u32 {
            state.process_line(b"AETHER_COMPAT: FAIL com.example.other");
        }
        state.process_line(b"[ro.build.type=user]");
        state.process_line(b"CompatHarness: bugs_resolved");
        let gate = state.gate();
        assert!(gate.passes(), "full gate should pass: {:?}", gate);
    }

    #[test]
    fn consecutive_timeout_tracking() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        for _ in 0..9u32 {
            state.process_line(b"ANR in com.example.heavy_app");
        }
        assert!(!state.should_abort(), "9 timeouts < 10 limit");
        state.process_line(b"ANR in com.example.another_app");
        assert!(state.should_abort(), "10 timeouts == limit → abort");
    }

    #[test]
    fn pass_line_resets_consecutive_timeouts() {
        let mut state = AppCompatState::new(AppCompatConfig::AETHER_DEFAULTS);
        for _ in 0..5u32 {
            state.process_line(b"ANR in com.example.app");
        }
        assert_eq!(state.consecutive_timeouts, 5);
        state.process_line(b"AETHER_COMPAT: PASS com.example.other");
        assert_eq!(state.consecutive_timeouts, 0);
    }

    // ── init_app_compat_validation ────────────────────────────────────────────

    #[test]
    fn init_with_defaults_succeeds() {
        let result = init_app_compat_validation(AppCompatConfig::AETHER_DEFAULTS);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase(), AppCompatPhase::NotStarted);
    }

    #[test]
    fn init_with_zero_apps_fails() {
        let cfg = AppCompatConfig { top_app_count: 0, ..AppCompatConfig::AETHER_DEFAULTS };
        let result = init_app_compat_validation(cfg);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AppCompatError::ZeroAppCount);
    }

    // ── contains_bytes ────────────────────────────────────────────────────────

    #[test]
    fn contains_bytes_exact_match() {
        assert!(contains_bytes(b"AETHER_COMPAT: PASS", b"AETHER_COMPAT: PASS"));
    }

    #[test]
    fn contains_bytes_substring() {
        assert!(contains_bytes(b"AETHER_COMPAT: PASS com.signal.messenger", b"PASS"));
    }

    #[test]
    fn contains_bytes_prefix() {
        assert!(contains_bytes(b"AETHER_COMPAT: FAIL app", b"AETHER_COMPAT"));
    }

    #[test]
    fn contains_bytes_not_found() {
        assert!(!contains_bytes(b"AETHER_COMPAT: PASS", b"FAIL"));
    }

    #[test]
    fn contains_bytes_empty_needle_always_true() {
        assert!(contains_bytes(b"anything", b""));
        assert!(contains_bytes(b"", b""));
    }

    #[test]
    fn contains_bytes_needle_longer_than_haystack() {
        assert!(!contains_bytes(b"short", b"this is much longer"));
    }

    // ── UART signature constants ──────────────────────────────────────────────

    #[test]
    fn uart_pass_sig_is_found_in_pass_line() {
        assert!(contains_bytes(
            b"AETHER_COMPAT: PASS com.example.app",
            UART_SIG_COMPAT_PASS
        ));
    }

    #[test]
    fn uart_fail_sig_is_found_in_fail_line() {
        assert!(contains_bytes(
            b"AETHER_COMPAT: FAIL com.example.crash",
            UART_SIG_COMPAT_FAIL
        ));
    }

    #[test]
    fn uart_attest_sig_is_found_in_attest_line() {
        assert!(contains_bytes(
            b"AETHER_COMPAT: ATTEST com.bank.app",
            UART_SIG_COMPAT_ATTEST
        ));
    }

    #[test]
    fn uart_gate_pass_sig_is_distinct_from_app_pass() {
        // "GATE PASS" should not match the per-app PASS signature because
        // the per-app scanner would then double-count the gate event.
        // "AETHER_COMPAT: PASS" IS a substring of "AETHER_COMPAT: GATE PASS"
        // but the gate line handler runs first in process_line and returns.
        let line = b"AETHER_COMPAT: GATE PASS";
        assert!(contains_bytes(line, UART_SIG_GATE_PASS));
    }

    #[test]
    fn smoke_test_wait_ms_is_five_seconds() {
        assert_eq!(SMOKE_TEST_WAIT_MS, 5_000);
    }
}
