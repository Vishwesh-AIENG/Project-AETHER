# SKILL.md — Chapter 22: The microG Substitution

## Confidence Disclosure

**LOW overall.** microG is a project-specific codebase that Claude has sparse training on. The API surface it reimplements is large and evolving. Claude can describe what microG does at a conceptual level but cannot reliably describe which specific API calls are implemented, which are stubbed, and which are missing. Always consult the microG source and issue tracker directly.

## Required Primary Sources

**microG project repository** at github.com/microg — The authoritative source for everything microG. Read these in order:

| Repository | Content | Priority |
|---|---|---|
| `GmsCore` | Core Google Play Services reimplementation | MANDATORY |
| `GmsCore/README.md` | Overview and compatibility | Read first |
| `GmsCore/CHANGELOG.md` | What changed in recent versions | Read |
| `GsfProxy` | Google Services Framework proxy | Read |
| `FakeStore` | Play Store replacement | Read |

**Google Play Services API documentation** at developers.google.com — What the real GMS implements. Claude's knowledge of the microG subset of this is unreliable; cross-reference every assumption.

**Android AIDL/HIDL interface definitions** for the Google services interfaces at `frameworks/base/core/java/com/google/android/` — These are the interfaces microG implements.

## Secondary Sources

**LineageOS microG builds** at lineage.microg.org — A maintained LineageOS fork with microG pre-integrated. Its build configuration reveals the correct integration approach for AOSP-based builds.

**CalyxOS** at calyxos.org — Another Android distribution with microG integration. Their integration patches are open source.

**microG issue tracker** at github.com/microg/GmsCore/issues — Essential reading for known limitations and workarounds. Many compatibility issues are documented there.

## Critical Concepts

**Signature Spoofing.** microG requires a feature called signature spoofing to function. Google Play Services is identified by its package name (`com.google.android.gms`) and its cryptographic signature. Apps that call GMS check both. When microG installs itself with the same package name but a different signature (because it's not signed with Google's keys), apps that check the signature reject it. Signature spoofing is a framework patch that makes the system report microG's signature as the real GMS signature when queried. This patch is NOT in AOSP — it must be applied to the Android framework source before building. The patch is available in the microG repository under `patches/`.

**What microG Does And Does Not Implement.** This is the most important thing to know and the area where Claude is least reliable. As of recent versions:

Implemented reasonably well:
- Google Account authentication (OAuth2)
- Firebase Cloud Messaging (push notifications)
- Google Maps API (basic location)
- Fused Location Provider (WiFi/cell-based location)
- SafetyNet attestation (partially — returns "basic" attestation)

Partially implemented or known issues:
- Google Play Games (limited functionality)
- Google Nearby (limited)
- AdMob (deliberate stub — no ads)
- ML Kit (not implemented)

Not implemented:
- Google Pay / Wallet
- Full Play Integrity API (returns unverified status)
- Android Auto integration
- Cast SDK

**Play Integrity And SafetyNet.** The Play Integrity API (formerly SafetyNet) is what apps use to detect non-standard Android environments. microG's implementation returns responses that claim basic integrity but not strong (device) integrity. Apps that check only basic integrity work. Apps that require device integrity (banking apps, some games) will refuse to run. This is a known and accepted limitation of microG — there is no fully legal way to return a genuine device integrity attestation from a non-certified device.

**F-Droid And Aurora Store Integration.** AETHER's Android image ships with F-Droid as the default app store and Aurora Store as the Google Play frontend. Aurora Store authenticates with anonymous Google accounts to access the Play Store catalog. It downloads apps as APKs directly. Most apps work; apps that check for Play Store presence using `PackageManager.getInstallerPackageName()` may behave differently than when installed from the real Play Store.

**Network Time With microG.** microG's location backend uses Mozilla Location Services or similar open databases by default (not Google's location services). This affects the accuracy of WiFi-based location — it may be less accurate than real GMS-based location in some geographic areas. For AETHER's primary use case (gaming), location accuracy is not critical.

## Common AI Mistakes In This Domain

Claude describes microG as a complete, drop-in replacement for Google Play Services with no limitations. It is not. Always qualify microG integration with the known limitations above.

Claude describes signature spoofing as a simple configuration change. It requires a source-level patch to the Android framework — it cannot be done with APKs or configuration files.

Claude generates integration instructions for wrong Android versions. The signature spoofing patch is version-specific and must be re-ported to each new Android release.

## Verification Protocol

For microG integration:
1. Verify signature spoofing is working: install the `microG Self-Check` app from F-Droid and verify all checks pass
2. Test push notifications by sending a test FCM message and verifying delivery
3. Test Google Sign-In with a real Google account
4. Document which apps used in testing work and which don't — maintain a compatibility list

## Pre-Flight Checklist

- [ ] Clone microG GmsCore repository and read README completely
- [ ] Read the signature spoofing patch in the microG patches directory — understand every line before applying it
- [ ] Study LineageOS microG build configuration for integration patterns
- [ ] Set up a test Android build in QEMU with microG integrated and verify Self-Check passes before integrating into AETHER's build
- [ ] Create a compatibility matrix for the target apps (especially games) against microG — know which ones work before shipping
