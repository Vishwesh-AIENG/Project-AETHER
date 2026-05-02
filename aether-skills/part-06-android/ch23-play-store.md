# SKILL.md — Chapter 23: The Play Store Question

## Confidence Disclosure

**HIGH for the conceptual and legal framing, MEDIUM for Aurora Store internals, LOW for Google Play certification process specifics.** This chapter is more about policy and product decisions than technical implementation. The engineering work here is straightforward — packaging F-Droid and Aurora Store — but the legal and business considerations require careful judgment.

## Required Primary Sources

**F-Droid documentation** at f-droid.org/docs — Covers how to include F-Droid in an AOSP build and how to add repositories.

**Aurora Store source** at gitlab.com/AuroraOSS/AuroraStore — The source code and README describe how Aurora Store works.

**Google Play developer policy** at play.google.com/about/developer-content-policy — For understanding what apps may not be distributed and how Aurora Store's anonymous accounts interact with Google's terms.

**Android Compatibility Test Suite (CTS)** documentation at source.android.com — The test suite Google uses for certification. Understanding what CTS tests check reveals what a certified device must provide.

## Secondary Sources

**Obtainium** at github.com/ImranR98/Obtainium — An alternative app source that installs directly from GitHub releases and similar. Useful supplementary source for developer tools.

**Droidify** at github.com/Droidify/Droidify — A modern F-Droid client UI, better than the official client for new users.

## Critical Concepts

**Why F-Droid Ships By Default.** F-Droid is legally redistributable, contains no Google dependencies, and requires no network account to use. It covers the most important open-source ecosystem including VLC, Signal, Telegram FOSS, KDE apps, and thousands of others. For developers, F-Droid contains every major developer tool available on Android. It is a complete app distribution system that AETHER can ship in its Android image without any legal questions.

**Aurora Store's Legal Position.** Aurora Store accesses the Google Play Store backend using anonymous accounts it maintains internally. Google has tolerated this for years without taking action, but it exists in a gray area of Google's terms of service. AETHER ships Aurora Store as a convenience tool that users may choose to use, with clear documentation that it is not officially supported by Google and that its continued operation depends on Google's tolerance.

**The Manual Google Play Installation Path.** For users who want the real Google Play Store, AETHER provides a documented manual path. The user downloads a Google Play Services APK package (available through community sites) and installs it via adb. This is the same process used by custom ROM users. AETHER provides the documentation but does not automate this process or ship Google's APKs, because shipping Google's proprietary code without a license would be legally problematic.

**App Compatibility Signaling.** Some apps check `PackageManager.getInstallerPackageName()` to verify they were installed from the Play Store, and behave differently or refuse to run if they weren't. Aurora Store can optionally spoof the installer package name to appear as Play Store. This setting is off by default in Aurora Store but is available. AETHER's documentation should explain this option for users who encounter apps with this behavior.

## Common AI Mistakes In This Domain

Claude suggests shipping Google Play Services APKs in the AETHER image. This would require a Google Mobile Services license that AETHER does not have. Do not include any Google proprietary APKs in the shipped image.

Claude suggests that Aurora Store's anonymous account functionality is definitely legal and sanctioned. It is not — it operates in a tolerance zone that could end if Google chose to act on it.

## Verification Protocol

For app store integration:
1. Verify F-Droid's repository signature verification works — install an app and verify the signature matches F-Droid's published key
2. Test Aurora Store anonymous login on a fresh AETHER install
3. Verify that app updates work through both stores after initial installation

## Pre-Flight Checklist

- [ ] Read F-Droid inclusion documentation to understand how to pre-install it in the AOSP image
- [ ] Read Aurora Store README and understand its anonymous account mechanism
- [ ] Create AETHER's documentation page for the manual Google Play installation path
- [ ] Test both stores in an AOSP build in QEMU before including in AETHER
