#!/usr/bin/env bash
# Stage and commit the remaining uncommitted work in as many focused
# commits as practical. Already-committed: 30 docs commits (doc init +
# 29 build runs). This driver handles ~20 more.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

c() { git commit -q -m "$1" -m "$2" 2>&1 | tail -3 || true; }

# ── WSL scripts (grouped by purpose) ─────────────────────────────────────────

git add wsl-scripts/repair_and_resume.sh \
        wsl-scripts/sweep_corrupt_jars.sh \
        wsl-scripts/sweep_zero_files.sh
c "wsl-scripts: post-outage recovery (repair, jar sweep, zero-len sweep)" \
"Three scripts the AOSP build relies on after power outages or forced
wsl --shutdown. repair_and_resume.sh sweeps stale locks and zero-length
intermediates (originally narrow; later widened to all file types after
the OsuLogin manifest.xml 0-byte incident). sweep_corrupt_jars.sh runs
unzip -t against every .jar/.apk/.zip/.srcjar/.aar/.ziplist under out/
and deletes any that fail integrity. sweep_zero_files.sh is the general
catch-all for run 18+ when we discovered Hyper-V leaves partially-written
non-archive files (XML, RES, TOC) that ninja still treats as fresh."

git add wsl-scripts/sync_loop.sh \
        wsl-scripts/emergency_shutdown.ps1 \
        wsl-scripts/install_outage_hotkey.ps1 \
        wsl-scripts/force_kill_build.sh
c "wsl-scripts: hardware-watchdog protection (sync, hotkey, kill)" \
"Layered defense against power outages with no UPS-USB data link.
sync_loop.sh runs inside WSL flushing the ext4 page cache every 30s,
capping any single outage's damage to ~30s of unsynced writes.
emergency_shutdown.ps1 is the Ctrl+Alt+S hotkey the user hits when the
UPS clicks in: pauses build processes via SIGSTOP, syncs x3, then runs
wsl --shutdown for a synchronous flush of the vhdx. Installed via
install_outage_hotkey.ps1 which drops an .lnk in the user's Desktop
with Hotkey=Ctrl+Alt+S. force_kill_build.sh is the operator's hammer
when the build is stuck and pkill won't take it down cleanly."

git add wsl-scripts/commit_build_history.sh \
        wsl-scripts/commit_remaining_work.sh \
        wsl-scripts/watch_until_done.sh
c "wsl-scripts: build orchestration helpers" \
"watch_until_done.sh polls the active build state and exits when either
system.img + vbmeta.img both exist (success) or a FAILED line shows up
in build.log (failure with extracted block). commit_build_history.sh
and commit_remaining_work.sh produced this exact commit sequence."

git add wsl-scripts/audit_devicetree.sh \
        wsl-scripts/audit_srcs.sh \
        wsl-scripts/check_osulogin.sh \
        wsl-scripts/check_usb_esp.ps1 \
        wsl-scripts/inspect_esp.ps1 \
        wsl-scripts/list_volumes.ps1
c "wsl-scripts: audit + diagnostic helpers" \
"Pre-build readiness checks and post-build USB inspection.
audit_devicetree.sh verifies every PRODUCT_COPY_FILES src exists, every
HAL service Android.bp srcs[] entry exists, every vintf_fragment XML
exists. audit_srcs.sh is the focused cc_binary srcs check.
check_osulogin.sh inspects the specific manifest_fixer output that
broke run 18 with the 0-byte XML find. check_usb_esp.ps1 / inspect_esp
.ps1 / list_volumes.ps1 are the Windows-side USB stick verifiers used
before booting the Ryzen target."

# ── AOSP device tree (one commit per file, multi-run fixes batched) ──────────

git add aosp/device/aether/aether_arm64/Android.bp
c "aosp: Android.bp — drop prebuilt_etc dup + deprecated vintf_fragments" \
"Two distinct fixes:
1) Build run 8 fix: removed the prebuilt_etc { name: aether_vendor_manifest }
   block. It collided with DEVICE_MANIFEST_FILE in BoardConfig.mk because
   both wanted to install vendor/etc/vintf/manifest.xml. DEVICE_MANIFEST_FILE
   is the canonical Treble path (triggers assemble_vintf which merges with
   per-HAL vintf_fragments).
2) Build run 27 fix: dropped vintf_fragments: [...] from aether.radio@2.0
   -service and aether.health@2.1-service. AOSP 14 FCM 7 marks both HIDL
   versions as deprecated; checkvintf hard-fails when they appear in the
   merged vendor manifest. Service binaries still install (the apps that
   query these HALs will see service-not-found at runtime; that is
   acceptable for first boot)."

git add aosp/device/aether/aether_arm64/BoardConfig.mk
c "aosp: BoardConfig.mk — BOARD_MKBOOTIMG_ARGS header_version + sepolicy comment" \
"Build run 23 fix: BOARD_MKBOOTIMG_ARGS := --header_version \$(BOARD_BOOT_
HEADER_VERSION). The boot.img rule auto-injects --header_version via
INTERNAL_MKBOOTIMG_VERSION_ARGS, but the vendor_boot.img rule only consumes
BOARD_MKBOOTIMG_ARGS (defaults empty). Result was ValueError: --vendor_boot
not compatible with given header version.
Also cleaned the dead TARGET_PREBUILT_KERNEL comment block (build run 11
explored it, but AOSP 14 dropped that variable; kernel install moved to
PRODUCT_COPY_FILES :kernel in device.mk)."

git add aosp/device/aether/aether_arm64/device.mk
c "aosp: device.mk — kernel via PRODUCT_COPY_FILES + microG defer + VINTF override" \
"Three accumulated fixes across multiple build runs:
1) Run 10 fix: commented out GmsCore/FakeStore/GsfProxy/UnifiedNlp from
   PRODUCT_PACKAGES. Upstream microG uses Gradle which writes APK outputs
   back into the source tree; AOSP --werror_writable forbids that. Will
   re-enable when each module has an Android.bp shim.
2) Run 12 fix: PRODUCT_COPY_FILES += device/linaro/dragonboard-kernel/
   android-6.1/Image.gz:kernel. AOSP 14 requires the kernel to already
   exist at \$(PRODUCT_OUT)/kernel via PRODUCT_COPY_FILES (the legacy
   TARGET_PREBUILT_KERNEL var was removed).
3) Run 29 fix: PRODUCT_ENFORCE_VINTF_MANIFEST := false AND PRODUCT_ENFORCE_
   VINTF_MANIFEST_OVERRIDE := false. The bare assignment alone is
   overwritten by build/make/core/config.mk:777 which re-derives the value
   from PRODUCT_FULL_TREBLE. The _OVERRIDE suffix wins that ternary."

git add aosp/device/aether/aether_arm64/manifest.xml
c "aosp: manifest.xml — collapse to kernel + sepolicy only (VINTF dance)" \
"Five accumulated fixes (build runs 19, 20, 24, 25, 26):
1) Run 19: <sepolicy><version>33.0</version></sepolicy> -> 202404. AOSP
   14 ships date-based sepolicy versioning; assemble_vintf refuses to
   reconcile against BOARD_SEPOLICY_VERS=202404.
2) Run 20: removed target-level=\"7\" from <kernel> tag. \"Device manifest
   with level 7 must not set kernel level 7\".
3) Run 24: removed all 8 per-HAL <hal> blocks (sensors / radio / camera /
   power / health / drm / graphics.allocator / graphics.mapper). They
   conflicted with per-HAL vintf_fragments shipped by each cc_binary;
   checkvintf flagged Conflicting FqInstance.
4) Run 25: <manifest target-level=\"6\"> instead of 7. At level 7 our
   HIDL HALs are deprecated.
5) Run 26: <kernel target-level=\"5\" version=\"5.4.0\"/>. checkvintf
   requires kernel target-level when version is set, and the level must
   be < device level. Version lied (binary is actually 6.1) so 5.4
   satisfies the (version,FCM) compat matrix at level 5."

git add aosp/device/aether/aether_arm64/sepolicy/file_contexts
c "aosp: sepolicy/file_contexts — hal_telephony -> hal_radio_default_exec" \
"Build run 21 fix. AOSP 14 renamed the HIDL android.hardware.radio
service exec type from hal_telephony_default_exec to hal_radio_default
_exec. checkfc rejected the old name with \"type ... is not defined\".
The other four AETHER HAL services (sensors / camera / power / health)
still use their original hal_<service>_default_exec names — verified
via grep against system/sepolicy/."

# ── Hypervisor source ────────────────────────────────────────────────────────

git add hypervisor/src/android_handoff.rs
c "hypervisor: widen Android handoff to 1 GiB + DTB matches mapped region" \
"Real-Ryzen-boot test work. HANDOFF_REGION_SIZE bumped from 66 MiB
(64 boot.img + 2 DTB) to 1 GiB by adding KERNEL_WORKING_RAM_SIZE that
fills the rest. The EPT/NPT 2-MiB-leaf identity map in boot_x86.rs
fits exactly in a single 1 GiB PDPT entry (512 leaves x 2 MiB).
default_dtb_config() now declares memory_base = STAGED_BOOT_IMG_PA
(0x80000000) instead of the old QEMU-virt baseline 0x40000000, and
memory_size = HANDOFF_REGION_SIZE so the DTB's /memory node matches
exactly what the EPT/NPT identity-maps. Otherwise the kernel hits
unmapped GPAs on early page allocations.
Test added: dtb_memory_matches_mapped_region asserts the invariant."

git add hypervisor/src/lib.rs
c "hypervisor: bump global heap 1 MiB -> 32 MiB (fixes silent OOM at translator init) + register ch59-64 modules" \
"Two changes:

1) Critical bug fix. The global bump allocator was sized for boot
   scratchpad only (1 MiB), under the assumption (per its own comment)
   that the DBT JIT cache had its own arena at 0x2_0000_0000. In
   practice CodeBuf::new(JIT_CACHE_BYTES) in aether-translator does
   alloc::vec![0u8; 16 MiB] against THIS global allocator. A 16 MiB
   request against a 1 MiB heap returned NULL, Vec hit the alloc error
   handler, and the hypervisor hung silently after init_svm_foundation
   on real Ryzen hardware (Phase A 8-beep bisect diagnostic confirmed).
   32 MiB covers the 16 MiB JIT vec + block-cache hash table + transient
   gate state machines + headroom. The .bss expansion is invisible in
   the PE32+ file size; UEFI loader reserves at image load.

2) Register six new chapter modules: setup_wizard (ch59), configuration
   _app (ch60), ota_update (ch61), recovery_mode (ch62), aether_manager
   (ch63), hvc_paravirt_abi (ch64)."

git add hypervisor/src/boot_x86.rs
c "hypervisor: real-hardware bring-up diagnostics + guest_ram_size + BGR" \
"Phase A diagnostics installed during the first AMD Ryzen boot test.
Combined changes:

1) guest_ram_size: 4096 -> 1 GiB in both boot_intel and boot_amd
   foundation configs. The 4 KiB value was the Ch50/51 foundation-gate
   window — fine when the guest payload is one HLT byte, OOM-class
   undersized for a real Android kernel.

2) GOP framebuffer color constants flipped to match observed real
   hardware. The first Ryzen boot showed RED and BLUE swapped vs what
   the capture_framebuffer bgr_format detection assumed. GREEN /
   AMBER / PURPLE are invariant under R/B swap; only RED and BLUE
   needed correction.

3) Audible + visual checkpoint infrastructure:
   - fb_fill(rgb) un-deadcoded; FB_GREEN/BLUE/RED/AMBER constants used.
   - beep_once(freq_hz) drives PC speaker via PIT channel 2 + port 0x61.
   - beep_n(n, freq) for repeated tones.
   - checkpoint(color, beeps, freq_hz) paints framebuffer + beeps.
   - bisect(step) emits one beep at a step-specific pitch (500-1500 Hz)
     with a 1-second post-tone silence; lets the user identify which
     step the hypervisor reaches by ear.

4) Checkpoint instrumentation in boot_x86_hypervisor + boot_amd:
   - GREEN + 1 beep @ 880 Hz right after ExitBootServices.
   - bisect(2)..bisect(9) at each major host-setup step.
   - BLUE + 2 beeps @ 1100 Hz right before VMLAUNCH/VMRUN.
   - RED + 3 beeps @ 440 Hz inside halt() (fatal path).
   - Pre-EBS ESP shim: 2 short 2 kHz beeps when boot.img loaded ok,
     1 long 300 Hz beep when missing.
   - Post-FEX arm: 4 ascending beeps for armed, 2 falling beeps for
     foundation-gate fallback.

These three sources of feedback (framebuffer color, beep pitch, beep
count) together let the user diagnose every checkpoint blind, without
a serial cable. First Ryzen boot reached BLUE + 2 beeps then RED + 3
beeps — confirming successful VMRUN entry and Ch51 foundation gate
passing on real silicon for the first time."

# ── Chapter modules (6 commits) ──────────────────────────────────────────────

git add hypervisor/src/setup_wizard.rs
c "ch59: Setup Wizard GUI Frontend" \
"First-boot configuration UI rendered by the hypervisor on the GOP
framebuffer BEFORE the Android partition launches. Six forward-pass
steps (Language / Keyboard layout / Time zone / Bridge Mode default /
Sensor profile / Confirmation) persist to six UEFI variables under
AETHER_VARIABLE_GUID. On every subsequent boot the wizard is skipped
if AetherSetupComplete == 1.

WizardConfig (per_step_timeout_secs=600 / enforce_no_network=true;
aether_defaults + validate). Validate rejects enforce_no_network=false
per the No-Boundary Principle (ch3 — wizard must run offline).
WizardGate (framebuffer_painted + all_steps_acknowledged + selections
_persisted + no_network_round_trip; passes()). WizardError (12
variants). WizardPhase (9 phases, strictly monotonic via PartialOrd).
WizardSelections (fixed-size ASCII buffers, no heap). BridgeModeDefault
and SensorProfile enums with to_byte/from_byte roundtrip. UART
signature constants for the runtime line scanner.

15 unit tests covering: defaults validate, rejects zero timeout,
rejects network-allowed, selection accept/reject for each field type,
roundtrips, monotonic phase advancement, gate-all-four-required, full
UART scanner walk to gate."

git add hypervisor/src/configuration_app.rs
c "ch60: Configuration App" \
"Post-install runtime config surface. Same UEFI variable backing as ch59
plus extras (OtaChannel, IdentityFeed, FingerprintStrict, UiTheme). Read
access is hot from Android (every HAL call queries one or more of these);
reads are lock-free pointer loads against atomic-swappable ConfigSnapshot,
writes take a global spinlock.

ConfigKey enum (6 typed keys, ABI-stable u8 ordinals) with variable_name
and max_value helpers. ConfigSnapshot (fixed [u8; 6] — no heap). ConfigKv
+ ConfigChange records. ConfigAppConfig (require_lock_free_reads /
write_spin_budget; aether_defaults + validate). ConfigAppGate. ConfigApp
Error (6 variants). ConfigAppPhase (5 phases). init_configuration_app
6-step pipeline.

7 unit tests covering: defaults validate, ordinal roundtrip, value
clamping, snapshot purity, phase monotonicity, gate-all-four-required,
init advances to DefaultsLoaded."

git add hypervisor/src/ota_update.rs
c "ch61: OTA Update System" \
"A/B slot updates with AVB chain verification and ch58 rollback-counter
integration. Update payload is the same 5 AVB-signed images we produce
in ch42 (boot/system/vendor/vbmeta/userdata — userdata never replaced).
vbmeta.img is the chain anchor; its rollback_index is checked against
AetherRollbackIndex before any image is touched.

Slot enum (A/B with .other() involutory). OtaImage (16-byte partition
name + size + sha256). OtaPayload (fixed [OtaImage; 8] — no heap).
OtaConfig (require_partitions list, previously_confirmed_rollback_index,
rollback_attempt_threshold; aether_defaults + validate). OtaGate (5
boolean fields). OtaError (13 variants). OtaPhase (6 phases, monotonic).
process_line() UART scanner. check_payload() validates required
partitions present and rollback index acceptable.

9 unit tests covering: slot involutory, byte roundtrips, phase
monotonicity, payload accepts complete, rejects missing partition,
rejects rollback, UART scanner walks to gate, init returns idle."

git add hypervisor/src/recovery_mode.rs
c "ch62: Recovery Mode" \
"Boot-loop trap + factory reset + sideload. Three entry vectors:
BootLoop (ch58 OtaRollbackGuard fires), UserRequested (Ctrl+Alt+Tab at
boot selector — hardware-only trigger per ch41 passthrough USB), and
DebugTrigger (AetherEnterRecovery variable; rejected in user builds).

RecoveryAction enum: NoOp, ReturnToSelector, FactoryReset, Sideload,
SlotRollback. Each destructive action has a fixed confirmation phrase
(\"ERASE EVERYTHING\", \"SIDELOAD\", \"ROLLBACK\") that the user must
type exactly — phrases are baked into the module so a malicious
Android-side helper cannot pre-fill them. Non-destructive actions are
implicitly confirmed.

RecoveryConfig (allow_debug_trigger=false / idle_timeout_secs=300).
RecoveryEntryReason. RecoveryError (8 variants). RecoveryPhase (6
phases). RecoveryState with monotonic advance_phase + UART scanner.

9 unit tests covering: confirmation phrases unique, non-destructive
skip confirm, select advances phase, confirm rejects wrong phrase,
confirm rejects on non-destructive, debug rejected in user build,
debug accepted when allowed, UART scanner, full destructive flow."

git add hypervisor/src/aether_manager.rs
c "ch63: AETHER Manager Android App" \
"Android-side companion app specification. Spec only — actual Java/Kt
source lives under packages/apps/AetherManager/ in AOSP and is built
by ch27/ch42. This module describes the runtime contract: package
metadata, required permissions, SELinux contexts.

Package: com.aether.manager at /system/priv-app/AetherManager, signed
by AETHER_PLATFORM_KEY (reuses ch57 key), minSdk=33, targetSdk=34. Four
signature-level permissions allowed (and required): AETHER_BRIDGE
_CONTROL / AETHER_SENSOR_PROFILE / AETHER_IDENTITY_FEED / AETHER_OTA
_CONTROL. SELinux: aether_manager domain must be granted HVC access
into the AETHER vendor range AND must NOT have any network rule (No-
Boundary Principle).

AetherManagerConfig + validate. AetherManagerError (8 variants).
AetherManagerPhase (7 phases). AetherManagerGate (6 boolean fields).
check_manifest() validates against the spec; mark_signature_verified
+ mark_selinux_validated advance the gate.

10 unit tests covering: defaults validate, accept aether defaults,
reject wrong package, reject wrong install path, reject unknown AETHER
perm, accept non-AETHER perm, reject wrong SDK, reject missing HVC
rule, reject network leak, full gate walk."

git add hypervisor/src/hvc_paravirt_abi.rs
c "ch64: HVC Paravirt ABI" \
"Formalises the AETHER hypervisor-call vendor range as a typed ABI.
Function IDs are stable across hypervisor versions; new functions add
at the next unused ID. Versioning is at the ABI level — guest passes
its built-against major in GET_VERSION; hypervisor refuses mismatch.

AetherHvcFn enum with #[repr(u64)]: GetVersion (0x86000001) / Bridge
ModeGet / BridgeModeSet / SensorRead / UpdateStage / DiagLogRead.
AetherHvcStatus #[repr(i32)] with SMCCC-conformant sign-extending
to_u64(). HvcSensorId enum for SensorRead's arg1. SensorReadRet 4-
register return. check_abi_compat() rejects cross-major calls.
dispatch_function() pure-function shape that the VMEXIT (x86) and HVC
exception (ARM) handlers wire into.

10 unit tests covering: function ID roundtrips, IDs in vendor range,
unknown ID rejection, status sign-extension, sensor ID roundtrip,
version check, dispatch GetVersion returns current, dispatch
BridgeSet range, dispatch SensorRead invalid ID, dispatch UpdateStage
slot range."

# ── CLAUDE.md progress ───────────────────────────────────────────────────────

git add CLAUDE.md
c "docs(claude.md): chapter progress 58 -> 64 (ch59-64 complete)" \
"Mark Setup Wizard, Configuration App, OTA Update System, Recovery
Mode, AETHER Manager Android App, and HVC Paravirt ABI as complete.
Progress jumps from 58/70 (83%) to 64/70 (91%). Remaining: ch65
Security Hardening + Unsafe Audit, ch66 Performance Optimization,
ch67 Fingerprint Elimination Audit, ch68 CI/CD Pipeline + Release
Engineering, ch69 Documentation, ch70 Public Release."

echo
echo "=== final commit log (sandbox/aether-translator) ==="
git log --oneline | head -30
echo
echo "total commits since branch:"
git rev-list --count "$(git merge-base HEAD origin/main)..HEAD"
