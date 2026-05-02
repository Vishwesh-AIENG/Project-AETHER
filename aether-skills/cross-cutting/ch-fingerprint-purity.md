# SKILL.md — Fingerprint Purity: The Exact Replica Discipline

## Where This Fits

This skill is cross-cutting. It does not belong to one chapter — it is the lens through which **every** chapter must be reviewed. Every design decision in AETHER must pass one test:

> **Would a real Android phone on real Qualcomm hardware produce identical output at this interface?**

If the answer is "no" or "probably not" or "close enough", that is a fingerprint. Anti-cheat systems, integrity verifiers, and detection networks collect fingerprints. A single fingerprint is sufficient for detection. AETHER's goal is zero fingerprints.

## Confidence Disclosure

**HIGH for fingerprint taxonomy (what to check), LOW for specific anti-cheat implementation details (what Garena/ACE/GameGuard actually checks internally).** The detection methods of commercial anti-cheat systems are proprietary and not publicly documented. Claude can enumerate known public fingerprint surfaces but cannot guarantee coverage of undocumented checks. This skill should be treated as a starting point, not a complete audit.

## The Fingerprint Surface — Full Taxonomy

### Layer 0: CPU And Instruction Execution

| Fingerprint | What A Real Phone Produces | AETHER Risk | Mitigation |
|---|---|---|---|
| Instruction timing | Native cycles, no overhead | LOW — passthrough means native timing | None needed if SR-IOV is correct |
| System register values | Real hardware values | MEDIUM — some EL2-visible regs differ | Trap and return real values |
| MIDR_EL1 (CPU identity) | Cortex-X4 MIDR value | HIGH — guest reads this, AETHER must not modify it | Do NOT trap MIDR reads; let guest see real CPU identity |
| Cache line behavior | Real L1/L2/L3 hit/miss patterns | LOW — shared physical cache, native behavior | None needed |
| Speculative execution artifacts | Platform-specific | LOW | Spectre mitigations handle this |

**Critical rule:** AETHER must never modify CPU identity registers (MIDR, MPIDR within the guest's assigned range). A phone running Snapdragon X Elite reports Cortex-X4. AETHER's Android partition must also report Cortex-X4. If AETHER traps MIDR reads and returns a fake value, it creates a fingerprint.

### Layer 1: Memory System

| Fingerprint | What A Real Phone Produces | AETHER Risk | Mitigation |
|---|---|---|---|
| Memory access latency | Physical cache hierarchy timing | LOW — Stage 2 with large pages adds ~0 latency | Use 2MB blocks for all guest memory |
| `/proc/meminfo` total RAM | Physical RAM amount | MEDIUM — guest sees less than total if poorly configured | Assign RAM in round numbers that match plausible phone specs |
| Memory allocation patterns | OS-level behavior | LOW — Android kernel runs unmodified | None needed |
| NUMA topology | Single-node phone | LOW | Ensure device tree describes single NUMA domain |

**Critical rule:** The amount of RAM assigned to Android must look like a plausible Android phone. 4GB, 6GB, 8GB, 12GB are real phone configurations. 3.7GB or 7.2GB are not.

### Layer 2: Process And Kernel

| Fingerprint | What A Real Phone Produces | AETHER Risk | Mitigation |
|---|---|---|---|
| `/proc/cpuinfo` | ARM64 CPU info, no hypervisor mention | HIGH — some hypervisors add "Hypervisor" flag | Verify Android kernel does NOT set HWCAP_HYPERVISOR |
| `/proc/version` | Kernel version string | MEDIUM — must look like a real Android kernel | Build kernel with a version string matching real devices |
| `uname -r` | Kernel release matching build | LOW if kernel is properly configured | Set `CONFIG_LOCALVERSION` to match |
| Kernel command line (`/proc/cmdline`) | Real Android boot args | HIGH — must not contain QEMU/hypervisor keywords | Audit AETHER-generated kernel cmdline for leaks |
| `/proc/interrupts` | Only real device interrupts visible | MEDIUM — virtual devices appear | Ensure virtual device interrupt names look plausible |
| SELinux status | `enforcing` | HIGH — must be enforcing, not permissive | Never boot in permissive mode in production |
| System call availability | All standard syscalls present | LOW — unmodified kernel | None needed |

**Critical rule:** `/proc/cmdline` is actively read by some detection systems. It must not contain words like `qemu`, `virtio`, `hypervisor`, `virt`, or `emu`. AETHER's bootloader must construct a cmdline that matches what a real Qualcomm device would have.

### Layer 3: Build Identity And Properties

This is the most commonly checked layer in anti-cheat systems. Every property is checkable from an app without root.

| Property | What AETHER Must Return | Risk |
|---|---|---|
| `ro.product.manufacturer` | A real manufacturer (e.g., `Qualcomm`) | HIGH |
| `ro.product.model` | A real phone model or plausible AETHER model | HIGH |
| `ro.product.brand` | Matching brand | HIGH |
| `ro.hardware` | SoC hardware identifier | HIGH |
| `ro.board.platform` | Platform identifier | HIGH |
| `ro.build.fingerprint` | Canonical Android fingerprint format | CRITICAL |
| `ro.build.type` | `user` — NOT `userdebug` | CRITICAL |
| `ro.debuggable` | `0` | CRITICAL |
| `ro.secure` | `1` | CRITICAL |
| `ro.build.tags` | `release-keys` | HIGH |
| `ro.product.cpu.abi` | `arm64-v8a` | MEDIUM |
| `ro.hardware.egl` | Adreno EGL identifier | MEDIUM |

**Critical rule:** `ro.build.type` must be `user`, `ro.debuggable` must be `0`, and `ro.secure` must be `1`. These three properties together define a "production build." Any anti-cheat system checks these first. A `userdebug` build is immediately flagged on any production game server.

**Critical rule:** `ro.build.fingerprint` must follow the format `brand/product/device:version/buildId/buildDate:buildType/buildTags`. The build type must be `user` and the build tags must be `release-keys`. Example of a valid fingerprint: `Qualcomm/aether_x1/aether:14/AP1A.240505.005/2024050500:user/release-keys`. Do not use test keys.

### Layer 4: Hardware Sensors

| Sensor | Real Phone Behavior | AETHER Risk | Mitigation |
|---|---|---|---|
| Accelerometer | Gaussian noise at σ≈150µg/√Hz, bias drift | HIGH — fake sensors are trivially distinguishable | Ch12 Gaussian noise model |
| Gyroscope | Random walk bias, noise at σ≈0.01°/s/√Hz | HIGH | Ch12 first-order drift model |
| Magnetometer | Local declination + noise | HIGH | Calibrated offset + noise |
| Barometer | Altitude-dependent pressure + drift | MEDIUM | Static + small noise |
| Proximity sensor | Reports NEAR/FAR, not distance | LOW | Simple paravirtualized stub |
| Light sensor | Ambient lux with noise | LOW | Simple paravirtualized stub |
| Step counter | Hardware pedometer, counts footsteps | MEDIUM | Accumulate steps from accelerometer model |
| **Sensor polling rate** | Delivered at EXACT requested interval ±jitter | HIGH | Virtual sensor driver must implement correct timing with jitter |
| **Sensor data timestamps** | Monotonic nanosecond timestamps | HIGH | Must use the same clock source as the kernel's monotonic clock |

**Critical rule:** Sensor timestamps must use `CLOCK_BOOTTIME` nanoseconds, not wall clock. A timestamp discontinuity (caused by the sensor delivering data at wrong intervals) is a detectable fingerprint.

### Layer 5: Connectivity And Identity

| Fingerprint | Real Phone | AETHER Risk | Mitigation |
|---|---|---|---|
| IMEI | 15-digit hardware ID | HIGH if empty/fake | Phone Bridge Mode provides real IMEI; virtual modem provides configured IMEI |
| IMSI | SIM card ID | MEDIUM | Phone Bridge provides real IMSI |
| Android ID | 64-bit persistent ID, per-device | LOW | Generated on first boot, persists in storage |
| MAC address | OUI from Qualcomm/phone vendor range | MEDIUM | Set MAC OUI to Qualcomm's registered range: `9C:3A:AF` or similar |
| Bluetooth address | Similar to MAC | MEDIUM | Pair with MAC address scheme |
| WiFi BSSID scan results | Real local networks | LOW — WiFi passthrough means real scan results | None needed if WiFi is passed through |
| IP address | Normal ISP-assigned address | LOW | None needed |
| Network operator | Real carrier name | HIGH if missing | Phone Bridge provides real operator; virtual modem provides configured values |

**Critical rule:** IMEI cannot be zero, empty, or a repeated digit (like `000000000000000` or `123456789012345`). Both are immediately flagged. The virtual modem's IMEI must either come from the connected phone (Phone Bridge Mode) or be a valid IMEI with correct Luhn checksum from a valid TAC (Type Allocation Code) range registered to a real manufacturer.

### Layer 6: Display And Graphics

| Fingerprint | Real Phone | AETHER Risk | Mitigation |
|---|---|---|---|
| Screen resolution | Fixed per-device (e.g., 2880×1800) | MEDIUM | Set a resolution that matches a real device in `device.mk` |
| Screen DPI | Matching physical pixel density | MEDIUM | Set `ro.sf.lcd_density` to match the screen's real DPI |
| Refresh rate | 60Hz, 90Hz, 120Hz, or 144Hz | LOW | Set to match physical display |
| OpenGL ES version | ES 3.2 on modern Adreno | MEDIUM | Adreno VF driver must report correct ES version |
| OpenGL renderer string | `Adreno (TM) 830` or correct Adreno model | HIGH | Must match real Adreno hardware in the GPU VF |
| OpenGL vendor string | `Qualcomm` | HIGH | Adreno driver returns this automatically |
| Vulkan API version | Matching Adreno capabilities | MEDIUM | Driver reports this |
| Frame timing | Consistent 16.7ms or 8.3ms frames | HIGH — jitter is fingerprint | SR-IOV passthrough achieves this; check with Perfetto |

**Critical rule:** The OpenGL renderer string is checked by many games. It must say `Adreno (TM) X70` or whatever the Snapdragon X Elite's GPU model is. If the string is wrong, games that check renderer strings will refuse to run or flag the device.

### Layer 7: Android Runtime And App Layer

| Fingerprint | Real Phone | AETHER Risk | Mitigation |
|---|---|---|---|
| `isEmulator()` result | `false` | HIGH | Multiple checks — see below |
| Play Integrity API | MEETS_DEVICE_INTEGRITY | MEDIUM — microG returns BASIC only | Document limitation; use Garena partnership for Free Fire |
| SafetyNet (deprecated) | Passes basic attestation | MEDIUM | microG handles basic attestation |
| ADB status | Disabled in production | HIGH | Set `ro.adb.secure=1` and disable adb in production build |
| Developer options | Off | HIGH | Build as `user` type, developer options are hidden |
| USB debugging | Off | HIGH | Consequence of `user` build type |
| Root access | Not present | CRITICAL | Do NOT include Magisk, su, or root in production build |

**The `isEmulator()` Detection Surface.** Android's `Build.isEmulator` checks these properties. AETHER must ensure all return false-for-emulator values:

```java
// These all return true for emulators — AETHER must ensure they return false
Build.FINGERPRINT.startsWith("generic")           // must NOT start with generic
Build.FINGERPRINT.startsWith("unknown")           // must NOT start with unknown
Build.MODEL.contains("google_sdk")               // must NOT contain this
Build.MODEL.contains("Emulator")                 // must NOT contain this
Build.MODEL.contains("Android SDK built")        // must NOT contain this
Build.MANUFACTURER.contains("Genymotion")        // must NOT contain this
Build.HOST.startsWith("Build")                   // should be a real hostname
Build.BRAND.startsWith("generic")                // must NOT start with generic
Build.PRODUCT.startsWith("sdk")                  // must NOT start with sdk
```

Additionally, many apps perform their own emulator detection using:
```java
// Checks for emulator-specific files
new File("/dev/socket/qemud").exists()           // must be false
new File("/dev/qemu_pipe").exists()              // must be false
new File("/proc/tty/drivers").contains("goldfish")  // must be false
SystemProperties.get("ro.kernel.qemu")           // must be empty or "0"
```

**Critical rule:** `ro.kernel.qemu` must be `0` or absent. This single property, if set to `1`, causes nearly every emulator detection library to immediately flag the device. AETHER's kernel command line must not set `androidboot.qemu=1` or any equivalent.

### Layer 8: Timing And Jitter

This is the hardest fingerprint category to eliminate completely and the most sophisticated detection method.

| Test | Real Phone Behavior | Emulator Behavior | AETHER Behavior |
|---|---|---|---|
| System call latency | 100–500ns for simple syscalls | 1000–10000ns due to host OS overhead | ~100–500ns — native ARM64 |
| `clock_gettime()` jitter | <100ns jitter | High jitter from scheduling | <100ns — static core partitioning eliminates scheduling jitter |
| I/O latency | Physical NVMe latency | Software emulation latency | Physical NVMe latency — passthrough |
| GPU frame time | Consistent hardware timing | Variable software timing | Consistent hardware timing — SR-IOV passthrough |
| VM exit detection test | N/A — no VM exits on real phone | Detectable via TSC/counter discontinuity | ELIMINATED by static partitioning — no scheduling = no discontinuities |

**Critical rule:** The most sophisticated anti-cheat timing test measures the ratio of `CNTPCT_EL0` reads to elapsed real time. On a Type-2 emulator, the guest is periodically preempted, causing the counter to jump forward unexpectedly when the guest is rescheduled. On AETHER with static CPU partitioning, Android cores are NEVER preempted or rescheduled — they run continuously. The counter advances at exactly the physical rate, always. This is AETHER's decisive advantage over every Type-2 solution.

## The Exact Replica Build Checklist

This is the master checklist to run before shipping any AETHER build. Every item must be verified on real hardware, not in QEMU.

### Identity
- [ ] `ro.build.type = user`
- [ ] `ro.debuggable = 0`
- [ ] `ro.secure = 1`
- [ ] `ro.build.tags = release-keys`
- [ ] `ro.kernel.qemu` is absent or `0`
- [ ] `ro.build.fingerprint` is in canonical format with `user/release-keys`
- [ ] `/proc/cmdline` contains no emulator keywords
- [ ] No emulator-specific files exist in `/dev/` or `/proc/`

### Hardware Identity
- [ ] `/proc/cpuinfo` shows correct Cortex-X4 CPU, no "Hypervisor" flag
- [ ] `Build.MANUFACTURER`, `Build.MODEL`, `Build.BRAND` are plausible non-emulator values
- [ ] IMEI passes Luhn checksum validation
- [ ] MAC address OUI is from a real Qualcomm/phone vendor range
- [ ] OpenGL renderer string matches real Adreno GPU model

### Sensors
- [ ] Accelerometer noise distribution passes Kolmogorov-Smirnov test for Gaussianity
- [ ] Gyroscope exhibits random walk drift, not constant bias
- [ ] Sensor timestamps use `CLOCK_BOOTTIME` and have realistic jitter
- [ ] Sensor polling rate matches requested rate within ±5%

### Performance
- [ ] System call latency <500ns for `clock_gettime()` — measured with `strace -T`
- [ ] Frame time consistent at 16.7ms for 60fps content — measured with Perfetto
- [ ] No frame time spikes >2× normal during sustained gameplay
- [ ] VM exit rate <1000/second during active gameplay — measured via AETHER diagnostic counter

### App Compatibility
- [ ] `Build.isEmulator` returns `false` — verify with `adb shell getprop | grep -E "(qemu|emulator|emu)"`
- [ ] Free Fire launches without detection
- [ ] Free Fire connects to Garena's emulator pool (via partnership)
- [ ] Google Sign-In works through microG
- [ ] Push notifications delivered within 30 seconds of send

### Security
- [ ] ADB is disabled — `adb devices` returns empty or unauthorized
- [ ] Root is not present — `su` command fails with "not found"
- [ ] SELinux is enforcing — `adb shell getenforce` returns `Enforcing`
- [ ] Play Integrity returns at least MEETS_BASIC_INTEGRITY

## Primary References For This Skill

**Anti-Cheat Research:**
- `github.com/apkunpacker/AntiCheat-Collection` — catalogue of known anti-cheat detection methods (community-maintained, use for awareness, not as authoritative)
- Security research papers on emulator detection — search Google Scholar for "Android emulator detection"

**Android Properties:**
- `source.android.com/docs/core/architecture/bootloader/boot-image-header` — for cmdline format
- Android CDD (Compatibility Definition Document) for required property formats

**Build Identity:**
- AOSP `build/make/core/` — how Android build properties are generated
- `frameworks/base/core/java/android/os/Build.java` — all Build fields and their sources

## Common AI Mistakes In This Entire Domain

Claude designs AETHER's Android image as a "developer build" (`userdebug`) for debugging convenience and assumes production hardening can be added later. It cannot be added later — production identity must be correct from the first user-facing build.

Claude forgets that `ro.kernel.qemu` is set automatically by QEMU/Android emulator tooling and must be explicitly suppressed in AETHER's bootloader.

Claude assumes that because AETHER uses native hardware passthrough, all fingerprints are automatically eliminated. Native hardware eliminates timing fingerprints but not identity fingerprints — the properties, IMEI, OpenGL strings, and sensor behavior must all be explicitly configured.

Claude suggests keeping ADB enabled for support purposes. ADB enabled in a production build is an immediate emulator detection signal and a security hole.
