# Project AETHER
## A Bare-Metal Android Hypervisor for ARM64 and x86

**A complete, sovereign Android universe — native on Snapdragon X, translated on Intel and AMD — sharing nothing with the host machine.**

---

## Overview

**AETHER** is a Type-1 hypervisor written from scratch in Rust and assembly that boots directly on hardware before any operating system. It delivers a complete, production Android environment with no host OS, no emulation overhead, and no fingerprints detectable by apps.

AETHER ships in two hardware tiers, auto-detected at install time:

- **ARM Tier** — Snapdragon X Elite / X Plus. Rust hypervisor at EL2. Android runs natively — zero translation, full SR-IOV GPU passthrough, NVMe namespace isolation, GICv3 virtualization. Native hardware speed throughout.
- **x86 Tier** — any Intel or AMD machine with VT-x or AMD-V. Rust hypervisor at VMX/SVM root. Android runs inside the hypervisor with an integrated DBT engine (FEX-Emu) that translates ARM64 to x86 below the Android kernel. No host OS. Full Android experience on any hardware.

Both tiers support **Phone Bridge Mode**: connect any Android phone via USB, toggle on real sensor data — gyroscope, accelerometer, magnetometer, barometer, GPS, camera, IMEI, IMSI, and carrier identity stream directly from your phone's hardware. Toggle it off and AETHER's physics-accurate software sensor models take over.

---

## Part I — The Vision

### Chapter 1: What AETHER Is

AETHER is a Type-1 hypervisor that boots directly on hardware before any operating system, delivering a complete, production Android environment that behaves identically to a real Android phone at every layer of software inspection.

**ARM Tier** (Snapdragon X Elite / X Plus):
- Boots at Exception Level 2 (EL2), directly on ARM64 silicon
- Android guest executes native ARM64 instructions at full hardware speed
- Zero translation layers between Android and processor
- SR-IOV GPU partitioning, NVMe namespace isolation, GICv3 virtual interrupts
- Invisible to Android at every inspection point

**x86 Tier** (Intel / AMD with VT-x or AMD-V):
- Boots in VMX/SVM root mode directly on x86 silicon — no host OS
- Integrated DBT engine (FEX-Emu) translates ARM64 guest code to x86 inside the hypervisor
- Android kernel and userspace run unmodified as ARM64 — DBT is invisible to Android
- EPT/NPT enforces memory isolation; hardware-accelerated x86 virtualization underneath
- Full Android experience on any Intel or AMD machine

**Hardware auto-detection:** AETHER installer detects CPU family at install time and deploys the correct tier automatically.

**User experience:** Any laptop running the full Android experience — native apps, games, banking, anything — with behavior indistinguishable from a real Android phone, on ARM or x86 hardware.

### Chapter 2: Why AETHER Exists

Every existing Android-on-PC product (BlueStacks, LDPlayer, NoxPlayer, MEmu, Waydroid, Genymotion, Android Studio emulator) makes architectural compromises that produce detectable seams:

- **File system sharing** for drag-and-drop convenience
- **Proxy graphics calls** through host's graphics driver
- **Route Android's network** through host's network stack
- **Simulate sensors** with simple noise generators
- **Generic device identifiers** that anti-cheat systems recognize

Each compromise saves engineering time but introduces places where Android behaves differently than real hardware. Anti-cheat systems, banking apps, and DRM systems detect these differences.

**AETHER's reason for existing:** Take none of these compromises. By driving the boundary between the host machine and Android down to the silicon itself, every layer above the silicon is genuinely Android, talking to genuinely simulated Android hardware with genuine physical fidelity. There is no place for a fingerprint to form because there is no place where the host leaks through.

**Commercial outcome:** An Android environment in which apps cannot tell they are not running on real devices — because at every level of inspection they are running on real devices: real ARM64 processor (or ARMv8 instruction set via DBT), real GPU partition (ARM tier), real memory, real storage, real network, real sensor physics. Two hardware tiers, one consistent experience.

### Chapter 3: The Non-Negotiables

The following design constraints are inviolable. Every engineering decision must satisfy all simultaneously. If a proposed feature violates any, it is rejected.

#### Non-Negotiable 1: Resource Isolation
The Android partition must never depend on any host OS or external system for the purpose of accessing resources. Every resource Android uses must be either:
- **Dedicated via hardware passthrough**, or
- **Simulated by hypervisor's internal virtual device subsystem**

No shortcuts. No shared drivers. No proxying through Windows.

#### Non-Negotiable 2: Host Opaqueness
No software running outside AETHER's Android partition — including any OS sharing the physical machine — must ever have visibility into the Android partition's memory, devices, or execution state. From the Android partition's perspective, it owns the entire machine.

#### Non-Negotiable 3: Hypervisor Invisibility
The hypervisor itself must be invisible to both guests at the level of normal operation. Guests can detect virtualization only through deliberate ARM64 instructions that the architecture exposes for that purpose, and even those signals must be configured to match what real ARM64 hardware would report.

#### Non-Negotiable 4: No Host
There is no "host" in AETHER. The hypervisor is not a host. The hypervisor is a referee that allocates resources at boot and then steps out of the way. Android is the sole guest with full access to assigned resources.

---

## Part II — The Silicon

### Chapter 4: ARM64 As The Substrate

The ARM64 architecture (formally AArch64) is the only thing AETHER assumes exists. Everything else is built on top of it.

**ARM Architecture Reference Manual** — a public document of approximately 12,000 pages — is the only specification AETHER treats as authoritative for the hardware layer. Every behavior the hypervisor depends on is something the reference manual guarantees. Every behavior exposed to guests is something the reference manual describes for real hardware.

**Processor primitives:**
- 31 general-purpose 64-bit registers
- Stack pointer and program counter
- Register file for floating-point and SIMD operations
- Memory management unit (MMU) for virtual-to-physical address translation
- Generic interrupt controller (GIC) for hardware signals
- Architectural timers for cycle and elapsed-time counting

These primitives form the foundation. Operating systems, applications, and user experiences are constructed entirely from them.

### Chapter 5: Exception Levels

ARM64 defines a hierarchy of privilege called **exception levels**, numbered 0–3. Code at higher levels can do things code at lower levels cannot. This hierarchy is enforced by processor hardware, not software, and is the foundation of all isolation in AETHER.

#### Exception Level 0 (EL0) — User Applications
- Lowest privilege
- Application code executes here (e.g., Free Fire)
- Processor disallows any instruction that would affect another process or the OS
- Cannot access page tables, interrupt configuration, or kernel resources

#### Exception Level 1 (EL1) — Operating System Kernels
- Linux kernel inside Android partition runs here
- Windows NT kernel inside Windows partition runs here
- Access to page tables, interrupt configuration, and other kernel-level resources
- Cannot reach above itself

#### Exception Level 2 (EL2) — Hypervisor
- Designed specifically for hypervisors
- AETHER runs here
- Can intercept and control what happens at EL1 and EL0 in either guest
- Configures Stage 2 address translation (nested page tables)
- Ensures Android's write to physical address 0x40000000 lands in Android's memory region, not Windows's

#### Exception Level 3 (EL3) — Secure Firmware
- Secure firmware runs here
- AETHER does not run at EL3
- System's existing firmware (typically ARM Trusted Firmware on ARM laptops) runs at EL3
- AETHER cooperates with EL3 firmware during boot

### Chapter 6: The Virtualization Extensions

AETHER's existence is enabled by optional ARM64 features called **Virtualization Extensions** (VHE in modern form). These include:

- **EL2 execution mode** — hypervisor privilege level
- **Stage 2 translation tables** — nested address translation for memory isolation
- **Virtual interrupt controller interface** — inject and route interrupts to guests
- **System register trapping** — catch sensitive operations by guests

These extensions are present and enabled on:
- Snapdragon X Elite
- Apple Silicon
- AWS Graviton
- Most modern ARM64 systems-on-chip

AETHER will not run on processors lacking these extensions. The build system explicitly checks and refuses to produce hypervisor binaries for unsupported processors.

**x86 Tier virtualization hardware:**

Intel VT-x and AMD-V provide equivalent capabilities on x86:
- **VMCS / VMCB** — VM Control Structure (Intel) / VM Control Block (AMD): per-vCPU structure controlling which guest operations cause VM exits and what host state is restored on exit. Equivalent to ARM64's exception-level hardware context.
- **EPT / NPT** — Extended Page Tables (Intel) / Nested Page Tables (AMD): x86 equivalent of Stage 2 translation. AETHER programs EPT/NPT to restrict Android's physical memory view to its assigned region.
- **DBT Integration** — FEX-Emu translates ARM64 instruction blocks to x86 inside the hypervisor. Translated blocks are JIT-cached; after warmup, overhead targets less than 20% versus native ARM64 execution. The translation is invisible to the Android kernel and userspace — they execute as ARM64 software throughout.

**How it works:** When a guest at EL1 attempts a sensitive operation (e.g., modifying page tables conflicting with Stage 2 translation), the processor automatically traps to EL2, transferring control to AETHER. AETHER inspects the operation, decides whether to allow it, modifies its parameters if necessary, and either performs it on the guest's behalf or returns control with the operation completed. The guest never knows this happened — time simply passed slightly slower for that one instruction.

---

## Part III — The Hypervisor

### Chapter 7: Boot

When the machine is powered on, control passes through a sequence of firmware stages:

1. **Boot ROM** — baked into silicon, unchangeable
2. **Platform firmware** — UEFI on most ARM laptops, initializes RAM, storage, bootable device tree
3. **EL3 secure firmware** — establishes secure world and chain of trust
4. **AETHER** — inserts here, replacing what would normally be the Windows boot manager

AETHER is loaded as the bootable EFI image by platform firmware and takes control at EL2, immediately performing three operations:

#### Operation 1: Hardware Inventory Discovery
Parse firmware-provided ACPI tables and device tree, building internal map of:
- Every CPU core
- Memory regions
- GPU
- Network interfaces
- Storage controllers
- USB controllers
- All other peripherals

This inventory becomes the basis for resource partitioning.

#### Operation 2: Configuration Loading
Read AETHER's configuration from small partition on primary storage device. Configuration specifies:
- How many CPU cores each guest receives
- How much memory per guest
- Which GPU partition
- Which network interface
- Which storage region
- And so on

Configuration is established at install time and rarely changes.

#### Operation 3: Guest State Construction
Construct initial state for both guests:
- Create Stage 2 page tables mapping each guest's view of physical memory to actual machine memory regions assigned to it
- Configure virtual interrupt controller to route interrupts from guest's assigned devices to that guest
- Load bootable image of each guest (Windows boot manager and Android bootloader) into respective memory regions
- Start both guests by transferring execution to their entry points at EL1 in their respective contexts

**After boot:** Guests run at full hardware speed. AETHER intervenes only when a guest performs an operation requiring hypervisor mediation. Most of the time, both guests execute native ARM64 instructions on real CPU at full speed while AETHER sleeps.

### Chapter 8: Memory Architecture

Memory is the most carefully managed resource in AETHER because mistakes compromise isolation between Windows and Android. Memory partitioning works through three layers of address translation, the third controlled by AETHER.

#### Layer 1: Guest's Own Page Tables
Translate virtual addresses (VAs) seen by applications into intermediate physical addresses (IPAs) that guest kernel believes are physical. Guest manages these freely and is unaware that its "physical" addresses are not actual machine physical addresses.

#### Layer 2: AETHER's Stage 2 Page Tables
Translate intermediate physical addresses into actual physical addresses (PAs) on the machine. These tables are owned by AETHER and inaccessible to either guest.

**How it works:** Every memory access by either guest passes through Stage 2 translation. AETHER ensures translations only resolve to memory regions assigned to that specific guest. Attempt by Android guest to access Windows's memory region results in Stage 2 translation fault that traps to EL2, where AETHER terminates the offending access.

#### Layer 3: IOMMU (SMMU in ARM)
System Memory Management Unit performs the same Stage 2 translation for memory accesses initiated by hardware devices, not just by CPU.

**Why this matters:** Without SMMU, a device assigned to Android could be programmed by malicious or buggy Android driver to write to memory address belonging to Windows. SMMU prevents this by enforcing same address translation policy on device DMA operations as AETHER enforces on CPU memory accesses.

**Result:** No instruction executed by either guest, and no DMA operation performed by either guest's devices, can ever touch memory belonging to the other guest. Isolation is enforced by hardware, not software, and cannot be defeated by any code running at EL1 or below.

### Chapter 9: CPU Partitioning

AETHER allocates CPU cores to guests at boot. After that point, each core belongs exclusively to one guest until system reboot. There is no time-sliced multiplexing of CPU cores between guests.

**Why this matters for design:**
- **Performance** — no scheduling overhead, no context switching between guests on single core, no jitter from interleaving
- **Fingerprint purity** — predictability closer to native hardware

**Typical configuration** (Snapdragon X Elite with 12 cores):
- All 12 cores assigned to Android partition
- Hypervisor reserves no dedicated cores; it runs transiently during VM exits only

**x86 Tier:** Same model — all physical cores assigned to Android. Hypervisor runs only during VM exits and DBT compilation events.

Each core runs its assigned guest's code at native speed. Within each guest, normal scheduling happens entirely inside that guest's kernel. Windows schedules Windows threads across its assigned cores. Android kernel schedules Android processes across its assigned cores. Neither kernel is aware that other cores exist because AETHER reports to each guest only the cores assigned to that guest.

### Chapter 10: Interrupt Routing

When hardware device needs CPU's attention (disk finished read, network packet arrived, timer expired), it raises interrupt through Generic Interrupt Controller (GIC). GIC determines which CPU core should handle it and signals that core.

**In virtualized system:** Interrupts must be routed to correct guest. If device assigned to Android raises interrupt, it must reach Android kernel. If device assigned to Windows raises interrupt, it must reach Windows kernel. AETHER must never deliver Android device's interrupt to Windows or vice versa.

**Solution:** ARM virtualization extensions provide **GIC Virtualization Extension** that handles routing in hardware. AETHER configures GIC at boot to associate each device's interrupt line with specific guest. Thereafter, when interrupt arrives, GIC consults routing table and delivers interrupt directly to appropriate guest's virtual GIC, making it appear to that guest's kernel exactly as if it arrived on real hardware.

**Performance benefit:** Hypervisor itself does not need to mediate most interrupts; hardware does it correctly without software involvement, preserving performance.

**Hypervisor-handled interrupts:**
- EL2 timer interrupt (AETHER uses for internal time)
- Inter-processor interrupts (AETHER uses for hypervisor-internal coordination across cores)

---

## Part IV — Device Strategy

### Chapter 11: The Passthrough Principle

Every hardware device on the machine must be assigned to exactly one guest, and that guest gets exclusive direct access to it. This is called **passthrough**. AETHER does not virtualize devices for purposes that matter to Android.

**Exception:** Only virtualization that occurs is for devices that Android partition needs to believe exist but that don't physically exist on a laptop:
- Cellular modem
- Phone-specific sensors
- Certain phone-specific peripherals

**For everything else:** Passthrough or nothing.

**Reasoning:** Every paravirtualized device is a fingerprint. A paravirtualized network card responds to register reads with timing characteristics that don't match any real network card. A paravirtualized GPU has performance characteristics that don't match any real GPU. The only way to make device behave like real hardware is for it to **be** real hardware.

**Implementation:**
- **GPU** — SR-IOV (Single Root I/O Virtualization)
- **Network** — entire WiFi or Ethernet adapter assigned exclusively, or different physical adapter per guest
- **Storage** — dedicated NVMe controller or dedicated namespace within single NVMe drive per guest
- **USB** — assign specific USB controllers to specific guests; USB device in "Android" port connects directly to Android

### Chapter 12: The Necessity Of Paravirtualization

Three categories of devices make passthrough impossible, requiring paravirtualization:

#### Category 1: Cellular Modem
Laptop does not have cellular modem in form factor Android expects. AETHER's hypervisor includes virtual modem device that:
- Responds to AT commands
- Presents itself as Qualcomm or Samsung baseband processor
- Reports valid IMEI from pool of legitimate IMEIs
- Responds to network registration requests with synthetic but plausible cellular network data
- Routes actual data traffic through network interface assigned to Android
- Responses timed and parameterized to match real baseband processor behavior

#### Category 2: Sensor Suite
Laptop has much smaller sensor set than phone:
- No gyroscope
- No magnetometer
- No proximity sensor
- Sometimes no accelerometer

AETHER's virtual sensor subsystem generates synthetic sensor data using physically realistic models:
- **Accelerometer:** thermal noise from Gaussian distribution with parameters matching Bosch BMI160 or InvenSense MPU6500 (common in real Android phones)
- **Gyroscope:** drift modeled as random walk with correct integration characteristics
- **Magnetometer:** realistic deviation from true magnetic north plus appropriate noise
- Data generated in real time at polling rates real sensors use
- API responses match timing and format that real sensor drivers produce

#### Category 3: Phone-Specific Peripherals
Fingerprint sensor, front-facing camera, etc. Simulated as virtual devices that report not-currently-available status when queried. Apps that depend on these features see them as present but inactive — a normal state on real devices when user has disabled them or they are obscured.

#### Phone Bridge Mode

Phone Bridge Mode is a first-class feature on both ARM and x86 tiers. Connect any Android phone via USB and toggle it on or off at any time.

**Toggle ON — real hardware data:**
- Gyroscope, accelerometer, magnetometer, barometer: live MEMS sensor data from the phone's hardware, carrying exact thermal noise, drift patterns, and calibration signatures of that specific sensor
- GPS: real position from phone's GPS chip
- Camera: frames streamed from phone camera hardware over USB
- IMEI: real, registered, verifiable IMEI from phone's baseband
- IMSI: real SIM card identity
- Carrier name and network registration: real data from phone's modem
- All data streams at the polling rates Android requests, timestamped with CLOCK_BOOTTIME nanoseconds

**Toggle OFF — physics-accurate software models:**
- Accelerometer: Gaussian noise, σ≈150µg/√Hz (matches Bosch BMI160 specification)
- Gyroscope: random walk bias drift with correct integration characteristics
- Magnetometer: local magnetic declination plus calibrated sensor noise
- Barometer: altitude-appropriate pressure plus thermal drift
- IMEI: Luhn-valid configured identifier
- Carrier: configured network identity matching IMEI TAC range
- GPS: static user-configured location

Phone Bridge Mode is entirely optional. The software models are designed to be sufficient without it. Bridge Mode exists for users wanting maximum hardware fidelity.

**Implementation:** AETHER companion app on the phone sends sensor data over USB; AETHER's virtual HAL layer presents it to Android through the standard Android sensor HAL interface. Phone runs its normal workload simultaneously — the data stream imposes negligible load.

#### Hardware Authenticity Requirements

AETHER builds production Android. Every detail must match what real hardware reports:

**Build identity:** `ro.build.type = user`, `ro.debuggable = 0`, `ro.secure = 1`, `ro.build.tags = release-keys`. Developer builds are not shipped — they are structurally different from production devices.

**Sensor physics:** All software sensor models use Gaussian noise distributions, not uniform random. Uniform noise is not physically correct for MEMS sensors and fails statistical tests that anti-cheat systems run. Timestamps use CLOCK_BOOTTIME nanoseconds. Polling rate within ±5% of requested.

**Connectivity identity:** IMEI passes Luhn checksum validation. MAC address OUI from Qualcomm registered vendor range. Android ID persistent across reboots, generated on first boot.

**Production hardening:** ADB disabled (`ro.adb.secure=1`), root not present, SELinux enforcing. These are properties of a complete production Android device, not optional.

**CPU identity:** MIDR_EL1 reports the real ARM64 CPU. AETHER never traps or modifies CPU identity registers. The Android kernel reads what the silicon actually is.

### Chapter 13: GPU Partitioning Through SR-IOV

Graphics is most performance-sensitive subsystem in entire architecture because key use case is gaming. Graphics partitioning strategy uses **SR-IOV (Single Root I/O Virtualization)** — hardware feature allowing single physical GPU to present itself as multiple independent GPUs.

**How SR-IOV works:**
When enabled on GPU, driver subsystem creates small number of virtual functions, each appearing as separate PCI device with:
- Own memory regions
- Own command queues
- Own interrupt sources

Host OS sees one or more virtual functions and can assign them to different guests. GPU's hardware enforces isolation between virtual functions, ensuring work submitted to one cannot interfere with work submitted to another.

**AETHER's implementation:**
- Configure SR-IOV at boot to create two virtual functions on integrated GPU
- One assigned to Windows, other to Android
- Each guest's graphics driver communicates directly with assigned virtual function with no software mediation by hypervisor
- Android graphics stack (Adreno or Mali driver, OpenGL ES library, Vulkan library) talks to virtual function exactly as it would to real GPU
- Performance is native; hypervisor does not see graphics commands

**Android graphics driver selection:**
Selected at AOSP build time to match virtual function's reported identity. If AETHER configures Android virtual function to identify as Adreno 740, Android image built with Adreno graphics driver. Driver communicates with what it believes is real Adreno hardware, and at hardware level, GPU's SR-IOV responds correctly because virtual function genuinely presents Adreno-compatible registers and command formats.

**Current hardware status:**
- Snapdragon X Elite's Adreno X1 GPU supports SR-IOV in newer firmware revisions
- Apple Silicon GPUs do not expose SR-IOV
- Future AETHER revisions may need to fall back to software-based GPU sharing (Intel GVT-g or NVIDIA vGPU techniques)
- Architectural target is full SR-IOV passthrough

**x86 Tier GPU:** SR-IOV passthrough is not available on x86 tier in Phase One. Android's graphics stack runs through the DBT engine with software-emulated Adreno GPU registers. GPU passthrough for x86 is a Phase Four target, dependent on hardware SR-IOV support in Intel Arc or AMD consumer GPUs.

### Chapter 14: Storage Partitioning

Storage partitioned at NVMe namespace level. Modern NVMe SSD supports multiple namespaces, each appearing as separate block device. AETHER assigns the Android namespace exclusively, with the remainder available to other system software outside the hypervisor.

NVMe controller's SR-IOV implementation (where supported) or built-in namespace isolation ensures Android's NVMe driver can only see and access its assigned namespace.

**Android namespace:**
- Formatted with Android-standard partition layout
- Boot partition, system partition, vendor partition, userdata partition, etc.
- Contains complete Android filesystem

The Android namespace is inaccessible to any software outside AETHER's partition. No shared partition, no shared folder, no clipboard sync at storage level.

**Performance:** Storage I/O happens at native NVMe speed in both guests with no hypervisor mediation in data path. Read or write issued by either guest is dispatched directly to NVMe controller through guest's own NVMe driver, executes against guest's assigned namespace, and returns directly to guest. AETHER not involved.

### Chapter 15: Network Partitioning

Networking strategy depends on laptop's hardware. Most ARM laptops have single wireless network adapter, presenting partitioning challenge because two guests cannot share single radio without paravirtualization or SR-IOV support.

**Preferred configuration:**
Laptops with separate WiFi and cellular modems, or WiFi adapters supporting SR-IOV. In SR-IOV case, mirrors GPU strategy — two virtual functions, one per guest, isolation enforced in hardware. In dual-adapter case, WiFi assigned to Windows, cellular modem to Android.

**Fallback for single non-SR-IOV adapter:**
Paravirtualized network where adapter assigned to one guest and other guest receives virtual network interface that tunnels traffic through assigned guest. This is deliberate compromise reserved for hardware that cannot support proper passthrough.

**Design goal:** Minimize how often fallback is needed by recommending hardware supporting clean passthrough.

### Chapter 16: USB And Input Routing

USB partitioned at controller level, not device level. Laptop typically has multiple USB controllers:
- One for integrated keyboard and trackpad
- One for external USB-A ports
- One for USB-C ports

AETHER assigns each controller to specific guest at boot. Keyboard plugged into port managed by Android-assigned controller appears in Android only, not Windows.

**Enforcement:** SMMU (same as other DMA-capable devices). Android USB controller's DMA operations constrained by SMMU to access only Android memory regions. Controller's interrupts routed only to Android cores. Windows has no visibility into USB activity on Android-assigned controller and cannot interfere.

**Integrated keyboard/trackpad:** AETHER provides small mechanism for user to switch which guest currently receives input — typically key combination that signals AETHER to reassign integrated input controller from one guest to other. This is the only point where AETHER provides user-facing affordance crossing partition boundary, done only for practical reality that laptop has only one physical keyboard.

---

## Part V — Platform Tier Configuration

### Chapter 17: ARM Tier — Hardware And Partition Configuration

On ARM Tier hardware (Snapdragon X Elite / X Plus), AETHER configures the following at boot:

**Resource assignment:**
- CPU cores assigned to Android partition (all physical cores; no second guest)
- Memory partitioned: hypervisor reservation + Android working set
- GPU SR-IOV virtual function configured for Android's Adreno driver
- NVMe namespace assigned exclusively to Android filesystem
- USB controllers assigned per-device to Android

**ACPI and device tree:**
AETHER constructs device tree blobs describing Android's assigned hardware exactly. The Android bootloader and kernel read these descriptions and load drivers for what they believe is real hardware — because it is real hardware, passed through directly.

**Stage 2 page tables:**
Programmed at boot to map Android's IPA space to its assigned PA regions. Any out-of-bounds access traps to EL2, where AETHER terminates it.

**GIC configuration:**
Each device's interrupt lines configured to route only to Android's assigned cores via GICv3 virtualization extension. AETHER configures this once at boot; hardware enforces it thereafter.

### Chapter 18: x86 Tier — DBT And VMCS Configuration

On x86 Tier hardware (Intel / AMD), AETHER configures:

**VMCS / VMCB initialization:**
- Host state fields: AETHER's register state restored on every VM exit
- Guest state fields: Android's initial register state, GDT, IDT, page table roots
- VM-execution controls: which MSR accesses and memory accesses cause exits
- EPT / NPT root: AETHER programs nested page table root pointing to Android's physical memory region

**DBT engine (FEX-Emu) initialization:**
- ARM64 instruction decoder and x86 code emitter initialized at hypervisor startup
- JIT translation cache allocated in hypervisor memory (inaccessible to Android)
- First execution of each ARM64 basic block: DBT translates → caches → jumps to translated block
- Subsequent executions: JIT cache hit, translated x86 runs directly with no re-translation
- ARM64 system register accesses emulated by DBT engine to return correct values for the emulated CPU model (Cortex-X4)

**Memory model:**
- EPT maps Android's IPA → PA for its assigned physical memory
- DBT translated code pages execute in x86 VMX non-root mode under EPT enforcement
- Android kernel's own page tables are respected; DBT operates below the kernel's view

**Android's perspective:**
The Android kernel and all userspace code run as ARM64 software. They read ARM64 system registers, execute ARM64 instructions, and receive ARM64 exception semantics. The x86 hardware underneath is completely invisible.

---

## Part VI — The Android Partition

### Chapter 19: The Bootloader

Android partition begins its life with Android-compliant bootloader — specifically a port of U-Boot or custom bootloader following Android Verified Boot specification. AETHER loads bootloader into Android partition's memory at entry point Android expects, and execution begins there at EL1 inside Android partition's context.

**Bootloader operations:**
- Initializes its view of platform (AETHER has prepared to look like specific Android device, complete with device tree, ACPI-equivalent hardware description, verified boot keys)
- Verifies cryptographic signature of Android boot image
- Loads Linux kernel into memory
- Places device tree blob at address kernel expects
- Transfers execution to kernel entry point

**Verified boot subsystem:**
- Reports "locked" bootloader state (state real Android devices ship in)
- State that SafetyNet and similar attestation systems expect
- AETHER's bootloader not actually unlocked — it cryptographically verifies Android image it loads using keys controlled by AETHER's build system
- Because AETHER built the Android image and signed it, verification succeeds
- Bootloader truthfully reports locked state

### Chapter 20: The Linux Kernel

Linux kernel inside Android partition built from Android Common Kernel source tree (Google's curated branch of mainline Linux with Android-specific patches). AETHER builds this kernel for ARM64 architecture targeting AETHER's virtual hardware platform.

**Kernel configuration includes drivers for:**
- Hardware Android partition has been assigned
- Adreno GPU driver (because partition has Adreno virtual function)
- Qualcomm WiFi driver or cellular modem driver (to match network hardware)
- Standard ARM architectural timer driver
- GIC driver
- SMMU driver

**Critical:** Kernel does not include any AETHER-specific drivers:
- No virtio driver
- No paravirtualization client
- No hypervisor integration code

Kernel believes it is running on real ARM64 SoC and uses standard drivers for what it perceives as standard hardware. This is what makes partition appear genuine — every driver in kernel is real driver for real hardware, and hardware those drivers communicate with is either real (passed through) or genuinely simulated to specification (few paravirtualized devices).

### Chapter 21: AOSP And The Android Userspace

Above kernel runs Android userspace, built from Android Open Source Project. Build target is custom AETHER device configuration specifying:
- Hardware identity
- Included system services
- Preinstalled applications

**Device configuration tells AOSP build system:**
This device has hardware AETHER's virtual platform exposes — specific CPU cores, specific GPU, specific sensors, specific identifiers. Build system generates appropriate vendor partition contents, including hardware abstraction layer libraries matching this hardware.

**When Android runs:**
- Userspace HALs talk to same hardware kernel drivers do
- Chain from app to kernel to hardware is unbroken Android software all way down
- Android Runtime (ART) compiles applications from DEX bytecode to native ARM64 machine code at install time (just as on real device)
- Native code executes directly on real CPU at native speed
- No interpretation, no translation, no performance penalty
- Apps run as fast as they would on real Android device with equivalent hardware
- Given Android partition has access to Snapdragon X Elite's CPU cores, means apps run faster than on most actual phones

### Chapter 22: The microG Substitution

Google Play Services is Google's proprietary collection of cloud-connected services most Android applications depend on:
- Google account authentication
- Push notifications through Firebase Cloud Messaging
- Location services through Fused Location Provider
- Advertising identifiers
- In-app purchasing
- Play Integrity API that detects non-certified Android environments

AETHER does not include Google Play Services because Google does not license it to non-certified Android implementations. Obtaining certification for hypervisor-based Android image would require Google's cooperation.

**Instead:** AETHER integrates **microG**, open-source reimplementation of Google Play Services API surface.

**microG provides:**
- API-level compatibility for most commonly used Google services
- Apps authenticating users through Google Sign-In work (microG implements same authentication flow)
- Apps receiving push notifications through FCM work (microG's GmsCore reimplements FCM client)
- Apps looking up user's location through Fused Location Provider receive location data (from microG location backend rather than Google's servers)

**Play Integrity API challenge:**
Hardest case because its purpose is specifically to detect non-Google Android environments. microG's Play Integrity implementation returns responses indicating unverified environment, causing some apps (primarily banking apps and certain games with strict integrity requirements) to refuse to run.

**Compatibility path:** For applications not checking Play Integrity, microG provides full functional compatibility. For applications checking it, AETHER offers future path through compatibility shim that responds to integrity checks with cached attestations from real devices — remains research direction rather than current feature.

### Chapter 23: The Play Store Question

Google Play Store is application AETHER users most want to install applications from. It is itself Google application depending on Play Services. Without official Google certification, Play Store cannot be legitimately included in AETHER's Android image.

**AETHER addresses through alternative app sources:**

**Default:** F-Droid carries open-source applications and is freely redistributable.

**For applications not on F-Droid:** Aurora Store, open-source frontend to Google Play Store backend allowing users to download Play Store apps using anonymous accounts. Provides access to most Play Store catalog without requiring AETHER itself to be certified.

**For users wishing to install genuine Google Play Store:** Manual installation path requiring user to acknowledge legal and technical implications of running Google's proprietary services on non-certified Android implementation. Path is supported but not default.

---

## Part VII — Cross-Cutting Concerns

### Chapter 24: Performance

Performance philosophy of AETHER is that nothing should be slower than it would be on equivalent native hardware, and many things should be faster because underlying ARM64 chip in Snapdragon X Elite is more capable than any phone's chip.

**CPU performance:** Native. Guests execute instructions directly on real CPU at full speed. Hypervisor only intervenes for trapped operations, which are rare during normal application execution.

**Memory performance:** Native. Stage 2 translation happens in hardware via MMU's two-stage translation, fully pipelined with no measurable overhead to normal memory accesses.

**GPU performance:** Native via SR-IOV. Graphics commands flow from Android graphics stack directly to GPU virtual function with no software mediation.

**Storage performance:** Native via NVMe namespace passthrough. Reads and writes flow from Android NVMe driver directly to controller.

**Network performance:** Native via SR-IOV or dedicated adapter passthrough. Packets flow through assigned hardware without hypervisor involvement.

**Overhead places:** Paravirtualized devices (modem, sensors, phone-specific peripherals) — but these not performance-critical for any normal use case. Reading gyroscope at 100 Hz not bottlenecked by anything AETHER does.

### Chapter 25: Security

Security model of AETHER rests on **hardware enforcement of partitioning:**
- SMMU enforces device DMA isolation
- Stage 2 translation enforces CPU memory isolation
- GIC enforces interrupt isolation

None are software policies that can be bypassed by buggy or malicious code in either guest. They are hardware mechanisms that processor enforces unconditionally.

**Hypervisor itself:**
- Runs at EL2, above both guests
- Memory not mapped into either guest's address space
- No way for code in either guest to read or write hypervisor memory

**Attack surface:**
- Small by design
- Exposes no API to guests beyond what ARM architecture defines for guest-host communication
- Guest-host communication paths minimal — small number of hypercall handlers for operations genuinely requiring hypervisor mediation
- Each handler is few dozen lines of carefully audited code

**Implementation language:**
- Written in Rust for memory safety at language level for everything outside few hand-written assembly entry points
- Assembly portions limited to EL2 exception vectors and context-switching code
- Both small enough to be audited line by line

### Chapter 26: Time

Time deserves its own chapter because it is one of subtlest aspects of virtualization and one where most hypervisors leak fingerprints.

**Architectural timer:** Each ARM64 core has architectural timer that counts cycles since system started. Guests read this timer to measure elapsed time. Many anti-cheat systems compare timer readings to detect virtualization through inconsistencies.

**AETHER's approach:** Configures virtual architectural timer such that each guest sees coherent, monotonic time stream matching what real hardware would produce.

**Why this works:** Because AETHER does not multiplex CPU cores between guests, time in each guest flows continuously and naturally. No gaps in time stream where AETHER took CPU away to run something else. Android partition's clock advances at exactly rate real CPU's architectural timer advances. Windows partition's clock does same, on its own cores.

**Wall-clock time:** Separate from architectural timer, initialized at boot from platform's real-time clock, then maintained internally by each guest using own NTP synchronization through its assigned network interface. AETHER does not provide time services to either guest.

---

## Part VIII — Build And Toolchain

### Chapter 27: The Build System

AETHER is built from unified build system that produces three artifacts:
1. Hypervisor binary
2. Windows boot configuration
3. Android image

Build system implemented in combination of:
- **Make** — orchestration
- **Cargo** — Rust hypervisor code
- **Soong** — AOSP portion of Android image

Top-level orchestration script invokes each subsystem in correct order with correct configuration.

**Hypervisor source tree:** Structured as Rust workspace with separate crates for:
- EL2 entry code
- Stage 2 translation manager
- SMMU manager
- GIC manager
- Device assignment manager
- Paravirtualized device implementations
- Boot orchestration logic

Each crate has its own unit tests. Workspace as a whole has integration tests running inside QEMU's virtualization emulation for development.

**Android image build:** Performed by fork of AOSP including AETHER's device configuration and integrated microG components. Fork is rebased regularly against upstream AOSP to incorporate security patches and feature updates.

### Chapter 28: The Development Workflow

Development happens primarily on x86-64 Linux workstations using cross-compilation toolchains for ARM64:
- Hypervisor binary built with Rust ARM64 target
- Android image built with AOSP's standard build system targeting AETHER's device configuration

**Testing at three levels:**

1. **Unit tests** — run on development machine for individual hypervisor components
2. **Integration tests** — run hypervisor inside QEMU's ARM64 system emulation with simulated guests on development machine
3. **Hardware tests** — run full hypervisor on real ARM64 hardware (initially development boards like SolidRun HoneyComb or actual Snapdragon X Elite laptops in development partition)

**Continuous integration:** Unit and integration test suites run on every commit. Hardware tests run nightly on small fleet of physical test machines.

---

## Part IX — Roadmap

### Chapter 29: Phase One — Foundation (ARM Tier)
**Timeline:** 12–18 months for small team

Produces hypervisor that:
- Boots on real Snapdragon X Elite hardware at EL2
- Runs minimal Linux guest in Android partition
- Guest executes code, allocates memory, handles interrupts from assigned devices
- NVMe namespace passthrough working, GIC routing working
- No Android userspace, no graphics yet
- ARM Tier architecture validated end to end on real hardware

### Chapter 30: Phase Two — Android Bring-Up (ARM Tier)
**Timeline:** 6–9 months

Brings full Android stack into the ARM Tier partition:
- Building AOSP for AETHER's ARM Tier device target
- Integrating microG and Phone Bridge Mode
- Configuring physics-accurate virtual sensors and virtual modem
- SR-IOV GPU passthrough working with Adreno driver
- Validating full Android application compatibility
- System is a functional, app-store-compatible Android device on Snapdragon X hardware

### Chapter 31: Phase Three — x86 Tier Foundation
**Timeline:** 12 months

Ports AETHER to Intel / AMD hardware:
- VMX/SVM root mode boot, VMCS/VMCB initialization
- FEX-Emu DBT engine integration inside hypervisor
- EPT/NPT memory isolation
- Android boots inside DBT layer on x86 hardware
- Core applications validated through translation layer
- x86 Tier architecture validated end to end

### Chapter 32: Phase Four — Performance And Compatibility
**Timeline:** 12 months

Focus on performance optimization and application compatibility testing:
- Graphics path tuned for native performance
- Sensor models refined against real device measurements
- Application compatibility validated across top thousand Play Store applications
- Bug fixes for any that misbehave

### Chapter 33: Phase Five — Polish And Release
**Timeline:** 6–12 months

Product polish:
- Installer
- Configuration tools
- Documentation
- Support infrastructure
- Cross-partition input switching mechanism
- Culminates in public release

**Total timeline:** 4–5 years from phase one to phase five for dedicated team of 5–10 engineers. Working part-time alongside four-year computer science degree, expect 6–8 year project for full vision, with intermediate milestones producing real capability along the way.

---

## Appendix A: Glossary

**AArch64** — 64-bit execution state of ARM architecture; synonymous with ARM64

**ACPI** — Advanced Configuration and Power Interface, standard for describing hardware to operating systems

**AOSP** — Android Open Source Project, Google's open-source Android codebase

**ART** — Android Runtime, execution environment for Android applications

**DMA** — Direct Memory Access, hardware-initiated memory transfers bypassing CPU

**EL** — Exception Level, ARM64 privilege hierarchy from EL0 (applications) to EL3 (secure firmware)

**GIC** — Generic Interrupt Controller, ARM standard interrupt controller

**Hypervisor** — Software creating and managing virtual machines; here specifically Type-1 hypervisor running directly on hardware

**IPA** — Intermediate Physical Address, address guest believes is physical but actually requires Stage 2 translation

**microG** — Open-source reimplementation of Google Play Services

**Passthrough** — Direct exclusive assignment of hardware device to single guest

**Paravirtualization** — Software simulation of hardware device by hypervisor

**SMMU** — System Memory Management Unit, ARM IOMMU implementation

**SR-IOV** — Single Root I/O Virtualization, hardware feature for partitioning PCI devices

**Stage 2** — Hypervisor-controlled second phase of address translation mapping guest physical addresses to machine physical addresses

**Type-1 Hypervisor** — Hypervisor running directly on hardware with no underlying operating system

**DBT** — Dynamic Binary Translation, JIT compilation of guest instruction set (ARM64) to host instruction set (x86) at runtime

**EPT** — Extended Page Tables (Intel), x86 equivalent of Stage 2 translation; controls guest physical memory access

**FEX-Emu** — Open-source ARM64-to-x86 dynamic binary translator; integrated inside AETHER's x86 Tier hypervisor

**NPT** — Nested Page Tables (AMD), AMD equivalent of Intel EPT

**SVM** — Secure Virtual Machine (AMD), AMD's hardware virtualization feature set equivalent to Intel VMX

**VHE** — Virtualization Host Extensions, modern ARM64 virtualization feature set

**VMX** — Virtual Machine Extensions (Intel), the x86 hardware virtualization feature set; AETHER x86 Tier runs in VMX root mode

**VMCS** — VM Control Structure, Intel per-vCPU structure controlling VM entry, VM exit, and execution behavior of a guest

---

## Appendix B: Required Reading

**ARM Architecture Reference Manual for ARMv8-A** — Most important document for this project. Read chapters on:
- Exception levels
- Memory management unit
- Stage 2 translation
- GIC architecture
- SMMU
- Architectural timer

**AOSP source tree** — Build it, modify it, understand its structure. Hardware abstraction layer interfaces and device configuration system are where AETHER's customization happens.

**Linux kernel source (ARM64 architecture)** — Particularly KVM subsystem provides reference implementation of every concept AETHER implements. KVM is not what AETHER is, but solves many same problems. Source is most readable specification of solutions.

**Xen Project documentation** — Particularly for Xen on ARM. Describes Type-1 hypervisor architecture closer to AETHER's than KVM's. Xen's design choices not all appropriate for AETHER, but rationale Xen documents for each choice is invaluable.

**microG project documentation** — Describes API surface microG implements and gaps relative to genuine Google Play Services.

---

## Appendix C: Prerequisites For Contributors

A contributor to AETHER must possess working knowledge of all of the following:

- **ARM64 architecture** — at level of someone who has read the architecture reference manual
- **Rust programming language** — intermediate or advanced level
- **Linux kernel** — at level of having read and modified driver code
- **Android operating system** — at level of having built AOSP from source and modified its system services
- **Computer architecture concepts** — caching, memory hierarchies, out-of-order execution
- **Operating system theory** — scheduling, virtual memory, interrupt handling

This is a high bar. It is the bar required to do this work without producing subtle, hard-to-diagnose bugs that compromise either correctness or fingerprint fidelity.

The project is not friendly to learners in way some open-source projects are. It is friendly to people who are already competent at systems programming and want to apply that competence to one of hardest problems in field.

---

## Closing Words

AETHER is, by design, an extreme project. It rejects every shortcut that other Android-on-PC products have taken. It demands hardware features that not all laptops have. It requires expertise that few engineers possess. It will take years to build and more years to perfect.

But the result, if executed correctly, is something that does not currently exist anywhere — an Android environment so faithful to real hardware that no software can tell the difference, running on any PC laptop whether ARM64 or x86, with absolute isolation from everything else on the machine.

That has value far beyond the original use case that motivated this project. It is a foundation for any future work requiring a sovereign, untraceable, fully-faithful Android execution environment — on any hardware, for any user.

**The journey is long. The destination is clear. The work begins at the silicon and proceeds upward, layer by layer, exactly as this document describes.**

---

*This document is a living specification. As the project evolves, so will this text. The principles, however, are fixed.*
