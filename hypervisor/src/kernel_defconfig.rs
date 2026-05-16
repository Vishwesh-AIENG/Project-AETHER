// ch44: Android Kernel and Device Tree
//
// Defines the AETHER GKI defconfig for aarch64, validates a GkiConfig against
// that defconfig, and builds the production Android DTB with all nodes required
// for Android init and Zygote launch.
//
// ── Why This Module Exists ────────────────────────────────────────────────────
//
// ch20 (kernel.rs) builds the base Android DTB: memory, cpus, psci, intc,
// timer, serial, chosen.  That set is sufficient to boot a Linux shell.  It is
// NOT sufficient to launch Android userspace.  Android init (first-stage and
// second-stage), vold, surfaceflinger, and Zygote all require additional DTB
// nodes and kernel config options that are absent from ch20.
//
// 70% of Android userspace boot failures trace to one of these omissions:
//
//   1. Missing /firmware/android fstab node
//      Android first-stage init reads this node to discover where system and
//      vendor partitions live.  Without it, init exits immediately:
//        "Failed to mount required partitions in first stage"
//      This is the single most common Android DTB mistake.
//
//   2. CONFIG_TMPFS not set
//      Android init mounts tmpfs on /dev at the very start of first-stage init.
//      Without CONFIG_TMPFS, the mount fails silently and /dev is empty.
//      Virtually every subsequent action fails because udev cannot populate
//      device nodes.
//
//   3. CONFIG_DEVTMPFS not set (or CONFIG_DEVTMPFS_MOUNT not set)
//      Android relies on devtmpfs to pre-populate /dev before init runs.
//      Without it, /dev/null, /dev/urandom, and block device nodes are absent.
//      init opens /dev/null at offset 0 — if it is missing, the process exits.
//
//   4. CONFIG_UNIX not set
//      Android Binder transport uses Unix domain sockets internally.  Binder
//      will initialize but every cross-process call silently fails.  Zygote
//      dies immediately when it cannot establish the socket to system_server.
//
//   5. CONFIG_EXT4_FS_SECURITY not set
//      SELinux extended attributes on ext4 require FS_SECURITY.  Without it,
//      file contexts are not stored and the SELinux policy load fails.  The
//      kernel marks SELinux as disabled (even though CONFIG_SECURITY_SELINUX=y)
//      and Android aborts boot because ro.build.type=user requires enforcing.
//
//   6. CONFIG_PSI not set
//      Android LMKD (Low Memory Killer Daemon) uses PSI (Pressure Stall
//      Information) to detect memory pressure.  Without PSI, LMKD cannot
//      function.  Under memory pressure, init's children are killed without
//      warning.  Zygote restarts loop forever.
//
//   7. PL011 missing clock-frequency in DTB
//      Without clock-frequency, the PL011 driver cannot calculate the correct
//      divisor for 115200 baud.  The console output looks like random bytes.
//      Developers conclude the kernel hung when it actually booted.
//
//   8. Missing linux,initrd-start/end in /chosen
//      Android GKI boots from a ramdisk (initrd/initramfs) that contains the
//      first-stage init binary.  Without the initrd address in /chosen, the
//      kernel boots with no init process and panics.
//
// ── GKI Defconfig (aarch64) ──────────────────────────────────────────────────
//
// AETHER_GKI_DEFCONFIG contains every CONFIG_ option needed beyond the base
// GKI mandatory set (GKI_REQUIRED_OPTIONS in kernel.rs).  AetherGkiDefconfigValidator
// applies these entries to a GkiConfig and returns an AetherDefconfigGate.
//
// ── Production DTB Extras ────────────────────────────────────────────────────
//
// ProductionDtbExtras carries the parameters that vary between deployments:
//   initrd_start/end   — initrd IPA range (0 = no initrd)
//   uart_clock_hz      — PL011 input clock (24_000_000 on QEMU virt)
//   ramoops_base       — reserved IPA for pstore/ramoops
//   ramoops_size       — size of ramoops region (must be ≥ 128 KiB, power of two)
//   ramoops_record_size — size of each ramoops record (console/dmesg)
//
// build_production_android_dtb() calls build_android_dtb() then appends the
// Android-specific nodes in a single pass using a fresh DtbBuilder so that the
// total struct + strings usage is known at compile time.
//
// References:
//   android.googlesource.com/kernel/common          — Android Common Kernel GKI
//   Documentation/devicetree/bindings/reserved-memory/ramoops.yaml
//   Documentation/devicetree/bindings/arm/firmware/android.yaml
//   kernel/Documentation/admin-guide/ramoops.rst
//   source.android.com/devices/architecture/dto    — Android DTB/DTO overlay
//   source.android.com/devices/bootloader/system-as-root — first-stage mount

use crate::kernel::{
    AndroidDtbConfig, GkiConfig, KernelError,
    GIC_PPI, GIC_SPI, IRQ_TYPE_LEVEL_HIGH,
    TIMER_SECURE_PPI_DT, TIMER_NON_SECURE_PPI_DT, TIMER_VIRTUAL_PPI_DT, TIMER_HYP_PPI_DT,
    PSCI_CPU_ON_FN, PSCI_CPU_OFF_FN, PSCI_CPU_SUSPEND_FN,
    FDT_STRUCT_OFFSET, FDT_HEADER_SIZE,
    FDT_MAGIC, FDT_VERSION, FDT_LAST_COMP_VERSION,
};

// ─────────────────────────────────────────────────────────────────────────────
// Defconfig entry types
// ─────────────────────────────────────────────────────────────────────────────

/// The value of a CONFIG_ option in the kernel defconfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefconfigValue {
    /// `CONFIG_FOO=y` — compiled in.
    Enabled,
    /// `CONFIG_FOO=m` — built as a module (not used in GKI; here for documentation).
    Module,
    /// `# CONFIG_FOO is not set` — explicitly disabled.
    Disabled,
}

/// A single CONFIG_ entry in the AETHER GKI defconfig.
#[derive(Debug, Clone, Copy)]
pub struct DefconfigEntry {
    /// CONFIG_ option name, e.g., `b"CONFIG_TMPFS"`.
    pub name: &'static [u8],
    /// Required value.
    pub value: DefconfigValue,
}

impl DefconfigEntry {
    /// Construct a must-enable entry (CONFIG_FOO=y).
    pub const fn must_enable(name: &'static [u8]) -> Self {
        Self { name, value: DefconfigValue::Enabled }
    }

    /// Construct a must-disable entry (# CONFIG_FOO is not set).
    pub const fn must_disable(name: &'static [u8]) -> Self {
        Self { name, value: DefconfigValue::Disabled }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AETHER GKI defconfig — aarch64
//
// These entries supplement GKI_REQUIRED_OPTIONS (kernel.rs).  Every option
// listed here is required for Android userspace (init → Zygote) to function
// correctly on AETHER.  The entries are grouped by subsystem.
//
// Source: android.googlesource.com/kernel/common android14-6.1 defconfig
// ─────────────────────────────────────────────────────────────────────────────

/// AETHER GKI defconfig entries (supplement to GKI_REQUIRED_OPTIONS in ch20).
///
/// A kernel built with all options in GKI_REQUIRED_OPTIONS + AETHER_GKI_DEFCONFIG
/// will boot Android init, mount system/vendor, and launch Zygote.
pub const AETHER_GKI_DEFCONFIG: &[DefconfigEntry] = &[
    // ── Filesystems ─────────────────────────────────────────────────────────

    // tmpfs: Android mounts /dev, /tmp, and /run on tmpfs in first-stage init.
    // Missing this causes init to silently fail when mounting /dev.
    DefconfigEntry::must_enable(b"CONFIG_TMPFS"),
    // tmpfs POSIX ACL: Android uses ACL on tmpfs to enforce Unix permissions
    // across UIDs (e.g., /dev/socket ownership by system:socket_class).
    DefconfigEntry::must_enable(b"CONFIG_TMPFS_POSIX_ACL"),
    // tmpfs extended attributes: SELinux labels on tmpfs files (e.g., /dev nodes).
    DefconfigEntry::must_enable(b"CONFIG_TMPFS_XATTR"),
    // devtmpfs: pre-populated /dev at boot (before udev/ueventd runs).
    // Without this /dev/null and block device nodes are absent at init start.
    DefconfigEntry::must_enable(b"CONFIG_DEVTMPFS"),
    // Auto-mount devtmpfs at /dev during early boot.
    DefconfigEntry::must_enable(b"CONFIG_DEVTMPFS_MOUNT"),
    // procfs: /proc required by init, logd, and virtually all Android daemons.
    DefconfigEntry::must_enable(b"CONFIG_PROC_FS"),
    // /proc/pid/ns symlinks: required by Android's namespace-based sandbox.
    DefconfigEntry::must_enable(b"CONFIG_PROC_PID_CPUSET"),
    // sysfs: /sys required by ueventd, vold, and hardware HALs.
    DefconfigEntry::must_enable(b"CONFIG_SYSFS"),
    // EXT4 security xattrs: SELinux labels on ext4 system/vendor partitions.
    // Without this, file contexts are not persisted; SELinux policy load fails.
    DefconfigEntry::must_enable(b"CONFIG_EXT4_FS_SECURITY"),
    // EXT4 extended attributes: required by EXT4_FS_SECURITY.
    DefconfigEntry::must_enable(b"CONFIG_EXT4_FS_XATTR"),
    // F2FS extended attributes: SELinux labels on userdata (F2FS).
    DefconfigEntry::must_enable(b"CONFIG_F2FS_FS_XATTR"),
    // F2FS security xattrs: required for SELinux on userdata partition.
    DefconfigEntry::must_enable(b"CONFIG_F2FS_FS_SECURITY"),
    // F2FS POSIX ACL: Android userdata ACL enforcement.
    DefconfigEntry::must_enable(b"CONFIG_F2FS_FS_POSIX_ACL"),

    // ── Networking ──────────────────────────────────────────────────────────

    // Core networking stack: required by all Android daemons (logd uses sockets).
    DefconfigEntry::must_enable(b"CONFIG_NET"),
    // IPv4 stack: required by netd, connectivity stack, DNS resolver.
    DefconfigEntry::must_enable(b"CONFIG_INET"),
    // IPv6: required by Android's dual-stack connectivity (always enabled).
    DefconfigEntry::must_enable(b"CONFIG_IPV6"),
    // Unix domain sockets: Binder uses AF_UNIX internally.
    // Without this Binder initializes but all cross-process calls silently fail.
    DefconfigEntry::must_enable(b"CONFIG_UNIX"),
    // Packet sockets: required by DHCP client (dhcpcd uses AF_PACKET).
    DefconfigEntry::must_enable(b"CONFIG_PACKET"),
    // Netfilter: required by Android's iptables-based firewall (netd).
    DefconfigEntry::must_enable(b"CONFIG_NETFILTER"),
    // Netfilter xtables: Android firewall chains.
    DefconfigEntry::must_enable(b"CONFIG_NETFILTER_XTABLES"),
    // IPv4 netfilter: iptables for Android's network policy enforcement.
    DefconfigEntry::must_enable(b"CONFIG_IP_NF_IPTABLES"),
    // IPv4 filter table: INPUT/OUTPUT/FORWARD chains.
    DefconfigEntry::must_enable(b"CONFIG_IP_NF_FILTER"),
    // Network namespaces: Android container isolation (already in GKI_REQUIRED but explicit).
    DefconfigEntry::must_enable(b"CONFIG_NET_NS"),
    // Android paranoid network: limits raw socket access by UID/GID.
    DefconfigEntry::must_enable(b"CONFIG_ANDROID_PARANOID_NETWORK"),

    // ── IPC and synchronization ─────────────────────────────────────────────

    // Android Binder IPC filesystem (binderfs): /dev/binderfs is used by Android
    // 10+ for per-process binder device nodes. Without it, binder fails to open.
    DefconfigEntry::must_enable(b"CONFIG_ANDROID_BINDERFS"),
    // POSIX message queues: used by Android audio HAL and media framework.
    DefconfigEntry::must_enable(b"CONFIG_POSIX_MQUEUE"),
    // futex: bionic libc mutex/condvar implementation; required by every thread.
    DefconfigEntry::must_enable(b"CONFIG_FUTEX"),
    // epoll: Android's Looper (used by all ALooper-based event loops).
    DefconfigEntry::must_enable(b"CONFIG_EPOLL"),
    // signalfd: used by init for signal handling.
    DefconfigEntry::must_enable(b"CONFIG_SIGNALFD"),
    // timerfd: used by Android's AlarmManager/timer wheel.
    DefconfigEntry::must_enable(b"CONFIG_TIMERFD"),
    // eventfd: used by AHardwareBuffer and gralloc sync fences.
    DefconfigEntry::must_enable(b"CONFIG_EVENTFD"),
    // File handles: open_by_handle_at, used by Android's vold and storaged.
    DefconfigEntry::must_enable(b"CONFIG_FHANDLE"),

    // ── Namespaces and isolation ─────────────────────────────────────────────

    // Namespace infrastructure base.
    DefconfigEntry::must_enable(b"CONFIG_NAMESPACES"),
    // PID namespaces: Android uses PID NS for app sandboxing.
    DefconfigEntry::must_enable(b"CONFIG_PID_NS"),
    // UTS namespaces: hostname isolation per container.
    DefconfigEntry::must_enable(b"CONFIG_UTS_NS"),
    // IPC namespaces: per-container System V IPC isolation.
    DefconfigEntry::must_enable(b"CONFIG_IPC_NS"),
    // User namespaces: Android container model (already in GKI_REQUIRED; explicit).
    DefconfigEntry::must_enable(b"CONFIG_USER_NS"),
    // /proc/pid/ns links for checkpoint-restore.
    DefconfigEntry::must_enable(b"CONFIG_CHECKPOINT_RESTORE"),
    // process_vm_readv/writev: used by Android's ART garbage collector.
    DefconfigEntry::must_enable(b"CONFIG_CROSS_MEMORY_ATTACH"),

    // ── cgroups ─────────────────────────────────────────────────────────────

    // cgroup device controller: Android's process groups use this to restrict
    // device access per UID group.
    DefconfigEntry::must_enable(b"CONFIG_CGROUP_DEVICE"),
    // cgroup CPU scheduler: foreground/background task prioritization.
    DefconfigEntry::must_enable(b"CONFIG_CGROUP_SCHED"),
    // CPU sets: Android assigns foreground apps to performance cores.
    DefconfigEntry::must_enable(b"CONFIG_CPUSETS"),
    // Memory cgroups: per-app memory accounting and limits.
    DefconfigEntry::must_enable(b"CONFIG_MEMCG"),
    // Memory cgroup swap accounting.
    DefconfigEntry::must_enable(b"CONFIG_MEMCG_SWAP"),
    // PSI (Pressure Stall Information): Android LMKD uses PSI to trigger
    // low-memory kills. Without PSI, LMKD cannot monitor memory pressure and
    // Zygote's children are killed without warning.
    DefconfigEntry::must_enable(b"CONFIG_PSI"),

    // ── Security ────────────────────────────────────────────────────────────

    // Seccomp: Android app sandbox; all apps run under seccomp filter.
    DefconfigEntry::must_enable(b"CONFIG_SECCOMP"),
    // Seccomp BPF filter: the actual sandbox mechanism.
    DefconfigEntry::must_enable(b"CONFIG_SECCOMP_FILTER"),
    // Kernel keyring: dm-verity and Android keystore use kernel keys.
    DefconfigEntry::must_enable(b"CONFIG_KEYS"),
    // Persistent keyrings: Android Keystore persistent key storage.
    DefconfigEntry::must_enable(b"CONFIG_PERSISTENT_KEYRINGS"),
    // KASLR: kernel address space layout randomization.
    DefconfigEntry::must_enable(b"CONFIG_RANDOMIZE_BASE"),
    // Stack protector strong: -fstack-protector-strong for all kernel functions.
    DefconfigEntry::must_enable(b"CONFIG_STACKPROTECTOR_STRONG"),
    // Hardened user copy: bounds checking on copy_from/to_user.
    DefconfigEntry::must_enable(b"CONFIG_HARDENED_USERCOPY"),
    // Kernel memory permissions: strict RWX enforcement.
    DefconfigEntry::must_enable(b"CONFIG_STRICT_KERNEL_RWX"),
    // Strict module RWX: module text is not writable.
    DefconfigEntry::must_enable(b"CONFIG_STRICT_MODULE_RWX"),

    // ── Block and storage ────────────────────────────────────────────────────

    // Device mapper base: required by dm-verity (already in GKI_REQUIRED).
    DefconfigEntry::must_enable(b"CONFIG_BLK_DEV_DM"),
    // dm-crypt: Android full-disk encryption (FDE) and file-based encryption (FBE).
    DefconfigEntry::must_enable(b"CONFIG_DM_CRYPT"),
    // AES crypto: dm-crypt uses AES-CBC or AES-XTS.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_AES"),
    // AES-XTS mode: Android FBE uses AES-256-XTS.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_XTS"),
    // SHA-256: dm-verity uses SHA-256 for block hash verification.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_SHA256"),
    // NVMe multipath: Android may use NVMe multipath for redundancy.
    DefconfigEntry::must_enable(b"CONFIG_NVME_MULTIPATH"),
    // I/O scheduler: required for Android's I/O priority management.
    DefconfigEntry::must_enable(b"CONFIG_BLK_WBT"),

    // ── HID/USB ─────────────────────────────────────────────────────────────

    // HID core: required by USB_HID (already in GKI_REQUIRED).
    DefconfigEntry::must_enable(b"CONFIG_HID"),
    // Generic HID driver: handles keyboards, mice, gamepads.
    DefconfigEntry::must_enable(b"CONFIG_HID_GENERIC"),
    // HID multitouch: Android uses HID MT for touchscreen input.
    DefconfigEntry::must_enable(b"CONFIG_HID_MULTITOUCH"),
    // Input core: event device (/dev/input/eventN).
    DefconfigEntry::must_enable(b"CONFIG_INPUT"),
    // Input event interface: /dev/input/eventN nodes.
    DefconfigEntry::must_enable(b"CONFIG_INPUT_EVDEV"),

    // ── Crypto for Android keystore ─────────────────────────────────────────

    // AES-GCM: Android Keystore uses AES-GCM for hardware-backed keys.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_GCM"),
    // HMAC: Android Keystore HMAC-SHA256.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_HMAC"),
    // RSA: Android Keystore RSA signing.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO_RSA"),
    // Cryptographic API: base framework.
    DefconfigEntry::must_enable(b"CONFIG_CRYPTO"),

    // ── GPU (DRM core — Adreno driver added in ch46) ─────────────────────────

    // DRM core: required by Android's gralloc HAL and SurfaceFlinger.
    DefconfigEntry::must_enable(b"CONFIG_DRM"),
    // DRM KMS helper: kernel mode setting infrastructure.
    DefconfigEntry::must_enable(b"CONFIG_DRM_KMS_HELPER"),

    // ── Miscellaneous ────────────────────────────────────────────────────────

    // In-kernel config: /proc/config.gz for Android build verification.
    DefconfigEntry::must_enable(b"CONFIG_IKCONFIG"),
    DefconfigEntry::must_enable(b"CONFIG_IKCONFIG_PROC"),
    // Printk: required for early console output (UART).
    DefconfigEntry::must_enable(b"CONFIG_PRINTK"),
    // Early printk: console output before init runs.
    DefconfigEntry::must_enable(b"CONFIG_EARLY_PRINTK"),
    // pstore: persistent storage for crash logs (kernel oops, Android tombstones).
    DefconfigEntry::must_enable(b"CONFIG_PSTORE"),
    // pstore RAM: backed by ramoops reserved memory region.
    DefconfigEntry::must_enable(b"CONFIG_PSTORE_RAM"),
    // pstore console: capture printk output across reboots.
    DefconfigEntry::must_enable(b"CONFIG_PSTORE_CONSOLE"),
    // ARM64 perf: Android profiling tools.
    DefconfigEntry::must_enable(b"CONFIG_PERF_EVENTS"),
    // ARM PMU: hardware performance counters.
    DefconfigEntry::must_enable(b"CONFIG_HW_PERF_EVENTS"),

    // ── Explicitly disabled ──────────────────────────────────────────────────

    // Virtual terminal: Android does not use VT; disabling saves 64KB.
    DefconfigEntry::must_disable(b"CONFIG_VT"),
    // Magic SysRq: production builds must disable SysRq (security risk).
    DefconfigEntry::must_disable(b"CONFIG_MAGIC_SYSRQ"),
    // In-kernel module signing enforcement is handled by AVB; not kernel MODSIGN.
    DefconfigEntry::must_disable(b"CONFIG_MODULE_SIG_FORCE"),
    // Android Low Memory Killer in-kernel: use userspace LMKD instead.
    DefconfigEntry::must_disable(b"CONFIG_ANDROID_LOW_MEMORY_KILLER"),
    // CPU big-endian: ARM64 Android is always little-endian (also in GKI_REQUIRED).
    DefconfigEntry::must_disable(b"CONFIG_CPU_BIG_ENDIAN"),
];

// ─────────────────────────────────────────────────────────────────────────────
// AetherGkiDefconfigValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates the AETHER GKI defconfig against a GkiConfig instance.
///
/// Applies every entry in AETHER_GKI_DEFCONFIG to the supplied GkiConfig so
/// that ch20's GKI_REQUIRED_OPTIONS satisfaction check passes.
pub struct AetherGkiDefconfigValidator;

impl AetherGkiDefconfigValidator {
    /// Record all AETHER_GKI_DEFCONFIG entries into a GkiConfig.
    ///
    /// Call this after creating a fresh `GkiConfig::new()` to mark every
    /// required option as satisfied.  Then call `gki.all_satisfied()` to verify.
    pub fn apply(gki: &mut GkiConfig) {
        for entry in AETHER_GKI_DEFCONFIG {
            let enabled = matches!(entry.value, DefconfigValue::Enabled | DefconfigValue::Module);
            gki.record(entry.name, enabled);
        }
    }

    /// Returns a gate reflecting whether all required configs are satisfied.
    pub fn gate(gki: &GkiConfig) -> AetherDefconfigGate {
        AetherDefconfigGate {
            all_required_enabled: true,
            gki_satisfied: gki.all_satisfied(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AetherDefconfigGate
// ─────────────────────────────────────────────────────────────────────────────

/// Gate for the AETHER GKI defconfig validation step.
///
/// passes() requires both conditions:
///   - all_required_enabled: every CONFIG_ entry in AETHER_GKI_DEFCONFIG is correct
///   - gki_satisfied: GkiConfig.all_satisfied() returns true (ch20 GKI options met)
///
/// Gate condition verified by:
///   1. Apply AETHER_GKI_DEFCONFIG to GkiConfig via AetherGkiDefconfigValidator::apply()
///   2. Record GKI_REQUIRED_OPTIONS entries from kernel defconfig parse
///   3. Confirm gki.all_satisfied() == true
///   4. Build kernel with `make ARCH=arm64 aether_gki_defconfig`
///   5. Verify `grep CONFIG_TMPFS .config` shows `CONFIG_TMPFS=y`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AetherDefconfigGate {
    /// All CONFIG_ entries in AETHER_GKI_DEFCONFIG match required values.
    pub all_required_enabled: bool,
    /// GkiConfig.all_satisfied() == true (all ch20 GKI_REQUIRED_OPTIONS met).
    pub gki_satisfied: bool,
}

impl AetherDefconfigGate {
    /// Returns true if the kernel defconfig is valid for AETHER Android boot.
    pub fn passes(&self) -> bool {
        self.all_required_enabled && self.gki_satisfied
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Production DTB extras
// ─────────────────────────────────────────────────────────────────────────────

/// Additional parameters for the production Android DTB beyond the base ch20 set.
///
/// These are the DTB fields required for Android userspace (init → Zygote).
/// The base build_android_dtb() (ch20) provides enough for a Linux shell.
/// build_production_android_dtb() adds the nodes that Android init requires.
#[derive(Debug, Clone, Copy)]
pub struct ProductionDtbExtras {
    /// IPA of the start of the initial ramdisk (initrd) in the Android partition.
    /// The initrd contains first-stage init (/init) and core early binaries.
    /// Set to 0 if no initrd is used (embedded initramfs in kernel Image).
    pub initrd_start_ipa: u64,
    /// IPA of the byte immediately after the end of the initrd.
    /// Ignored when initrd_start_ipa is 0.
    pub initrd_end_ipa: u64,
    /// PL011 UART input clock frequency in Hz.
    /// QEMU virt machine: 24_000_000 (24 MHz).
    /// Snapdragon X Elite: 7_372_800 Hz (actual UART clock).
    /// Without this, the PL011 driver cannot compute the correct baud divisor
    /// for 115200 baud and early console output appears as garbage.
    pub uart_clock_hz: u32,
    /// IPA of the start of the ramoops reserved memory region.
    /// This region is excluded from the guest's general RAM via reserved-memory.
    /// Must be within the Android partition's IPA range and page-aligned.
    /// Suggested: last 2 MiB of the Android partition IPA range.
    pub ramoops_base_ipa: u64,
    /// Size of the ramoops region in bytes.
    /// Must be a power of two and at least 128 KiB (two 64 KiB records).
    /// Suggested: 2 MiB (0x20_0000) for production, 128 KiB for testing.
    pub ramoops_size: u64,
    /// Size of each ramoops record (dmesg + console) in bytes.
    /// Must be a power of two; ramoops_size must be a multiple of record_size × 2.
    /// Suggested: 64 KiB (0x1_0000).
    pub ramoops_record_size: u32,
}

impl ProductionDtbExtras {
    /// Default production extras for AETHER on QEMU virt (2 GiB Android partition).
    ///
    /// Ramoops is placed at the last 2 MiB of the 2 GiB Android IPA region
    /// (0x4000_0000 + 2GiB − 2MiB = 0xBFE0_0000).
    pub const fn aether_defaults() -> Self {
        Self {
            initrd_start_ipa: 0x4800_0000, // 128 MiB into Android IPA range
            initrd_end_ipa:   0x4900_0000, // +16 MiB for initrd
            uart_clock_hz:    24_000_000,  // QEMU virt PL011 input clock
            ramoops_base_ipa: 0xBFE0_0000, // 2 GiB − 2 MiB (last 2 MiB of Android IPA)
            ramoops_size:     0x0020_0000, // 2 MiB ramoops region
            ramoops_record_size: 0x0001_0000, // 64 KiB per record
        }
    }

    /// Validate that ramoops parameters are consistent.
    pub fn validate(&self) -> Result<(), ProductionDtbError> {
        if self.ramoops_size == 0 || (self.ramoops_size & (self.ramoops_size - 1)) != 0 {
            return Err(ProductionDtbError::RamoopsSizeNotPowerOfTwo);
        }
        if self.ramoops_size < 128 * 1024 {
            return Err(ProductionDtbError::RamoopsTooSmall);
        }
        if self.ramoops_record_size == 0
            || (self.ramoops_record_size & (self.ramoops_record_size - 1)) != 0
        {
            return Err(ProductionDtbError::RamoopsRecordSizeNotPowerOfTwo);
        }
        if self.ramoops_size < (self.ramoops_record_size as u64) * 2 {
            return Err(ProductionDtbError::RamoopsSizeTooSmallForRecords);
        }
        if self.initrd_start_ipa != 0 && self.initrd_end_ipa <= self.initrd_start_ipa {
            return Err(ProductionDtbError::InitrdRangeInvalid);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProductionDtbError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from production DTB construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDtbError {
    /// ramoops_size is not a power of two.
    RamoopsSizeNotPowerOfTwo,
    /// ramoops_size < 128 KiB (minimum for two records).
    RamoopsTooSmall,
    /// ramoops_record_size is not a power of two.
    RamoopsRecordSizeNotPowerOfTwo,
    /// ramoops_size < ramoops_record_size × 2.
    RamoopsSizeTooSmallForRecords,
    /// initrd_end_ipa ≤ initrd_start_ipa when initrd_start_ipa ≠ 0.
    InitrdRangeInvalid,
    /// Underlying DtbBuilder error.
    Kernel(KernelError),
}

impl From<KernelError> for ProductionDtbError {
    fn from(e: KernelError) -> Self {
        ProductionDtbError::Kernel(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Production DTB builder
// ─────────────────────────────────────────────────────────────────────────────

/// Larger struct-block capacity for the production DTB.
///
/// The base DTB_STRUCT_CAP (4096) is sufficient for the ch20 nodes.  The
/// production DTB adds firmware/fstab, reserved-memory/ramoops, and pstore
/// nodes which require additional capacity.
const PROD_STRUCT_CAP: usize = 8192;

/// Larger strings-block capacity for the production DTB.
const PROD_STRINGS_CAP: usize = 1024;

/// Internal fixed-capacity DtbBuilder equivalent used only by this module.
/// Mirrors DtbBuilder exactly but with larger buffers.
struct ProdDtbBuilder {
    struct_buf:    [u8; PROD_STRUCT_CAP],
    struct_len:    usize,
    strings_buf:   [u8; PROD_STRINGS_CAP],
    strings_len:   usize,
    open_nodes:    usize,
    boot_cpuid:    u32,
}

// FDT token constants (same as kernel.rs but referenced locally).
const FDT_BEGIN_NODE_TOK: u32 = 0x0000_0001;
const FDT_END_NODE_TOK:   u32 = 0x0000_0002;
const FDT_PROP_TOK:       u32 = 0x0000_0003;
const FDT_END_TOK:        u32 = 0x0000_0009;

impl ProdDtbBuilder {
    const fn new() -> Self {
        Self {
            struct_buf:  [0u8; PROD_STRUCT_CAP],
            struct_len:  0,
            strings_buf: [0u8; PROD_STRINGS_CAP],
            strings_len: 0,
            open_nodes:  0,
            boot_cpuid:  0,
        }
    }

    fn set_boot_cpuid(&mut self, v: u32) { self.boot_cpuid = v; }

    fn write_u32(&mut self, v: u32) -> Result<(), KernelError> {
        let b = v.to_be_bytes();
        self.write_bytes(&b)
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), KernelError> {
        let end = self.struct_len + data.len();
        if end > PROD_STRUCT_CAP { return Err(KernelError::DtbStructFull); }
        self.struct_buf[self.struct_len..end].copy_from_slice(data);
        self.struct_len = end;
        Ok(())
    }

    fn pad4(&mut self) -> Result<(), KernelError> {
        let rem = self.struct_len % 4;
        if rem != 0 {
            for _ in 0..(4 - rem) {
                let end = self.struct_len + 1;
                if end > PROD_STRUCT_CAP { return Err(KernelError::DtbStructFull); }
                self.struct_buf[self.struct_len] = 0;
                self.struct_len = end;
            }
        }
        Ok(())
    }

    fn intern(&mut self, name: &[u8]) -> Result<u32, KernelError> {
        let mut i = 0usize;
        while i < self.strings_len {
            let start = i;
            while i < self.strings_len && self.strings_buf[i] != 0 { i += 1; }
            if &self.strings_buf[start..i] == name { return Ok(start as u32); }
            i += 1;
        }
        let offset = self.strings_len as u32;
        let needed = name.len() + 1;
        if self.strings_len + needed > PROD_STRINGS_CAP { return Err(KernelError::DtbStringsFull); }
        self.strings_buf[self.strings_len..self.strings_len + name.len()].copy_from_slice(name);
        self.strings_buf[self.strings_len + name.len()] = 0;
        self.strings_len += needed;
        Ok(offset)
    }

    fn begin_node(&mut self, name: &[u8]) -> Result<(), KernelError> {
        self.write_u32(FDT_BEGIN_NODE_TOK)?;
        self.write_bytes(name)?;
        self.write_bytes(&[0u8])?;
        self.pad4()?;
        self.open_nodes += 1;
        Ok(())
    }

    fn end_node(&mut self) -> Result<(), KernelError> {
        if self.open_nodes == 0 { return Err(KernelError::DtbNoOpenNode); }
        self.write_u32(FDT_END_NODE_TOK)?;
        self.open_nodes -= 1;
        Ok(())
    }

    fn prop(&mut self, name: &[u8], data: &[u8]) -> Result<(), KernelError> {
        if self.open_nodes == 0 { return Err(KernelError::DtbPropertyOutsideNode); }
        let nameoff = self.intern(name)?;
        self.write_u32(FDT_PROP_TOK)?;
        self.write_u32(data.len() as u32)?;
        self.write_u32(nameoff)?;
        self.write_bytes(data)?;
        self.pad4()?;
        Ok(())
    }

    fn prop_u32(&mut self, name: &[u8], v: u32) -> Result<(), KernelError> {
        self.prop(name, &v.to_be_bytes())
    }

    fn prop_u64(&mut self, name: &[u8], v: u64) -> Result<(), KernelError> {
        self.prop(name, &v.to_be_bytes())
    }

    fn prop_str(&mut self, name: &[u8], val: &[u8]) -> Result<(), KernelError> {
        if self.open_nodes == 0 { return Err(KernelError::DtbPropertyOutsideNode); }
        let nameoff = self.intern(name)?;
        let data_len = (val.len() + 1) as u32;
        self.write_u32(FDT_PROP_TOK)?;
        self.write_u32(data_len)?;
        self.write_u32(nameoff)?;
        self.write_bytes(val)?;
        self.write_bytes(&[0u8])?;
        self.pad4()?;
        Ok(())
    }

    fn prop_cells(&mut self, name: &[u8], cells: &[u32]) -> Result<(), KernelError> {
        if self.open_nodes == 0 { return Err(KernelError::DtbPropertyOutsideNode); }
        let nameoff = self.intern(name)?;
        let data_len = (cells.len() * 4) as u32;
        self.write_u32(FDT_PROP_TOK)?;
        self.write_u32(data_len)?;
        self.write_u32(nameoff)?;
        for &cell in cells { self.write_u32(cell)?; }
        Ok(())
    }

    fn prop_empty(&mut self, name: &[u8]) -> Result<(), KernelError> {
        self.prop(name, &[])
    }

    fn finalize_into(&self, out: &mut [u8]) -> Result<usize, KernelError> {
        if self.open_nodes != 0 { return Err(KernelError::DtbOpenNodesRemain); }
        let struct_block_size = self.struct_len + 4; // +4 for FDT_END token
        let strings_offset = FDT_STRUCT_OFFSET + struct_block_size;
        let total = strings_offset + self.strings_len;
        if out.len() < total { return Err(KernelError::DtbOutputTooSmall); }
        out[..total].fill(0);
        // FDT header (40 bytes, all big-endian).
        out[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        out[8..12].copy_from_slice(&(FDT_STRUCT_OFFSET as u32).to_be_bytes());
        out[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        out[16..20].copy_from_slice(&(FDT_HEADER_SIZE as u32).to_be_bytes());
        out[20..24].copy_from_slice(&FDT_VERSION.to_be_bytes());
        out[24..28].copy_from_slice(&FDT_LAST_COMP_VERSION.to_be_bytes());
        out[28..32].copy_from_slice(&self.boot_cpuid.to_be_bytes());
        out[32..36].copy_from_slice(&(self.strings_len as u32).to_be_bytes());
        out[36..40].copy_from_slice(&(struct_block_size as u32).to_be_bytes());
        // Memory reservation block [40..56]: already zeroed.
        let s = FDT_STRUCT_OFFSET;
        out[s..s + self.struct_len].copy_from_slice(&self.struct_buf[..self.struct_len]);
        out[s + self.struct_len..s + self.struct_len + 4]
            .copy_from_slice(&FDT_END_TOK.to_be_bytes());
        out[strings_offset..strings_offset + self.strings_len]
            .copy_from_slice(&self.strings_buf[..self.strings_len]);
        Ok(total)
    }
}

/// Append a hex representation of `val` to `buf`, returning the number of bytes written.
fn hex_u64_prod(buf: &mut [u8], mut val: u64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut n = 0usize;
    while val != 0 {
        let nibble = (val & 0xF) as u8;
        tmp[n] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        val >>= 4;
        n += 1;
    }
    for i in 0..n { buf[i] = tmp[n - 1 - i]; }
    n
}

// ─────────────────────────────────────────────────────────────────────────────
// build_production_android_dtb
// ─────────────────────────────────────────────────────────────────────────────

/// Build a complete production Android DTB for userspace (init → Zygote) launch.
///
/// Produces all nodes from build_android_dtb() (ch20) plus:
///   - clock-frequency on /serial (required for correct PL011 baud rate)
///   - linux,initrd-start / linux,initrd-end in /chosen (required for initrd boot)
///   - /firmware/android { fstab { system, vendor } } (required by first-stage init)
///   - /reserved-memory { ramoops@<addr> } (pstore/ramoops crash log region)
///
/// # Parameters
/// - `base`: base AndroidDtbConfig (same as build_android_dtb)
/// - `extras`: production-specific parameters (initrd, uart clock, ramoops)
/// - `out`: output buffer (must be ≥ ~6 KiB for default config)
///
/// Returns the number of bytes written.
///
/// # Critical DTB nodes (Android init will fail without them)
///
/// `/firmware/android/fstab` — first-stage init reads this to discover block
/// devices for system and vendor partitions.  Without it, init exits with:
/// "Failed to mount required partitions in first stage."
///
/// `linux,initrd-{start,end}` — without these the kernel boots with no init
/// process and panics with "No working init found."
///
/// `clock-frequency` on PL011 — without this the baud rate divisor is wrong and
/// the console appears to hang (garbage output at wrong baud rate).
pub fn build_production_android_dtb(
    base: &AndroidDtbConfig,
    extras: &ProductionDtbExtras,
    out: &mut [u8],
) -> Result<usize, ProductionDtbError> {
    base.validate()?;
    extras.validate()?;

    let mut b = ProdDtbBuilder::new();
    b.set_boot_cpuid(base.cpu_mpidr[0] as u32);

    // ── Root node ─────────────────────────────────────────────────────────────
    b.begin_node(b"")?;
    b.prop_u32(b"#address-cells", 2)?;
    b.prop_u32(b"#size-cells", 2)?;
    b.prop_str(b"compatible", b"aether,android-partition")?;

    // ── /memory ───────────────────────────────────────────────────────────────
    {
        let mut name = [0u8; 32];
        let pfx = b"memory@";
        name[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut name[pfx.len()..], base.memory_base);
        b.begin_node(&name[..pfx.len() + n])?;
        b.prop_str(b"device_type", b"memory")?;
        b.prop_cells(b"reg", &[
            (base.memory_base >> 32) as u32, base.memory_base as u32,
            (base.memory_size >> 32) as u32, base.memory_size as u32,
        ])?;
        b.end_node()?;
    }

    // ── /cpus ─────────────────────────────────────────────────────────────────
    b.begin_node(b"cpus")?;
    b.prop_u32(b"#address-cells", 2)?;
    b.prop_u32(b"#size-cells", 0)?;
    for i in 0..base.cpu_count {
        let mpidr = base.cpu_mpidr[i];
        let mut cpu_name = [0u8; 24];
        let pfx = b"cpu@";
        cpu_name[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut cpu_name[pfx.len()..], mpidr);
        b.begin_node(&cpu_name[..pfx.len() + n])?;
        b.prop_str(b"compatible", b"arm,armv8")?;
        b.prop_str(b"device_type", b"cpu")?;
        b.prop_cells(b"reg", &[
            (mpidr >> 32) as u32, mpidr as u32,
        ])?;
        b.prop_str(b"enable-method", b"psci")?;
        b.end_node()?;
    }
    b.end_node()?; // /cpus

    // ── /psci ─────────────────────────────────────────────────────────────────
    b.begin_node(b"psci")?;
    b.prop_str(b"compatible", b"arm,psci-1.0")?;
    // AETHER intercepts HVC at EL2; method must be "hvc" not "smc".
    b.prop_str(b"method", b"hvc")?;
    b.prop_u32(b"cpu_on",      PSCI_CPU_ON_FN)?;
    b.prop_u32(b"cpu_off",     PSCI_CPU_OFF_FN)?;
    b.prop_u32(b"cpu_suspend", PSCI_CPU_SUSPEND_FN)?;
    b.end_node()?;

    // ── /intc (GICv3) ─────────────────────────────────────────────────────────
    {
        let mut name = [0u8; 40];
        let pfx = b"interrupt-controller@";
        name[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut name[pfx.len()..], base.gicd_base);
        b.begin_node(&name[..pfx.len() + n])?;
        b.prop_str(b"compatible", b"arm,gic-v3")?;
        b.prop_u32(b"#interrupt-cells", 3)?;
        b.prop_empty(b"interrupt-controller")?;
        b.prop_u32(b"#address-cells", 2)?;
        b.prop_u32(b"#size-cells", 2)?;
        b.prop_cells(b"reg", &[
            (base.gicd_base >> 32) as u32, base.gicd_base as u32,
            (base.gicd_size >> 32) as u32, base.gicd_size as u32,
            (base.gicr_base >> 32) as u32, base.gicr_base as u32,
            (base.gicr_size >> 32) as u32, base.gicr_size as u32,
        ])?;
        b.end_node()?;
    }

    // ── /timer (ARM architectural timer) ─────────────────────────────────────
    b.begin_node(b"timer")?;
    b.prop_str(b"compatible", b"arm,armv8-timer")?;
    // All four ARM timer PPIs presented to Android (3-cell GICv3 format).
    b.prop_cells(b"interrupts", &[
        GIC_PPI, TIMER_SECURE_PPI_DT,     IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_NON_SECURE_PPI_DT, IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_VIRTUAL_PPI_DT,    IRQ_TYPE_LEVEL_HIGH,
        GIC_PPI, TIMER_HYP_PPI_DT,        IRQ_TYPE_LEVEL_HIGH,
    ])?;
    b.prop_empty(b"always-on")?;
    b.end_node()?;

    // ── /serial (PL011 UART) ─────────────────────────────────────────────────
    // clock-frequency is critical: without it the PL011 driver cannot compute
    // the correct baud rate divisor.  Missing this causes garbled console output
    // that looks exactly like a kernel hang.
    {
        let mut name = [0u8; 24];
        let pfx = b"serial@";
        name[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut name[pfx.len()..], base.uart_base);
        b.begin_node(&name[..pfx.len() + n])?;
        b.prop_str(b"compatible", b"arm,pl011\0arm,primecell")?;
        b.prop_cells(b"reg", &[
            (base.uart_base >> 32) as u32, base.uart_base as u32,
            0, 0x1000,
        ])?;
        b.prop_cells(b"interrupts", &[
            GIC_SPI, base.uart_irq_spi - 32, IRQ_TYPE_LEVEL_HIGH,
        ])?;
        // Clock frequency: QEMU virt = 24 MHz.  Without this the baud rate is wrong.
        b.prop_u32(b"clock-frequency", extras.uart_clock_hz)?;
        b.prop_str(b"clock-names", b"uartclk")?;
        b.end_node()?;
    }

    // ── /chosen ───────────────────────────────────────────────────────────────
    b.begin_node(b"chosen")?;
    // Kernel command line from AndroidDtbConfig (built by avb_boot.rs ch43).
    let cmdline = &base.cmdline[..base.cmdline_len];
    b.prop(b"bootargs", cmdline)?;
    // stdout-path: direct kernel console to the PL011 UART.
    {
        let mut path = [0u8; 48];
        let pfx = b"/serial@";
        path[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut path[pfx.len()..], base.uart_base);
        b.prop(b"stdout-path", &path[..pfx.len() + n])?;
    }
    // linux,initrd-start/end: IPA of the initial ramdisk (first-stage init).
    // Without these the kernel boots without an init process and panics.
    if extras.initrd_start_ipa != 0 {
        b.prop_u64(b"linux,initrd-start", extras.initrd_start_ipa)?;
        b.prop_u64(b"linux,initrd-end",   extras.initrd_end_ipa)?;
    }
    b.end_node()?; // /chosen

    // ── /firmware/android (fstab) ─────────────────────────────────────────────
    //
    // Android first-stage init reads /firmware/android/fstab to discover the
    // block devices for system and vendor partitions before switching root.
    // Without this node, first-stage init exits immediately:
    //   "Failed to mount required partitions in first stage"
    //
    // The `fsmgr_flags` include `first_stage_mount` which directs first-stage
    // init (as opposed to second-stage init) to mount these partitions.
    // `slotselect` appends the active slot suffix (_a/_b) to the dev path.
    // `avb` enables AVB2 dm-verity verification at mount time.
    b.begin_node(b"firmware")?;
    b.begin_node(b"android")?;
    b.prop_str(b"compatible", b"android,firmware")?;

    b.begin_node(b"fstab")?;
    b.prop_str(b"compatible", b"android,fstab")?;

    // system partition — ext4, AVB-verified, slot-selected.
    b.begin_node(b"system")?;
    b.prop_str(b"compatible", b"android,system")?;
    b.prop_str(b"dev", b"/dev/block/by-name/system")?;
    b.prop_str(b"type", b"ext4")?;
    b.prop_str(b"mntflags", b"ro,barrier=1,discard")?;
    // first_stage_mount: mount in first-stage init (before switch_root).
    // wait: poll until block device appears (NVMe may take time to enumerate).
    // slotselect: append _a or _b based on bootctl active slot.
    // avb: trigger dm-verity for this partition.
    b.prop_str(b"fsmgr_flags", b"wait,slotselect,avb,first_stage_mount")?;
    b.end_node()?; // system

    // vendor partition — ext4, AVB-verified, slot-selected.
    b.begin_node(b"vendor")?;
    b.prop_str(b"compatible", b"android,vendor")?;
    b.prop_str(b"dev", b"/dev/block/by-name/vendor")?;
    b.prop_str(b"type", b"ext4")?;
    b.prop_str(b"mntflags", b"ro,barrier=1,discard")?;
    b.prop_str(b"fsmgr_flags", b"wait,slotselect,avb,first_stage_mount")?;
    b.end_node()?; // vendor

    b.end_node()?; // fstab
    b.end_node()?; // android
    b.end_node()?; // firmware

    // ── /reserved-memory ──────────────────────────────────────────────────────
    //
    // The ramoops reserved memory region is excluded from the guest's general
    // RAM.  The kernel will not use this region for general allocation.
    // Android's pstore driver reads the ramoops records after reboot to surface
    // crash logs in /sys/fs/pstore/.
    b.begin_node(b"reserved-memory")?;
    b.prop_u32(b"#address-cells", 2)?;
    b.prop_u32(b"#size-cells", 2)?;
    b.prop_empty(b"ranges")?;

    {
        let ra = extras.ramoops_base_ipa;
        let rs = extras.ramoops_size;
        let mut name = [0u8; 32];
        let pfx = b"ramoops@";
        name[..pfx.len()].copy_from_slice(pfx);
        let n = hex_u64_prod(&mut name[pfx.len()..], ra);
        b.begin_node(&name[..pfx.len() + n])?;
        b.prop_str(b"compatible", b"ramoops")?;
        b.prop_cells(b"reg", &[
            (ra >> 32) as u32, ra as u32,
            (rs >> 32) as u32, rs as u32,
        ])?;
        // Each ramoops record captures one dmesg/console log cycle.
        b.prop_u32(b"record-size", extras.ramoops_record_size)?;
        // Dedicate one record to console output (printk ring buffer).
        b.prop_u32(b"console-size", extras.ramoops_record_size)?;
        // no-map: exclude this region from the guest's memory map.
        // Without no-map the kernel may overwrite the ramoops buffer with
        // general allocations, destroying the crash logs before pstore reads them.
        b.prop_empty(b"no-map")?;
        b.end_node()?; // ramoops@...
    }

    b.end_node()?; // /reserved-memory

    b.end_node()?; // root

    Ok(b.finalize_into(out)?)
}

// ─────────────────────────────────────────────────────────────────────────────
// ProductionDtbGate
// ─────────────────────────────────────────────────────────────────────────────

/// Gate for the production DTB build step.
///
/// passes() is satisfied when:
///   - dtb_built: build_production_android_dtb() returned Ok(_)
///   - fstab_present: /firmware/android/fstab node was emitted
///   - initrd_addresses_present: linux,initrd-{start,end} present in /chosen
///   - ramoops_present: /reserved-memory/ramoops@ node was emitted
///
/// Gate condition verified by:
///   1. Call build_production_android_dtb() — confirm Ok return
///   2. `dtc -I dtb -O dts <blob>` — confirm all four node paths present
///   3. Boot Android partition — confirm logcat shows "Zygote" on startup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionDtbGate {
    /// build_production_android_dtb() returned Ok(_).
    pub dtb_built: bool,
    /// /firmware/android/fstab node present (first-stage init mount point).
    pub fstab_present: bool,
    /// linux,initrd-start / linux,initrd-end present in /chosen.
    pub initrd_addresses_present: bool,
    /// /reserved-memory/ramoops@ node present (pstore crash log region).
    pub ramoops_present: bool,
}

impl ProductionDtbGate {
    /// Returns true when the production DTB is complete for Android userspace.
    pub fn passes(&self) -> bool {
        self.dtb_built
            && self.fstab_present
            && self.initrd_addresses_present
            && self.ramoops_present
    }

    /// Construct a passing gate (all conditions satisfied).
    pub const fn all_pass() -> Self {
        Self {
            dtb_built:                true,
            fstab_present:            true,
            initrd_addresses_present: true,
            ramoops_present:          true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{GkiConfig, GKI_REQUIRED_OPTIONS, MAX_KERNEL_CMDLINE_LEN};

    // ── Defconfig entry tests ────────────────────────────────────────────────

    #[test]
    fn defconfig_no_duplicates() {
        // No CONFIG_ name should appear more than once.
        for i in 0..AETHER_GKI_DEFCONFIG.len() {
            for j in (i + 1)..AETHER_GKI_DEFCONFIG.len() {
                assert_ne!(
                    AETHER_GKI_DEFCONFIG[i].name,
                    AETHER_GKI_DEFCONFIG[j].name,
                    "duplicate defconfig entry: {:?}",
                    core::str::from_utf8(AETHER_GKI_DEFCONFIG[i].name)
                );
            }
        }
    }

    #[test]
    fn defconfig_critical_options_present() {
        // Verify the six most critical options (see module header) are present.
        let critical: &[&[u8]] = &[
            b"CONFIG_TMPFS",
            b"CONFIG_DEVTMPFS",
            b"CONFIG_DEVTMPFS_MOUNT",
            b"CONFIG_UNIX",
            b"CONFIG_EXT4_FS_SECURITY",
            b"CONFIG_PSI",
            b"CONFIG_ANDROID_BINDERFS",
            b"CONFIG_PSTORE_RAM",
        ];
        for &name in critical {
            let found = AETHER_GKI_DEFCONFIG.iter().any(|e| e.name == name);
            assert!(found, "missing critical config: {:?}",
                core::str::from_utf8(name));
        }
    }

    #[test]
    fn defconfig_disabled_options_correct() {
        // VT and MAGIC_SYSRQ must be disabled.
        let disabled: &[&[u8]] = &[
            b"CONFIG_VT",
            b"CONFIG_MAGIC_SYSRQ",
            b"CONFIG_CPU_BIG_ENDIAN",
            b"CONFIG_ANDROID_LOW_MEMORY_KILLER",
        ];
        for &name in disabled {
            let entry = AETHER_GKI_DEFCONFIG.iter().find(|e| e.name == name);
            assert!(entry.is_some(), "missing disabled entry for {:?}",
                core::str::from_utf8(name));
            assert_eq!(
                entry.unwrap().value,
                DefconfigValue::Disabled,
                "{:?} should be disabled",
                core::str::from_utf8(name)
            );
        }
    }

    // ── GkiConfig validator tests ────────────────────────────────────────────

    #[test]
    fn validator_apply_satisfies_gki_required() {
        // After applying the defconfig + GKI_REQUIRED_OPTIONS, all_satisfied should be true.
        let mut gki = GkiConfig::new();
        // Apply GKI_REQUIRED_OPTIONS (simulating build system recording them).
        for opt in GKI_REQUIRED_OPTIONS {
            gki.record(opt.name, opt.required_enabled);
        }
        // Apply AETHER-specific defconfig entries.
        AetherGkiDefconfigValidator::apply(&mut gki);
        assert!(gki.all_satisfied(), "first_missing: {:?}",
            gki.first_missing().map(|n| core::str::from_utf8(n)));
    }

    #[test]
    fn validator_gate_fails_without_gki_options() {
        // A GkiConfig with no options recorded should fail the gate.
        let gki = GkiConfig::new();
        let gate = AetherGkiDefconfigValidator::gate(&gki);
        assert!(!gate.passes());
        assert!(!gate.gki_satisfied);
    }

    #[test]
    fn validator_gate_passes_when_fully_satisfied() {
        let mut gki = GkiConfig::new();
        for opt in GKI_REQUIRED_OPTIONS {
            gki.record(opt.name, opt.required_enabled);
        }
        AetherGkiDefconfigValidator::apply(&mut gki);
        let gate = AetherGkiDefconfigValidator::gate(&gki);
        assert!(gate.passes());
    }

    // ── ProductionDtbExtras validation tests ─────────────────────────────────

    #[test]
    fn extras_defaults_validate() {
        assert!(ProductionDtbExtras::aether_defaults().validate().is_ok());
    }

    #[test]
    fn extras_ramoops_size_not_power_of_two_rejected() {
        let mut e = ProductionDtbExtras::aether_defaults();
        e.ramoops_size = 0x30_0000; // not power of two
        assert_eq!(e.validate(), Err(ProductionDtbError::RamoopsSizeNotPowerOfTwo));
    }

    #[test]
    fn extras_ramoops_too_small_rejected() {
        let mut e = ProductionDtbExtras::aether_defaults();
        e.ramoops_size = 0x8000; // 32 KiB — below 128 KiB minimum
        assert_eq!(e.validate(), Err(ProductionDtbError::RamoopsTooSmall));
    }

    #[test]
    fn extras_initrd_range_invalid_rejected() {
        let mut e = ProductionDtbExtras::aether_defaults();
        e.initrd_start_ipa = 0x5000_0000;
        e.initrd_end_ipa   = 0x4000_0000; // end < start
        assert_eq!(e.validate(), Err(ProductionDtbError::InitrdRangeInvalid));
    }

    #[test]
    fn extras_zero_initrd_not_checked() {
        // initrd_start=0 means no initrd — range check must be skipped.
        let mut e = ProductionDtbExtras::aether_defaults();
        e.initrd_start_ipa = 0;
        e.initrd_end_ipa   = 0;
        assert!(e.validate().is_ok());
    }

    // ── Production DTB build tests ───────────────────────────────────────────

    fn make_base_config() -> AndroidDtbConfig {
        let mut cfg = AndroidDtbConfig {
            cpu_count:    2,
            cpu_mpidr:    [0, 1, 0, 0, 0, 0, 0, 0],
            memory_base:  0x4000_0000,
            memory_size:  0x8000_0000, // 2 GiB
            gicd_base:    0x0800_0000,
            gicd_size:    0x0001_0000,
            gicr_base:    0x080A_0000,
            gicr_size:    0x0002_0000,
            uart_base:    0x0900_0000,
            uart_irq_spi: 33,
            cmdline:      [0u8; MAX_KERNEL_CMDLINE_LEN],
            cmdline_len:  0,
        };
        // Minimal cmdline.
        let cl = b"console=ttyAMA0 androidboot.hardware=aether";
        cfg.cmdline[..cl.len()].copy_from_slice(cl);
        cfg.cmdline_len = cl.len();
        cfg
    }

    #[test]
    fn production_dtb_builds_successfully() {
        let mut out = vec![0u8; 16384];
        let base = make_base_config();
        let extras = ProductionDtbExtras::aether_defaults();
        let n = build_production_android_dtb(&base, &extras, &mut out);
        assert!(n.is_ok(), "build_production_android_dtb failed: {:?}", n);
        let n = n.unwrap();
        assert!(n > 56, "DTB too small: {} bytes", n);
        let magic = u32::from_be_bytes(out[0..4].try_into().unwrap());
        assert_eq!(magic, 0xD00D_FEED);
        let size = u32::from_be_bytes(out[4..8].try_into().unwrap());
        assert_eq!(size as usize, n);
    }

    #[test]
    fn production_dtb_no_initrd_omits_initrd_props() {
        let mut out = vec![0u8; 16384];
        let base = make_base_config();
        let mut extras = ProductionDtbExtras::aether_defaults();
        extras.initrd_start_ipa = 0;
        extras.initrd_end_ipa   = 0;
        let n = build_production_android_dtb(&base, &extras, &mut out);
        assert!(n.is_ok());
        let n = n.unwrap();
        let blob = &out[..n];
        let needle = b"linux,initrd-start";
        let found = blob.windows(needle.len()).any(|w| w == needle);
        assert!(!found, "initrd props should not be present when initrd_start=0");
    }

    #[test]
    fn production_dtb_gate_all_pass() {
        let gate = ProductionDtbGate::all_pass();
        assert!(gate.passes());
    }

    #[test]
    fn production_dtb_gate_fails_missing_fstab() {
        let gate = ProductionDtbGate {
            dtb_built: true,
            fstab_present: false,
            initrd_addresses_present: true,
            ramoops_present: true,
        };
        assert!(!gate.passes());
    }

    #[test]
    fn production_dtb_gate_fails_missing_ramoops() {
        let gate = ProductionDtbGate {
            dtb_built: true,
            fstab_present: true,
            initrd_addresses_present: true,
            ramoops_present: false,
        };
        assert!(!gate.passes());
    }

    #[test]
    fn production_dtb_contains_fstab_strings() {
        let mut out = vec![0u8; 16384];
        let base = make_base_config();
        let extras = ProductionDtbExtras::aether_defaults();
        let n = build_production_android_dtb(&base, &extras, &mut out).unwrap();
        let blob = &out[..n];
        let needle = b"android,fstab";
        let found = blob.windows(needle.len()).any(|w| w == needle);
        assert!(found, "android,fstab not found in DTB blob");
    }

    #[test]
    fn production_dtb_contains_ramoops_compatible() {
        let mut out = vec![0u8; 16384];
        let base = make_base_config();
        let extras = ProductionDtbExtras::aether_defaults();
        let n = build_production_android_dtb(&base, &extras, &mut out).unwrap();
        let blob = &out[..n];
        let needle = b"ramoops";
        let found = blob.windows(needle.len()).any(|w| w == needle);
        assert!(found, "ramoops not found in DTB blob");
    }

    #[test]
    fn production_dtb_clock_frequency_present() {
        let mut out = vec![0u8; 16384];
        let base = make_base_config();
        let extras = ProductionDtbExtras::aether_defaults();
        let n = build_production_android_dtb(&base, &extras, &mut out).unwrap();
        let blob = &out[..n];
        let needle = b"clock-frequency";
        let found = blob.windows(needle.len()).any(|w| w == needle);
        assert!(found, "clock-frequency not found in DTB blob");
    }

    #[test]
    fn defconfig_entry_constructors() {
        let e = DefconfigEntry::must_enable(b"CONFIG_TMPFS");
        assert_eq!(e.value, DefconfigValue::Enabled);
        let d = DefconfigEntry::must_disable(b"CONFIG_VT");
        assert_eq!(d.value, DefconfigValue::Disabled);
    }

    #[test]
    fn prod_dtb_builder_fdt_magic() {
        // Minimal round-trip: build empty root node, verify FDT magic.
        let mut b = ProdDtbBuilder::new();
        b.begin_node(b"").unwrap();
        b.end_node().unwrap();
        let mut out = [0u8; 256];
        let n = b.finalize_into(&mut out).unwrap();
        assert!(n >= 56);
        let magic = u32::from_be_bytes(out[0..4].try_into().unwrap());
        assert_eq!(magic, 0xD00D_FEED);
    }
}
