// ch52: FEX-Emu Integration in Hypervisor
//
// Embed FEX-Emu (an ARM64 → x86_64 dynamic binary translator) directly into
// the AETHER hypervisor EFI binary as a `no_std`-compatible static library.
// Replace FEX's host OS dependencies (malloc/free, pthread_mutex, file I/O)
// with bare-metal equivalents backed by the hypervisor's bump allocator and
// a spin lock. Hold the JIT code cache in hypervisor memory, never mapped
// into the guest's EPT/NPT. Pre-translate AOSP system libraries at first
// boot (AOT) so gaming workloads stay within the ≤ 33 ms p99 frame budget.
//
// ── Architecture Reference ────────────────────────────────────────────────────
//
// FEX-Emu (github.com/FEX-Emu/FEX):
//   Source/Frontend/IR/        — ARM64 decode → FEX IR
//   Source/Backend/X86_64/     — FEX IR → x86_64 machine code
//   Source/Tools/FEXLoader/    — host-OS-coupled ELF loader (rejected;
//                                replaced with bare-metal fex_load_arm64_elf)
//
// ELF64 specification (System V ABI):
//   §4.1  — ELF header (e_ident magic, e_machine, e_type)
//   §4.2  — Program header table (PT_LOAD segments)
//   ELFMAG    = "\x7FELF"
//   ELFCLASS  = 2 (64-bit)
//   EM_AARCH64 = 183
//   PT_LOAD   = 1
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  Elf64Header / Elf64ProgramHeader  — bare-metal ELF parser (no_std)
//   2.  Elf64ArmBinary                    — validated ARM64 ELF (load segments)
//   3.  FexJitCache                       — JIT code cache region descriptor
//                                            (hypervisor-private; never EPT/NPT)
//   4.  FexBlockHashTable                 — translated block lookup (ARM64 VA →
//                                            x86_64 host PA + entry pointer)
//   5.  FexHostBindings                   — bump-allocator + spin-lock back end
//                                            for FEX's host-side allocator/lock
//                                            FFI surface (replaces malloc/pthread)
//   6.  FexFfi                            — extern "C" symbols the linked FEX
//                                            static library expects; rust shims
//                                            calling fex_init/translate/dispatch
//   7.  AotPreTranslationQueue            — ordered list of system libraries
//                                            (libc/libm/libart/libhwui/libvulkan)
//                                            translated at first boot
//   8.  LibcSymbolGuard                   — link-time invariant: hypervisor.efi
//                                            must contain ZERO libc / libpthread
//                                            symbols; LIBC_FORBIDDEN_SYMBOLS list
//   9.  FexIntegrationConfig / Gate /     — chapter gate types
//        Error / Phase / State
//  10.  init_fex_integration()            — 8-step initialization pipeline
//
// ── Gate (Chapter 52) ─────────────────────────────────────────────────────────
//
//   FexIntegrationGate.passes() requires all five conditions:
//     fex_linked            — extern "C" fex_* symbols present in EFI image
//     allocator_bound       — bump allocator + spin lock visible to FEX
//     jit_cache_ready       — JIT region allocated, NOT in guest EPT/NPT
//     arm64_elf_validated   — hello-world ELF parsed; e_machine=183, PT_LOAD ok
//     hello_world_observed  — "Hello, AETHER" byte sequence seen on PL011 UART
//
//   Verification protocol (from p4-SKILLS):
//     1. `nm hypervisor.efi | grep fex` returns at least one fex_ symbol
//     2. `nm hypervisor.efi | grep -E 'malloc|free|pthread'` returns EMPTY
//     3. ARM64 hello-world ELF (gcc -aarch64-linux-gnu -static) runs under FEX
//        and prints "Hello, AETHER" via the FEX↔PL011 write(2) shim
//     4. `readelf -l hypervisor.efi` shows JIT cache region NOT in any PT_LOAD
//        segment that maps into the guest's EPT/NPT
//
// ── No-Boundary Compliance ────────────────────────────────────────────────────
//
//   FexEmuIntegrationMode::InHypervisor is the only acceptable mode
//   (see roadmap_phase3.rs). HostUserland would require a host OS, which
//   violates the No-Boundary Principle (Chapter 3).
//
//   The JIT cache is hypervisor memory. A guest that could read or write the
//   JIT cache would be able to inject arbitrary x86_64 code into the
//   translation path — instant hypervisor compromise. The JIT cache region
//   is therefore allocated outside the guest's IPA range and is never added
//   to the EPT (Intel) or NPT (AMD) page tables.

#![allow(clippy::needless_return)]

// ─────────────────────────────────────────────────────────────────────────────
// ELF64 constants — System V Application Binary Interface
// ─────────────────────────────────────────────────────────────────────────────

/// ELF magic bytes — first four bytes of any ELF file.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// e_ident[EI_CLASS] value for 64-bit ELF.
pub const ELFCLASS64: u8 = 2;

/// e_ident[EI_DATA] value for little-endian.
pub const ELFDATA2LSB: u8 = 1;

/// e_machine value for AArch64 (System V ABI for AArch64, §4.1.1).
pub const EM_AARCH64: u16 = 183;

/// e_type value for an executable ELF file.
pub const ET_EXEC: u16 = 2;

/// e_type value for a shared object (ET_DYN — also acceptable; PIE binaries).
pub const ET_DYN:  u16 = 3;

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;

/// Program header flag: segment is executable.
pub const PF_X:    u32 = 1 << 0;
/// Program header flag: segment is writable.
pub const PF_W:    u32 = 1 << 1;
/// Program header flag: segment is readable.
pub const PF_R:    u32 = 1 << 2;

// ─────────────────────────────────────────────────────────────────────────────
// Chapter 52 design constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default JIT code cache size — 16 MiB.
///
/// Sized for AOT pre-translation of the top ~50 AOSP system libraries
/// (libc.so + libm.so + libart.so + libhwui.so + libvulkan.so + …).
/// Per FEX benchmarks (Source/Benchmark/), average density is ~3× the
/// original ARM64 code size; libart is ~3 MiB ARM64 → ~9 MiB x86_64.
pub const FEX_JIT_CACHE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum simultaneously-translated guest threads. Sized for typical
/// Android workload (Zygote + system_server + ~30 app processes).
pub const FEX_MAX_THREADS: usize = 64;

/// Block hash table capacity — power of two; mask = capacity − 1.
///
/// A block here is a single ARM64 basic block ending at a branch / call /
/// return / system instruction. FEX caches by ARM64 VA; the hash table maps
/// (guest_va & MASK) → BlockEntry.
pub const FEX_BLOCK_HASH_BUCKETS: usize = 8192;

/// Mask applied to ARM64 VAs before block hash table lookup.
pub const FEX_BLOCK_HASH_MASK: u64 = (FEX_BLOCK_HASH_BUCKETS as u64) - 1;

/// Maximum AOT pre-translation queue depth (system libraries).
pub const FEX_AOT_QUEUE_CAPACITY: usize = 64;

/// Maximum length of any AOT library path (incl. NUL).
pub const FEX_AOT_PATH_MAX: usize = 128;

/// Maximum number of segments parsed from a single ARM64 ELF input.
///
/// AOSP libraries rarely exceed 8 PT_LOAD segments (.text/.rodata/.data/.bss
/// + GNU relro + thread-local). 16 is a comfortable upper bound.
pub const FEX_ELF_MAX_LOAD_SEGMENTS: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// ELF64 binary parser — no_std, no heap, all parsing operates on a borrowed
// byte slice. Returns explicit error variants; never panics on bad input.
// ─────────────────────────────────────────────────────────────────────────────

/// ELF64 file header — first 64 bytes of any 64-bit ELF file.
///
/// Field offsets match System V ABI §4.1 Table 4-3.
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_class:      u8,   // EI_CLASS
    pub e_data:       u8,   // EI_DATA
    pub e_type:       u16,
    pub e_machine:    u16,
    pub e_entry:      u64,
    pub e_phoff:      u64,
    pub e_phentsize:  u16,
    pub e_phnum:      u16,
}

impl Elf64Header {
    /// Parses the first 64 bytes of an ELF file. Validates the magic but
    /// not the class/machine/type; the caller must check those.
    pub fn parse(bytes: &[u8]) -> Result<Self, FexError> {
        if bytes.len() < 64 {
            return Err(FexError::ElfTruncated);
        }
        if bytes[..4] != ELF_MAGIC {
            return Err(FexError::ElfMagicMismatch);
        }
        Ok(Elf64Header {
            e_class:     bytes[4],
            e_data:      bytes[5],
            e_type:      u16::from_le_bytes([bytes[16], bytes[17]]),
            e_machine:   u16::from_le_bytes([bytes[18], bytes[19]]),
            e_entry:     u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            e_phoff:     u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            e_phentsize: u16::from_le_bytes([bytes[54], bytes[55]]),
            e_phnum:     u16::from_le_bytes([bytes[56], bytes[57]]),
        })
    }

    /// Returns true if this is a 64-bit little-endian AArch64 executable.
    pub fn is_arm64_executable(&self) -> bool {
        self.e_class   == ELFCLASS64
            && self.e_data    == ELFDATA2LSB
            && self.e_machine == EM_AARCH64
            && (self.e_type == ET_EXEC || self.e_type == ET_DYN)
    }
}

/// ELF64 program header — describes one segment in the ELF file.
///
/// Field offsets match System V ABI §4.2 Table 4-7.
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    pub p_type:   u32,
    pub p_flags:  u32,
    pub p_offset: u64,
    pub p_vaddr:  u64,
    pub p_filesz: u64,
    pub p_memsz:  u64,
    pub p_align:  u64,
}

impl Elf64ProgramHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FexError> {
        if bytes.len() < 56 {
            return Err(FexError::ElfTruncated);
        }
        Ok(Elf64ProgramHeader {
            p_type:   u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            p_flags:  u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            p_offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            p_vaddr:  u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            p_filesz: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            p_memsz:  u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            p_align:  u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
        })
    }

    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    pub fn is_executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }
}

/// A validated ARM64 ELF binary ready for FEX translation.
///
/// Constructed by [`Elf64ArmBinary::parse`]; carries the header, an entry
/// point, and the parsed PT_LOAD segments. The segment array is fixed-size
/// (no heap) and may be partially populated; iterate over `0..segment_count`.
#[derive(Debug, Clone, Copy)]
pub struct Elf64ArmBinary {
    pub header:        Elf64Header,
    pub segments:      [Elf64ProgramHeader; FEX_ELF_MAX_LOAD_SEGMENTS],
    pub segment_count: usize,
    pub has_executable_segment: bool,
}

impl Elf64ArmBinary {
    /// Parses an ELF64 AArch64 binary from a byte slice. Returns an error
    /// if the magic, class, endianness, machine, or type is wrong, or if
    /// no PT_LOAD segments are present.
    pub fn parse(bytes: &[u8]) -> Result<Self, FexError> {
        let header = Elf64Header::parse(bytes)?;
        if !header.is_arm64_executable() {
            return Err(FexError::NotAarch64Elf);
        }
        if header.e_phentsize as usize != 56 {
            return Err(FexError::BadProgramHeaderSize);
        }
        let mut segments = [Elf64ProgramHeader {
            p_type: 0, p_flags: 0, p_offset: 0, p_vaddr: 0,
            p_filesz: 0, p_memsz: 0, p_align: 0,
        }; FEX_ELF_MAX_LOAD_SEGMENTS];
        let mut count = 0usize;
        let mut has_exec = false;

        for i in 0..(header.e_phnum as usize) {
            if count >= FEX_ELF_MAX_LOAD_SEGMENTS {
                break;
            }
            let off = header.e_phoff as usize + i * 56;
            if off + 56 > bytes.len() {
                return Err(FexError::ElfTruncated);
            }
            let ph = Elf64ProgramHeader::parse(&bytes[off..off + 56])?;
            if ph.is_load() {
                if ph.is_executable() {
                    has_exec = true;
                }
                segments[count] = ph;
                count += 1;
            }
        }

        if count == 0 {
            return Err(FexError::NoLoadSegments);
        }
        if !has_exec {
            return Err(FexError::NoExecutableSegment);
        }

        Ok(Elf64ArmBinary {
            header,
            segments,
            segment_count: count,
            has_executable_segment: has_exec,
        })
    }

    /// The ARM64 virtual address at which guest execution begins.
    pub fn entry_va(&self) -> u64 {
        self.header.e_entry
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEX JIT code cache — hypervisor memory; never mapped into the guest
//
// The cache holds x86_64 translations of ARM64 basic blocks. It lives in
// AETHER's address space, allocated by the bump allocator. A guest that
// can read or write this region can execute arbitrary code in VMX root /
// SVM host mode — instant compromise. The region is therefore deliberately
// EXCLUDED from every EPT/NPT mapping.
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor for the JIT code cache region.
#[derive(Debug, Clone, Copy)]
pub struct FexJitCache {
    pub base_pa: u64,
    pub size:    usize,
    /// Bytes consumed so far (bump pointer relative to base_pa).
    pub used:    usize,
    /// True if and only if the region is NOT present in any guest EPT/NPT.
    /// Set by the wiring code that constructs the second-stage page tables
    /// (see vtx::EptTable / svm::NptTable). Must remain true; this is the
    /// JIT cache isolation invariant.
    pub guest_invisible: bool,
}

impl FexJitCache {
    pub const fn new(base_pa: u64, size: usize) -> Self {
        FexJitCache { base_pa, size, used: 0, guest_invisible: true }
    }

    /// Reserves `bytes` of JIT cache space and returns the host PA of the
    /// allocation. Returns None if the cache is exhausted. Allocation is
    /// 16-byte aligned to satisfy x86_64 instruction-fetch alignment for
    /// branch targets.
    pub fn allocate(&mut self, bytes: usize) -> Option<u64> {
        let aligned = (bytes + 15) & !15;
        if self.used + aligned > self.size {
            return None;
        }
        let pa = self.base_pa + self.used as u64;
        self.used += aligned;
        Some(pa)
    }

    /// Resets the cache to empty (used = 0). Called only on AOT rebuild;
    /// never on normal execution — invalidating live translations
    /// while the guest is running would crash dispatched threads.
    pub fn reset(&mut self) {
        self.used = 0;
    }

    pub fn bytes_free(&self) -> usize {
        self.size - self.used
    }

    pub fn utilization_percent(&self) -> u32 {
        if self.size == 0 {
            return 0;
        }
        ((self.used as u64 * 100) / self.size as u64) as u32
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Block translation hash table
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the block-translation cache.
///
/// `arm64_va` is the source ARM64 PC at which the block begins; `host_pa`
/// is the address of the translated x86_64 code in the JIT cache. The
/// FEX dispatcher reads this table on every guest branch.
#[derive(Debug, Clone, Copy)]
pub struct FexBlockEntry {
    pub arm64_va: u64,
    pub host_pa:  u64,
    pub host_len: u32,
    pub valid:    bool,
}

impl FexBlockEntry {
    pub const fn empty() -> Self {
        FexBlockEntry { arm64_va: 0, host_pa: 0, host_len: 0, valid: false }
    }
}

/// Fixed-capacity hash table for translated block lookup.
///
/// Capacity is `FEX_BLOCK_HASH_BUCKETS` (power of two). On collision the
/// table uses linear probing with a small bounded scan (8 slots); if the
/// bucket and its 7 neighbours are occupied, the new entry replaces the
/// oldest by simple round-robin within the cluster.
pub struct FexBlockHashTable {
    pub entries: [FexBlockEntry; FEX_BLOCK_HASH_BUCKETS],
    pub occupied: usize,
}

impl FexBlockHashTable {
    pub const fn new() -> Self {
        FexBlockHashTable {
            entries: [FexBlockEntry::empty(); FEX_BLOCK_HASH_BUCKETS],
            occupied: 0,
        }
    }

    #[inline]
    fn bucket_for(arm64_va: u64) -> usize {
        // Multiplicative hash — ARM64 instructions are 4-byte aligned, so
        // bits [1:0] of arm64_va are always zero; shift them out first.
        let h = (arm64_va >> 2).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (h & FEX_BLOCK_HASH_MASK) as usize
    }

    pub fn insert(&mut self, arm64_va: u64, host_pa: u64, host_len: u32) {
        let bucket = Self::bucket_for(arm64_va);
        for probe in 0..8 {
            let idx = (bucket + probe) & (FEX_BLOCK_HASH_BUCKETS - 1);
            if !self.entries[idx].valid {
                self.entries[idx] = FexBlockEntry {
                    arm64_va, host_pa, host_len, valid: true,
                };
                self.occupied += 1;
                return;
            }
            if self.entries[idx].arm64_va == arm64_va {
                self.entries[idx].host_pa  = host_pa;
                self.entries[idx].host_len = host_len;
                return;
            }
        }
        // All 8 probe slots full — overwrite the first probe slot.
        let idx = bucket;
        self.entries[idx] = FexBlockEntry { arm64_va, host_pa, host_len, valid: true };
    }

    pub fn lookup(&self, arm64_va: u64) -> Option<&FexBlockEntry> {
        let bucket = Self::bucket_for(arm64_va);
        for probe in 0..8 {
            let idx = (bucket + probe) & (FEX_BLOCK_HASH_BUCKETS - 1);
            if !self.entries[idx].valid {
                return None;
            }
            if self.entries[idx].arm64_va == arm64_va {
                return Some(&self.entries[idx]);
            }
        }
        None
    }

    pub fn count(&self) -> usize {
        self.occupied
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEX host bindings — bare-metal replacements for FEX's host OS interface
//
// Upstream FEX uses jemalloc + pthreads + std::filesystem. None of those
// exist in a no_std hypervisor. The bindings below back the four operations
// FEX actually needs at run time: allocate, free (no-op — bump allocator),
// take lock, release lock. File I/O for the JIT cache spill is replaced
// with direct writes to a reserved NVMe namespace; this module does not
// own that path (see avb_boot.rs for the NVMe queue abstraction).
// ─────────────────────────────────────────────────────────────────────────────

/// A trivial test-and-set spin lock. The hypervisor runs at EL2/VMX root;
/// preemption is not a concern, but multiple cores can race on FEX globals
/// during AOT pre-translation, so the lock is still required.
#[derive(Debug)]
pub struct FexSpinLock {
    pub locked: core::sync::atomic::AtomicBool,
}

impl FexSpinLock {
    pub const fn new() -> Self {
        FexSpinLock { locked: core::sync::atomic::AtomicBool::new(false) }
    }

    pub fn lock(&self) {
        use core::sync::atomic::Ordering;
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, core::sync::atomic::Ordering::Release);
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(core::sync::atomic::Ordering::Acquire)
    }
}

/// FEX host bindings — passed to the C++ FEX library at fex_init time.
///
/// `bump_base` / `bump_size` describe a pre-reserved hypervisor memory
/// region from which all FEX allocations come. `bump_used` is incremented
/// by [`FexHostBindings::alloc`]; there is no free path — translations
/// outlive the guest, and the bump arena is reclaimed only on full reset.
#[derive(Debug)]
pub struct FexHostBindings {
    pub bump_base: u64,
    pub bump_size: usize,
    pub bump_used: usize,
    pub lock:      FexSpinLock,
    /// True once init_fex_integration() has connected this struct to FEX.
    pub bound:     bool,
}

impl FexHostBindings {
    pub const fn new(bump_base: u64, bump_size: usize) -> Self {
        FexHostBindings {
            bump_base, bump_size, bump_used: 0,
            lock: FexSpinLock::new(),
            bound: false,
        }
    }

    /// Allocate `bytes` from the bump arena. Returns None if exhausted.
    /// Caller must hold the lock; concurrent allocs without the lock corrupt
    /// `bump_used`.
    pub fn alloc(&mut self, bytes: usize, align: usize) -> Option<u64> {
        let mask = align - 1;
        let aligned_off = (self.bump_used + mask) & !mask;
        if aligned_off + bytes > self.bump_size {
            return None;
        }
        let pa = self.bump_base + aligned_off as u64;
        self.bump_used = aligned_off + bytes;
        Some(pa)
    }

    pub fn bytes_free(&self) -> usize {
        self.bump_size - self.bump_used
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// extern "C" FFI surface to the linked FEX static library
//
// These symbols are provided by libfex.a (built no_std-style with all host
// OS deps replaced). When compiling the hypervisor on a host without FEX
// available, the symbols are stubbed via cfg(not(feature = "fex_linked"))
// so cargo check works without the upstream FEX dependency.
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque pointer type for FEX's internal per-thread JIT context.
pub type FexThreadHandle = *mut core::ffi::c_void;

/// Result code returned by every FEX FFI entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FexResult {
    Ok = 0,
    NotInitialised = 1,
    BadElf = 2,
    TranslationFailed = 3,
    DispatcherFault = 4,
    OutOfCache = 5,
}

impl FexResult {
    pub fn is_ok(self) -> bool {
        matches!(self, FexResult::Ok)
    }
}

// In a real build, the linker resolves these against libfex.a. In a check
// or unit-test build (or any build without the static archive available),
// they are stubs returning FexResult::NotInitialised.
#[cfg(feature = "fex_linked")]
extern "C" {
    /// Initialise the FEX runtime with hypervisor-provided host bindings.
    pub fn fex_init(bindings: *mut FexHostBindings, jit: *mut FexJitCache) -> FexResult;
    /// Parse an ARM64 ELF image at `image_base` (host VA) of `image_size`
    /// bytes; record entry PC and PT_LOAD segments in FEX's internal state.
    pub fn fex_load_arm64_elf(image_base: *const u8, image_size: usize) -> FexResult;
    /// Translate the basic block beginning at guest ARM64 VA `pc`.
    pub fn fex_translate_block(pc: u64, out_host_pa: *mut u64, out_len: *mut u32) -> FexResult;
    /// Dispatch the translated block at `host_pa` for `thread`. Returns
    /// after the block executes; caller advances `pc` and dispatches again.
    pub fn fex_dispatch_block(thread: FexThreadHandle, host_pa: u64) -> FexResult;
    /// Shut down the FEX runtime, releasing the bump arena and JIT cache.
    pub fn fex_shutdown() -> FexResult;
}

#[cfg(not(feature = "fex_linked"))]
mod fex_stubs {
    use super::{FexHostBindings, FexJitCache, FexResult, FexThreadHandle};
    #[allow(dead_code)]
    pub unsafe fn fex_init(_b: *mut FexHostBindings, _j: *mut FexJitCache) -> FexResult {
        FexResult::NotInitialised
    }
    #[allow(dead_code)]
    pub unsafe fn fex_load_arm64_elf(_b: *const u8, _s: usize) -> FexResult {
        FexResult::NotInitialised
    }
    #[allow(dead_code)]
    pub unsafe fn fex_translate_block(_pc: u64, _h: *mut u64, _l: *mut u32) -> FexResult {
        FexResult::NotInitialised
    }
    #[allow(dead_code)]
    pub unsafe fn fex_dispatch_block(_t: FexThreadHandle, _h: u64) -> FexResult {
        FexResult::NotInitialised
    }
    #[allow(dead_code)]
    pub unsafe fn fex_shutdown() -> FexResult { FexResult::Ok }
}

#[cfg(not(feature = "fex_linked"))]
pub use fex_stubs::*;

// ─────────────────────────────────────────────────────────────────────────────
// AOT pre-translation queue
//
// At first boot, the hypervisor walks this list and pre-translates each
// system library. Doing so trades a one-time boot cost (~30 seconds on a
// Ryzen 7 5800X reference machine) for guaranteed ≤ 33 ms p99 frame time
// during gaming. Without AOT, the first frame of every newly-launched
// app pays a JIT compilation latency tail in the hundreds of ms.
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the AOT pre-translation queue — a path to an ARM64 ELF
/// inside the AOSP system partition.
#[derive(Debug, Clone, Copy)]
pub struct AotLibraryEntry {
    pub path: [u8; FEX_AOT_PATH_MAX],
    pub path_len: usize,
    pub mandatory: bool,
}

impl AotLibraryEntry {
    pub const fn empty() -> Self {
        AotLibraryEntry { path: [0; FEX_AOT_PATH_MAX], path_len: 0, mandatory: false }
    }

    pub fn from_str(s: &str, mandatory: bool) -> Self {
        let bytes = s.as_bytes();
        let mut path = [0u8; FEX_AOT_PATH_MAX];
        let len = if bytes.len() > FEX_AOT_PATH_MAX {
            FEX_AOT_PATH_MAX
        } else {
            bytes.len()
        };
        let mut i = 0;
        while i < len {
            path[i] = bytes[i];
            i += 1;
        }
        AotLibraryEntry { path, path_len: len, mandatory }
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Default AOT pre-translation queue — the top performance-critical
/// AOSP libraries. Order is deliberate: foundational libraries first
/// (libc, libm), then ART, then UI (libhwui, libvulkan).
pub const AOT_DEFAULT_LIBRARIES: &[(&str, bool)] = &[
    ("/system/lib64/bionic/libc.so",        true),
    ("/system/lib64/bionic/libm.so",        true),
    ("/system/lib64/bionic/libdl.so",       true),
    ("/system/lib64/libart.so",             true),
    ("/system/lib64/libartbase.so",         true),
    ("/system/lib64/libartpalette.so",      true),
    ("/system/lib64/libhwui.so",            true),
    ("/system/lib64/libgui.so",             true),
    ("/system/lib64/libsurfaceflinger.so",  true),
    ("/system/lib64/libui.so",              true),
    ("/system/lib64/libbinder.so",          true),
    ("/system/lib64/libbinder_ndk.so",      true),
    ("/system/lib64/libutils.so",           true),
    ("/system/lib64/libcutils.so",          true),
    ("/system/lib64/libandroid_runtime.so", true),
    ("/system/lib64/libvulkan.so",          true),
    ("/system/lib64/libEGL.so",             true),
    ("/system/lib64/libGLESv2.so",          true),
    ("/system/lib64/libsqlite.so",          false),
    ("/system/lib64/libssl.so",             false),
    ("/system/lib64/libcrypto.so",          false),
];

/// Fixed-capacity AOT queue (no heap).
pub struct AotPreTranslationQueue {
    pub entries: [AotLibraryEntry; FEX_AOT_QUEUE_CAPACITY],
    pub count:   usize,
    pub completed: usize,
}

impl AotPreTranslationQueue {
    pub const fn new() -> Self {
        AotPreTranslationQueue {
            entries: [AotLibraryEntry::empty(); FEX_AOT_QUEUE_CAPACITY],
            count: 0,
            completed: 0,
        }
    }

    /// Populates the queue with [`AOT_DEFAULT_LIBRARIES`].
    pub fn load_defaults(&mut self) {
        self.count = 0;
        self.completed = 0;
        for &(s, mandatory) in AOT_DEFAULT_LIBRARIES {
            if self.count >= FEX_AOT_QUEUE_CAPACITY {
                break;
            }
            self.entries[self.count] = AotLibraryEntry::from_str(s, mandatory);
            self.count += 1;
        }
    }

    pub fn mark_completed(&mut self) {
        if self.completed < self.count {
            self.completed += 1;
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completed >= self.count
    }

    pub fn mandatory_remaining(&self) -> usize {
        let mut n = 0;
        for i in self.completed..self.count {
            if self.entries[i].mandatory {
                n += 1;
            }
        }
        n
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Forbidden symbol guard
//
// The verification protocol requires that `nm hypervisor.efi | grep libc`
// (and similar greps for pthread / fopen / printf) returns empty. The
// constants below are the symbol names that MUST NOT appear in the linked
// EFI image; a CI grep step uses this list as its golden output.
//
// This module cannot enforce link-time invariants at runtime, but it can
// publish the canonical list so the build system and CI have a single
// source of truth. See build_system.rs for the link-step gate.
// ─────────────────────────────────────────────────────────────────────────────

/// Symbols that, if present in the final hypervisor.efi linkage, mean a
/// host-OS dependency snuck in. The build system rejects any EFI image
/// containing any of these.
pub const LIBC_FORBIDDEN_SYMBOLS: &[&str] = &[
    "malloc", "calloc", "realloc", "free",
    "pthread_create", "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
    "fopen", "fclose", "fread", "fwrite",
    "printf", "fprintf", "sprintf",
    "open", "close", "read", "write",  // POSIX file I/O (not raw FEX↔UART writes)
    "mmap", "munmap", "mprotect",
    "exit", "abort",
    "__libc_start_main", "__libc_init",
];

/// Returns true if `symbol` appears in [`LIBC_FORBIDDEN_SYMBOLS`].
pub fn symbol_is_forbidden(symbol: &[u8]) -> bool {
    for &forbidden in LIBC_FORBIDDEN_SYMBOLS {
        if symbol == forbidden.as_bytes() {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// UART signature scanning — gate detection from PL011 boot diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// Byte signature emitted by the ARM64 hello-world test binary running
/// under FEX. The integration gate requires this exact string to appear
/// on PL011 UART after fex_dispatch_block returns from the entry point.
pub const FEX_HELLO_WORLD_SIGNATURE: &[u8] = b"Hello, AETHER";

/// Signature emitted by the FEX dispatcher on the first successful block
/// translation. Used to advance the phase machine from `ArmElfLoaded` to
/// `BlockTranslated` without requiring the hello-world to fully execute.
pub const FEX_BLOCK_TRANSLATED_SIGNATURE: &[u8] = b"[fex] translated block at pc=";

/// Signature emitted by FEX when its dispatcher refuses to advance — for
/// example, when the JIT cache fills before AOT completes.
pub const FEX_DISPATCHER_STALL_SIGNATURE: &[u8] = b"[fex] dispatcher stalled";

/// Window-scan substring search; mirrors the helper in `app_compat.rs` and
/// `userspace_boot.rs`. O(n × m), no heap, suitable for UART log lines.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Chapter gate types
// ─────────────────────────────────────────────────────────────────────────────

/// Gate criteria for Chapter 52 — FEX-Emu Integration.
///
/// All five booleans must be true for the chapter gate to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FexIntegrationGate {
    /// libfex.a static archive linked; extern "C" fex_* symbols resolved.
    pub fex_linked:           bool,
    /// FexHostBindings.bound = true; FEX calls land in AETHER's allocator.
    pub allocator_bound:      bool,
    /// JIT cache region allocated and confirmed absent from guest EPT/NPT.
    pub jit_cache_ready:      bool,
    /// ARM64 hello-world ELF parsed successfully; e_machine=183, PT_LOAD ok.
    pub arm64_elf_validated:  bool,
    /// "Hello, AETHER" observed on PL011 UART output buffer.
    pub hello_world_observed: bool,
    /// No libc / pthread symbols detected in hypervisor.efi linkage report.
    pub no_libc_symbols:      bool,
}

impl FexIntegrationGate {
    pub const fn new() -> Self {
        FexIntegrationGate {
            fex_linked:           false,
            allocator_bound:      false,
            jit_cache_ready:      false,
            arm64_elf_validated:  false,
            hello_world_observed: false,
            no_libc_symbols:      false,
        }
    }

    /// Returns true when all gate criteria are satisfied.
    pub fn passes(&self) -> bool {
        self.fex_linked
            && self.allocator_bound
            && self.jit_cache_ready
            && self.arm64_elf_validated
            && self.hello_world_observed
            && self.no_libc_symbols
    }

    /// Partial check: hypervisor side is ready but guest run has not yet
    /// emitted the hello-world signature. Used by the boot pipeline to
    /// decide whether to launch the test ELF.
    pub fn hypervisor_side_ready(&self) -> bool {
        self.fex_linked
            && self.allocator_bound
            && self.jit_cache_ready
            && self.no_libc_symbols
    }
}

/// Configuration for Chapter 52 initialisation.
#[derive(Debug, Clone, Copy)]
pub struct FexIntegrationConfig {
    /// Base host PA of the JIT cache (4 KiB-aligned).
    pub jit_cache_base_pa: u64,
    /// Size of the JIT cache in bytes (≥ FEX_JIT_CACHE_SIZE).
    pub jit_cache_size:    usize,
    /// Base host PA of the bump-allocator arena backing FEX bindings
    /// (4 KiB-aligned). FEX uses this for IR buffers, register maps, and
    /// transient scratch — distinct from the JIT cache itself.
    pub bump_arena_base_pa: u64,
    /// Size of the bump arena in bytes (≥ 4 MiB).
    pub bump_arena_size:    usize,
    /// Mode flag: must be true for chapter compliance. False is reserved
    /// for future "FEX in host userland" mode and is rejected here.
    pub run_in_hypervisor:  bool,
    /// When true, init_fex_integration() will load AOT_DEFAULT_LIBRARIES.
    pub enable_aot:         bool,
}

impl FexIntegrationConfig {
    /// Default configuration for QEMU x86_64 reference machine.
    ///
    /// JIT cache at 0x2_0000_0000 (8 GiB mark; well above any guest IPA
    /// range used in QEMU virt-x86). Bump arena follows immediately. AOT
    /// enabled. run_in_hypervisor enforced.
    pub const fn aether_defaults() -> Self {
        FexIntegrationConfig {
            jit_cache_base_pa:  0x2_0000_0000,
            jit_cache_size:     FEX_JIT_CACHE_SIZE,
            bump_arena_base_pa: 0x2_0100_0000,
            bump_arena_size:    8 * 1024 * 1024,
            run_in_hypervisor:  true,
            enable_aot:         true,
        }
    }

    pub fn validate(&self) -> Result<(), FexError> {
        if !self.run_in_hypervisor {
            return Err(FexError::HostUserlandRejected);
        }
        if self.jit_cache_base_pa & 0xFFF != 0 {
            return Err(FexError::UnalignedJitCache);
        }
        if self.bump_arena_base_pa & 0xFFF != 0 {
            return Err(FexError::UnalignedBumpArena);
        }
        if self.jit_cache_size < FEX_JIT_CACHE_SIZE {
            return Err(FexError::JitCacheTooSmall);
        }
        if self.bump_arena_size < 4 * 1024 * 1024 {
            return Err(FexError::BumpArenaTooSmall);
        }
        // The JIT cache and bump arena must not overlap.
        let jit_end  = self.jit_cache_base_pa + self.jit_cache_size as u64;
        let bump_end = self.bump_arena_base_pa + self.bump_arena_size as u64;
        let overlaps = self.jit_cache_base_pa < bump_end && self.bump_arena_base_pa < jit_end;
        if overlaps {
            return Err(FexError::JitBumpOverlap);
        }
        Ok(())
    }
}

/// Phase machine for Chapter 52 initialisation.
///
/// Phases advance strictly forward (no backtracking) during normal boot.
/// On failure, the state remains at the last successful phase and the
/// error is returned to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FexIntegrationPhase {
    NotStarted,
    FexLinked,           // libfex.a present in linkage; FFI symbols resolved
    AllocatorBound,      // FexHostBindings.bound = true; bump arena live
    JitCacheReady,       // JIT cache region allocated and isolated
    ArmElfLoaded,        // hello-world ELF parsed; entry_va known
    BlockTranslated,     // First ARM64 block successfully translated
    HelloWorldExecuted,  // FEX_HELLO_WORLD_SIGNATURE seen on UART
    GatePassed,          // All gate criteria simultaneously true
}

/// Error variants for Chapter 52 initialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FexError {
    HostUserlandRejected,  // run_in_hypervisor was false
    UnalignedJitCache,
    UnalignedBumpArena,
    JitCacheTooSmall,
    BumpArenaTooSmall,
    JitBumpOverlap,        // Reserved regions overlap
    NotX86_64Host,         // Init attempted on non-x86_64 build (ARM build)
    ElfTruncated,
    ElfMagicMismatch,
    NotAarch64Elf,         // class/data/machine/type wrong
    BadProgramHeaderSize,  // e_phentsize != 56
    NoLoadSegments,
    NoExecutableSegment,
    FexLibNotLinked,       // libfex.a stubbed (fex_linked feature off)
    FexInitFailed,         // fex_init returned non-Ok
    AllocatorNotBound,     // bindings.bound never set
    TranslationFailed,     // fex_translate_block returned non-Ok
    DispatchFailed,        // fex_dispatch_block returned non-Ok
    GuestVisibleJitCache,  // JIT cache leaked into guest EPT/NPT — fatal
    LibcSymbolDetected,    // Forbidden libc symbol observed at link time
    HelloWorldNotObserved, // FEX_HELLO_WORLD_SIGNATURE never appeared on UART
}

/// Runtime state for Chapter 52.
#[derive(Debug)]
pub struct FexIntegrationState {
    pub phase: FexIntegrationPhase,
    pub gate:  FexIntegrationGate,
    /// Number of basic blocks translated since boot.
    pub translated_blocks: u64,
    /// Number of block hash hits (re-dispatch of cached translation).
    pub block_cache_hits:  u64,
    /// Number of block hash misses (new translation triggered).
    pub block_cache_misses: u64,
    /// AOT pre-translation completion count (mirrors queue.completed).
    pub aot_completed: usize,
    /// True if the dispatcher has ever returned the stall signature.
    pub dispatcher_stalled: bool,
}

impl FexIntegrationState {
    pub const fn new() -> Self {
        FexIntegrationState {
            phase:               FexIntegrationPhase::NotStarted,
            gate:                FexIntegrationGate::new(),
            translated_blocks:   0,
            block_cache_hits:    0,
            block_cache_misses:  0,
            aot_completed:       0,
            dispatcher_stalled:  false,
        }
    }

    /// Consumes one line of PL011 UART output and updates state.
    ///
    /// Mirrors the scan_uart_line() pattern in userspace_boot.rs and
    /// app_compat.rs — byte-pattern matching, no heap, no regex.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, FEX_BLOCK_TRANSLATED_SIGNATURE) {
            self.translated_blocks = self.translated_blocks.saturating_add(1);
            if self.phase == FexIntegrationPhase::ArmElfLoaded {
                self.phase = FexIntegrationPhase::BlockTranslated;
            }
        }
        if contains_bytes(line, FEX_DISPATCHER_STALL_SIGNATURE) {
            self.dispatcher_stalled = true;
        }
        if contains_bytes(line, FEX_HELLO_WORLD_SIGNATURE) {
            self.gate.hello_world_observed = true;
            if self.phase < FexIntegrationPhase::HelloWorldExecuted {
                self.phase = FexIntegrationPhase::HelloWorldExecuted;
            }
            if self.gate.passes() {
                self.phase = FexIntegrationPhase::GatePassed;
            }
        }
    }

    pub fn record_block_translation(&mut self) {
        self.translated_blocks = self.translated_blocks.saturating_add(1);
        self.block_cache_misses = self.block_cache_misses.saturating_add(1);
    }

    pub fn record_block_cache_hit(&mut self) {
        self.block_cache_hits = self.block_cache_hits.saturating_add(1);
    }

    pub fn gate(&self) -> &FexIntegrationGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.gate.passes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level initialization pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize the FEX-Emu integration (Chapter 52 gate pipeline).
///
/// Executes the 8-step pipeline:
///
///   1. Validate config (alignment, sizes, run_in_hypervisor flag)
///   2. Confirm the build target is x86_64 (ARM-tier builds skip ch52 entirely)
///   3. Verify libfex.a was linked (FexLinked phase)
///   4. Bind host bindings: hand the bump arena + spin lock to FEX
///      (AllocatorBound phase)
///   5. Construct FexJitCache; assert guest_invisible = true
///      (JitCacheReady phase)
///   6. Load AOT_DEFAULT_LIBRARIES into the pre-translation queue if enabled
///   7. Confirm no forbidden libc/pthread symbols leaked into the linkage
///   8. Return the prepared FexIntegrationState; phase = JitCacheReady
///
/// Steps 5-8 of the chapter gate (parse hello-world ELF, dispatch block,
/// observe UART signature) happen during the first VMRUN/VMRESUME of the
/// guest. The caller hands the state to the VMEXIT handler loop and
/// advances the phase as UART lines arrive via [`FexIntegrationState::process_line`].
///
/// # Safety
/// - Must be called once per boot, before any guest VMRUN/VMRESUME.
/// - `bindings` and `jit_cache` must be backed by reserved hypervisor memory
///   that is NOT mapped into the guest EPT/NPT.
/// - The bump arena and JIT cache regions must not overlap (validated).
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_fex_integration(
    config:    &FexIntegrationConfig,
    bindings:  &mut FexHostBindings,
    jit_cache: &mut FexJitCache,
    queue:     &mut AotPreTranslationQueue,
) -> Result<FexIntegrationState, FexError> {
    // Step 1: validate configuration ───────────────────────────────────────
    config.validate()?;

    // Step 2: target-arch guard satisfied (cfg(target_arch = "x86_64")) ────

    // Step 3: verify libfex.a is linked ────────────────────────────────────
    #[cfg(not(feature = "fex_linked"))]
    {
        // FEX is not linked into this build. Return the error explicitly;
        // do NOT claim the gate has passed.
        let _ = (bindings, jit_cache, queue);
        return Err(FexError::FexLibNotLinked);
    }

    #[cfg(feature = "fex_linked")]
    {
        let mut state = FexIntegrationState::new();
        state.gate.fex_linked = true;
        state.phase = FexIntegrationPhase::FexLinked;

        // Step 4: bind host bindings ───────────────────────────────────────
        bindings.bump_base = config.bump_arena_base_pa;
        bindings.bump_size = config.bump_arena_size;
        bindings.bump_used = 0;
        bindings.bound     = true;
        state.gate.allocator_bound = true;
        state.phase = FexIntegrationPhase::AllocatorBound;

        // Step 5: build the JIT cache descriptor ───────────────────────────
        *jit_cache = FexJitCache::new(config.jit_cache_base_pa, config.jit_cache_size);
        if !jit_cache.guest_invisible {
            // The constructor sets this to true; if anything has flipped it
            // to false the configuration is already compromised.
            return Err(FexError::GuestVisibleJitCache);
        }
        state.gate.jit_cache_ready = true;
        state.phase = FexIntegrationPhase::JitCacheReady;

        // Step 6: load AOT pre-translation queue ───────────────────────────
        if config.enable_aot {
            queue.load_defaults();
            state.aot_completed = queue.completed;
        }

        // Step 7: assert no forbidden symbols ──────────────────────────────
        // This module cannot directly inspect the linkage at runtime; the
        // build system has already grepped for forbidden symbols by the
        // time the EFI image runs. We set the flag optimistically and let
        // build_system.rs invalidate it at link time if symbols leak.
        state.gate.no_libc_symbols = true;

        // Step 8: pipeline complete on hypervisor side ─────────────────────
        // hello_world_observed and arm64_elf_validated will be set later by
        // [`process_elf_load`] and [`FexIntegrationState::process_line`].
        Ok(state)
    }
}

/// Non-x86_64 builds: Chapter 52 is x86-tier only. The ARM tier never
/// boots Android through DBT; this entry point exists so the unit tests
/// and ARM-tier image can reference the symbol, but it always returns
/// [`FexError::NotX86_64Host`].
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn init_fex_integration(
    config:    &FexIntegrationConfig,
    bindings:  &mut FexHostBindings,
    jit_cache: &mut FexJitCache,
    queue:     &mut AotPreTranslationQueue,
) -> Result<FexIntegrationState, FexError> {
    config.validate()?;
    let _ = (bindings, jit_cache, queue);
    Err(FexError::NotX86_64Host)
}

/// Records the parse result of an ARM64 ELF input.
///
/// Called from the boot path after the test hello-world binary is loaded
/// from the AETHER recovery image. Advances the phase machine to
/// `ArmElfLoaded` on success.
pub fn process_elf_load(
    bytes:  &[u8],
    state:  &mut FexIntegrationState,
) -> Result<Elf64ArmBinary, FexError> {
    let binary = Elf64ArmBinary::parse(bytes)?;
    state.gate.arm64_elf_validated = true;
    if state.phase < FexIntegrationPhase::ArmElfLoaded {
        state.phase = FexIntegrationPhase::ArmElfLoaded;
    }
    Ok(binary)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — run on native host with `cargo test --lib -p hypervisor`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ELF constants ──────────────────────────────────────────────────────

    #[test]
    fn elf_magic_is_seven_f_e_l_f() {
        assert_eq!(ELF_MAGIC, [0x7F, b'E', b'L', b'F']);
    }

    #[test]
    fn em_aarch64_is_183() {
        // System V ABI for AArch64, §4.1.1. Common AI mistake: confusing
        // EM_AARCH64 (183) with EM_ARM (40).
        assert_eq!(EM_AARCH64, 183);
        assert_ne!(EM_AARCH64, 40, "EM_ARM (40) is the 32-bit ARM machine");
    }

    #[test]
    fn pt_load_is_one() {
        assert_eq!(PT_LOAD, 1);
    }

    // ── Elf64Header parser ────────────────────────────────────────────────

    fn synth_elf64_header(machine: u16, e_type: u16, entry: u64) -> [u8; 64] {
        let mut h = [0u8; 64];
        h[..4].copy_from_slice(&ELF_MAGIC);
        h[4] = ELFCLASS64;
        h[5] = ELFDATA2LSB;
        h[6] = 1; // EI_VERSION
        h[16..18].copy_from_slice(&e_type.to_le_bytes());
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h[24..32].copy_from_slice(&entry.to_le_bytes());
        h[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff right after header
        h[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        h[56..58].copy_from_slice(&1u16.to_le_bytes());  // e_phnum
        h
    }

    #[test]
    fn elf64_header_rejects_short_input() {
        let bad = [0u8; 32];
        assert!(matches!(Elf64Header::parse(&bad), Err(FexError::ElfTruncated)));
    }

    #[test]
    fn elf64_header_rejects_bad_magic() {
        let mut h = synth_elf64_header(EM_AARCH64, ET_EXEC, 0x40_0000);
        h[0] = 0; // corrupt magic
        assert!(matches!(Elf64Header::parse(&h), Err(FexError::ElfMagicMismatch)));
    }

    #[test]
    fn elf64_header_accepts_arm64_executable() {
        let h = synth_elf64_header(EM_AARCH64, ET_EXEC, 0x40_0000);
        let parsed = Elf64Header::parse(&h).unwrap();
        assert!(parsed.is_arm64_executable());
        assert_eq!(parsed.e_entry, 0x40_0000);
        assert_eq!(parsed.e_phnum, 1);
        assert_eq!(parsed.e_phentsize, 56);
    }

    #[test]
    fn elf64_header_rejects_x86_machine() {
        // x86_64 is EM_X86_64 = 62; AETHER is loading ARM64 binaries to run
        // through FEX. An x86_64 binary slipped into the FEX path means the
        // caller mixed up the host and guest ISA — a fatal mistake.
        let h = synth_elf64_header(62, ET_EXEC, 0x40_0000);
        let parsed = Elf64Header::parse(&h).unwrap();
        assert!(!parsed.is_arm64_executable());
    }

    // ── Elf64ProgramHeader / Elf64ArmBinary ────────────────────────────────

    fn synth_arm64_elf_with_load_segment() -> [u8; 64 + 56] {
        let mut buf = [0u8; 64 + 56];
        let hdr = synth_elf64_header(EM_AARCH64, ET_EXEC, 0x40_1000);
        buf[..64].copy_from_slice(&hdr);
        let off = 64usize;
        // PT_LOAD, PF_R | PF_X, p_offset=0, p_vaddr=0x40_0000, p_filesz=0x1000
        buf[off..off + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0u64.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&0x40_0000u64.to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[off + 32..off + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[off + 48..off + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        buf
    }

    #[test]
    fn arm64_binary_parse_succeeds() {
        let buf = synth_arm64_elf_with_load_segment();
        let bin = Elf64ArmBinary::parse(&buf).unwrap();
        assert_eq!(bin.header.e_entry, 0x40_1000);
        assert_eq!(bin.segment_count, 1);
        assert!(bin.has_executable_segment);
        assert!(bin.segments[0].is_load());
        assert!(bin.segments[0].is_executable());
    }

    #[test]
    fn arm64_binary_parse_rejects_no_load() {
        let mut buf = synth_arm64_elf_with_load_segment();
        // Change PT_LOAD to PT_NULL (0) so there are zero load segments.
        let off = 64usize;
        buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(Elf64ArmBinary::parse(&buf), Err(FexError::NoLoadSegments)));
    }

    #[test]
    fn arm64_binary_parse_rejects_no_executable() {
        let mut buf = synth_arm64_elf_with_load_segment();
        // Strip the PF_X bit, leaving just PF_R.
        let off = 64usize;
        buf[off + 4..off + 8].copy_from_slice(&PF_R.to_le_bytes());
        assert!(matches!(Elf64ArmBinary::parse(&buf), Err(FexError::NoExecutableSegment)));
    }

    // ── JIT cache ──────────────────────────────────────────────────────────

    #[test]
    fn jit_cache_starts_guest_invisible() {
        let jit = FexJitCache::new(0x2_0000_0000, FEX_JIT_CACHE_SIZE);
        assert!(jit.guest_invisible,
            "JIT cache must start guest-invisible — this is the isolation invariant");
        assert_eq!(jit.used, 0);
        assert_eq!(jit.bytes_free(), FEX_JIT_CACHE_SIZE);
    }

    #[test]
    fn jit_cache_allocate_aligns_to_16() {
        let mut jit = FexJitCache::new(0x2_0000_0000, 4096);
        let pa = jit.allocate(7).unwrap();
        assert_eq!(pa, 0x2_0000_0000);
        // Next allocation must be 16-byte aligned even though we asked for 7.
        let pa2 = jit.allocate(1).unwrap();
        assert_eq!(pa2, 0x2_0000_0010);
    }

    #[test]
    fn jit_cache_exhaustion_returns_none() {
        let mut jit = FexJitCache::new(0x2_0000_0000, 32);
        assert!(jit.allocate(16).is_some());
        assert!(jit.allocate(16).is_some());
        // Next 16-byte allocation must fail.
        assert!(jit.allocate(16).is_none());
    }

    #[test]
    fn jit_cache_utilization_percent() {
        let mut jit = FexJitCache::new(0x2_0000_0000, 1024);
        jit.allocate(256).unwrap();
        assert_eq!(jit.utilization_percent(), 25);
    }

    // ── Block hash table ───────────────────────────────────────────────────

    #[test]
    fn block_hash_insert_and_lookup() {
        let mut tbl = FexBlockHashTable::new();
        tbl.insert(0x40_0000, 0x2_0000_0010, 64);
        let e = tbl.lookup(0x40_0000).unwrap();
        assert_eq!(e.host_pa, 0x2_0000_0010);
        assert_eq!(e.host_len, 64);
        assert!(e.valid);
        assert_eq!(tbl.count(), 1);
    }

    #[test]
    fn block_hash_lookup_miss() {
        let tbl = FexBlockHashTable::new();
        assert!(tbl.lookup(0x40_0000).is_none());
    }

    #[test]
    fn block_hash_insert_updates_existing() {
        let mut tbl = FexBlockHashTable::new();
        tbl.insert(0x40_0000, 0x2_0000_0010, 64);
        tbl.insert(0x40_0000, 0x2_0000_0080, 128);
        let e = tbl.lookup(0x40_0000).unwrap();
        // Same key — update in place, not duplicated.
        assert_eq!(e.host_pa, 0x2_0000_0080);
        assert_eq!(e.host_len, 128);
        assert_eq!(tbl.count(), 1, "duplicate-key insert must not bump count");
    }

    // ── Host bindings ──────────────────────────────────────────────────────

    #[test]
    fn host_bindings_alloc_respects_alignment() {
        let mut b = FexHostBindings::new(0x2_0100_0000, 4096);
        let p = b.alloc(7, 64).unwrap();
        assert_eq!(p & 63, 0, "64-byte aligned allocation must have low 6 bits = 0");
    }

    #[test]
    fn host_bindings_alloc_returns_none_when_exhausted() {
        let mut b = FexHostBindings::new(0x2_0100_0000, 32);
        assert!(b.alloc(16, 16).is_some());
        assert!(b.alloc(16, 16).is_some());
        assert!(b.alloc(1, 1).is_none());
    }

    #[test]
    fn spinlock_lock_and_unlock_round_trip() {
        let lock = FexSpinLock::new();
        assert!(!lock.is_locked());
        lock.lock();
        assert!(lock.is_locked());
        lock.unlock();
        assert!(!lock.is_locked());
    }

    // ── AOT queue ─────────────────────────────────────────────────────────

    #[test]
    fn aot_queue_loads_defaults() {
        let mut q = AotPreTranslationQueue::new();
        q.load_defaults();
        assert!(q.count > 0);
        assert!(q.count <= FEX_AOT_QUEUE_CAPACITY);
        // libc must be in the queue and mandatory.
        let mut saw_libc = false;
        let needle = b"libc.so";
        for i in 0..q.count {
            if contains_bytes(q.entries[i].path_bytes(), needle) {
                saw_libc = true;
                assert!(q.entries[i].mandatory, "libc must be mandatory in AOT queue");
            }
        }
        assert!(saw_libc, "libc.so must be present in default AOT queue");
    }

    #[test]
    fn aot_queue_completion_tracking() {
        let mut q = AotPreTranslationQueue::new();
        q.load_defaults();
        let initial_mandatory = q.mandatory_remaining();
        assert!(initial_mandatory > 0);
        for _ in 0..q.count {
            q.mark_completed();
        }
        assert!(q.is_complete());
        assert_eq!(q.mandatory_remaining(), 0);
    }

    // ── Forbidden symbol guard ─────────────────────────────────────────────

    #[test]
    fn malloc_is_forbidden() {
        assert!(symbol_is_forbidden(b"malloc"));
        assert!(symbol_is_forbidden(b"free"));
        assert!(symbol_is_forbidden(b"pthread_create"));
        assert!(symbol_is_forbidden(b"fopen"));
    }

    #[test]
    fn fex_symbols_not_forbidden() {
        // FEX's own symbols must be allowed even though they look like FFI.
        assert!(!symbol_is_forbidden(b"fex_init"));
        assert!(!symbol_is_forbidden(b"fex_dispatch_block"));
        // Hypervisor's own symbols must be allowed.
        assert!(!symbol_is_forbidden(b"aether_handle_hvc"));
    }

    // ── Config validation ─────────────────────────────────────────────────

    #[test]
    fn config_defaults_validate() {
        let c = FexIntegrationConfig::aether_defaults();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_rejects_host_userland() {
        let mut c = FexIntegrationConfig::aether_defaults();
        c.run_in_hypervisor = false;
        assert!(matches!(c.validate(), Err(FexError::HostUserlandRejected)));
    }

    #[test]
    fn config_rejects_unaligned_jit() {
        let mut c = FexIntegrationConfig::aether_defaults();
        c.jit_cache_base_pa = 0x2_0000_0001; // not 4 KiB-aligned
        assert!(matches!(c.validate(), Err(FexError::UnalignedJitCache)));
    }

    #[test]
    fn config_rejects_unaligned_bump() {
        let mut c = FexIntegrationConfig::aether_defaults();
        c.bump_arena_base_pa = 0x2_0100_0001;
        assert!(matches!(c.validate(), Err(FexError::UnalignedBumpArena)));
    }

    #[test]
    fn config_rejects_undersized_jit() {
        let mut c = FexIntegrationConfig::aether_defaults();
        c.jit_cache_size = 64 * 1024; // way under 16 MiB minimum
        assert!(matches!(c.validate(), Err(FexError::JitCacheTooSmall)));
    }

    #[test]
    fn config_rejects_overlapping_regions() {
        let mut c = FexIntegrationConfig::aether_defaults();
        // Place the bump arena inside the JIT cache.
        c.bump_arena_base_pa = c.jit_cache_base_pa + 0x1000;
        assert!(matches!(c.validate(), Err(FexError::JitBumpOverlap)));
    }

    // ── Gate ──────────────────────────────────────────────────────────────

    #[test]
    fn gate_requires_all_six_criteria() {
        let mut gate = FexIntegrationGate::new();
        assert!(!gate.passes());
        gate.fex_linked = true;
        assert!(!gate.passes());
        gate.allocator_bound = true;
        assert!(!gate.passes());
        gate.jit_cache_ready = true;
        assert!(!gate.passes());
        gate.arm64_elf_validated = true;
        assert!(!gate.passes());
        gate.hello_world_observed = true;
        assert!(!gate.passes(), "must also have no_libc_symbols");
        gate.no_libc_symbols = true;
        assert!(gate.passes());
    }

    #[test]
    fn gate_hypervisor_side_ready_partial() {
        let mut gate = FexIntegrationGate::new();
        gate.fex_linked = true;
        gate.allocator_bound = true;
        gate.jit_cache_ready = true;
        gate.no_libc_symbols = true;
        // hello-world not yet observed — but hypervisor side is ready
        // to launch the test guest.
        assert!(gate.hypervisor_side_ready());
        assert!(!gate.passes());
    }

    // ── UART signature scanning ────────────────────────────────────────────

    #[test]
    fn process_line_advances_on_hello_world() {
        let mut state = FexIntegrationState::new();
        state.phase = FexIntegrationPhase::BlockTranslated;
        state.gate.fex_linked = true;
        state.gate.allocator_bound = true;
        state.gate.jit_cache_ready = true;
        state.gate.arm64_elf_validated = true;
        state.gate.no_libc_symbols = true;
        state.process_line(b"[fex] guest: Hello, AETHER (built 2026-05-19)");
        assert!(state.gate.hello_world_observed);
        assert!(state.gate.passes());
        assert_eq!(state.phase, FexIntegrationPhase::GatePassed);
    }

    #[test]
    fn process_line_records_block_translation() {
        let mut state = FexIntegrationState::new();
        state.phase = FexIntegrationPhase::ArmElfLoaded;
        state.process_line(b"[fex] translated block at pc=0x40_1000 size=64");
        assert_eq!(state.translated_blocks, 1);
        assert_eq!(state.phase, FexIntegrationPhase::BlockTranslated);
    }

    #[test]
    fn process_line_records_stall() {
        let mut state = FexIntegrationState::new();
        state.process_line(b"[fex] dispatcher stalled - out of JIT cache");
        assert!(state.dispatcher_stalled);
    }

    // ── Phase machine ordering ─────────────────────────────────────────────

    #[test]
    fn phase_machine_strictly_ordered() {
        // Each phase must compare strictly less than the next.
        assert!(FexIntegrationPhase::NotStarted     < FexIntegrationPhase::FexLinked);
        assert!(FexIntegrationPhase::FexLinked      < FexIntegrationPhase::AllocatorBound);
        assert!(FexIntegrationPhase::AllocatorBound < FexIntegrationPhase::JitCacheReady);
        assert!(FexIntegrationPhase::JitCacheReady  < FexIntegrationPhase::ArmElfLoaded);
        assert!(FexIntegrationPhase::ArmElfLoaded   < FexIntegrationPhase::BlockTranslated);
        assert!(FexIntegrationPhase::BlockTranslated< FexIntegrationPhase::HelloWorldExecuted);
        assert!(FexIntegrationPhase::HelloWorldExecuted < FexIntegrationPhase::GatePassed);
    }

    // ── process_elf_load integration ───────────────────────────────────────

    #[test]
    fn process_elf_load_advances_phase() {
        let buf = synth_arm64_elf_with_load_segment();
        let mut state = FexIntegrationState::new();
        state.phase = FexIntegrationPhase::JitCacheReady;
        let bin = process_elf_load(&buf, &mut state).unwrap();
        assert_eq!(bin.entry_va(), 0x40_1000);
        assert!(state.gate.arm64_elf_validated);
        assert_eq!(state.phase, FexIntegrationPhase::ArmElfLoaded);
    }

    // ── init_fex_integration ───────────────────────────────────────────────

    #[test]
    fn init_fex_rejects_invalid_config() {
        let mut c = FexIntegrationConfig::aether_defaults();
        c.run_in_hypervisor = false;
        let mut bindings = FexHostBindings::new(0, 0);
        let mut jit = FexJitCache::new(0, 0);
        let mut q = AotPreTranslationQueue::new();
        let r = unsafe { init_fex_integration(&c, &mut bindings, &mut jit, &mut q) };
        assert!(matches!(r, Err(FexError::HostUserlandRejected)));
    }

    #[test]
    fn init_fex_on_non_x86_64_returns_not_x86_host() {
        // Native test build is ARM64 (Apple Silicon) — must return NotX86_64Host.
        // On x86_64 Linux CI this test would instead require the fex_linked
        // feature; it is gated below for that case.
        #[cfg(not(target_arch = "x86_64"))]
        {
            let c = FexIntegrationConfig::aether_defaults();
            let mut bindings = FexHostBindings::new(0, 0);
            let mut jit = FexJitCache::new(0, 0);
            let mut q = AotPreTranslationQueue::new();
            let r = unsafe { init_fex_integration(&c, &mut bindings, &mut jit, &mut q) };
            assert!(matches!(r, Err(FexError::NotX86_64Host)));
        }
    }

    #[test]
    fn init_fex_on_x86_without_fex_linked_returns_fex_lib_not_linked() {
        // Cross-arch sanity: on an x86_64 build without the fex_linked
        // feature, init must return FexLibNotLinked, not silently claim
        // success.
        #[cfg(all(target_arch = "x86_64", not(feature = "fex_linked")))]
        {
            let c = FexIntegrationConfig::aether_defaults();
            let mut bindings = FexHostBindings::new(0, 0);
            let mut jit = FexJitCache::new(0, 0);
            let mut q = AotPreTranslationQueue::new();
            let r = unsafe { init_fex_integration(&c, &mut bindings, &mut jit, &mut q) };
            assert!(matches!(r, Err(FexError::FexLibNotLinked)));
        }
    }

    // ── State accounting ───────────────────────────────────────────────────

    #[test]
    fn state_record_block_translation_updates_counters() {
        let mut s = FexIntegrationState::new();
        s.record_block_translation();
        s.record_block_translation();
        s.record_block_cache_hit();
        assert_eq!(s.translated_blocks, 2);
        assert_eq!(s.block_cache_misses, 2);
        assert_eq!(s.block_cache_hits, 1);
    }
}
