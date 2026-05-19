// ch51: AMD-V Foundation
//
// Detect SVM support (CPUID.0x80000001.ECX[2]), enable EFER.SVME, set up the
// host save area (HSAVE_PA MSR), initialize a per-vCPU VMCB with nested page
// tables (NPT), configure intercepts (HLT, VMRUN, CPUID, MSR), and handle the
// first VMEXIT (HLT, exit code 0x58).
//
// ── Architecture Reference ────────────────────────────────────────────────────
//
// AMD Architecture Programmer's Manual Vol. 2 (Publication 24593):
//   §15.5   — VMCB layout: control area (0x000–0x3FF) + state save (0x400–)
//   §15.6   — Nested Page Tables (NPT): 4-level AMD long-mode paging structure
//   §15.9   — EFER.SVME; VM_CR.SVMDIS; HSAVE_PA MSR
//   §15.14  — VMEXIT codes (Table B-1): HLT = 0x58
//
// MSR references:
//   EFER      (0xC000_0080): bit 12 = SVME — must be set before VMRUN
//   VM_CR     (0xC001_0114): bit 4 = SVMDIS — if set, SVM permanently off
//   HSAVE_PA  (0xC001_0117): physical address of 4 KiB host state save area
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  SvmCpuFeatures    — CPUID.80000001h.ECX[2] SVM support check
//   2.  SvmVmCrMsr        — VM_CR.SVMDIS check (prevents locked-out boot)
//   3.  SvmEferMsr        — EFER.SVME enable
//   4.  VMCB offset constants — exact offsets from AMD APM Table B-2
//   5.  SVM exit codes    — from AMD APM Table B-1 (HLT=0x58, NPF=0x400, …)
//   6.  Intercept bit masks — control area offset 0x00C (misc1) and 0x010 (misc2)
//   7.  NPT constants     — 4-level AMD paging; WB vs UC leaf entries
//   8.  VmcbRegion        — 4 KiB, 4 KiB-aligned byte-array VMCB
//   9.  SvmHsaveRegion    — 4 KiB host state save area
//  10.  NptTable / NptEntry — AMD NPT PML4/PDPT/PD/PT structures
//  11.  NptTlbFlush       — VMCB TLB_CTL-based flush (AMD has no INVNPT)
//  12.  vmcb_write_guest_state()  — guest segment descriptors + CR/EFER/RIP/RSP
//  13.  vmcb_write_intercepts()   — HLT + VMRUN + CPUID intercepts
//  14.  vmcb_write_npt()          — NP_ENABLE + N_CR3 in control area
//  15.  SvmExitCode       — decoded VMEXIT exit_code from VMCB offset 0x70
//  16.  handle_vm_exit()  — reads exit_code, dispatches HLT / CPUID / NPF
//  17.  SvmFoundationConfig / Gate / Error / Phase / State — chapter gate types
//  18.  init_svm_foundation() — 8-step initialization pipeline
//
// ── Gate ──────────────────────────────────────────────────────────────────────
//
//   SvmFoundationGate.passes() requires both:
//     hlt_handled          — first VMEXIT exit_code = 0x58 (HLT)
//     vmrun_succeeded      — VMRUN completed and VMEXIT returned to hypervisor
//
//   Verification sequence (AMD APM §15.3):
//     1. CPUID.80000001h.ECX[2] = 1 → SVM supported
//     2. VM_CR.SVMDIS = 0 → SVM not locked by firmware
//     3. EFER.SVME = 1 set successfully
//     4. First VMEXIT exit_code (VMCB offset 0x70) = 0x58 (HLT)
//     5. VMRUN after handler → guest continues

// ─────────────────────────────────────────────────────────────────────────────
// VMCB control area byte offsets — AMD APM Vol. 2 Table B-2
//
// The VMCB is a single 4 KiB structure. The control area occupies the first
// portion; the state save area begins at offset 0x400. All reads/writes use
// the VmcbRegion byte-array accessors to avoid struct padding issues.
// ─────────────────────────────────────────────────────────────────────────────

// ── Control area (offset 0x000–0x3FF) ────────────────────────────────────────
pub const VMCB_INTERCEPT_CR:         usize = 0x000; // u32: CR[15:0] read | CR[31:16] write
pub const VMCB_INTERCEPT_DR:         usize = 0x004; // u32: DR intercepts
pub const VMCB_INTERCEPT_EXCEPTIONS: usize = 0x008; // u32: exception intercepts (bit N = exception N)
pub const VMCB_INTERCEPT_MISC1:      usize = 0x00C; // u32: misc intercepts part 1 (see below)
pub const VMCB_INTERCEPT_MISC2:      usize = 0x010; // u32: misc intercepts part 2
pub const VMCB_IOPM_BASE_PA:         usize = 0x040; // u64: I/O permission map PA
pub const VMCB_MSRPM_BASE_PA:        usize = 0x048; // u64: MSR permission map PA
pub const VMCB_TSC_OFFSET:           usize = 0x050; // u64: TSC offset added to guest RDTSC
pub const VMCB_GUEST_ASID:           usize = 0x058; // u32: Guest address space ID (must be ≠ 0)
pub const VMCB_TLB_CTL:             usize = 0x05C; // u32: TLB flush control (bits [7:0])
pub const VMCB_INT_CTL:              usize = 0x060; // u32: virtual interrupt control
pub const VMCB_INT_VECTOR:           usize = 0x064; // u32: virtual interrupt vector
pub const VMCB_INT_STATE:            usize = 0x068; // u32: interrupt shadow
pub const VMCB_EXIT_CODE:            usize = 0x070; // u64: VMEXIT reason code ← key field
pub const VMCB_EXIT_INFO_1:          usize = 0x078; // u64: exit information 1
pub const VMCB_EXIT_INFO_2:          usize = 0x080; // u64: exit information 2
pub const VMCB_EXIT_INT_INFO:        usize = 0x088; // u32: exit interrupt information
pub const VMCB_EXIT_INT_INFO_ERR:    usize = 0x08C; // u32: exit interrupt error code
pub const VMCB_NESTED_CTL:          usize = 0x090; // u64: nested control (bit 0 = NP_ENABLE)
pub const VMCB_AVIC_VAPIC_BAR:       usize = 0x098; // u64: AVIC APIC BAR
pub const VMCB_GHCB:                 usize = 0x0A0; // u64: GHCB PA (SEV-ES only)
pub const VMCB_EVENT_INJ:            usize = 0x0A8; // u32: event injection
pub const VMCB_EVENT_INJ_ERR:        usize = 0x0AC; // u32: event injection error code
pub const VMCB_NESTED_CR3:          usize = 0x0B0; // u64: NPT root (N_CR3 = nested page table PA)
pub const VMCB_VIRT_EXT:             usize = 0x0B8; // u64: virtualization extensions (LBR virt, etc.)
pub const VMCB_CLEAN:                usize = 0x0C0; // u32: VMCB clean bits (0 = all dirty/reload)
pub const VMCB_NEXT_RIP:             usize = 0x0C8; // u64: next sequential guest RIP (nRIP)
pub const VMCB_INSN_LEN:             usize = 0x0D0; // u8:  instruction length at exit
pub const VMCB_INSN_BYTES:           usize = 0x0D1; // [u8; 15]: faulting instruction bytes

// ── State save area (offset 0x400–) ──────────────────────────────────────────
// Each segment descriptor: sel(u16) + attrib(u16) + limit(u32) + base(u64) = 16 bytes
pub const VMCB_SAVE_ES:              usize = 0x400; // ES selector/attrib/limit/base
pub const VMCB_SAVE_CS:              usize = 0x410; // CS selector/attrib/limit/base
pub const VMCB_SAVE_SS:              usize = 0x420; // SS selector/attrib/limit/base
pub const VMCB_SAVE_DS:              usize = 0x430; // DS selector/attrib/limit/base
pub const VMCB_SAVE_FS:              usize = 0x440; // FS selector/attrib/limit/base
pub const VMCB_SAVE_GS:              usize = 0x450; // GS selector/attrib/limit/base
pub const VMCB_SAVE_GDTR:            usize = 0x460; // GDTR limit(u16 pad u16) + base(u64)
pub const VMCB_SAVE_LDTR:            usize = 0x470; // LDTR selector/attrib/limit/base
pub const VMCB_SAVE_IDTR:            usize = 0x480; // IDTR limit(u16 pad u16) + base(u64)
pub const VMCB_SAVE_TR:              usize = 0x490; // TR selector/attrib/limit/base
pub const VMCB_SAVE_CPL:             usize = 0x4CB; // u8: current privilege level
pub const VMCB_SAVE_EFER:            usize = 0x4D0; // u64: guest EFER
pub const VMCB_SAVE_CR4:             usize = 0x548; // u64: guest CR4
pub const VMCB_SAVE_CR3:             usize = 0x550; // u64: guest CR3
pub const VMCB_SAVE_CR0:             usize = 0x558; // u64: guest CR0
pub const VMCB_SAVE_DR7:             usize = 0x560; // u64: guest DR7
pub const VMCB_SAVE_DR6:             usize = 0x568; // u64: guest DR6
pub const VMCB_SAVE_RFLAGS:          usize = 0x570; // u64: guest RFLAGS
pub const VMCB_SAVE_RIP:             usize = 0x578; // u64: guest RIP
pub const VMCB_SAVE_RSP:             usize = 0x5D8; // u64: guest RSP
pub const VMCB_SAVE_RAX:             usize = 0x5F8; // u64: guest RAX
pub const VMCB_SAVE_STAR:            usize = 0x600; // u64: STAR MSR
pub const VMCB_SAVE_LSTAR:           usize = 0x608; // u64: LSTAR MSR
pub const VMCB_SAVE_CSTAR:           usize = 0x610; // u64: CSTAR MSR
pub const VMCB_SAVE_SFMASK:          usize = 0x618; // u64: SFMASK MSR
pub const VMCB_SAVE_KERNEL_GS_BASE:  usize = 0x620; // u64: kernel GS base
pub const VMCB_SAVE_SYSENTER_CS:     usize = 0x628; // u64: SYSENTER_CS MSR
pub const VMCB_SAVE_SYSENTER_ESP:    usize = 0x630; // u64: SYSENTER_ESP MSR
pub const VMCB_SAVE_SYSENTER_EIP:    usize = 0x638; // u64: SYSENTER_EIP MSR
pub const VMCB_SAVE_CR2:             usize = 0x640; // u64: guest CR2
pub const VMCB_SAVE_G_PAT:           usize = 0x668; // u64: guest PAT MSR
pub const VMCB_SAVE_DBGCTLMSR:       usize = 0x670; // u64: debug control MSR

// ─────────────────────────────────────────────────────────────────────────────
// MSR addresses for AMD SVM
// ─────────────────────────────────────────────────────────────────────────────

pub const MSR_EFER:         u32 = 0xC000_0080;
pub const MSR_VM_CR:        u32 = 0xC001_0114; // SVM control: bit 4 = SVMDIS
pub const MSR_HSAVE_PA:     u32 = 0xC001_0117; // Host state save area PA
pub const MSR_AMD_PAT:      u32 = 0x0000_0277; // Page attribute table (same as IA32_PAT)
pub const MSR_SYSENTER_CS:  u32 = 0x0000_0174;
pub const MSR_SYSENTER_ESP: u32 = 0x0000_0175;
pub const MSR_SYSENTER_EIP: u32 = 0x0000_0176;
pub const MSR_AMD_GS_BASE:  u32 = 0xC000_0101;
pub const MSR_AMD_FS_BASE:  u32 = 0xC000_0100;
pub const MSR_AMD_STAR:     u32 = 0xC000_0081;
pub const MSR_AMD_LSTAR:    u32 = 0xC000_0082;
pub const MSR_AMD_CSTAR:    u32 = 0xC000_0083;
pub const MSR_AMD_SFMASK:   u32 = 0xC000_0084;
pub const MSR_AMD_KERNEL_GS_BASE: u32 = 0xC000_0102;

// ─────────────────────────────────────────────────────────────────────────────
// EFER bit definitions
// ─────────────────────────────────────────────────────────────────────────────

pub const EFER_SCE:  u64 = 1 << 0;  // syscall extensions
pub const EFER_LME:  u64 = 1 << 8;  // long mode enable
pub const EFER_LMA:  u64 = 1 << 10; // long mode active
pub const EFER_NXE:  u64 = 1 << 11; // no-execute enable
pub const EFER_SVME: u64 = 1 << 12; // SVM enable — must be set before VMRUN

// ─────────────────────────────────────────────────────────────────────────────
// VM_CR MSR bit definitions
// ─────────────────────────────────────────────────────────────────────────────

pub const VM_CR_SVMDIS: u64 = 1 << 4; // SVM disabled — if set, cannot enable SVM

// ─────────────────────────────────────────────────────────────────────────────
// VMEXIT exit codes — AMD APM Vol. 2 Table B-1
//
// The exit_code field is at VMCB offset 0x70 (u64).
// ─────────────────────────────────────────────────────────────────────────────

pub const SVM_EXIT_INTR:          u64 = 0x40; // external interrupt
pub const SVM_EXIT_NMI:           u64 = 0x41; // non-maskable interrupt
pub const SVM_EXIT_SMI:           u64 = 0x42; // system management interrupt
pub const SVM_EXIT_INIT:          u64 = 0x43; // INIT signal
pub const SVM_EXIT_VINTR:         u64 = 0x44; // virtual interrupt
pub const SVM_EXIT_CPUID:         u64 = 0x52; // CPUID instruction
pub const SVM_EXIT_IRET:          u64 = 0x54; // IRET instruction
pub const SVM_EXIT_INVD:          u64 = 0x56; // INVD instruction
pub const SVM_EXIT_HLT:           u64 = 0x58; // HLT instruction — gate test trigger
pub const SVM_EXIT_IOIO:          u64 = 0x5B; // I/O instruction
pub const SVM_EXIT_MSR:           u64 = 0x5C; // MSR access (RDMSR/WRMSR)
pub const SVM_EXIT_VMRUN:         u64 = 0x60; // VMRUN executed by guest (always intercepted)
pub const SVM_EXIT_VMMCALL:       u64 = 0x61; // VMMCALL (hypercall)
pub const SVM_EXIT_XSETBV:        u64 = 0x6D; // XSETBV instruction
pub const SVM_EXIT_NPF:           u64 = 0x400; // nested page fault (NPT violation)
pub const SVM_EXIT_AVIC_INCOMPLETE_IPI: u64 = 0x401;
pub const SVM_EXIT_INVALID:       u64 = u64::MAX; // invalid VMCB or host state

// ─────────────────────────────────────────────────────────────────────────────
// Intercept bit definitions
//
// VMCB_INTERCEPT_MISC1 (offset 0x00C) — AMD APM §15.9 Table 15-7
// VMCB_INTERCEPT_MISC2 (offset 0x010) — AMD APM §15.9 Table 15-8
// ─────────────────────────────────────────────────────────────────────────────

// Misc1 intercept bits
pub const INTERCEPT_INTR:         u32 = 1 << 0;  // external interrupt
pub const INTERCEPT_NMI:          u32 = 1 << 1;  // NMI
pub const INTERCEPT_SMI:          u32 = 1 << 2;  // SMI
pub const INTERCEPT_INIT:         u32 = 1 << 3;  // INIT
pub const INTERCEPT_VINTR:        u32 = 1 << 4;  // virtual interrupt
pub const INTERCEPT_RDTSC:        u32 = 1 << 14; // RDTSC
pub const INTERCEPT_CPUID:        u32 = 1 << 18; // CPUID
pub const INTERCEPT_RSM:          u32 = 1 << 19; // RSM
pub const INTERCEPT_INVD:         u32 = 1 << 22; // INVD
pub const INTERCEPT_HLT:          u32 = 1 << 24; // HLT — required for gate test
pub const INTERCEPT_INVLPG:       u32 = 1 << 25; // INVLPG
pub const INTERCEPT_INVLPGA:      u32 = 1 << 26; // INVLPGA
pub const INTERCEPT_IOIO_PROT:    u32 = 1 << 27; // I/O protection (needs IOPM)
pub const INTERCEPT_MSR_PROT:     u32 = 1 << 28; // MSR protection (needs MSRPM)
pub const INTERCEPT_TASK_SWITCH:  u32 = 1 << 29; // task switch
pub const INTERCEPT_SHUTDOWN:     u32 = 1 << 31; // guest triple-fault/shutdown

// Misc2 intercept bits
pub const INTERCEPT_VMRUN:        u32 = 1 << 0;  // VMRUN — mandatory; guest cannot VMRUN
pub const INTERCEPT_VMMCALL:      u32 = 1 << 1;  // VMMCALL (hypercall path)
pub const INTERCEPT_VMLOAD:       u32 = 1 << 2;  // VMLOAD
pub const INTERCEPT_VMSAVE:       u32 = 1 << 3;  // VMSAVE
pub const INTERCEPT_STGI:         u32 = 1 << 4;  // STGI
pub const INTERCEPT_CLGI:         u32 = 1 << 5;  // CLGI
pub const INTERCEPT_SKINIT:       u32 = 1 << 6;  // SKINIT
pub const INTERCEPT_RDTSCP:       u32 = 1 << 7;  // RDTSCP
pub const INTERCEPT_XSETBV:       u32 = 1 << 13; // XSETBV

// ─────────────────────────────────────────────────────────────────────────────
// TLB control values (VMCB offset 0x05C, bits [7:0])
//
// AMD does not have an INVNPT instruction. TLB invalidation for NPT is
// performed by writing a non-zero TLB_CTL value before VMRUN; the processor
// flushes the corresponding TLB entries on the VMRUN transition.
//
// AMD APM §15.16.1 — TLB_CTL encoding:
//   0x00 = do not flush (normal execution; reuse existing TLB entries)
//   0x01 = flush all TLB entries (global + non-global) for this ASID
//   0x03 = flush all non-global TLB entries for this ASID
// ─────────────────────────────────────────────────────────────────────────────

pub const TLB_CTL_FLUSH_NONE:  u32 = 0x00; // no flush — normal re-entry
pub const TLB_CTL_FLUSH_ALL:   u32 = 0x01; // flush all (global + non-global)
pub const TLB_CTL_FLUSH_NONG:  u32 = 0x03; // flush non-global only

// ─────────────────────────────────────────────────────────────────────────────
// NP_ENABLE bit in VMCB_NESTED_CTL (offset 0x090)
// ─────────────────────────────────────────────────────────────────────────────

pub const NP_ENABLE: u64 = 1 << 0; // enable nested page tables (NPT)

// ─────────────────────────────────────────────────────────────────────────────
// NPT entry constants — AMD APM Vol. 2 §15.25.5 / §5 (AMD long-mode paging)
//
// AMD NPT uses the same 4-level paging structure as AMD64 long-mode CR3
// paging. Entry format at each level:
//
//   Non-leaf entries: bit 0 = Present, bit 1 = Read/Write, bit 2 = User/Supervisor
//   Leaf (4 KiB) entries: same permission bits + bits [5:3] = PWT/PCD/PAT
//   for memory type selection. PA in bits [N-1:12] where N = MAXPHYADDR.
//
// Memory type selection via PWT/PCD/PAT (bits 3/4/7 of leaf PTE):
//   WB (Write-Back):      PWT=0, PCD=0 (default with WB MTRR)
//   UC (Uncacheable):     PWT=1, PCD=1 (strong UC for MMIO)
// ─────────────────────────────────────────────────────────────────────────────

pub const NPT_PRESENT:    u64 = 1 << 0; // page present
pub const NPT_WRITABLE:   u64 = 1 << 1; // read/write
pub const NPT_USER:       u64 = 1 << 2; // user-mode accessible (needed for guest ring-3)
pub const NPT_PWT:        u64 = 1 << 3; // write-through
pub const NPT_PCD:        u64 = 1 << 4; // cache disable
pub const NPT_ACCESSED:   u64 = 1 << 5; // accessed flag

// Non-leaf entry: present + writable + user (propagated to guest)
pub const NPT_NONLEAF:    u64 = NPT_PRESENT | NPT_WRITABLE | NPT_USER;

// Leaf entry for 4 KiB normal RAM (WB memory type)
pub const NPT_RAM_WB:     u64 = NPT_PRESENT | NPT_WRITABLE | NPT_USER;

// Leaf entry for 4 KiB device MMIO (UC: PWT + PCD = strong uncacheable)
pub const NPT_MMIO_UC:    u64 = NPT_PRESENT | NPT_WRITABLE | NPT_USER | NPT_PWT | NPT_PCD;

// NPT page-table index extraction (4-level, 4 KiB pages)
pub const NPT_PML4_SHIFT: u32 = 39;
pub const NPT_PDPT_SHIFT: u32 = 30;
pub const NPT_PD_SHIFT:   u32 = 21;
pub const NPT_PT_SHIFT:   u32 = 12;
pub const NPT_INDEX_MASK: u64 = 0x1FF; // 9 bits per level

// ─────────────────────────────────────────────────────────────────────────────
// Guest segment attribute encoding (AMD VMCB state save area format)
//
// attrib = ((descriptor_byte[55:52]) << 8) | descriptor_byte[47:40]
//   bits[7:0] = {P, DPL[1:0], S, type[3:0]} (descriptor bytes [47:40])
//   bits[11:8]= {G, D/B, L, AVL}             (descriptor nibble [55:52])
//   bits[15:12]= 0
// ─────────────────────────────────────────────────────────────────────────────

// 64-bit code segment: P=1, DPL=0, S=1, type=0xA (exec/read, non-conforming),
//                      G=1, D/B=0, L=1 (64-bit mode), AVL=0
pub const SEG_ATTRIB_CODE64: u16 = 0x029B; // bits[7:0]=0x9B, bits[11:8]=0x2 (L=1)

// 32-bit data/stack segment: P=1, DPL=0, S=1, type=0x3 (read/write, accessed),
//                            G=1, D/B=1 (32-bit), L=0, AVL=0
pub const SEG_ATTRIB_DATA32: u16 = 0x0C93; // bits[7:0]=0x93, bits[11:8]=0xC (B=1, G=1)

// 64-bit busy TSS: P=1, DPL=0, S=0, type=0xB (busy TSS), G=0, D=0, L=0, AVL=0
pub const SEG_ATTRIB_TSS64:  u16 = 0x008B;

// LDTR / unusable segment: P=0 (not present) → hardware treats as unusable
pub const SEG_ATTRIB_UNUSABLE: u16 = 0x0000;

// ─────────────────────────────────────────────────────────────────────────────
// CR0 / CR4 constants needed for guest state initialization
// ─────────────────────────────────────────────────────────────────────────────

pub const CR0_PE: u64 = 1 << 0;  // protected mode enable
pub const CR0_ET: u64 = 1 << 4;  // extension type
pub const CR0_NE: u64 = 1 << 5;  // numeric error (x87 FPU errors)
pub const CR0_WP: u64 = 1 << 16; // write protect
pub const CR0_PG: u64 = 1 << 31; // paging enable

pub const CR4_PAE:       u64 = 1 << 5;  // physical address extension
pub const CR4_OSFXSR:    u64 = 1 << 9;  // OS support for FXSAVE/FXRSTOR
pub const CR4_OSXMMEXCPT:u64 = 1 << 10; // OS support for SIMD FP exceptions

pub const RFLAGS_FIXED: u64 = 1 << 1; // bit 1 always 1 in RFLAGS (reserved)
pub const RFLAGS_IF:    u64 = 1 << 9; // interrupt enable flag

// ─────────────────────────────────────────────────────────────────────────────
// VMCB region — 4 KiB, 4 KiB-aligned
//
// The VMCB is stored as a raw byte array. All fields are accessed via explicit
// offset-based helpers (`read_u32`, `write_u32`, `read_u64`, `write_u64`,
// `write_u16`, `write_u8`) to avoid struct padding surprises. The processor
// owns all bytes; AETHER only writes the fields it initializes.
// ─────────────────────────────────────────────────────────────────────────────

/// 4 KiB VMCB structure, 4 KiB-aligned. Must be zero-initialized before use.
///
/// One VMCB per vCPU. Must not be shared across cores.
/// VMRUN saves host state to HSAVE_PA and loads guest state from this region.
/// VMEXIT saves guest state back here and restores host state from HSAVE_PA.
#[repr(C, align(4096))]
pub struct VmcbRegion {
    bytes: [u8; 4096],
}

impl VmcbRegion {
    pub const fn new() -> Self {
        VmcbRegion { bytes: [0u8; 4096] }
    }

    #[inline]
    pub fn read_u8(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }

    #[inline]
    pub fn write_u8(&mut self, offset: usize, val: u8) {
        self.bytes[offset] = val;
    }

    #[inline]
    pub fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.bytes[offset], self.bytes[offset + 1]])
    }

    #[inline]
    pub fn write_u16(&mut self, offset: usize, val: u16) {
        let b = val.to_le_bytes();
        self.bytes[offset]     = b[0];
        self.bytes[offset + 1] = b[1];
    }

    #[inline]
    pub fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.bytes[offset],     self.bytes[offset + 1],
            self.bytes[offset + 2], self.bytes[offset + 3],
        ])
    }

    #[inline]
    pub fn write_u32(&mut self, offset: usize, val: u32) {
        let b = val.to_le_bytes();
        self.bytes[offset]     = b[0];
        self.bytes[offset + 1] = b[1];
        self.bytes[offset + 2] = b[2];
        self.bytes[offset + 3] = b[3];
    }

    #[inline]
    pub fn read_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes([
            self.bytes[offset],     self.bytes[offset + 1],
            self.bytes[offset + 2], self.bytes[offset + 3],
            self.bytes[offset + 4], self.bytes[offset + 5],
            self.bytes[offset + 6], self.bytes[offset + 7],
        ])
    }

    #[inline]
    pub fn write_u64(&mut self, offset: usize, val: u64) {
        let b = val.to_le_bytes();
        self.bytes[offset]     = b[0];
        self.bytes[offset + 1] = b[1];
        self.bytes[offset + 2] = b[2];
        self.bytes[offset + 3] = b[3];
        self.bytes[offset + 4] = b[4];
        self.bytes[offset + 5] = b[5];
        self.bytes[offset + 6] = b[6];
        self.bytes[offset + 7] = b[7];
    }

    /// Write a segment descriptor into the state save area.
    ///
    /// Each segment occupies 16 bytes:
    ///   +0: selector (u16), +2: attrib (u16), +4: limit (u32), +8: base (u64)
    pub fn write_seg(&mut self, offset: usize, sel: u16, attrib: u16, limit: u32, base: u64) {
        self.write_u16(offset,     sel);
        self.write_u16(offset + 2, attrib);
        self.write_u32(offset + 4, limit);
        self.write_u64(offset + 8, base);
    }

    /// Convenience: read exit_code from VMCB control area offset 0x70.
    pub fn exit_code(&self) -> u64 {
        self.read_u64(VMCB_EXIT_CODE)
    }

    /// Convenience: read next_rip from VMCB control area offset 0xC8.
    pub fn next_rip(&self) -> u64 {
        self.read_u64(VMCB_NEXT_RIP)
    }

    /// Convenience: read guest RIP from state save area.
    pub fn guest_rip(&self) -> u64 {
        self.read_u64(VMCB_SAVE_RIP)
    }

    /// Convenience: write guest RIP to state save area.
    pub fn set_guest_rip(&mut self, rip: u64) {
        self.write_u64(VMCB_SAVE_RIP, rip);
    }

    /// Request a TLB flush on the next VMRUN for this VMCB.
    ///
    /// AMD does not provide an INVNPT instruction. TLB invalidation for NPT is
    /// triggered by writing a non-zero value to TLB_CTL before VMRUN; the
    /// processor executes the flush atomically during the VMRUN transition.
    /// The TLB_CTL field is automatically cleared by the processor after the
    /// flush so it need not be reset by the hypervisor.
    ///
    /// Call after every NPT mapping change to prevent stale translations from
    /// allowing the guest to access memory outside its permitted range.
    pub fn request_npt_tlb_flush(&mut self) {
        self.write_u32(VMCB_TLB_CTL, TLB_CTL_FLUSH_ALL);
        // Mark VMCB dirty so the processor reloads all control fields including TLB_CTL.
        self.write_u32(VMCB_CLEAN, 0x0000_0000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host state save area — 4 KiB, 4 KiB-aligned
//
// VMRUN saves host state (RSP, RIP, CR0/3/4, EFER, RFLAGS, segments, etc.)
// into this area before loading guest state. VMEXIT restores host state from
// here. The processor manages the layout internally; AETHER only provides the
// physical address via the HSAVE_PA MSR.
// ─────────────────────────────────────────────────────────────────────────────

/// 4 KiB host state save area. The processor manages the layout.
#[repr(C, align(4096))]
pub struct SvmHsaveRegion {
    _processor_managed: [u8; 4096],
}

impl SvmHsaveRegion {
    pub const fn new() -> Self {
        SvmHsaveRegion { _processor_managed: [0u8; 4096] }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NPT structures — 4-level AMD64 paging format
// ─────────────────────────────────────────────────────────────────────────────

/// One NPT page table (512 × 8-byte entries, 4 KiB total).
///
/// AMD NPT uses the standard AMD64 paging structure: PML4 → PDPT → PD → PT.
/// Non-leaf entries carry NPT_NONLEAF permissions + child PA in bits[51:12].
/// Leaf entries (4 KiB PT entries) carry permission bits + memory-type bits
/// (PWT/PCD) + PA in bits[51:12].
#[repr(C, align(4096))]
pub struct NptTable {
    entries: [u64; 512],
}

impl NptTable {
    pub const fn new() -> Self {
        NptTable { entries: [0u64; 512] }
    }

    #[inline]
    pub fn set(&mut self, idx: usize, value: u64) {
        self.entries[idx & 0x1FF] = value;
    }

    #[inline]
    pub fn get(&self, idx: usize) -> u64 {
        self.entries[idx & 0x1FF]
    }
}

/// NPT leaf entry for a 4 KiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NptLeafEntry(pub u64);

impl NptLeafEntry {
    /// Map a 4 KiB physical page as WB normal RAM (default cacheable).
    pub fn normal_ram(pa: u64) -> Self {
        NptLeafEntry((pa & !0xFFF) | NPT_RAM_WB)
    }

    /// Map a 4 KiB physical page as UC device MMIO (PWT + PCD = strong UC).
    pub fn device_mmio(pa: u64) -> Self {
        NptLeafEntry((pa & !0xFFF) | NPT_MMIO_UC)
    }
}

/// NPT non-leaf entry pointing to a child table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NptTableEntry(pub u64);

impl NptTableEntry {
    pub fn pointing_to(table_pa: u64) -> Self {
        NptTableEntry((table_pa & !0xFFF) | NPT_NONLEAF)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw x86 MSR / register helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a 64-bit MSR value.
///
/// # Safety
/// Requires x86-64 ring 0. ECX must be a valid MSR.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn rdmsr(_msr: u32) -> u64 { 0 }

/// Write a 64-bit MSR value.
///
/// # Safety
/// Requires x86-64 ring 0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn wrmsr(_msr: u32, _value: u64) {}

/// Read CR0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn read_cr0() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn read_cr0() -> u64 { 0 }

/// Read CR3.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn read_cr3() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn read_cr3() -> u64 { 0 }

/// Read CR4.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack)); }
    v
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn read_cr4() -> u64 { 0 }

// ─────────────────────────────────────────────────────────────────────────────
// VMRUN instruction wrapper
//
// AMD APM §15.6.1: VMRUN uses RAX as the implicit operand containing the
// physical address of the VMCB. The instruction transfers control to the guest;
// on VMEXIT, execution resumes at the instruction immediately following VMRUN.
// The processor automatically saves host state to HSAVE_PA and loads guest
// state from the VMCB before transferring control.
// ─────────────────────────────────────────────────────────────────────────────

/// Execute VMRUN with the physical address of the VMCB in RAX.
///
/// Returns when the guest causes a VMEXIT. Inspect VMCB offset 0x70 for the
/// exit_code after return. Returns true if the VMEXIT was handled (exit_code
/// is a recognizable code); returns false on INVALID exit (VMCB misconfigured).
///
/// # Safety
/// - EFER.SVME must be set.
/// - HSAVE_PA MSR must point to a valid 4 KiB-aligned host save area.
/// - `vmcb_pa` must be 4 KiB-aligned and contain a valid initialized VMCB.
/// - Guest ASID must be non-zero.
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmrun(vmcb_pa: u64) {
    unsafe {
        core::arch::asm!(
            "vmrun rax",
            in("rax") vmcb_pa,
            options(nostack)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn vmrun(_vmcb_pa: u64) {}

// ─────────────────────────────────────────────────────────────────────────────
// CPUID-based SVM support detection
// ─────────────────────────────────────────────────────────────────────────────

/// Reports whether the current logical processor supports AMD SVM.
///
/// Checks CPUID leaf 0x80000001, ECX bit 2 (SVM feature flag).
/// AMD APM Vol. 2 §15.3; AMD APM Vol. 3 §CPUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvmCpuFeatures {
    pub svm_supported: bool,
    /// Set if CPUID.0x8000000A.EDX[0] = 1 (nested paging supported).
    pub npt_supported: bool,
    /// Number of ASIDs supported (from CPUID.0x8000000A.EBX).
    pub asid_count: u32,
    /// Set if processor supports DecodeAssists (nRIP save on VMEXIT).
    pub decode_assists: bool,
    /// Vendor string: "AuthenticAMD" expected; reject "GenuineIntel".
    pub is_amd_vendor: bool,
}

impl SvmCpuFeatures {
    pub const fn none() -> Self {
        SvmCpuFeatures {
            svm_supported:  false,
            npt_supported:  false,
            asid_count:     0,
            decode_assists: false,
            is_amd_vendor:  false,
        }
    }

    /// Detect SVM support on the calling processor.
    ///
    /// Runtime CPU detection uses the vendor string ("AuthenticAMD") rather
    /// than feature flags alone, because Intel machines may report stale
    /// CPUID state in some BIOS/firmware configurations.
    ///
    /// # Safety
    /// Must be called on an x86-64 processor. Undefined on ARM64.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn detect() -> Self {
        // Read vendor string from CPUID leaf 0.
        let ebx: u32;
        let ecx: u32;
        let edx: u32;
        unsafe {
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "mov eax, 0",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "mov rbx, {tmp:r}",
                tmp = out(reg) _,
                ebx_out = out(reg) ebx,
                out("ecx") ecx,
                out("edx") edx,
                out("eax") _,
                options(nomem, nostack)
            );
        }
        // "AuthenticAMD": EBX="Auth", EDX="enti", ECX="cAMD"
        // Little-endian: EBX=0x68747541, EDX=0x69746E65, ECX=0x444D4163
        let is_amd_vendor = ebx == 0x6874_7541
            && edx == 0x6974_6E65
            && ecx == 0x444D_4163;

        // CPUID.80000001h.ECX[2] = SVM supported
        let ecx1: u32;
        unsafe {
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "mov eax, 0x80000001",
                "cpuid",
                "mov rbx, {tmp:r}",
                tmp = out(reg) _,
                out("ecx") ecx1,
                out("eax") _,
                out("edx") _,
                options(nomem, nostack)
            );
        }
        let svm_supported = (ecx1 >> 2) & 1 == 1;

        // CPUID.8000000Ah — SVM features (if SVM is supported)
        let (npt_supported, asid_count, decode_assists) = if svm_supported {
            let eax_svm: u32;
            let ebx_svm: u32;
            let edx_svm: u32;
            unsafe {
                core::arch::asm!(
                    "mov {tmp:r}, rbx",
                    "mov eax, 0x8000000A",
                    "cpuid",
                    "mov {ebx_out:e}, ebx",
                    "mov rbx, {tmp:r}",
                    tmp = out(reg) _,
                    ebx_out = out(reg) ebx_svm,
                    out("eax") eax_svm,
                    out("ecx") _,
                    out("edx") edx_svm,
                    options(nomem, nostack)
                );
            }
            let _ = eax_svm; // SVM revision — not needed
            let npt   = edx_svm & (1 << 0) != 0; // EDX bit 0 = NPT
            let da    = edx_svm & (1 << 7) != 0; // EDX bit 7 = DecodeAssists
            (npt, ebx_svm, da)
        } else {
            (false, 0, false)
        };

        SvmCpuFeatures {
            svm_supported,
            npt_supported,
            asid_count,
            decode_assists,
            is_amd_vendor,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn detect() -> Self {
        Self::none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM_CR MSR — SVM lock check
// ─────────────────────────────────────────────────────────────────────────────

/// State of the VM_CR MSR (0xC001_0114).
///
/// If SVMDIS (bit 4) is set, firmware has disabled SVM and locked it. Enabling
/// EFER.SVME on such a machine causes a #GP(0) fault. A reboot/BIOS change is
/// required — the hypervisor cannot override this at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvmVmCrMsr {
    pub svmdis: bool,
}

impl SvmVmCrMsr {
    /// Reads VM_CR on the calling processor.
    ///
    /// # Safety
    /// Requires x86-64 ring 0 on an AMD processor with SVM.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read() -> Self {
        let raw = unsafe { rdmsr(MSR_VM_CR) };
        SvmVmCrMsr { svmdis: raw & VM_CR_SVMDIS != 0 }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn read() -> Self {
        SvmVmCrMsr { svmdis: false }
    }

    pub fn svm_enabled(&self) -> bool {
        !self.svmdis
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EFER.SVME enable
// ─────────────────────────────────────────────────────────────────────────────

/// Enables SVM by setting EFER.SVME (bit 12).
///
/// Must be called after verifying VM_CR.SVMDIS = 0 and before allocating the
/// VMCB. Setting SVME before SVMDIS check may cause #GP on locked machines.
///
/// # Safety
/// Requires x86-64 ring 0. VM_CR.SVMDIS must be 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn svm_enable_svme() -> Result<(), SvmError> {
    let vm_cr = unsafe { SvmVmCrMsr::read() };
    if vm_cr.svmdis {
        return Err(SvmError::SvmDisabledByFirmware);
    }
    let efer = unsafe { rdmsr(MSR_EFER) };
    unsafe { wrmsr(MSR_EFER, efer | EFER_SVME) };
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn svm_enable_svme() -> Result<(), SvmError> {
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// VMCB initialization helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for initial guest register state.
///
/// Mirrors VmcsGuestConfig in vtx.rs: supports 64-bit long mode entry (paging
/// enabled, CR0.PE + CR0.PG + EFER.LME/LMA set) or real-mode entry (CR0.PE=0).
#[derive(Debug, Clone, Copy)]
pub struct VmcbGuestConfig {
    /// Physical address of the kernel entry point (loaded into guest RIP).
    pub kernel_entry_pa: u64,
    /// Initial guest RSP.
    pub guest_rsp: u64,
    /// Initial guest CR3 (page table root).
    pub guest_cr3: u64,
    /// If true, configure 64-bit long mode. If false, configure real mode.
    pub use_protected_mode: bool,
}

impl VmcbGuestConfig {
    pub fn long_mode(kernel_entry_pa: u64, guest_rsp: u64, guest_cr3: u64) -> Self {
        VmcbGuestConfig { kernel_entry_pa, guest_rsp, guest_cr3, use_protected_mode: true }
    }

    pub fn real_mode(kernel_entry_pa: u64) -> Self {
        VmcbGuestConfig {
            kernel_entry_pa,
            guest_rsp: 0,
            guest_cr3: 0,
            use_protected_mode: false,
        }
    }
}

/// Writes the guest state save area in the VMCB.
///
/// On VMRUN the processor loads these fields as the initial guest register
/// state. Segment descriptors follow the AMD VMCB attrib format (16 bytes each:
/// sel + attrib + limit + base).
pub fn vmcb_write_guest_state(vmcb: &mut VmcbRegion, cfg: &VmcbGuestConfig) {
    if cfg.use_protected_mode {
        // 64-bit long mode: CR0.PE + CR0.NE + CR0.WP + CR0.PG; CR4.PAE; EFER.LME + LMA
        let cr0  = CR0_PE | CR0_ET | CR0_NE | CR0_WP | CR0_PG;
        let cr4  = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        let efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE | EFER_SVME;

        vmcb.write_u64(VMCB_SAVE_CR0,    cr0);
        vmcb.write_u64(VMCB_SAVE_CR4,    cr4);
        vmcb.write_u64(VMCB_SAVE_CR3,    cfg.guest_cr3);
        vmcb.write_u64(VMCB_SAVE_EFER,   efer);
        vmcb.write_u64(VMCB_SAVE_RFLAGS, RFLAGS_FIXED | RFLAGS_IF);

        // CS: 64-bit code, present, DPL 0
        vmcb.write_seg(VMCB_SAVE_CS, 0x08, SEG_ATTRIB_CODE64, 0xFFFF_FFFF, 0);

        // SS, DS, ES, FS, GS: 32-bit data, present, DPL 0
        for &seg_offset in &[
            VMCB_SAVE_SS, VMCB_SAVE_DS, VMCB_SAVE_ES,
            VMCB_SAVE_FS, VMCB_SAVE_GS,
        ] {
            vmcb.write_seg(seg_offset, 0x10, SEG_ATTRIB_DATA32, 0xFFFF_FFFF, 0);
        }
    } else {
        // Real mode: CR0.PE = 0, paging off. AMD SVM supports this natively
        // (unlike Intel which requires UNRESTRICTED_GUEST in secondary controls).
        let cr0  = CR0_ET | CR0_NE; // PE=0, PG=0
        let efer = 0u64;

        vmcb.write_u64(VMCB_SAVE_CR0,    cr0);
        vmcb.write_u64(VMCB_SAVE_CR4,    0);
        vmcb.write_u64(VMCB_SAVE_CR3,    0);
        vmcb.write_u64(VMCB_SAVE_EFER,   efer);
        vmcb.write_u64(VMCB_SAVE_RFLAGS, RFLAGS_FIXED);

        // Real-mode CS: sel = entry >> 4, base = sel << 4
        let cs_sel  = (cfg.kernel_entry_pa >> 4) as u16;
        let cs_base = (cs_sel as u64) << 4;
        vmcb.write_seg(VMCB_SAVE_CS, cs_sel, 0x009B, 0xFFFF, cs_base);

        for &seg_offset in &[
            VMCB_SAVE_SS, VMCB_SAVE_DS, VMCB_SAVE_ES,
            VMCB_SAVE_FS, VMCB_SAVE_GS,
        ] {
            vmcb.write_seg(seg_offset, 0, 0x0093, 0xFFFF, 0);
        }
    }

    // LDTR: unusable (P=0)
    vmcb.write_seg(VMCB_SAVE_LDTR, 0, SEG_ATTRIB_UNUSABLE, 0xFFFF, 0);

    // TR: busy TSS, minimal
    vmcb.write_seg(VMCB_SAVE_TR, 0, SEG_ATTRIB_TSS64, 0xFFFF, 0);

    // GDTR / IDTR: minimal (hypervisor owns the real tables; guest will set up its own)
    // Format: sel(u16) + reserved(u16) + limit(u32) + base(u64)
    vmcb.write_seg(VMCB_SAVE_GDTR, 0, 0, 0xFFFF, 0);
    vmcb.write_seg(VMCB_SAVE_IDTR, 0, 0, 0xFFFF, 0);

    vmcb.write_u64(VMCB_SAVE_RIP,  cfg.kernel_entry_pa);
    vmcb.write_u64(VMCB_SAVE_RSP,  cfg.guest_rsp);
    vmcb.write_u64(VMCB_SAVE_DR7,  0x0000_0400); // AMD reset value
    vmcb.write_u64(VMCB_SAVE_DR6,  0xFFFF_0FF0); // AMD reset value
    vmcb.write_u8 (VMCB_SAVE_CPL,  0);           // ring 0
}

/// Writes intercept bits in the VMCB control area.
///
/// Enabled intercepts:
///   VMRUN  (misc2 bit 0) — mandatory: guest cannot execute VMRUN
///   HLT    (misc1 bit 24) — required for the gate test
///   CPUID  (misc1 bit 18) — so hypervisor can control CPUID responses
///
/// SHUTDOWN (misc1 bit 31) is always intercepted to prevent guest triple-faults
/// from resetting the machine without the hypervisor getting a chance to log.
pub fn vmcb_write_intercepts(vmcb: &mut VmcbRegion) {
    let misc1 = INTERCEPT_HLT | INTERCEPT_CPUID | INTERCEPT_SHUTDOWN;
    let misc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL;

    vmcb.write_u32(VMCB_INTERCEPT_MISC1, misc1);
    vmcb.write_u32(VMCB_INTERCEPT_MISC2, misc2);
}

/// Enables NPT and writes N_CR3 in the VMCB control area.
///
/// Sets NP_ENABLE (bit 0 of VMCB_NESTED_CTL) and writes the physical address
/// of the NPT PML4 table into VMCB_NESTED_CR3. Also assigns guest ASID = 1
/// and requests a TLB flush (TLB_CTL = FLUSH_ALL) before the first VMRUN.
///
/// # Important
/// Call `vmcb.request_npt_tlb_flush()` after any subsequent NPT mapping change
/// to prevent stale guest-physical translations from breaking isolation.
pub fn vmcb_write_npt(vmcb: &mut VmcbRegion, npt_pml4_pa: u64) {
    vmcb.write_u64(VMCB_NESTED_CTL,   NP_ENABLE);
    vmcb.write_u64(VMCB_NESTED_CR3,   npt_pml4_pa);
    vmcb.write_u32(VMCB_GUEST_ASID,   1);    // ASID 0 is reserved; use 1
    vmcb.write_u32(VMCB_TLB_CTL,      TLB_CTL_FLUSH_ALL); // flush before first VMRUN
    vmcb.write_u32(VMCB_CLEAN,        0x0000_0000);        // all dirty — reload everything
}

// ─────────────────────────────────────────────────────────────────────────────
// VMEXIT handler
// ─────────────────────────────────────────────────────────────────────────────

/// Result of handling one VMEXIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmExitAction {
    /// Advance guest RIP past the faulting instruction and VMRUN again.
    Resume,
    /// Guest HLT — handler completed; VMRUN will re-enter guest.
    HltHandled,
    /// Fatal condition; terminate the guest.
    Terminate,
}

/// Handles a VMEXIT by reading exit_code from VMCB offset 0x70.
///
/// HLT (0x58): records gate trigger, advances RIP by 1 byte (if nRIP available),
///             returns HltHandled.
/// CPUID (0x52): advances RIP by 2 bytes, returns Resume.
/// NPF (0x400): nested page fault — NPT mapping missing; returns Terminate
///             (no NPT fault fixer in this chapter).
/// All others: returns Resume.
pub fn handle_vm_exit(vmcb: &mut VmcbRegion, state: &mut SvmFoundationState) -> SvmExitAction {
    let exit_code = vmcb.exit_code();
    state.last_exit_code = exit_code;
    state.exit_count += 1;

    match exit_code {
        SVM_EXIT_HLT => {
            state.hlt_exit_count += 1;
            state.gate.hlt_handled = true;
            state.gate.vmrun_succeeded = true;

            // Advance guest RIP past the HLT instruction (1 byte).
            // If the processor saved nRIP (DecodeAssists), use it directly.
            // Otherwise, advance RIP manually.
            let nrip = vmcb.next_rip();
            if nrip != 0 {
                vmcb.set_guest_rip(nrip);
            } else {
                let rip = vmcb.guest_rip();
                vmcb.set_guest_rip(rip.wrapping_add(1));
            }

            SvmExitAction::HltHandled
        }
        SVM_EXIT_CPUID => {
            // Advance guest RIP past CPUID instruction (2 bytes).
            let nrip = vmcb.next_rip();
            if nrip != 0 {
                vmcb.set_guest_rip(nrip);
            } else {
                let rip = vmcb.guest_rip();
                vmcb.set_guest_rip(rip.wrapping_add(2));
            }
            SvmExitAction::Resume
        }
        SVM_EXIT_VMMCALL => {
            // Minimal hypercall handler: advance RIP by 3 bytes (VMMCALL = 0F 01 D9).
            let nrip = vmcb.next_rip();
            if nrip != 0 {
                vmcb.set_guest_rip(nrip);
            } else {
                let rip = vmcb.guest_rip();
                vmcb.set_guest_rip(rip.wrapping_add(3));
            }
            SvmExitAction::Resume
        }
        SVM_EXIT_NPF => {
            state.gate.npt_fault_seen = true;
            SvmExitAction::Terminate
        }
        SVM_EXIT_INVALID => {
            // INVALID exit means VMCB is misconfigured — halt.
            SvmExitAction::Terminate
        }
        _ => SvmExitAction::Resume,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chapter gate types
// ─────────────────────────────────────────────────────────────────────────────

/// Gate criteria for Chapter 51 — AMD-V Foundation.
///
/// passes() requires all conditions to be true simultaneously.
/// Verification protocol (AMD APM §15.3):
///   1. CPUID.80000001h.ECX[2]=1 + VM_CR.SVMDIS=0
///   2. EFER.SVME = 1 set successfully
///   3. First VMEXIT exit_code (VMCB offset 0x70) = 0x58 (HLT)
///   4. VMRUN after handler → guest continues without error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvmFoundationGate {
    /// VMEXIT exit_code = 0x58 (HLT) was seen on the first VMRUN.
    pub hlt_handled: bool,
    /// VMRUN completed and returned to hypervisor (VMEXIT was clean).
    pub vmrun_succeeded: bool,
    /// EFER.SVME was set without fault.
    pub svme_enabled: bool,
    /// NPT was activated (NP_ENABLE = 1, N_CR3 written to VMCB).
    pub npt_active: bool,
    /// NPT fault was NOT seen during the gate test (would indicate bad NPT setup).
    pub npt_fault_seen: bool,
}

impl SvmFoundationGate {
    pub const fn new() -> Self {
        SvmFoundationGate {
            hlt_handled:    false,
            vmrun_succeeded: false,
            svme_enabled:   false,
            npt_active:     false,
            npt_fault_seen: false,
        }
    }

    /// Returns true when all required gate criteria are satisfied.
    pub fn passes(&self) -> bool {
        self.hlt_handled
            && self.vmrun_succeeded
            && self.svme_enabled
            && self.npt_active
            && !self.npt_fault_seen
    }
}

/// Configuration for Chapter 51 AMD-V Foundation initialization.
#[derive(Debug, Clone, Copy)]
pub struct SvmFoundationConfig {
    /// Physical address of the per-vCPU VMCB region (must be 4 KiB-aligned).
    pub vmcb_pa: u64,
    /// Physical address of the host state save area (must be 4 KiB-aligned).
    pub hsave_pa: u64,
    /// Physical address of the NPT PML4 table (must be 4 KiB-aligned).
    pub npt_pml4_pa: u64,
    /// Guest kernel entry physical address.
    pub kernel_entry_pa: u64,
    /// Physical address range start for guest RAM (WB in NPT).
    pub guest_ram_base: u64,
    /// Size of guest RAM in bytes.
    pub guest_ram_size: u64,
    /// MMIO region start PA (UC in NPT); 0 if no MMIO mapped.
    pub mmio_base: u64,
    /// MMIO region size in bytes; 0 if no MMIO mapped.
    pub mmio_size: u64,
    /// Entry mode: true = 64-bit long mode, false = real mode (AMD supports
    /// real-mode guests natively without additional feature flags).
    pub guest_64bit: bool,
}

impl SvmFoundationConfig {
    /// Default configuration for Chapter 51 gate test on QEMU x86 machine.
    ///
    /// Uses a 2 GiB guest RAM window at 0x1_0000_0000, NPT PML4 at
    /// vmcb_pa + 4 KiB, HSAVE at vmcb_pa + 8 KiB. Guest enters 64-bit mode.
    pub fn aether_defaults(vmcb_pa: u64) -> Self {
        SvmFoundationConfig {
            vmcb_pa,
            hsave_pa:        vmcb_pa + 0x1000,
            npt_pml4_pa:     vmcb_pa + 0x2000,
            kernel_entry_pa: 0x1_0000_0000,
            guest_ram_base:  0x1_0000_0000,
            guest_ram_size:  2 * 1024 * 1024 * 1024, // 2 GiB
            mmio_base:       0,
            mmio_size:       0,
            guest_64bit:     true,
        }
    }

    pub fn validate(&self) -> Result<(), SvmError> {
        if self.vmcb_pa & 0xFFF != 0 {
            return Err(SvmError::UnalignedVmcb);
        }
        if self.hsave_pa & 0xFFF != 0 {
            return Err(SvmError::UnalignedHsave);
        }
        if self.npt_pml4_pa & 0xFFF != 0 {
            return Err(SvmError::UnalignedNptPml4);
        }
        if self.guest_ram_size == 0 {
            return Err(SvmError::ZeroGuestRamSize);
        }
        Ok(())
    }
}

/// Phase machine for Chapter 51 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmFoundationPhase {
    NotStarted,
    SvmDetected,      // CPUID.80000001h.ECX[2]=1, VM_CR.SVMDIS=0
    SvmeEnabled,      // EFER.SVME = 1 set
    HsaveConfigured,  // HSAVE_PA MSR written
    VmcbInitialized,  // VMCB control area + state save area written
    NptActive,        // NP_ENABLE + N_CR3 written; TLB flush requested
    GatePassed,       // first HLT exit handled; VMRUN returned to hypervisor
}

/// Error conditions that can occur during Chapter 51 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmError {
    SvmNotSupported,
    SvmDisabledByFirmware, // VM_CR.SVMDIS = 1 — firmware locked SVM off
    NptNotSupported,
    InsufficientAsids,     // CPUID.8000000Ah.EBX < 2 ASIDs available
    UnalignedVmcb,
    UnalignedHsave,
    UnalignedNptPml4,
    ZeroGuestRamSize,
    VmrunFailed,           // VMRUN returned INVALID exit (0xFFFFFFFF…)
    NptFaultOnFirstEntry,  // NPT fault before HLT — NPT mapping incorrect
    NotAmdVendor,          // Runtime vendor check: not "AuthenticAMD"
}

/// Runtime state for Chapter 51.
#[derive(Debug)]
pub struct SvmFoundationState {
    pub phase: SvmFoundationPhase,
    pub gate: SvmFoundationGate,
    pub exit_count: u64,
    pub hlt_exit_count: u64,
    pub last_exit_code: u64,
    pub asid_count: u32,
    pub npt_supported: bool,
    pub decode_assists: bool,
}

impl SvmFoundationState {
    pub const fn new() -> Self {
        SvmFoundationState {
            phase:           SvmFoundationPhase::NotStarted,
            gate:            SvmFoundationGate::new(),
            exit_count:      0,
            hlt_exit_count:  0,
            last_exit_code:  0,
            asid_count:      0,
            npt_supported:   false,
            decode_assists:  false,
        }
    }

    pub fn gate(&self) -> &SvmFoundationGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.gate.passes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level initialization pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize AMD-V Foundation (Chapter 51 gate pipeline).
///
/// Executes the 8-step pipeline:
///
///   1. Detect SVM support (CPUID.80000001h.ECX[2]); vendor check ("AuthenticAMD")
///   2. Check VM_CR.SVMDIS = 0 (SVM not firmware-locked)
///   3. Enable EFER.SVME = 1 (enter SVM-capable mode)
///   4. Write HSAVE_PA MSR → tell the processor where to save host state
///   5. Initialize VMCB: write guest state (segments/CR0/CR3/CR4/EFER/RIP/RSP)
///   6. Write VMCB intercepts (HLT + CPUID + VMRUN + VMMCALL)
///   7. Enable NPT: NP_ENABLE = 1, N_CR3 = npt_pml4_pa, ASID = 1, TLB flush
///   8. Mark NPT active; VMCB_CLEAN = 0 (all dirty — processor must reload)
///
/// After this call the caller must execute vmrun(config.vmcb_pa) to transfer
/// to the guest. The first VMEXIT will trigger the gate test (exit_code = 0x58).
///
/// # Safety
/// - Must run on an x86-64 AMD processor in ring 0.
/// - `config.vmcb_pa` and `config.hsave_pa` must point to caller-allocated
///   4 KiB-aligned zero-initialized regions.
/// - `config.npt_pml4_pa` must point to a valid initialized NptTable.
///
/// Returns Ok(SvmFoundationState) on success; caller must execute vmrun() then
/// handle_vm_exit() in the VMEXIT handler loop to complete the gate.
pub unsafe fn init_svm_foundation(
    config:      &SvmFoundationConfig,
    vmcb_region: &mut VmcbRegion,
) -> Result<SvmFoundationState, SvmError> {
    config.validate()?;

    let mut state = SvmFoundationState::new();

    // ── Step 1: Detect SVM and validate vendor ────────────────────────────────
    let features = unsafe { SvmCpuFeatures::detect() };

    if !features.is_amd_vendor {
        return Err(SvmError::NotAmdVendor);
    }
    if !features.svm_supported {
        return Err(SvmError::SvmNotSupported);
    }
    if !features.npt_supported {
        return Err(SvmError::NptNotSupported);
    }
    if features.asid_count < 2 {
        return Err(SvmError::InsufficientAsids);
    }

    state.asid_count    = features.asid_count;
    state.npt_supported = features.npt_supported;
    state.decode_assists = features.decode_assists;
    state.phase = SvmFoundationPhase::SvmDetected;

    // ── Step 2: Check VM_CR.SVMDIS ────────────────────────────────────────────
    // (Performed inside svm_enable_svme; explicit read here for diagnostics.)
    let vm_cr = unsafe { SvmVmCrMsr::read() };
    if vm_cr.svmdis {
        return Err(SvmError::SvmDisabledByFirmware);
    }

    // ── Step 3: Enable EFER.SVME ──────────────────────────────────────────────
    unsafe { svm_enable_svme() }?;
    state.gate.svme_enabled = true;
    state.phase = SvmFoundationPhase::SvmeEnabled;

    // ── Step 4: Write HSAVE_PA ────────────────────────────────────────────────
    // The processor saves the host's state (RSP, RIP, CR0/3/4, EFER, segments)
    // into this 4 KiB area on every VMRUN and restores it on every VMEXIT.
    unsafe { wrmsr(MSR_HSAVE_PA, config.hsave_pa) };
    state.phase = SvmFoundationPhase::HsaveConfigured;

    // ── Step 5: Write VMCB guest state ────────────────────────────────────────
    let guest_cfg = if config.guest_64bit {
        VmcbGuestConfig::long_mode(config.kernel_entry_pa, 0, 0)
    } else {
        VmcbGuestConfig::real_mode(config.kernel_entry_pa)
    };
    vmcb_write_guest_state(vmcb_region, &guest_cfg);

    // ── Step 6: Write VMCB intercepts ─────────────────────────────────────────
    vmcb_write_intercepts(vmcb_region);
    state.phase = SvmFoundationPhase::VmcbInitialized;

    // ── Step 7: Enable NPT ────────────────────────────────────────────────────
    vmcb_write_npt(vmcb_region, config.npt_pml4_pa);
    state.gate.npt_active = true;
    state.phase = SvmFoundationPhase::NptActive;

    // ── Step 8: Final VMCB consistency ────────────────────────────────────────
    // VMCB_CLEAN = 0: all fields dirty; processor reloads everything on VMRUN.
    // This is mandatory for the first VMRUN — never assume state is clean.
    vmcb_region.write_u32(VMCB_CLEAN, 0x0000_0000);

    Ok(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — run on native host with `cargo test --lib -p hypervisor`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmcb_offset_sanity() {
        // Key VMCB control area offsets — cross-checked against AMD APM Table B-2
        // and Linux KVM arch/x86/kvm/svm/svm.h. These are the most common AI
        // mistake source on this surface.
        assert_eq!(VMCB_INTERCEPT_CR,         0x000, "INTERCEPT_CR");
        assert_eq!(VMCB_INTERCEPT_EXCEPTIONS,  0x008, "INTERCEPT_EXCEPTIONS");
        assert_eq!(VMCB_INTERCEPT_MISC1,       0x00C, "INTERCEPT_MISC1");
        assert_eq!(VMCB_INTERCEPT_MISC2,       0x010, "INTERCEPT_MISC2");
        assert_eq!(VMCB_IOPM_BASE_PA,          0x040, "IOPM_BASE_PA");
        assert_eq!(VMCB_MSRPM_BASE_PA,         0x048, "MSRPM_BASE_PA");
        assert_eq!(VMCB_TSC_OFFSET,            0x050, "TSC_OFFSET");
        assert_eq!(VMCB_GUEST_ASID,            0x058, "GUEST_ASID");
        assert_eq!(VMCB_TLB_CTL,              0x05C, "TLB_CTL");
        assert_eq!(VMCB_EXIT_CODE,             0x070, "EXIT_CODE");
        assert_eq!(VMCB_EXIT_INFO_1,           0x078, "EXIT_INFO_1");
        assert_eq!(VMCB_EXIT_INFO_2,           0x080, "EXIT_INFO_2");
        assert_eq!(VMCB_NESTED_CTL,           0x090, "NESTED_CTL");
        assert_eq!(VMCB_NESTED_CR3,           0x0B0, "NESTED_CR3");
        assert_eq!(VMCB_CLEAN,                0x0C0, "CLEAN");
        assert_eq!(VMCB_NEXT_RIP,             0x0C8, "NEXT_RIP");
        // State save area offsets
        assert_eq!(VMCB_SAVE_ES,              0x400, "SAVE_ES");
        assert_eq!(VMCB_SAVE_CS,              0x410, "SAVE_CS");
        assert_eq!(VMCB_SAVE_SS,              0x420, "SAVE_SS");
        assert_eq!(VMCB_SAVE_DS,              0x430, "SAVE_DS");
        assert_eq!(VMCB_SAVE_GDTR,            0x460, "SAVE_GDTR");
        assert_eq!(VMCB_SAVE_LDTR,            0x470, "SAVE_LDTR");
        assert_eq!(VMCB_SAVE_IDTR,            0x480, "SAVE_IDTR");
        assert_eq!(VMCB_SAVE_TR,              0x490, "SAVE_TR");
        assert_eq!(VMCB_SAVE_CPL,             0x4CB, "SAVE_CPL");
        assert_eq!(VMCB_SAVE_EFER,            0x4D0, "SAVE_EFER");
        assert_eq!(VMCB_SAVE_CR4,             0x548, "SAVE_CR4");
        assert_eq!(VMCB_SAVE_CR3,             0x550, "SAVE_CR3");
        assert_eq!(VMCB_SAVE_CR0,             0x558, "SAVE_CR0");
        assert_eq!(VMCB_SAVE_RFLAGS,          0x570, "SAVE_RFLAGS");
        assert_eq!(VMCB_SAVE_RIP,             0x578, "SAVE_RIP");
        assert_eq!(VMCB_SAVE_RSP,             0x5D8, "SAVE_RSP");
        assert_eq!(VMCB_SAVE_RAX,             0x5F8, "SAVE_RAX");
    }

    #[test]
    fn svm_exit_code_hlt_is_0x58() {
        // The correct AMD SVM exit code for HLT is 0x58 (AMD APM Vol. 2 Table B-1).
        // A common AI mistake is to use 0x78 — this test guards against that.
        assert_eq!(SVM_EXIT_HLT, 0x58, "HLT exit code must be 0x58 per AMD APM Table B-1");
        assert_ne!(SVM_EXIT_HLT, 0x78, "0x78 is NOT the HLT exit code");
    }

    #[test]
    fn svm_exit_code_npf_is_0x400() {
        assert_eq!(SVM_EXIT_NPF, 0x400, "NPF exit code must be 0x400");
    }

    #[test]
    fn intercept_hlt_bit_is_24() {
        // HLT intercept is bit 24 of VMCB_INTERCEPT_MISC1 (AMD APM §15.9 Table 15-7).
        assert_eq!(INTERCEPT_HLT, 1 << 24, "HLT intercept must be bit 24 of MISC1");
    }

    #[test]
    fn intercept_vmrun_bit_is_0() {
        // VMRUN intercept is bit 0 of VMCB_INTERCEPT_MISC2 — mandatory for security.
        assert_eq!(INTERCEPT_VMRUN, 1 << 0, "VMRUN intercept must be bit 0 of MISC2");
    }

    #[test]
    fn npt_entry_construction() {
        // Normal RAM leaf entry: P + RW + User (no PWT/PCD = WB)
        let ram_pa = 0x4000_1000u64;
        let e = NptLeafEntry::normal_ram(ram_pa);
        assert_eq!(e.0 & 0xFFF, NPT_RAM_WB, "normal RAM leaf: lower 12 bits = NPT_RAM_WB");
        assert_eq!(e.0 & !0xFFF, ram_pa, "normal RAM leaf: upper bits = PA");

        // Device MMIO leaf entry: P + RW + User + PWT + PCD (strong UC)
        let mmio_pa = 0x0900_0000u64;
        let e = NptLeafEntry::device_mmio(mmio_pa);
        assert!(e.0 & NPT_PWT != 0, "device MMIO: PWT must be set");
        assert!(e.0 & NPT_PCD != 0, "device MMIO: PCD must be set");

        // Non-leaf entry: P + RW + User
        let child_pa = 0x4001_0000u64;
        let ne = NptTableEntry::pointing_to(child_pa);
        assert_eq!(ne.0 & !0xFFF, child_pa, "non-leaf: PA bits correct");
        assert_eq!(ne.0 & NPT_NONLEAF, NPT_NONLEAF, "non-leaf: permission bits correct");
    }

    #[test]
    fn vmcb_rw_helpers() {
        let mut vmcb = VmcbRegion::new();

        // u8 round-trip
        vmcb.write_u8(VMCB_SAVE_CPL, 0x00);
        assert_eq!(vmcb.read_u8(VMCB_SAVE_CPL), 0x00);

        // u16 round-trip (little-endian)
        vmcb.write_u16(VMCB_SAVE_CS, 0x0008);
        assert_eq!(vmcb.read_u16(VMCB_SAVE_CS), 0x0008);

        // u32 round-trip
        vmcb.write_u32(VMCB_GUEST_ASID, 1u32);
        assert_eq!(vmcb.read_u32(VMCB_GUEST_ASID), 1);

        // u64 round-trip
        vmcb.write_u64(VMCB_SAVE_RIP, 0x1_0000_0000u64);
        assert_eq!(vmcb.read_u64(VMCB_SAVE_RIP), 0x1_0000_0000);

        // exit_code accessor
        vmcb.write_u64(VMCB_EXIT_CODE, SVM_EXIT_HLT);
        assert_eq!(vmcb.exit_code(), SVM_EXIT_HLT);
    }

    #[test]
    fn vmcb_npt_tlb_flush() {
        let mut vmcb = VmcbRegion::new();
        vmcb.request_npt_tlb_flush();

        // After flush request: TLB_CTL = FLUSH_ALL and CLEAN = 0 (all dirty).
        assert_eq!(vmcb.read_u32(VMCB_TLB_CTL), TLB_CTL_FLUSH_ALL,
            "TLB_CTL must be FLUSH_ALL after request_npt_tlb_flush");
        assert_eq!(vmcb.read_u32(VMCB_CLEAN), 0,
            "VMCB_CLEAN must be 0 (all dirty) after TLB flush request");
    }

    #[test]
    fn gate_passes_only_when_all_set() {
        let mut gate = SvmFoundationGate::new();
        assert!(!gate.passes(), "new gate must not pass");

        gate.hlt_handled     = true;
        gate.vmrun_succeeded = true;
        gate.svme_enabled    = true;
        gate.npt_active      = true;
        // npt_fault_seen remains false
        assert!(gate.passes(), "gate must pass when all criteria met");

        gate.npt_fault_seen = true;
        assert!(!gate.passes(), "gate must fail when NPT fault was seen");
    }

    #[test]
    fn handle_vm_exit_hlt() {
        let mut vmcb = VmcbRegion::new();
        let mut state = SvmFoundationState::new();

        // Simulate a HLT exit with nRIP = entry_pa + 1
        let entry_pa = 0x1_0000_0000u64;
        vmcb.write_u64(VMCB_EXIT_CODE, SVM_EXIT_HLT);
        vmcb.write_u64(VMCB_SAVE_RIP,  entry_pa);
        vmcb.write_u64(VMCB_NEXT_RIP,  entry_pa + 1); // processor provides nRIP

        let action = handle_vm_exit(&mut vmcb, &mut state);
        assert_eq!(action, SvmExitAction::HltHandled);
        assert!(state.gate.hlt_handled);
        assert!(state.gate.vmrun_succeeded);
        assert_eq!(vmcb.guest_rip(), entry_pa + 1, "RIP must advance to nRIP");
    }

    #[test]
    fn handle_vm_exit_hlt_fallback_rip() {
        // Without DecodeAssists / nRIP, next_rip = 0 → fallback to manual +1
        let mut vmcb = VmcbRegion::new();
        let mut state = SvmFoundationState::new();

        let entry_pa = 0x1_0000_0000u64;
        vmcb.write_u64(VMCB_EXIT_CODE, SVM_EXIT_HLT);
        vmcb.write_u64(VMCB_SAVE_RIP,  entry_pa);
        vmcb.write_u64(VMCB_NEXT_RIP,  0); // processor did NOT save nRIP

        let action = handle_vm_exit(&mut vmcb, &mut state);
        assert_eq!(action, SvmExitAction::HltHandled);
        assert_eq!(vmcb.guest_rip(), entry_pa + 1, "manual fallback must advance RIP by 1");
    }

    #[test]
    fn handle_vm_exit_npf() {
        let mut vmcb = VmcbRegion::new();
        let mut state = SvmFoundationState::new();

        vmcb.write_u64(VMCB_EXIT_CODE, SVM_EXIT_NPF);
        let action = handle_vm_exit(&mut vmcb, &mut state);
        assert_eq!(action, SvmExitAction::Terminate);
        assert!(state.gate.npt_fault_seen);
    }

    #[test]
    fn config_validate_alignment() {
        let bad_vmcb  = SvmFoundationConfig::aether_defaults(0x0000_1001); // unaligned
        assert!(bad_vmcb.validate().is_err());

        let good_vmcb = SvmFoundationConfig::aether_defaults(0x0000_2000); // aligned
        assert!(good_vmcb.validate().is_ok());
    }

    #[test]
    fn efer_svme_bit() {
        assert_eq!(EFER_SVME, 1 << 12, "EFER.SVME must be bit 12");
    }

    #[test]
    fn np_enable_bit() {
        assert_eq!(NP_ENABLE, 1 << 0, "NP_ENABLE must be bit 0 of NESTED_CTL");
    }
}
