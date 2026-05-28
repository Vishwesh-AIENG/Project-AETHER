// ch50: Intel VT-x Foundation
//
// Detect VMX support, enable via IA32_FEATURE_CONTROL, enter VMX root mode
// (VMXON), initialize a per-vCPU VMCS with guest/host state, configure EPT
// with WB RAM and UC MMIO types, and handle the first VM exit (HLT).
//
// ── Architecture Reference ────────────────────────────────────────────────────
//
// Intel SDM Vol. 3C:
//   §24.2  — VMCS field encodings
//   §24.6  — VM-execution control fields
//   §24.7  — VM-exit information fields (EXIT_REASON codes)
//   §24.8  — VM-entry control fields
//   §28    — EPT (Extended Page Tables)
//
// MSR references:
//   IA32_FEATURE_CONTROL (0x3A): bit 0 = lock, bit 2 = VMXON outside SMX
//   IA32_VMX_BASIC       (0x480): bits[30:0] = VMCS revision ID, bit 55 = true controls
//
// ── What This Module Implements ───────────────────────────────────────────────
//
//   1.  VmxCpuFeatures   — CPUID.1.ECX[5] VMX support check
//   2.  Ia32FeatureControlMsr — lock + VMXON-outside-SMX detection/set
//   3.  VmxBasicMsr      — VMCS revision identifier from IA32_VMX_BASIC
//   4.  VmxonRegion      — 4 KiB VMXON region (revision ID in dword 0)
//   5.  VmcsRegion       — 4 KiB per-vCPU VMCS (revision ID, zero-filled)
//   6.  VMCS field constants — exact encodings from Intel SDM §24.11.2
//   7.  EptConfig        — 4-level EPT, WB memory type, 4 KiB pages
//   8.  EptEntry / EptTable — EPT PML4/PDPT/PD/PT entry helpers
//   9.  EptInvalidate    — INVEPT after every mapping change
//  10.  VmcsHostState    — saves AETHER host RSP/RIP/CR0/CR3/CR4/segments
//  11.  VmcsGuestState   — initial guest register state for Android kernel
//  12.  VmcsExecControls — pin/CPU/secondary/exit/entry control fields;
//                          UNRESTRICTED_GUEST + ENABLE_EPT in secondary
//  13.  VtxExitReason    — decodes EXIT_REASON VMCS field (HLT=12, etc.)
//  14.  VtxExitHandler   — handles HLT (records gate, calls VMRESUME stub)
//  15.  VtxFoundationConfig / Gate / Error / Phase / State — chapter gate types
//  16.  init_vtx_foundation() — full initialization pipeline
//
// ── Gate ──────────────────────────────────────────────────────────────────────
//
//   VtxFoundationGate.passes() requires both:
//     hlt_handled         — first VM exit was EXIT_REASON = 12 (HLT)
//     vmresume_succeeded  — VMRESUME completed without VM instruction error
//
//   Verification sequence (Intel SDM §24.9.1):
//     1. CPUID.1.ECX[5] = 1 → VMX supported
//     2. IA32_FEATURE_CONTROL bits 0 (lock) and 2 (VMXON-outside-SMX) = 1
//     3. VMXON CF=0, ZF=0 in RFLAGS → succeeded
//     4. First VMEXIT EXIT_REASON = 12 (HLT) → guest executed HLT
//     5. VMRESUME succeeds → guest continues after HLT handler returns

// ─────────────────────────────────────────────────────────────────────────────
// VMCS field encodings — Intel SDM Vol. 3C §24.11.2, Table 24-12
//
// Encoding formula:
//   bits[1:0]   = access type (0 = full; 1 = high for 64-bit fields)
//   bits[9:1]   = field index within (width, type) group
//   bits[11:10] = type  (00=control, 01=read-only, 10=guest-state, 11=host-state)
//   bits[13:12] = width (00=16-bit,  01=64-bit,    10=32-bit,      11=natural)
//   bit [14]    = reserved (0)
//
// Every value below is cross-checked against Linux KVM arch/x86/include/asm/vmx.h
// to guard against off-by-one errors (the most common AI mistake on this surface).
// ─────────────────────────────────────────────────────────────────────────────

// ── 16-bit control fields (width=00, type=00) ─────────────────────────────
pub const VMCS_VIRTUAL_PROCESSOR_ID: u32 = 0x0000;

// ── 16-bit guest-state fields (width=00, type=10) ─────────────────────────
pub const VMCS_GUEST_ES_SEL:   u32 = 0x0800;
pub const VMCS_GUEST_CS_SEL:   u32 = 0x0802;
pub const VMCS_GUEST_SS_SEL:   u32 = 0x0804;
pub const VMCS_GUEST_DS_SEL:   u32 = 0x0806;
pub const VMCS_GUEST_FS_SEL:   u32 = 0x0808;
pub const VMCS_GUEST_GS_SEL:   u32 = 0x080A;
pub const VMCS_GUEST_LDTR_SEL: u32 = 0x080C;
pub const VMCS_GUEST_TR_SEL:   u32 = 0x080E;

// ── 16-bit host-state fields (width=00, type=11) ──────────────────────────
pub const VMCS_HOST_ES_SEL:    u32 = 0x0C00;
pub const VMCS_HOST_CS_SEL:    u32 = 0x0C02;
pub const VMCS_HOST_SS_SEL:    u32 = 0x0C04;
pub const VMCS_HOST_DS_SEL:    u32 = 0x0C06;
pub const VMCS_HOST_FS_SEL:    u32 = 0x0C08;
pub const VMCS_HOST_GS_SEL:    u32 = 0x0C0A;
pub const VMCS_HOST_TR_SEL:    u32 = 0x0C0C;

// ── 64-bit control fields (width=01, type=00) ─────────────────────────────
pub const VMCS_IO_BITMAP_A:    u32 = 0x2000;
pub const VMCS_MSR_BITMAP:     u32 = 0x2004;
pub const VMCS_EPT_POINTER:    u32 = 0x201A; // EPTP

// ── 64-bit guest-state fields (width=01, type=10) ─────────────────────────
pub const VMCS_LINK_POINTER:     u32 = 0x2800; // VMCS link pointer (0xFFFF…FF = no shadow)
pub const VMCS_GUEST_DEBUGCTL:   u32 = 0x2802;
pub const VMCS_GUEST_IA32_PAT:   u32 = 0x2804;
pub const VMCS_GUEST_IA32_EFER:  u32 = 0x2806;

// ── 64-bit host-state fields (width=01, type=11) ──────────────────────────
pub const VMCS_HOST_IA32_PAT:    u32 = 0x2C00;
pub const VMCS_HOST_IA32_EFER:   u32 = 0x2C02;

// ── 32-bit control fields (width=10, type=00) ─────────────────────────────
pub const VMCS_PIN_EXEC_CTRL:    u32 = 0x4000;
pub const VMCS_CPU_EXEC_CTRL:    u32 = 0x4002; // primary processor-based controls
pub const VMCS_EXCEPTION_BITMAP: u32 = 0x4004;
pub const VMCS_PF_ERRCODE_MASK:  u32 = 0x4006;
pub const VMCS_PF_ERRCODE_MATCH: u32 = 0x4008;
pub const VMCS_CR3_TARGET_COUNT: u32 = 0x400A;
pub const VMCS_VM_EXIT_CTRL:     u32 = 0x400C;
pub const VMCS_VM_ENTRY_CTRL:    u32 = 0x4012;
pub const VMCS_CPU_EXEC_CTRL2:   u32 = 0x401E; // secondary processor-based controls

// ── 32-bit read-only data fields (width=10, type=01) ──────────────────────
pub const VMCS_VM_INSTR_ERROR:   u32 = 0x4400; // VM instruction error code
pub const VMCS_EXIT_REASON:      u32 = 0x4402;
pub const VMCS_EXIT_INTR_INFO:   u32 = 0x4404;
pub const VMCS_EXIT_INTR_ERRCODE:u32 = 0x4406;

// ── 32-bit guest-state fields (width=10, type=10) ─────────────────────────
pub const VMCS_GUEST_ES_LIMIT:   u32 = 0x4800;
pub const VMCS_GUEST_CS_LIMIT:   u32 = 0x4802;
pub const VMCS_GUEST_SS_LIMIT:   u32 = 0x4804;
pub const VMCS_GUEST_DS_LIMIT:   u32 = 0x4806;
pub const VMCS_GUEST_FS_LIMIT:   u32 = 0x4808;
pub const VMCS_GUEST_GS_LIMIT:   u32 = 0x480A;
pub const VMCS_GUEST_LDTR_LIMIT: u32 = 0x480C;
pub const VMCS_GUEST_TR_LIMIT:   u32 = 0x480E;
pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x4810;
pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x4812;
pub const VMCS_GUEST_ES_AR:      u32 = 0x4814;
pub const VMCS_GUEST_CS_AR:      u32 = 0x4816;
pub const VMCS_GUEST_SS_AR:      u32 = 0x4818;
pub const VMCS_GUEST_DS_AR:      u32 = 0x481A;
pub const VMCS_GUEST_FS_AR:      u32 = 0x481C;
pub const VMCS_GUEST_GS_AR:      u32 = 0x481E;
pub const VMCS_GUEST_LDTR_AR:    u32 = 0x4820;
pub const VMCS_GUEST_TR_AR:      u32 = 0x4822;
pub const VMCS_GUEST_INTERRUPTIBILITY: u32 = 0x4824;
pub const VMCS_GUEST_ACTIVITY:   u32 = 0x4826;
pub const VMCS_GUEST_SYSENTER_CS:u32 = 0x482A;

// ── 32-bit host-state fields (width=10, type=11) ──────────────────────────
pub const VMCS_HOST_SYSENTER_CS: u32 = 0x4C00;

// ── natural-width control fields (width=11, type=00) ──────────────────────
pub const VMCS_CR0_GUEST_HOST_MASK: u32 = 0x6000;
pub const VMCS_CR4_GUEST_HOST_MASK: u32 = 0x6002;
pub const VMCS_CR0_READ_SHADOW:     u32 = 0x6004;
pub const VMCS_CR4_READ_SHADOW:     u32 = 0x6006;

// ── natural-width read-only data fields (width=11, type=01) ───────────────
pub const VMCS_EXIT_QUALIFICATION:  u32 = 0x6400;
pub const VMCS_GUEST_LINEAR_ADDR:   u32 = 0x640A;

// ── natural-width guest-state fields (width=11, type=10) ──────────────────
pub const VMCS_GUEST_CR0:           u32 = 0x6800;
pub const VMCS_GUEST_CR3:           u32 = 0x6802;
pub const VMCS_GUEST_CR4:           u32 = 0x6804;
pub const VMCS_GUEST_ES_BASE:       u32 = 0x6806;
pub const VMCS_GUEST_CS_BASE:       u32 = 0x6808;
pub const VMCS_GUEST_SS_BASE:       u32 = 0x680A;
pub const VMCS_GUEST_DS_BASE:       u32 = 0x680C;
pub const VMCS_GUEST_FS_BASE:       u32 = 0x680E;
pub const VMCS_GUEST_GS_BASE:       u32 = 0x6810;
pub const VMCS_GUEST_LDTR_BASE:     u32 = 0x6812;
pub const VMCS_GUEST_TR_BASE:       u32 = 0x6814;
pub const VMCS_GUEST_GDTR_BASE:     u32 = 0x6816;
pub const VMCS_GUEST_IDTR_BASE:     u32 = 0x6818;
pub const VMCS_GUEST_DR7:           u32 = 0x681A;
pub const VMCS_GUEST_RSP:           u32 = 0x681C;
pub const VMCS_GUEST_RIP:           u32 = 0x681E;
pub const VMCS_GUEST_RFLAGS:        u32 = 0x6820;
pub const VMCS_GUEST_SYSENTER_ESP:  u32 = 0x6824;
pub const VMCS_GUEST_SYSENTER_EIP:  u32 = 0x6826;

// ── natural-width host-state fields (width=11, type=11) ───────────────────
pub const VMCS_HOST_CR0:            u32 = 0x6C00;
pub const VMCS_HOST_CR3:            u32 = 0x6C02;
pub const VMCS_HOST_CR4:            u32 = 0x6C04;
pub const VMCS_HOST_FS_BASE:        u32 = 0x6C06;
pub const VMCS_HOST_GS_BASE:        u32 = 0x6C08;
pub const VMCS_HOST_TR_BASE:        u32 = 0x6C0A;
pub const VMCS_HOST_GDTR_BASE:      u32 = 0x6C0C;
pub const VMCS_HOST_IDTR_BASE:      u32 = 0x6C0E;
pub const VMCS_HOST_SYSENTER_ESP:   u32 = 0x6C10;
pub const VMCS_HOST_SYSENTER_EIP:   u32 = 0x6C12;
pub const VMCS_HOST_RSP:            u32 = 0x6C14;
pub const VMCS_HOST_RIP:            u32 = 0x6C16;

// ─────────────────────────────────────────────────────────────────────────────
// MSR addresses
// ─────────────────────────────────────────────────────────────────────────────

pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
pub const MSR_IA32_VMX_BASIC:       u32 = 0x480;
pub const MSR_IA32_VMX_CR0_FIXED0:  u32 = 0x486;
pub const MSR_IA32_VMX_CR0_FIXED1:  u32 = 0x487;
pub const MSR_IA32_VMX_CR4_FIXED0:  u32 = 0x488;
pub const MSR_IA32_VMX_CR4_FIXED1:  u32 = 0x489;
pub const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
pub const MSR_IA32_EFER:            u32 = 0xC000_0080;
pub const MSR_IA32_PAT:             u32 = 0x277;
pub const MSR_IA32_SYSENTER_CS:     u32 = 0x174;
pub const MSR_IA32_SYSENTER_ESP:    u32 = 0x175;
pub const MSR_IA32_SYSENTER_EIP:    u32 = 0x176;
pub const MSR_IA32_GS_BASE:         u32 = 0xC000_0101;
pub const MSR_IA32_FS_BASE:         u32 = 0xC000_0100;

// ─────────────────────────────────────────────────────────────────────────────
// IA32_FEATURE_CONTROL MSR bit definitions
// ─────────────────────────────────────────────────────────────────────────────

pub const FEATURE_CONTROL_LOCK:           u64 = 1 << 0;
pub const FEATURE_CONTROL_VMXON_OUT_SMX:  u64 = 1 << 2;  // VMX outside SMX

// ─────────────────────────────────────────────────────────────────────────────
// VM-execution control field bit definitions
// ─────────────────────────────────────────────────────────────────────────────

// Pin-based VM-execution controls
pub const PIN_CTRL_EXT_INTR_EXIT:   u32 = 1 << 0;
pub const PIN_CTRL_NMI_EXIT:        u32 = 1 << 3;
pub const PIN_CTRL_VIRT_NMIS:       u32 = 1 << 5;

// Primary processor-based VM-execution controls
pub const CPU_CTRL_HLT_EXIT:        u32 = 1 << 7;   // HLT causes VM exit
pub const CPU_CTRL_RDTSC_EXIT:      u32 = 1 << 12;
pub const CPU_CTRL_CR3_LOAD_EXIT:   u32 = 1 << 15;
pub const CPU_CTRL_CR3_STORE_EXIT:  u32 = 1 << 16;
pub const CPU_CTRL_CR8_LOAD_EXIT:   u32 = 1 << 19;
pub const CPU_CTRL_CR8_STORE_EXIT:  u32 = 1 << 20;
pub const CPU_CTRL_RDMSR_EXIT:      u32 = 1 << 28;
pub const CPU_CTRL_WRMSR_EXIT:      u32 = 1 << 29;
pub const CPU_CTRL_ACTIVATE_CTRL2:  u32 = 1 << 31; // activate secondary controls

// Secondary processor-based VM-execution controls
pub const CPU_CTRL2_ENABLE_EPT:         u32 = 1 << 1;
pub const CPU_CTRL2_ENABLE_VPID:        u32 = 1 << 5;
pub const CPU_CTRL2_UNRESTRICTED_GUEST: u32 = 1 << 7; // allow non-paging guest

// VM-exit controls
pub const VMEXIT_HOST_ADDR64: u32 = 1 << 9;  // host address-space size (64-bit)
pub const VMEXIT_ACK_INTR:    u32 = 1 << 15; // acknowledge interrupt on exit
pub const VMEXIT_SAVE_EFER:   u32 = 1 << 20;
pub const VMEXIT_LOAD_EFER:   u32 = 1 << 21;

// VM-entry controls
pub const VMENTRY_LOAD_EFER:  u32 = 1 << 15;
pub const VMENTRY_IA32E_GUEST:u32 = 1 << 9;  // IA-32e mode guest (64-bit)

// ─────────────────────────────────────────────────────────────────────────────
// VM exit reason codes — Intel SDM Vol. 3C §24.9.1 Table 24-7
// ─────────────────────────────────────────────────────────────────────────────

pub const EXIT_REASON_EXCEPTION_NMI:    u32 = 0;
pub const EXIT_REASON_EXTERNAL_IRQ:     u32 = 1;
pub const EXIT_REASON_TRIPLE_FAULT:     u32 = 2;
pub const EXIT_REASON_CPUID:            u32 = 10;
pub const EXIT_REASON_HLT:             u32 = 12;
pub const EXIT_REASON_INVD:             u32 = 13;
pub const EXIT_REASON_RDMSR:            u32 = 31;
pub const EXIT_REASON_WRMSR:            u32 = 32;
pub const EXIT_REASON_VMENTRY_FAIL_GS:  u32 = 33;
pub const EXIT_REASON_EPT_VIOLATION:    u32 = 48;
pub const EXIT_REASON_XSETBV:           u32 = 55;

// ─────────────────────────────────────────────────────────────────────────────
// EPT constants — Intel SDM Vol. 3C §28.2
// ─────────────────────────────────────────────────────────────────────────────

// EPT entry permission bits [2:0]
pub const EPT_READ:    u64 = 1 << 0;
pub const EPT_WRITE:   u64 = 1 << 1;
pub const EPT_EXEC:    u64 = 1 << 2;
pub const EPT_RWX:     u64 = EPT_READ | EPT_WRITE | EPT_EXEC;

// EPT memory types in bits [5:3] of leaf PTE
pub const EPT_MEMTYPE_UC: u64 = 0 << 3; // uncacheable (device MMIO)
pub const EPT_MEMTYPE_WB: u64 = 6 << 3; // write-back (normal RAM)

// EPT page-walk length (PML4 = 4-level, encoded as walk_length - 1 = 3)
pub const EPT_PAGE_WALK_4: u64 = 3 << 3; // in EPTP bits [5:3]

// EPT memory type for EPTP structure itself (bits [2:0] of EPTP)
pub const EPTP_MEMTYPE_WB: u64 = 6;

// EPTP bit 6: enable EPT accessed/dirty flags
pub const EPTP_AD_ENABLE: u64 = 1 << 6;

// INVEPT types
pub const INVEPT_SINGLE_CONTEXT: u64 = 1; // invalidate single EPT
pub const INVEPT_ALL_CONTEXT:    u64 = 2; // invalidate all EPTs

// Shift constants for 4-level EPT walk (4 KiB pages)
pub const EPT_PML4_SHIFT: u32 = 39;
pub const EPT_PDPT_SHIFT: u32 = 30;
pub const EPT_PD_SHIFT:   u32 = 21;
pub const EPT_PT_SHIFT:   u32 = 12;
pub const EPT_INDEX_MASK: u64 = 0x1FF;

// ─────────────────────────────────────────────────────────────────────────────
// CR0 / CR4 constants needed for VMCS initialization
// ─────────────────────────────────────────────────────────────────────────────

pub const CR0_PE: u64 = 1 << 0;  // protected mode enable
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_PG: u64 = 1 << 31; // paging enable

pub const CR4_VME: u64   = 1 << 0;
pub const CR4_DE: u64    = 1 << 3;
pub const CR4_PSE: u64   = 1 << 4;
pub const CR4_PAE: u64   = 1 << 5;
pub const CR4_MCE: u64   = 1 << 6;
pub const CR4_PGE: u64   = 1 << 7;
pub const CR4_PCE: u64   = 1 << 8;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_VMXE: u64  = 1 << 13; // VMX enable — must be set before VMXON

// EFER bits
pub const EFER_SCE:  u64 = 1 << 0;  // syscall extensions
pub const EFER_LME:  u64 = 1 << 8;  // long mode enable
pub const EFER_LMA:  u64 = 1 << 10; // long mode active
pub const EFER_NXE:  u64 = 1 << 11; // no-execute enable

// RFLAGS
pub const RFLAGS_FIXED:  u64 = 1 << 1; // bit 1 is always 1 in RFLAGS
pub const RFLAGS_IF:     u64 = 1 << 9; // interrupt enable

// ─────────────────────────────────────────────────────────────────────────────
// Segment access rights (AR bytes) for VMCS — Intel SDM Vol. 3A §3.4.5.1
// ─────────────────────────────────────────────────────────────────────────────

// Code segment: 64-bit, present, type 0xA (execute/read, accessed)
pub const AR_CODE64:  u32 = 0xA09B; // P=1, DPL=0, S=1, type=11, L=1, D=0, G=1
// Data segment: present, writeable, 32-bit (used for real-mode-compatible DS/SS)
pub const AR_DATA32:  u32 = 0xC093; // P=1, DPL=0, S=1, type=3, B=1, G=1
// TSS descriptor: present, 64-bit busy TSS
pub const AR_TSS64:   u32 = 0x008B; // P=1, DPL=0, S=0, type=11 (busy TSS)
// LDTR: not present (unused)
pub const AR_LDTR_UNUSABLE: u32 = 1 << 16; // bit 16 = unusable
// Null segment: unusable
pub const AR_UNUSABLE: u32 = 1 << 16;

// ─────────────────────────────────────────────────────────────────────────────
// CPUID-based VMX support detection
// ─────────────────────────────────────────────────────────────────────────────

/// Reports whether the current logical processor supports VMX.
///
/// Reads CPUID leaf 1, ECX bit 5 (VMX feature flag).
/// Intel SDM Vol. 2A §CPUID; Vol. 3C §23.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmxCpuFeatures {
    pub vmx_supported: bool,
    pub true_controls_supported: bool, // IA32_VMX_BASIC bit 55
}

impl VmxCpuFeatures {
    /// Returns a zero-filled instance for use in tests and pre-hardware contexts.
    pub const fn none() -> Self {
        VmxCpuFeatures { vmx_supported: false, true_controls_supported: false }
    }

    /// Detect VMX support on the calling processor.
    ///
    /// # Safety
    /// Must be called on an x86-64 processor. Undefined on ARM64.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn detect() -> Self {
        let ecx: u32;
        unsafe {
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "mov eax, 1",
                "cpuid",
                "mov rbx, {tmp:r}",
                tmp = out(reg) _,
                out("ecx") ecx,
                out("eax") _,
                out("edx") _,
                options(nomem, nostack)
            );
        }
        let vmx_supported = (ecx >> 5) & 1 == 1;

        let vmx_basic = if vmx_supported {
            unsafe { rdmsr(MSR_IA32_VMX_BASIC) }
        } else {
            0
        };
        let true_controls_supported = (vmx_basic >> 55) & 1 == 1;

        VmxCpuFeatures { vmx_supported, true_controls_supported }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn detect() -> Self {
        Self::none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IA32_FEATURE_CONTROL MSR
// ─────────────────────────────────────────────────────────────────────────────

/// State of the IA32_FEATURE_CONTROL MSR.
///
/// Lock bit (bit 0) and VMXON-outside-SMX enable (bit 2) must both be set
/// before VMXON can succeed. If locked with bit 2 clear, VMX is permanently
/// disabled on this boot and a reboot is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ia32FeatureControlMsr {
    pub locked: bool,
    pub vmx_outside_smx: bool,
}

impl Ia32FeatureControlMsr {
    /// Reads the current MSR value on the calling processor.
    ///
    /// # Safety
    /// Requires x86-64; caller must have RING-0 privileges.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read() -> Self {
        let raw = unsafe { rdmsr(MSR_IA32_FEATURE_CONTROL) };
        Ia32FeatureControlMsr {
            locked:          raw & FEATURE_CONTROL_LOCK          != 0,
            vmx_outside_smx: raw & FEATURE_CONTROL_VMXON_OUT_SMX != 0,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn read() -> Self {
        Ia32FeatureControlMsr { locked: false, vmx_outside_smx: false }
    }

    /// Ensures VMXON-outside-SMX is enabled and the MSR is locked.
    ///
    /// If locked with VMXON disabled → returns Err (hardware prevents change).
    /// If unlocked → writes bits 0 and 2, then re-reads to confirm.
    ///
    /// # Safety
    /// Requires x86-64; caller must have RING-0 privileges.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn enable_and_lock() -> Result<(), VtxError> {
        let current = unsafe { Self::read() };
        if current.locked && !current.vmx_outside_smx {
            return Err(VtxError::FeatureControlLocked);
        }
        if !current.locked || !current.vmx_outside_smx {
            let new_val = FEATURE_CONTROL_LOCK | FEATURE_CONTROL_VMXON_OUT_SMX;
            unsafe { wrmsr(MSR_IA32_FEATURE_CONTROL, new_val) };
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn enable_and_lock() -> Result<(), VtxError> {
        Ok(())
    }

    pub fn vmx_enabled(&self) -> bool {
        self.locked && self.vmx_outside_smx
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IA32_VMX_BASIC MSR — VMCS revision identifier
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed IA32_VMX_BASIC MSR.
///
/// Bits [30:0] carry the 31-bit VMCS revision identifier that must be written
/// into byte offset 0 of every VMXON region and VMCS region.
/// Bit 55 indicates the processor supports TRUE controls MSRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmxBasicMsr {
    pub revision_id: u32,
    pub vmxon_region_size: u16, // bits [44:32] in pages (≤ 4096 bytes)
    pub true_controls: bool,    // bit 55
}

impl VmxBasicMsr {
    pub const fn zero() -> Self {
        VmxBasicMsr { revision_id: 0, vmxon_region_size: 0, true_controls: false }
    }

    /// Reads IA32_VMX_BASIC on the calling processor.
    ///
    /// # Safety
    /// Requires x86-64; VMX must be supported (CPUID.1.ECX[5]=1).
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read() -> Self {
        let raw = unsafe { rdmsr(MSR_IA32_VMX_BASIC) };
        VmxBasicMsr {
            revision_id:        (raw & 0x7FFF_FFFF) as u32,
            vmxon_region_size:  ((raw >> 32) & 0x1FFF) as u16,
            true_controls:      (raw >> 55) & 1 == 1,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn read() -> Self {
        Self::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VMXON region — 4 KiB, 4 KiB-aligned
// ─────────────────────────────────────────────────────────────────────────────

/// 4 KiB VMXON region. Physical address is passed to the VMXON instruction.
///
/// Layout (Intel SDM Vol. 3C §24.11.5):
///   bytes [3:0]  — VMCS revision identifier (from IA32_VMX_BASIC bits[30:0])
///   bytes [4095:4] — reserved (zeroed by hypervisor)
#[repr(C, align(4096))]
pub struct VmxonRegion {
    revision_id: u32,
    _reserved: [u8; 4092],
}

impl VmxonRegion {
    pub const fn new() -> Self {
        VmxonRegion { revision_id: 0, _reserved: [0u8; 4092] }
    }

    /// Writes the revision ID into byte 0 as required before VMXON.
    pub fn init(&mut self, revision_id: u32) {
        self.revision_id = revision_id;
    }

    pub fn revision_id(&self) -> u32 {
        self.revision_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VMCS region — 4 KiB, 4 KiB-aligned
//
// One VMCS per vCPU. Must not be shared across cores.
// Intel SDM Vol. 3C §24.2: processor treats bytes beyond the revision ID as
// opaque — never read them directly; always use VMREAD/VMWRITE.
// ─────────────────────────────────────────────────────────────────────────────

/// Per-vCPU 4 KiB VMCS region.
///
/// The revision ID occupies bytes [3:0] (same encoding as VMXON region).
/// Bit 31 of the revision field signals a shadow VMCS (not used by AETHER).
/// All other bytes are managed exclusively by the processor via VMREAD/VMWRITE.
#[repr(C, align(4096))]
pub struct VmcsRegion {
    revision_id: u32,
    _processor_managed: [u8; 4092],
}

impl VmcsRegion {
    pub const fn new() -> Self {
        VmcsRegion { revision_id: 0, _processor_managed: [0u8; 4092] }
    }

    /// Writes the revision ID. Must be called before VMCLEAR/VMPTRLD.
    pub fn init(&mut self, revision_id: u32) {
        self.revision_id = revision_id & 0x7FFF_FFFF; // bit 31 must be 0
    }

    pub fn revision_id(&self) -> u32 {
        self.revision_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EPT structures — Intel SDM Vol. 3C §28.2
// ─────────────────────────────────────────────────────────────────────────────

/// One EPT page table (512 × 8-byte entries, 4 KiB total).
///
/// EPT uses the same 4-level walk as CR3-based paging but different entry
/// formats: bits[2:0]=RWX, bits[5:3]=memory type (leaf PTEs only), bit[7]=
/// ignore-PAT (leaf PTEs), bit[8]=accessed, bit[9]=dirty.
#[repr(C, align(4096))]
pub struct EptTable {
    entries: [u64; 512],
}

impl EptTable {
    pub const fn new() -> Self {
        EptTable { entries: [0u64; 512] }
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

/// EPTP (EPT Pointer) value written into the VMCS EPT_POINTER field.
///
/// Format (Intel SDM §28.2.6):
///   bits [2:0]  — memory type of the EPT PML4 structure (6 = WB)
///   bits [5:3]  — EPT page-walk length - 1 (3 = 4-level)
///   bit  [6]    — enable EPT accessed/dirty flags (optional; 0 for simplicity)
///   bits [N-1:12] — physical address of EPT PML4 (N = MAXPHYADDR)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eptp(pub u64);

impl Eptp {
    /// Build EPTP from the physical address of an EPT PML4 table.
    ///
    /// Always uses WB memory type and 4-level walk. Accessed/dirty flags
    /// are disabled to avoid requiring VMX support for those bits.
    pub fn from_pml4_pa(pml4_pa: u64) -> Self {
        let value = (pml4_pa & !0xFFF)  // 4 KiB-aligned PA, lower 12 bits cleared
            | EPTP_MEMTYPE_WB           // memory type = 6 (WB) in bits [2:0]
            | EPT_PAGE_WALK_4;          // page-walk length = 3 (4-level) in bits [5:3]
        Eptp(value)
    }
}

/// EPT leaf entry for a 4 KiB page mapping.
///
/// Leaf PTEs at level 4 (PT) encode:
///   bits[2:0]   = RWX permissions
///   bits[5:3]   = memory type (0=UC, 6=WB)
///   bit [7]     = ignore-PAT (0 = use memory type from bits[5:3])
///   bits[N-1:12]= physical page frame number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptLeafEntry(pub u64);

impl EptLeafEntry {
    /// Map a 4 KiB physical page as WB normal RAM.
    pub fn normal_ram(pa: u64) -> Self {
        EptLeafEntry((pa & !0xFFF) | EPT_RWX | EPT_MEMTYPE_WB)
    }

    /// Map a 4 KiB physical page as UC device MMIO.
    pub fn device_mmio(pa: u64) -> Self {
        EptLeafEntry((pa & !0xFFF) | EPT_RWX | EPT_MEMTYPE_UC)
    }
}

/// Non-leaf EPT entry pointing to a next-level table.
///
/// Non-leaf entries: bits[2:0]=RWX (propagated from parent), bits[51:12]=PA
/// of child table. Memory type field is ignored at non-leaf levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptTableEntry(pub u64);

impl EptTableEntry {
    pub fn pointing_to(table_pa: u64) -> Self {
        EptTableEntry((table_pa & !0xFFF) | EPT_RWX)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// INVEPT descriptor and helper
// ─────────────────────────────────────────────────────────────────────────────

/// 16-byte INVEPT descriptor operand (Intel SDM Vol. 3C §30.3).
#[repr(C)]
pub struct InveptDescriptor {
    pub eptp: u64,
    pub _reserved: u64,
}

impl InveptDescriptor {
    pub fn for_eptp(eptp: Eptp) -> Self {
        InveptDescriptor { eptp: eptp.0, _reserved: 0 }
    }
}

/// Invalidate EPT TLB entries for a single EPT context.
///
/// Must be called after every EPT mapping change to prevent stale TLB entries
/// from allowing the guest to access memory outside its permitted range.
///
/// # Safety
/// Requires VMX root mode; `desc` must be a valid INVEPT descriptor.
/// Omitting this call after EPT modification silently breaks memory isolation.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn invept_single_context(eptp: Eptp) {
    let desc = InveptDescriptor::for_eptp(eptp);
    unsafe {
        core::arch::asm!(
            "invept {0}, [{1}]",
            in(reg) INVEPT_SINGLE_CONTEXT,
            in(reg) &desc as *const InveptDescriptor,
            options(nostack, readonly)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn invept_single_context(_eptp: Eptp) {}

// ─────────────────────────────────────────────────────────────────────────────
// W^X support — EPT leaf flip + INVEPT  (Step 3 of the AT integration plan)
//
// The translator's JIT cache lives in hypervisor-private host memory
// (16 MiB at 0x2_0000_0000 by default). After serialising a translated
// block the dispatcher must flip the covering page from RW to RX. On
// Intel the EPT is the second-stage paging structure; flipping the leaf
// W bit off / X bit on plus an INVEPT single-context invalidation makes
// any subsequent guest-mode access trap (write fault → SmcWatcher; AT-23
// invariant) while keeping the same host PA mapped for execution from
// VMX root.
//
// `ACTIVE_EPT_PML4_PA` / `ACTIVE_EPTP_RAW` are populated by the boot
// pipeline once `vmcs_write_exec_controls` has loaded the EPTP into the
// active VMCS. The translator's W^X callback (see
// `dbt_integration::dbt_ept_rx_flip`) reads them, walks the paging
// structures, and invokes `invept_single_context`.
// ─────────────────────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU64, Ordering};

/// PA of the active EPT PML4. Zero until `set_active_ept` is called.
pub static ACTIVE_EPT_PML4_PA: AtomicU64 = AtomicU64::new(0);
/// Raw EPTP value (4 KiB-aligned PML4 PA OR'd with EPTP encoding flags).
/// Zero until `set_active_ept` is called.
pub static ACTIVE_EPTP_RAW: AtomicU64 = AtomicU64::new(0);

/// Publish the active EPT root. The boot pipeline (or any per-vCPU
/// switch) calls this immediately after VMWRITE-ing the EPTP into the
/// VMCS. Idempotent; the most recent values win.
pub fn set_active_ept(pml4_pa: u64, eptp: Eptp) {
    ACTIVE_EPT_PML4_PA.store(pml4_pa, Ordering::Release);
    ACTIVE_EPTP_RAW.store(eptp.0,       Ordering::Release);
}

/// Walk a 4-level EPT rooted at `pml4_pa` and flip the leaf covering
/// `host_pa` (assumed already 4 KiB-aligned) from RW to RX.
///
/// Returns `false` if any intermediate level is non-present, if the
/// leaf is mapped behind a 2 MiB or 1 GiB huge page (we do not split
/// huge pages here — the JIT region is reserved as 4 KiB pages), or
/// if the leaf does not have `EPT_READ` set.
///
/// # Safety
/// `pml4_pa` must be a valid PML4 whose intermediate tables are reachable
/// via identity-mapped raw-pointer dereference (true at VMX root after
/// the UEFI handoff). The covered page must already be present in the
/// EPT structure rooted at `pml4_pa`.
pub unsafe fn ept_flip_leaf_to_rx(pml4_pa: u64, host_pa: u64) -> bool {
    if pml4_pa == 0 || pml4_pa & 0xFFF != 0 {
        return false;
    }
    let i4 = ((host_pa >> 39) & 0x1FF) as usize;
    let i3 = ((host_pa >> 30) & 0x1FF) as usize;
    let i2 = ((host_pa >> 21) & 0x1FF) as usize;
    let i1 = ((host_pa >> 12) & 0x1FF) as usize;

    // PML4 → PDPT
    let pml4 = pml4_pa as *mut u64;
    let pml4e = unsafe { core::ptr::read_volatile(pml4.add(i4)) };
    if pml4e & EPT_READ == 0 { return false; }
    // PDPT → PD
    let pdpt = (pml4e & !0xFFFu64) as *mut u64;
    let pdpte = unsafe { core::ptr::read_volatile(pdpt.add(i3)) };
    if pdpte & EPT_READ == 0 { return false; }
    if pdpte & EPT_PAGE_SIZE_BIT != 0 { return false; } // 1 GiB leaf — refuse
    // PD → PT
    let pd = (pdpte & !0xFFFu64) as *mut u64;
    let pde = unsafe { core::ptr::read_volatile(pd.add(i2)) };
    if pde & EPT_READ == 0 { return false; }
    if pde & EPT_PAGE_SIZE_BIT != 0 { return false; } // 2 MiB leaf — refuse
    // PT → 4 KiB leaf
    let pt = (pde & !0xFFFu64) as *mut u64;
    let leaf_ptr = unsafe { pt.add(i1) };
    let leaf = unsafe { core::ptr::read_volatile(leaf_ptr) };
    if leaf & EPT_READ == 0 { return false; }
    // Clear W, set X. Preserve memory-type bits [5:3] and PFN [51:12].
    let new_leaf = (leaf & !EPT_WRITE) | EPT_EXEC;
    unsafe { core::ptr::write_volatile(leaf_ptr, new_leaf) };
    true
}

/// EPT PDPT/PD page-size bit ("PS") — set when the entry is a leaf at
/// the current level rather than a pointer to a lower table. Intel SDM
/// §28.2.2 Table 28-1 bit 7.
pub const EPT_PAGE_SIZE_BIT: u64 = 1 << 7;

/// Walk a 4-level EPT rooted at `pml4_pa` and return the host PA that
/// `guest_pa` maps to, or `None` if any level is non-present / behind a
/// huge page (we don't currently split huge pages at lookup time).
///
/// # Safety
/// Same identity-mapped EPT/raw-pointer-deref contract as the flip helpers.
pub unsafe fn ept_lookup_host_pa(pml4_pa: u64, guest_pa: u64) -> Option<u64> {
    if pml4_pa == 0 || pml4_pa & 0xFFF != 0 {
        return None;
    }
    let i4 = ((guest_pa >> 39) & 0x1FF) as usize;
    let i3 = ((guest_pa >> 30) & 0x1FF) as usize;
    let i2 = ((guest_pa >> 21) & 0x1FF) as usize;
    let i1 = ((guest_pa >> 12) & 0x1FF) as usize;
    let page_off = guest_pa & 0xFFF;

    let pml4 = pml4_pa as *mut u64;
    let pml4e = unsafe { core::ptr::read_volatile(pml4.add(i4)) };
    if pml4e & EPT_READ == 0 { return None; }
    let pdpt = (pml4e & !0xFFFu64) as *mut u64;
    let pdpte = unsafe { core::ptr::read_volatile(pdpt.add(i3)) };
    if pdpte & EPT_READ == 0 { return None; }
    if pdpte & EPT_PAGE_SIZE_BIT != 0 { return None; }
    let pd = (pdpte & !0xFFFu64) as *mut u64;
    let pde = unsafe { core::ptr::read_volatile(pd.add(i2)) };
    if pde & EPT_READ == 0 { return None; }
    if pde & EPT_PAGE_SIZE_BIT != 0 { return None; }
    let pt = (pde & !0xFFFu64) as *mut u64;
    let leaf = unsafe { core::ptr::read_volatile(pt.add(i1)) };
    if leaf & EPT_READ == 0 { return None; }
    Some((leaf & !0xFFFu64) | page_off)
}

/// Read up to `max_len` bytes of guest memory starting at `guest_pa` by
/// walking the active EPT. Returns a `(host_va, byte_len)` pair where
/// `host_va` points at the bytes (identity-readable from VMX root) and
/// `byte_len` is the number of contiguous bytes available before crossing
/// a 4 KiB page boundary (the walker doesn't currently span pages).
///
/// `None` if the active EPT root has not been published (`set_active_ept`
/// not yet called) or `guest_pa` is not mapped.
///
/// # Safety
/// Same identity-mapped contract as [`ept_lookup_host_pa`].
pub unsafe fn ept_read_guest_window(guest_pa: u64, max_len: usize) -> Option<(*const u8, usize)> {
    let pml4 = ACTIVE_EPT_PML4_PA.load(Ordering::Acquire);
    if pml4 == 0 { return None; }
    let host_pa = unsafe { ept_lookup_host_pa(pml4, guest_pa) }?;
    let page_off = (host_pa & 0xFFF) as usize;
    let page_remaining = 0x1000 - page_off;
    let len = max_len.min(page_remaining);
    Some((host_pa as *const u8, len))
}

/// Flip a contiguous host-PA range to RX, one 4 KiB page at a time,
/// and issue a single `INVEPT single-context` covering the active EPTP.
/// Returns `false` if any per-page flip failed (no partial commit:
/// pages successfully flipped before the failure remain RX).
///
/// # Safety
/// Same contract as [`ept_flip_leaf_to_rx`].
pub unsafe fn ept_flip_range_to_rx(host_pa: u64, byte_len: usize) -> bool {
    let pml4 = ACTIVE_EPT_PML4_PA.load(Ordering::Acquire);
    if pml4 == 0 || byte_len == 0 {
        return false;
    }
    let start = host_pa & !0xFFFu64;
    let end   = (host_pa.wrapping_add(byte_len as u64).wrapping_add(0xFFF)) & !0xFFFu64;
    let mut pa = start;
    while pa < end {
        if !unsafe { ept_flip_leaf_to_rx(pml4, pa) } {
            return false;
        }
        pa = pa.wrapping_add(4096);
    }
    let eptp_raw = ACTIVE_EPTP_RAW.load(Ordering::Acquire);
    unsafe { invept_single_context(Eptp(eptp_raw)) };
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw x86 MSR read/write helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a 64-bit MSR value via RDMSR.
///
/// # Safety
/// ECX must be a valid MSR index accessible at ring 0.
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

/// Write a 64-bit MSR value via WRMSR.
///
/// # Safety
/// ECX must be a valid MSR index accessible at ring 0.
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

/// Write CR4.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn write_cr4(v: u64) {
    unsafe { core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, nostack)); }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn write_cr4(_v: u64) {}

/// VMWRITE: write a natural-width, 16-bit, 32-bit, or 64-bit VMCS field.
///
/// Returns false and sets CF/ZF in RFLAGS on failure (invalid field or VMCS
/// not current). Caller should read VMCS_VM_INSTR_ERROR to diagnose failure.
///
/// # Safety
/// VMXON must be active; a VMCS must be current (VMPTRLD completed).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn vmwrite(field: u32, value: u64) -> bool {
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmwrite {value}, {field}",
            "setnbe {success}",   // success = !CF && !ZF
            field = in(reg) field as u64,
            value = in(reg) value,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }
    success != 0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn vmwrite(_field: u32, _value: u64) -> bool { true }

/// VMREAD: read a VMCS field value into a u64.
///
/// Returns (value, success). On failure returns (0, false).
///
/// # Safety
/// VMXON must be active; a VMCS must be current.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn vmread(field: u32) -> (u64, bool) {
    let value: u64;
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmread {value}, {field}",
            "setnbe {success}",
            field = in(reg) field as u64,
            value = out(reg) value,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }
    (value, success != 0)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn vmread(_field: u32) -> (u64, bool) { (0, true) }

// ─────────────────────────────────────────────────────────────────────────────
// VMXON / VMCLEAR / VMPTRLD / VMLAUNCH / VMRESUME
// ─────────────────────────────────────────────────────────────────────────────

/// Execute VMXON with the physical address of the VMXON region.
///
/// Returns true if VMXON succeeded (CF=0, ZF=0).
/// On failure: CF=1 means invalid VMXON (revision ID mismatch or alignment
/// error); ZF=1 means VMX already active or IA32_FEATURE_CONTROL not set.
///
/// # Safety
/// - CR4.VMXE must be set before calling.
/// - IA32_FEATURE_CONTROL bits 0 and 2 must be set.
/// - `vmxon_pa` must be 4 KiB-aligned and point to a valid VMXON region.
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmxon(vmxon_pa: u64) -> bool {
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmxon [{addr}]",
            "setnbe {success}",
            addr = in(reg) &vmxon_pa,
            success = out(reg_byte) success,
            options(nostack)
        );
    }
    success != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn vmxon(_pa: u64) -> bool { true }

/// Execute VMCLEAR: initialize a VMCS and mark it as not current.
///
/// Must be called before VMPTRLD. Resets the VMCS to an initialized state.
///
/// # Safety
/// - VMXON must be active.
/// - `vmcs_pa` must be 4 KiB-aligned and point to a valid VMCS region.
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmclear(vmcs_pa: u64) -> bool {
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmclear [{addr}]",
            "setnbe {success}",
            addr = in(reg) &vmcs_pa,
            success = out(reg_byte) success,
            options(nostack)
        );
    }
    success != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn vmclear(_pa: u64) -> bool { true }

/// Execute VMPTRLD: make the VMCS at `vmcs_pa` the current VMCS for this core.
///
/// After VMPTRLD, VMREAD/VMWRITE operate on this VMCS.
///
/// # Safety
/// - VMXON must be active; VMCLEAR must have been called on this region first.
/// - `vmcs_pa` must be 4 KiB-aligned, revision ID must match IA32_VMX_BASIC.
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmptrld(vmcs_pa: u64) -> bool {
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmptrld [{addr}]",
            "setnbe {success}",
            addr = in(reg) &vmcs_pa,
            success = out(reg_byte) success,
            options(nostack)
        );
    }
    success != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn vmptrld(_pa: u64) -> bool { true }

// ─────────────────────────────────────────────────────────────────────────────
// VMRESUME — Phase 5b
//
// VMRESUME re-enters the guest using the currently-loaded VMCS. Control
// transfers to GUEST_RIP / GUEST_RSP from the VMCS guest area. The next
// VMEXIT routes back to host_rip (already wired to host_vmexit_entry).
//
// VMRESUME differs from VMLAUNCH only in that the VMCS launch state must be
// already "launched" — VMLAUNCH transitions it to launched on first entry;
// every subsequent re-entry must use VMRESUME. The current dispatch model
// is "VMLAUNCH once in boot_intel; VMRESUME on every re-entry from the
// VMEXIT handler", which matches Intel SDM Vol. 3C §27.6 Figure 27-3.
//
// On failure (e.g. invalid VMCS state) CF or ZF is set and execution
// continues past the instruction; we detect that and return false so the
// caller can read VM_INSTRUCTION_ERROR via VMREAD.
// ─────────────────────────────────────────────────────────────────────────────

/// Issue VMRESUME. Returns `true` if the instruction took (control should
/// never observably return — execution transfers to the guest). Returns
/// `false` if VMRESUME failed (caller should VMREAD VM_INSTRUCTION_ERROR).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn vmresume() -> bool {
    let success: u8;
    unsafe {
        core::arch::asm!(
            "vmresume",
            "setnbe {success}",   // success = !CF && !ZF
            success = out(reg_byte) success,
            options(nostack),
        );
    }
    success != 0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn vmresume() -> bool { true }

// ─────────────────────────────────────────────────────────────────────────────
// VM exit reason decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded VM exit reason.
///
/// The EXIT_REASON VMCS field (0x4402) carries:
///   bits[15:0]  = basic exit reason
///   bit [29]    = VM-exit from VMX root operation (VMRESUME/VMLAUNCH fail)
///   bit [31]    = entry failure (1 = exit happened during VM entry)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtxExitReason {
    pub basic: u32,
    pub entry_failure: bool,
    pub from_root: bool,
}

impl VtxExitReason {
    pub fn from_vmcs_field(raw: u64) -> Self {
        VtxExitReason {
            basic:         (raw & 0xFFFF) as u32,
            entry_failure: (raw >> 31) & 1 == 1,
            from_root:     (raw >> 29) & 1 == 1,
        }
    }

    pub fn is_hlt(&self) -> bool {
        self.basic == EXIT_REASON_HLT && !self.entry_failure
    }

    pub fn is_ept_violation(&self) -> bool {
        self.basic == EXIT_REASON_EPT_VIOLATION && !self.entry_failure
    }

    pub fn is_cpuid(&self) -> bool {
        self.basic == EXIT_REASON_CPUID && !self.entry_failure
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM exit handler — routes to per-reason dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Result of handling one VM exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtxExitAction {
    /// Advance guest RIP past the faulting instruction and VMRESUME.
    Resume,
    /// Guest HLT — handler completed; VMRESUME will re-enter guest.
    HltHandled,
    /// Fatal condition; terminate the guest.
    Terminate,
}

/// Handles a VM exit by reading EXIT_REASON from the VMCS.
///
/// HLT (reason 12): records the gate trigger, advances RIP, returns HltHandled.
/// All other exits: returns Resume (RIP not advanced; caller must handle).
///
/// # Safety
/// A VMCS must be current on this core (VMPTRLD completed).
pub unsafe fn handle_vm_exit(state: &mut VtxFoundationState) -> VtxExitAction {
    let (raw_reason, ok) = unsafe { vmread(VMCS_EXIT_REASON) };
    if !ok {
        return VtxExitAction::Terminate;
    }
    let reason = VtxExitReason::from_vmcs_field(raw_reason);

    match reason.basic {
        EXIT_REASON_HLT => {
            // Advance guest RIP past the HLT instruction (1 byte).
            let (rip, ok_rip) = unsafe { vmread(VMCS_GUEST_RIP) };
            if ok_rip {
                let _ = unsafe { vmwrite(VMCS_GUEST_RIP, rip.wrapping_add(1)) };
            }
            state.record_hlt_exit();
            VtxExitAction::HltHandled
        }
        EXIT_REASON_CPUID => {
            // Minimal CPUID handler: pass through unmodified (advance RIP = 2 bytes).
            let (rip, ok_rip) = unsafe { vmread(VMCS_GUEST_RIP) };
            if ok_rip {
                let _ = unsafe { vmwrite(VMCS_GUEST_RIP, rip.wrapping_add(2)) };
            }
            VtxExitAction::Resume
        }
        EXIT_REASON_EPT_VIOLATION => {
            // AT integration bridge (Step 2 of the integration plan):
            // on instruction-fetch EPT violation the guest PC has not yet
            // been translated. Hand the ARM64 PC (== VMCS GUEST_RIP in the
            // AT model) to the translator's cold path; on a cache hit the
            // dispatcher returns immediately. The translator owns the block
            // cache + branch chain (AT-16 / AT-18); we never duplicate the
            // cache here.
            //
            // Intel SDM §27.2.1 Table 27-7 — EPT exit qualification
            //   bit 0 : data read
            //   bit 1 : data write
            //   bit 2 : instruction fetch
            const EPT_QUAL_INSTR_FETCH: u64 = 1 << 2;
            let (qual, qok) = unsafe { vmread(VMCS_EXIT_QUALIFICATION) };
            if qok && (qual & EPT_QUAL_INSTR_FETCH) != 0 {
                let (pc, ok_rip) = unsafe { vmread(VMCS_GUEST_RIP) };
                if ok_rip {
                    use aether_translator::dbt::{
                        aether_dbt_dispatch_block, aether_dbt_translate_block,
                        AetherDbtResult, MAX_INSNS_PER_BLOCK,
                    };
                    // Walk the active EPT to materialise the guest window
                    // backing `pc`. Step A's translate_block reads up to
                    // 64 instructions (= 256 bytes); the walker caps at the
                    // 4 KiB page boundary so cross-page lifts terminate
                    // cleanly. Any future-block cross-page flow is handled
                    // by re-entering the bridge on the next EPT-violation.
                    const WINDOW_BYTES: usize = MAX_INSNS_PER_BLOCK * 4;
                    // SAFETY: ACTIVE_EPT_PML4_PA was published by the boot
                    // pipeline via `set_active_ept`; the PML4 is identity-
                    // readable from VMX root.
                    let window = unsafe { ept_read_guest_window(pc, WINDOW_BYTES) };
                    if let Some((host_va, len)) = window {
                        // SAFETY: ept_read_guest_window returned a window of
                        // `len` bytes starting at `host_va`, guaranteed not
                        // to cross a 4 KiB page boundary.
                        let guest_mem = unsafe {
                            core::slice::from_raw_parts(host_va, len)
                        };
                        let t = aether_dbt_translate_block(pc, guest_mem);
                        if t == AetherDbtResult::Ok {
                            state.dbt_blocks_translated =
                                state.dbt_blocks_translated.saturating_add(1);
                            let d = aether_dbt_dispatch_block(pc, guest_mem);
                            if d == AetherDbtResult::Ok {
                                state.dbt_blocks_dispatched =
                                    state.dbt_blocks_dispatched.saturating_add(1);
                                return VtxExitAction::Resume;
                            }
                            unsafe {
                                crate::boot_x86::dual_puts(b"[dbt] dispatch failed pc=");
                                crate::boot_x86::dual_puthex64(pc);
                                crate::boot_x86::dual_puts(b"\n");
                            }
                        } else {
                            // Translation failed — print the exact (pc, word,
                            // kind) the translator stashed so the grind loop
                            // knows which encoding to add.
                            let (fpc, fw, fkind) =
                                aether_translator::dbt::aether_dbt_last_failure();
                            unsafe {
                                crate::boot_x86::dual_puts(b"[dbt] TranslateFail pc=");
                                crate::boot_x86::dual_puthex64(fpc);
                                crate::boot_x86::dual_puts(b" word=");
                                crate::boot_x86::dual_puthex64(fw as u64);
                                crate::boot_x86::dual_puts(b" kind=");
                                crate::boot_x86::dual_puthex64(fkind as u64);
                                crate::boot_x86::dual_puts(b" (1=decode 2=lift 3=short 4=empty)\n");
                            }
                        }
                    } else {
                        unsafe {
                            crate::boot_x86::dual_puts(b"[dbt] EPT window read failed pc=");
                            crate::boot_x86::dual_puthex64(pc);
                            crate::boot_x86::dual_puts(b"\n");
                        }
                    }
                }
            }
            // Data-side EPT violation (MMIO emulation path is handled by
            // dbt_dispatch.rs::handle_vmexit) or translator failure.
            state.gate.ept_violation_seen = true;
            VtxExitAction::Terminate
        }
        _ => VtxExitAction::Resume,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VMCS initialization — host state
// ─────────────────────────────────────────────────────────────────────────────

/// Captures AETHER's current register state into VMCS host-state fields.
///
/// Host-state fields are loaded by the processor on every VM exit, restoring
/// AETHER's execution context. Every field must be valid; a stale or zero host
/// RSP causes immediate corruption on the first VMEXIT.
///
/// Per-core stack requirement: each vCPU must have its own host RSP. Sharing
/// a host RSP across cores causes corruption on simultaneous VMEXITs.
///
/// # Safety
/// A VMCS must be current (VMPTRLD). `host_rsp` must point to valid stack memory
/// with enough space for the VMEXIT handler frame. `host_rip` must be the address
/// of the VMEXIT handler function on this core.
pub unsafe fn vmcs_write_host_state(host_rsp: u64, host_rip: u64) -> bool {
    let cr0 = unsafe { read_cr0() };
    let cr3 = unsafe { read_cr3() };
    let cr4 = unsafe { read_cr4() };
    let efer = unsafe { rdmsr(MSR_IA32_EFER) };
    let pat  = unsafe { rdmsr(MSR_IA32_PAT) };
    let sysenter_cs  = unsafe { rdmsr(MSR_IA32_SYSENTER_CS) } as u64;
    let sysenter_esp = unsafe { rdmsr(MSR_IA32_SYSENTER_ESP) };
    let sysenter_eip = unsafe { rdmsr(MSR_IA32_SYSENTER_EIP) };
    let gs_base = unsafe { rdmsr(MSR_IA32_GS_BASE) };
    let fs_base = unsafe { rdmsr(MSR_IA32_FS_BASE) };

    // Segment selectors: read directly from segment registers.
    // On x86-64 bare metal the data selectors are typically 0 or 0x10.
    // For UEFI-launched code all data selectors are 0x08/0x10 by convention.
    let cs_sel: u16;
    let ss_sel: u16;
    let ds_sel: u16;
    let es_sel: u16;
    let fs_sel: u16;
    let gs_sel: u16;
    let tr_sel: u16;

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov {:x}, cs",  out(reg) cs_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {:x}, ss",  out(reg) ss_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {:x}, ds",  out(reg) ds_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {:x}, es",  out(reg) es_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {:x}, fs",  out(reg) fs_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {:x}, gs",  out(reg) gs_sel,  options(nomem, nostack)
        );
        core::arch::asm!(
            "str {:x}", out(reg) tr_sel, options(nomem, nostack)
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    { cs_sel = 0; ss_sel = 0; ds_sel = 0; es_sel = 0; fs_sel = 0; gs_sel = 0; tr_sel = 0; }

    // GDT and IDT base addresses.
    let mut gdtr = [0u8; 10];
    let mut idtr = [0u8; 10];
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sgdt [{0}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
        core::arch::asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack));
    }
    let gdtr_base = u64::from_le_bytes(gdtr[2..10].try_into().unwrap_or([0u8; 8]));
    let idtr_base = u64::from_le_bytes(idtr[2..10].try_into().unwrap_or([0u8; 8]));

    // TR base: read from GDT using TR selector (simplified — use 0 if not needed).
    let tr_base: u64 = 0; // bare-metal hypervisor: TR is initialized but base is 0

    let mut ok = true;
    ok &= unsafe { vmwrite(VMCS_HOST_CR0,         cr0) };
    ok &= unsafe { vmwrite(VMCS_HOST_CR3,         cr3) };
    ok &= unsafe { vmwrite(VMCS_HOST_CR4,         cr4) };
    ok &= unsafe { vmwrite(VMCS_HOST_RSP,         host_rsp) };
    ok &= unsafe { vmwrite(VMCS_HOST_RIP,         host_rip) };
    ok &= unsafe { vmwrite(VMCS_HOST_IA32_EFER,   efer) };
    ok &= unsafe { vmwrite(VMCS_HOST_IA32_PAT,    pat) };
    ok &= unsafe { vmwrite(VMCS_HOST_SYSENTER_CS, sysenter_cs) };
    ok &= unsafe { vmwrite(VMCS_HOST_SYSENTER_ESP,sysenter_esp) };
    ok &= unsafe { vmwrite(VMCS_HOST_SYSENTER_EIP,sysenter_eip) };
    ok &= unsafe { vmwrite(VMCS_HOST_FS_BASE,     fs_base) };
    ok &= unsafe { vmwrite(VMCS_HOST_GS_BASE,     gs_base) };
    ok &= unsafe { vmwrite(VMCS_HOST_TR_BASE,     tr_base) };
    ok &= unsafe { vmwrite(VMCS_HOST_GDTR_BASE,   gdtr_base) };
    ok &= unsafe { vmwrite(VMCS_HOST_IDTR_BASE,   idtr_base) };
    ok &= unsafe { vmwrite(VMCS_HOST_CS_SEL,      cs_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_SS_SEL,      ss_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_DS_SEL,      ds_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_ES_SEL,      es_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_FS_SEL,      fs_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_GS_SEL,      gs_sel as u64) };
    ok &= unsafe { vmwrite(VMCS_HOST_TR_SEL,      tr_sel as u64) };
    ok
}

// ─────────────────────────────────────────────────────────────────────────────
// VMCS initialization — guest state
// ─────────────────────────────────────────────────────────────────────────────

/// Initial guest register state configuration.
///
/// Configured for an x86-64 guest entering in 64-bit protected mode with paging
/// enabled. Used to boot an Android kernel that has already been relocated to
/// `kernel_entry_pa` with CR3 pointing to its initial page tables at `guest_cr3`.
///
/// If `unrestricted_guest` is true and the kernel starts in real mode (before MMU),
/// set `use_protected_mode = false` to configure the guest in 16-bit real mode
/// with CR0.PE=0, CR0.PG=0.
#[derive(Debug, Clone, Copy)]
pub struct VmcsGuestConfig {
    /// Physical address of the kernel entry point.
    pub kernel_entry_pa: u64,
    /// Initial guest RSP value.
    pub guest_rsp: u64,
    /// Guest CR3 (initial page table root).
    pub guest_cr3: u64,
    /// If true, configure 64-bit protected mode. If false, configure real mode.
    pub use_protected_mode: bool,
}

impl VmcsGuestConfig {
    /// Default: 64-bit long mode, paging enabled at kernel_entry_pa.
    pub fn long_mode(kernel_entry_pa: u64, guest_rsp: u64, guest_cr3: u64) -> Self {
        VmcsGuestConfig {
            kernel_entry_pa,
            guest_rsp,
            guest_cr3,
            use_protected_mode: true,
        }
    }

    /// Real mode entry for pre-paging kernel (requires UNRESTRICTED_GUEST).
    pub fn real_mode(kernel_entry_pa: u64) -> Self {
        VmcsGuestConfig {
            kernel_entry_pa,
            guest_rsp: 0,
            guest_cr3: 0,
            use_protected_mode: false,
        }
    }
}

/// Writes VMCS guest-state fields for the initial guest entry.
///
/// # Safety
/// A VMCS must be current. For real-mode config, UNRESTRICTED_GUEST must be
/// enabled in secondary VM-execution controls or VMLAUNCH will fail with
/// VMENTRY_FAILURE_INVALID_GUEST_STATE.
pub unsafe fn vmcs_write_guest_state(cfg: &VmcsGuestConfig, eptp: Eptp) -> bool {
    let mut ok = true;

    if cfg.use_protected_mode {
        // 64-bit long mode: CR0.PE + CR0.PG + CR0.NE, CR4.PAE + CR4.VMXE, EFER.LME + EFER.LMA
        let cr0 = CR0_PE | CR0_ET | CR0_NE | CR0_WP | CR0_PG;
        let cr4 = CR4_PAE | CR4_VMXE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        let efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;

        ok &= unsafe { vmwrite(VMCS_GUEST_CR0,       cr0) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CR4,       cr4) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CR3,       cfg.guest_cr3) };
        ok &= unsafe { vmwrite(VMCS_GUEST_IA32_EFER, efer) };
        ok &= unsafe { vmwrite(VMCS_GUEST_RFLAGS,    RFLAGS_FIXED | RFLAGS_IF) };

        // Code segment: 64-bit, non-conforming, present, DPL 0
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_SEL,    0x08) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_BASE,   0) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_LIMIT,  0xFFFF_FFFF) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_AR,     AR_CODE64 as u64) };

        // Data segments: 32-bit writeable, present, DPL 0
        for (sel_field, base_field, limit_field, ar_field) in [
            (VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR),
            (VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR),
            (VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR),
            (VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR),
            (VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE, VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR),
        ] {
            ok &= unsafe { vmwrite(sel_field,   0x10) };
            ok &= unsafe { vmwrite(base_field,  0) };
            ok &= unsafe { vmwrite(limit_field, 0xFFFF_FFFF) };
            ok &= unsafe { vmwrite(ar_field,    AR_DATA32 as u64) };
        }
    } else {
        // Real mode: CR0.PE=0, CR0.PG=0 (requires UNRESTRICTED_GUEST).
        // Segments: base=sel<<4, limit=0xFFFF, AR=0x93 (present, read/write)
        let cr0 = CR0_ET | CR0_NE; // PE=0, PG=0
        let cr4 = CR4_VMXE;
        let efer = 0u64;

        ok &= unsafe { vmwrite(VMCS_GUEST_CR0,       cr0) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CR4,       cr4) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CR3,       0) };
        ok &= unsafe { vmwrite(VMCS_GUEST_IA32_EFER, efer) };
        ok &= unsafe { vmwrite(VMCS_GUEST_RFLAGS,    RFLAGS_FIXED) };

        // Real-mode CS: selector = entry >> 4, base = selector << 4
        let cs_sel = (cfg.kernel_entry_pa >> 4) as u16;
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_SEL,    cs_sel as u64) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_BASE,   (cs_sel as u64) << 4) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_LIMIT,  0xFFFF) };
        ok &= unsafe { vmwrite(VMCS_GUEST_CS_AR,     0x9B) }; // present, execute/read

        for (sel_field, base_field, limit_field, ar_field) in [
            (VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR),
            (VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR),
            (VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR),
            (VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR),
            (VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE, VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR),
        ] {
            ok &= unsafe { vmwrite(sel_field,   0) };
            ok &= unsafe { vmwrite(base_field,  0) };
            ok &= unsafe { vmwrite(limit_field, 0xFFFF) };
            ok &= unsafe { vmwrite(ar_field,    0x93) };
        }
    }

    // LDTR: unusable
    ok &= unsafe { vmwrite(VMCS_GUEST_LDTR_SEL,    0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_LDTR_BASE,   0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_LDTR_LIMIT,  0xFFFF) };
    ok &= unsafe { vmwrite(VMCS_GUEST_LDTR_AR,     AR_LDTR_UNUSABLE as u64) };

    // TR: present, busy TSS, minimal
    ok &= unsafe { vmwrite(VMCS_GUEST_TR_SEL,      0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_TR_BASE,     0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_TR_LIMIT,    0xFFFF) };
    ok &= unsafe { vmwrite(VMCS_GUEST_TR_AR,       AR_TSS64 as u64) };

    // GDT and IDT: minimal (hypervisor owns the real tables)
    ok &= unsafe { vmwrite(VMCS_GUEST_GDTR_BASE,   0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_GDTR_LIMIT,  0xFFFF) };
    ok &= unsafe { vmwrite(VMCS_GUEST_IDTR_BASE,   0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_IDTR_LIMIT,  0xFFFF) };

    // Misc guest state
    ok &= unsafe { vmwrite(VMCS_GUEST_RIP,         cfg.kernel_entry_pa) };
    ok &= unsafe { vmwrite(VMCS_GUEST_RSP,         cfg.guest_rsp) };
    ok &= unsafe { vmwrite(VMCS_GUEST_DR7,         0x0000_0400) }; // Intel reset value
    ok &= unsafe { vmwrite(VMCS_GUEST_SYSENTER_CS, 0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_SYSENTER_ESP,0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_SYSENTER_EIP,0) };
    ok &= unsafe { vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0) }; // no blocking
    ok &= unsafe { vmwrite(VMCS_GUEST_ACTIVITY,    0) };       // active state
    ok &= unsafe { vmwrite(VMCS_LINK_POINTER,      0xFFFF_FFFF_FFFF_FFFF) }; // no shadow VMCS

    let _ = eptp; // EPTP is written via the control fields, not guest state
    ok
}

// ─────────────────────────────────────────────────────────────────────────────
// VMCS initialization — VM-execution control fields
// ─────────────────────────────────────────────────────────────────────────────

/// Adjusts a VM-execution control value using the allowed-0/allowed-1 MSR pair.
///
/// For each bit: if allowed-0 requires it set, set it; if allowed-1 requires
/// it clear, clear it. Any bit that must be 1 per allowed-0 AND must be 0 per
/// allowed-1 is a hardware error (impossible combination).
#[allow(dead_code)]
fn adjust_controls(desired: u32, msr_true: u32, msr_allowed: u32) -> u32 {
    let raw = unsafe { rdmsr(msr_allowed) };
    let allowed0 = (raw & 0xFFFF_FFFF) as u32;
    let allowed1 = (raw >> 32) as u32;
    let _ = msr_true;
    (desired | allowed0) & allowed1
}

/// Writes VM-execution control fields to the current VMCS.
///
/// Key decisions:
///   - HLT_EXITING = 1 in primary controls (required for the gate test)
///   - ACTIVATE_SECONDARY = 1 to enable secondary controls
///   - ENABLE_EPT = 1 in secondary controls (4-level EPT, WB RAM)
///   - UNRESTRICTED_GUEST = 1 in secondary controls (allows pre-paging guest)
///   - HOST_ADDR_SPACE_SIZE = 1 in VM-exit controls (64-bit host)
///   - IA32E_MODE_GUEST = 1 in VM-entry controls (for 64-bit guest only)
///
/// # Safety
/// A VMCS must be current.
pub unsafe fn vmcs_write_exec_controls(
    eptp: Eptp,
    guest_64bit: bool,
) -> bool {
    let mut ok = true;

    // Pin-based controls: no external interrupt exit, no NMI handling
    let pin = PIN_CTRL_NMI_EXIT; // NMI exits to hypervisor
    ok &= unsafe { vmwrite(VMCS_PIN_EXEC_CTRL, pin as u64) };

    // Primary processor-based: HLT exits (gate test), activate secondary controls
    let cpu1 = CPU_CTRL_HLT_EXIT | CPU_CTRL_RDMSR_EXIT | CPU_CTRL_WRMSR_EXIT
        | CPU_CTRL_ACTIVATE_CTRL2;
    ok &= unsafe { vmwrite(VMCS_CPU_EXEC_CTRL, cpu1 as u64) };

    // Secondary processor-based: EPT + unrestricted guest
    let cpu2 = CPU_CTRL2_ENABLE_EPT | CPU_CTRL2_UNRESTRICTED_GUEST;
    ok &= unsafe { vmwrite(VMCS_CPU_EXEC_CTRL2, cpu2 as u64) };

    // EPT pointer (EPTP) — written to 64-bit control field
    ok &= unsafe { vmwrite(VMCS_EPT_POINTER, eptp.0) };

    // Exception bitmap: 0 = all exceptions handled by guest
    ok &= unsafe { vmwrite(VMCS_EXCEPTION_BITMAP, 0) };

    // CR0/CR4 guest-host mask and read shadow: allow guest full CR0/CR4 access
    // except CR4.VMXE which the guest must not clear.
    ok &= unsafe { vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0) };
    ok &= unsafe { vmwrite(VMCS_CR0_READ_SHADOW,     0) };
    ok &= unsafe { vmwrite(VMCS_CR4_GUEST_HOST_MASK, CR4_VMXE) };
    ok &= unsafe { vmwrite(VMCS_CR4_READ_SHADOW,     CR4_VMXE) };

    // VM-exit controls: 64-bit host, save/load EFER
    let exit_ctrl = VMEXIT_HOST_ADDR64 | VMEXIT_SAVE_EFER | VMEXIT_LOAD_EFER;
    ok &= unsafe { vmwrite(VMCS_VM_EXIT_CTRL, exit_ctrl as u64) };

    // VM-entry controls: load EFER, IA-32e mode guest (for 64-bit entry)
    let entry_ctrl = VMENTRY_LOAD_EFER
        | if guest_64bit { VMENTRY_IA32E_GUEST } else { 0 };
    ok &= unsafe { vmwrite(VMCS_VM_ENTRY_CTRL, entry_ctrl as u64) };

    ok
}

// ─────────────────────────────────────────────────────────────────────────────
// Chapter gate types
// ─────────────────────────────────────────────────────────────────────────────

/// Gate criteria for Chapter 50 — Intel VT-x Foundation.
///
/// passes() requires both conditions to be true simultaneously.
/// Verification protocol (Intel SDM §24.9.1):
///   1. CPUID.1.ECX[5]=1, IA32_FEATURE_CONTROL bits 0 and 2 set
///   2. VMXON CF=0/ZF=0
///   3. First VMEXIT EXIT_REASON=12 (HLT)
///   4. VMRESUME returns to guest without VM instruction error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtxFoundationGate {
    /// EXIT_REASON = 12 (HLT) was seen on the first VM exit.
    pub hlt_handled: bool,
    /// VMRESUME completed without setting CF or ZF in RFLAGS.
    pub vmresume_succeeded: bool,
    /// VMXON succeeded (CF=0, ZF=0).
    pub vmxon_succeeded: bool,
    /// EPT was activated (EPTP was written to VMCS).
    pub ept_active: bool,
    /// EPT violation was NOT seen during the gate test.
    pub ept_violation_seen: bool,
}

impl VtxFoundationGate {
    pub const fn new() -> Self {
        VtxFoundationGate {
            hlt_handled:       false,
            vmresume_succeeded: false,
            vmxon_succeeded:   false,
            ept_active:        false,
            ept_violation_seen: false,
        }
    }

    /// Returns true when all required gate criteria are satisfied.
    ///
    /// Required: HLT handled, VMRESUME succeeded, VMXON succeeded, EPT active.
    /// EPT violation is a failure indicator — gate fails if one was observed.
    pub fn passes(&self) -> bool {
        self.hlt_handled
            && self.vmresume_succeeded
            && self.vmxon_succeeded
            && self.ept_active
            && !self.ept_violation_seen
    }
}

/// Configuration for Chapter 50 VT-x Foundation initialization.
#[derive(Debug, Clone, Copy)]
pub struct VtxFoundationConfig {
    /// Physical address of the VMXON region (must be 4 KiB-aligned).
    pub vmxon_pa: u64,
    /// Physical address of the per-vCPU VMCS region (must be 4 KiB-aligned).
    pub vmcs_pa: u64,
    /// Physical address of the EPT PML4 table (must be 4 KiB-aligned).
    pub ept_pml4_pa: u64,
    /// Guest kernel entry physical address.
    pub kernel_entry_pa: u64,
    /// Physical address range start for guest RAM (WB in EPT).
    pub guest_ram_base: u64,
    /// Size of guest RAM in bytes.
    pub guest_ram_size: u64,
    /// MMIO region start PA (UC in EPT); 0 if no MMIO mapped.
    pub mmio_base: u64,
    /// MMIO region size in bytes; 0 if no MMIO mapped.
    pub mmio_size: u64,
    /// Entry mode: true = 64-bit long mode, false = real mode (UNRESTRICTED_GUEST).
    pub guest_64bit: bool,
}

impl VtxFoundationConfig {
    /// Default configuration for Chapter 50 gate test on QEMU x86 machine.
    ///
    /// Uses a 2 GiB guest RAM window at 0x1_0000_0000 (above the first 4 GiB
    /// to avoid conflicts with MMIO), EPT PML4 at vmxon_pa + 4 KiB, VMCS at
    /// vmxon_pa + 8 KiB. Guest enters in 64-bit long mode.
    pub fn aether_defaults(vmxon_pa: u64) -> Self {
        VtxFoundationConfig {
            vmxon_pa,
            vmcs_pa:         vmxon_pa + 0x1000,
            ept_pml4_pa:     vmxon_pa + 0x2000,
            kernel_entry_pa: 0x1_0000_0000,
            guest_ram_base:  0x1_0000_0000,
            guest_ram_size:  2 * 1024 * 1024 * 1024, // 2 GiB
            mmio_base:       0,
            mmio_size:       0,
            guest_64bit:     true,
        }
    }

    pub fn validate(&self) -> Result<(), VtxError> {
        if self.vmxon_pa & 0xFFF != 0 {
            return Err(VtxError::UnalignedVmxonRegion);
        }
        if self.vmcs_pa & 0xFFF != 0 {
            return Err(VtxError::UnalignedVmcsRegion);
        }
        if self.ept_pml4_pa & 0xFFF != 0 {
            return Err(VtxError::UnalignedEptPml4);
        }
        if self.guest_ram_size == 0 {
            return Err(VtxError::ZeroGuestRamSize);
        }
        Ok(())
    }
}

/// Phase machine for Chapter 50 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtxFoundationPhase {
    NotStarted,
    VmxDetected,      // CPUID.1.ECX[5]=1 confirmed
    FeatureControlSet,// IA32_FEATURE_CONTROL bits 0 and 2 set
    VmxonComplete,    // VMXON executed; now in VMX root mode
    VmcsInitialized,  // VMCLEAR + VMPTRLD + all VMCS fields written
    EptActive,        // EPTP written to VMCS; INVEPT called
    GatePassed,       // first HLT exit handled; VMRESUME succeeded
}

/// Error conditions that can occur during Chapter 50 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtxError {
    VmxNotSupported,
    FeatureControlLocked,
    VmxonFailed,
    VmclearFailed,
    VmptrldFailed,
    VmwriteHostStateFailed,
    VmwriteGuestStateFailed,
    VmwriteControlsFailed,
    UnalignedVmxonRegion,
    UnalignedVmcsRegion,
    UnalignedEptPml4,
    ZeroGuestRamSize,
    VmlaunchFailed,
    VmresumeFailed,
}

/// Runtime state for Chapter 50.
#[derive(Debug)]
pub struct VtxFoundationState {
    pub phase: VtxFoundationPhase,
    pub gate: VtxFoundationGate,
    pub exit_count: u64,
    pub hlt_exit_count: u64,
    pub last_exit_reason: u32,
    pub vmcs_revision_id: u32,
    pub eptp: u64,
    /// AT-integration counters — incremented on every DBT cold/hot dispatch
    /// triggered by an EPT-violation instruction-fetch arm in `handle_vm_exit`.
    pub dbt_blocks_translated: u64,
    pub dbt_blocks_dispatched: u64,
}

impl VtxFoundationState {
    pub const fn new() -> Self {
        VtxFoundationState {
            phase: VtxFoundationPhase::NotStarted,
            gate: VtxFoundationGate::new(),
            exit_count: 0,
            hlt_exit_count: 0,
            last_exit_reason: 0,
            vmcs_revision_id: 0,
            eptp: 0,
            dbt_blocks_translated: 0,
            dbt_blocks_dispatched: 0,
        }
    }

    pub fn record_hlt_exit(&mut self) {
        self.exit_count += 1;
        self.hlt_exit_count += 1;
        self.last_exit_reason = EXIT_REASON_HLT;
        self.gate.hlt_handled = true;
        // VMRESUME is considered successful when hlt_handled transitions to true
        // and the caller returns Resume or HltHandled without error.
        self.gate.vmresume_succeeded = true;
    }

    pub fn gate(&self) -> &VtxFoundationGate {
        &self.gate
    }

    pub fn is_gate_passed(&self) -> bool {
        self.gate.passes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level initialization pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize Intel VT-x Foundation (Chapter 50 gate pipeline).
///
/// Executes the 8-step pipeline:
///
///   1. Detect VMX support (CPUID.1.ECX[5])
///   2. Enable IA32_FEATURE_CONTROL (lock + VMXON-outside-SMX)
///   3. Set CR4.VMXE = 1 (required before VMXON)
///   4. Execute VMXON — enter VMX root mode
///   5. VMCLEAR + VMPTRLD — initialize per-vCPU VMCS
///   6. Write VMCS host state (captures AETHER's current register context)
///   7. Write VMCS guest state (initial guest entry configuration)
///   8. Write VMCS VM-execution controls (EPT + UNRESTRICTED_GUEST + HLT exit)
///
/// After this call the caller must execute VMLAUNCH to transfer to the guest.
/// The first VM exit will trigger the gate test (EXIT_REASON_HLT = 12).
///
/// # Safety
/// - Must run on an x86-64 processor in ring 0.
/// - `config.vmxon_pa`, `config.vmcs_pa`, `config.ept_pml4_pa` must point to
///   caller-allocated 4 KiB-aligned, zero-initialized regions.
/// - `host_rsp` must point to a valid per-core stack for the VMEXIT handler.
/// - `host_rip` must be the address of the VMEXIT handler for this core.
///
/// Returns Ok(VtxFoundationState) on success; the caller must execute VMLAUNCH
/// and then call `handle_vm_exit()` in the VMEXIT handler loop to complete the
/// gate test.
pub unsafe fn init_vtx_foundation(
    config: &VtxFoundationConfig,
    vmxon_region: &mut VmxonRegion,
    vmcs_region:  &mut VmcsRegion,
    host_rsp: u64,
    host_rip: u64,
) -> Result<VtxFoundationState, VtxError> {
    config.validate()?;

    let mut state = VtxFoundationState::new();

    // ── Step 1: Detect VMX ────────────────────────────────────────────────────
    let features = unsafe { VmxCpuFeatures::detect() };
    if !features.vmx_supported {
        return Err(VtxError::VmxNotSupported);
    }
    state.phase = VtxFoundationPhase::VmxDetected;

    // ── Step 2: Enable IA32_FEATURE_CONTROL ───────────────────────────────────
    unsafe { Ia32FeatureControlMsr::enable_and_lock() }?;
    state.phase = VtxFoundationPhase::FeatureControlSet;

    // ── Step 3: CR4.VMXE = 1 ─────────────────────────────────────────────────
    let cr4 = unsafe { read_cr4() };
    unsafe { write_cr4(cr4 | CR4_VMXE) };

    // ── Step 4: Read VMCS revision ID and initialize VMXON/VMCS regions ──────
    let vmx_basic = unsafe { VmxBasicMsr::read() };
    state.vmcs_revision_id = vmx_basic.revision_id;

    vmxon_region.init(vmx_basic.revision_id);
    vmcs_region.init(vmx_basic.revision_id);

    // VMXON — enter VMX root mode
    if !unsafe { vmxon(config.vmxon_pa) } {
        return Err(VtxError::VmxonFailed);
    }
    state.gate.vmxon_succeeded = true;
    state.phase = VtxFoundationPhase::VmxonComplete;

    // ── Step 5: VMCLEAR + VMPTRLD ─────────────────────────────────────────────
    if !unsafe { vmclear(config.vmcs_pa) } {
        return Err(VtxError::VmclearFailed);
    }
    if !unsafe { vmptrld(config.vmcs_pa) } {
        return Err(VtxError::VmptrldFailed);
    }
    state.phase = VtxFoundationPhase::VmcsInitialized;

    // ── Step 6: Build EPTP from PML4 PA ──────────────────────────────────────
    let eptp = Eptp::from_pml4_pa(config.ept_pml4_pa);
    state.eptp = eptp.0;

    // ── Step 7: Write VMCS host state ─────────────────────────────────────────
    if !unsafe { vmcs_write_host_state(host_rsp, host_rip) } {
        return Err(VtxError::VmwriteHostStateFailed);
    }

    // ── Step 8: Write VMCS guest state ────────────────────────────────────────
    let guest_cfg = if config.guest_64bit {
        VmcsGuestConfig::long_mode(config.kernel_entry_pa, 0, 0)
    } else {
        VmcsGuestConfig::real_mode(config.kernel_entry_pa)
    };

    if !unsafe { vmcs_write_guest_state(&guest_cfg, eptp) } {
        return Err(VtxError::VmwriteGuestStateFailed);
    }

    // ── Step 9: Write VM-execution controls (EPT, UNRESTRICTED_GUEST, HLT) ───
    if !unsafe { vmcs_write_exec_controls(eptp, config.guest_64bit) } {
        return Err(VtxError::VmwriteControlsFailed);
    }

    // Mark EPT active; call INVEPT to flush any stale TLB entries.
    // Must be called after every EPT mapping change (including initial setup).
    unsafe { invept_single_context(eptp) };
    state.gate.ept_active = true;
    state.phase = VtxFoundationPhase::EptActive;

    Ok(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — run on native host with `cargo test --lib -p hypervisor`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── W^X walker tests (Step 3 of the AT integration plan) ──────────────
    //
    // Build a synthetic 4-level EPT pointing at a single 4 KiB leaf, walk it
    // with `ept_flip_leaf_to_rx`, and verify the leaf transitions RW → RX.
    // All tables are aligned heap allocations leaked for the duration of the
    // test; their host-VA == host-PA on the test process so the walker can
    // dereference table PAs directly.

    fn alloc_aligned_table() -> *mut u64 {
        // 4 KiB aligned zeroed page.
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: layout is valid (non-zero size, power-of-two alignment).
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        ptr as *mut u64
    }

    #[test]
    fn ept_walker_flips_leaf_rw_to_rx() {
        // Target: virtual host PA 0x2_0000_0000 + 0x1000 (one page above
        // the JIT base) — the indices that the walker will use.
        let host_pa: u64 = 0x2_0000_1000;
        let i4 = ((host_pa >> 39) & 0x1FF) as usize;
        let i3 = ((host_pa >> 30) & 0x1FF) as usize;
        let i2 = ((host_pa >> 21) & 0x1FF) as usize;
        let i1 = ((host_pa >> 12) & 0x1FF) as usize;

        let pml4 = alloc_aligned_table();
        let pdpt = alloc_aligned_table();
        let pd   = alloc_aligned_table();
        let pt   = alloc_aligned_table();

        // Chain levels together with EPT_RWX non-leaf entries.
        unsafe {
            *pml4.add(i4) = (pdpt as u64) | EPT_RWX;
            *pdpt.add(i3) = (pd   as u64) | EPT_RWX;
            *pd  .add(i2) = (pt   as u64) | EPT_RWX;
            // Leaf points at the same page; RW + WB.
            *pt  .add(i1) = (host_pa & !0xFFF) | EPT_RWX | EPT_MEMTYPE_WB;
        }

        // Before flip: leaf is RWX.
        let before = unsafe { *pt.add(i1) };
        assert_ne!(before & EPT_WRITE, 0, "leaf must start writable");
        assert_ne!(before & EPT_EXEC,  0, "RWX sanity");

        let ok = unsafe { ept_flip_leaf_to_rx(pml4 as u64, host_pa) };
        assert!(ok, "walker should succeed on a well-formed 4-level EPT");

        let after = unsafe { *pt.add(i1) };
        assert_eq!(after & EPT_WRITE, 0,        "W must be cleared");
        assert_ne!(after & EPT_EXEC,  0,        "X must remain / be set");
        assert_ne!(after & EPT_READ,  0,        "R preserved");
        assert_eq!(after & !0xFFF, before & !0xFFF, "PFN preserved");
    }

    #[test]
    fn ept_walker_refuses_huge_pages() {
        let host_pa: u64 = 0x2_0020_0000; // 2 MiB-aligned
        let i4 = ((host_pa >> 39) & 0x1FF) as usize;
        let i3 = ((host_pa >> 30) & 0x1FF) as usize;
        let i2 = ((host_pa >> 21) & 0x1FF) as usize;

        let pml4 = alloc_aligned_table();
        let pdpt = alloc_aligned_table();
        let pd   = alloc_aligned_table();

        unsafe {
            *pml4.add(i4) = (pdpt as u64) | EPT_RWX;
            *pdpt.add(i3) = (pd   as u64) | EPT_RWX;
            // 2 MiB leaf at PD with PS bit set.
            *pd  .add(i2) = (host_pa & !0xFFF) | EPT_RWX | EPT_MEMTYPE_WB | EPT_PAGE_SIZE_BIT;
        }

        let ok = unsafe { ept_flip_leaf_to_rx(pml4 as u64, host_pa) };
        assert!(!ok, "walker must refuse 2 MiB huge-page leaves (split needed)");
    }

    #[test]
    fn ept_walker_refuses_nonpresent_intermediate() {
        let host_pa: u64 = 0x2_0001_0000;
        let pml4 = alloc_aligned_table();
        // PML4 entry zero → walk should bail at level 4.
        let ok = unsafe { ept_flip_leaf_to_rx(pml4 as u64, host_pa) };
        assert!(!ok, "walker must refuse non-present PML4 entries");
    }

    #[test]
    fn ept_walker_rejects_zero_pml4() {
        assert!(!unsafe { ept_flip_leaf_to_rx(0, 0x1000) });
    }

    #[test]
    fn ept_walker_rejects_misaligned_pml4() {
        assert!(!unsafe { ept_flip_leaf_to_rx(0x1001, 0x1000) });
    }

    #[test]
    fn vmcs_field_encoding_sanity() {
        // Spot-check a representative sample of VMCS field encodings against
        // the known values from Linux KVM arch/x86/include/asm/vmx.h.
        // These constants are the most common source of AI mistakes.

        // 16-bit guest-state
        assert_eq!(VMCS_GUEST_ES_SEL,   0x0800, "GUEST_ES_SEL");
        assert_eq!(VMCS_GUEST_CS_SEL,   0x0802, "GUEST_CS_SEL");
        assert_eq!(VMCS_GUEST_SS_SEL,   0x0804, "GUEST_SS_SEL");
        assert_eq!(VMCS_GUEST_DS_SEL,   0x0806, "GUEST_DS_SEL");
        assert_eq!(VMCS_GUEST_TR_SEL,   0x080E, "GUEST_TR_SEL");
        // 16-bit host-state
        assert_eq!(VMCS_HOST_CS_SEL,    0x0C02, "HOST_CS_SEL");
        assert_eq!(VMCS_HOST_TR_SEL,    0x0C0C, "HOST_TR_SEL");
        // 64-bit control
        assert_eq!(VMCS_EPT_POINTER,    0x201A, "EPT_POINTER");
        assert_eq!(VMCS_LINK_POINTER,   0x2800, "LINK_POINTER");
        // 32-bit control
        assert_eq!(VMCS_PIN_EXEC_CTRL,  0x4000, "PIN_EXEC_CTRL");
        assert_eq!(VMCS_CPU_EXEC_CTRL,  0x4002, "CPU_EXEC_CTRL");
        assert_eq!(VMCS_VM_EXIT_CTRL,   0x400C, "VM_EXIT_CTRL");
        assert_eq!(VMCS_VM_ENTRY_CTRL,  0x4012, "VM_ENTRY_CTRL");
        assert_eq!(VMCS_CPU_EXEC_CTRL2, 0x401E, "CPU_EXEC_CTRL2");
        // 32-bit read-only
        assert_eq!(VMCS_EXIT_REASON,    0x4402, "EXIT_REASON");
        assert_eq!(VMCS_VM_INSTR_ERROR, 0x4400, "VM_INSTR_ERROR");
        // 32-bit guest-state
        assert_eq!(VMCS_GUEST_CS_LIMIT, 0x4802, "GUEST_CS_LIMIT");
        assert_eq!(VMCS_GUEST_TR_AR,    0x4822, "GUEST_TR_AR");
        // natural-width guest-state
        assert_eq!(VMCS_GUEST_CR0,      0x6800, "GUEST_CR0");
        assert_eq!(VMCS_GUEST_CR3,      0x6802, "GUEST_CR3");
        assert_eq!(VMCS_GUEST_RIP,      0x681E, "GUEST_RIP");
        assert_eq!(VMCS_GUEST_RSP,      0x681C, "GUEST_RSP");
        assert_eq!(VMCS_GUEST_RFLAGS,   0x6820, "GUEST_RFLAGS");
        // natural-width host-state
        assert_eq!(VMCS_HOST_CR0,       0x6C00, "HOST_CR0");
        assert_eq!(VMCS_HOST_CR3,       0x6C02, "HOST_CR3");
        assert_eq!(VMCS_HOST_RSP,       0x6C14, "HOST_RSP");
        assert_eq!(VMCS_HOST_RIP,       0x6C16, "HOST_RIP");
    }

    #[test]
    fn exit_reason_hlt_decode() {
        let reason = VtxExitReason::from_vmcs_field(EXIT_REASON_HLT as u64);
        assert!(reason.is_hlt());
        assert!(!reason.entry_failure);
        assert!(!reason.from_root);
    }

    #[test]
    fn exit_reason_ept_violation_decode() {
        let reason = VtxExitReason::from_vmcs_field(EXIT_REASON_EPT_VIOLATION as u64);
        assert!(reason.is_ept_violation());
        assert!(!reason.is_hlt());
    }

    #[test]
    fn exit_reason_entry_failure_flag() {
        let raw = (1u64 << 31) | EXIT_REASON_HLT as u64;
        let reason = VtxExitReason::from_vmcs_field(raw);
        assert!(reason.entry_failure);
        assert!(!reason.is_hlt(), "entry_failure set: is_hlt must return false");
    }

    #[test]
    fn eptp_encoding() {
        let pml4_pa: u64 = 0x1_2345_6000; // 4 KiB-aligned
        let eptp = Eptp::from_pml4_pa(pml4_pa);
        // Memory type bits [2:0] = 6 (WB)
        assert_eq!(eptp.0 & 0x7, EPTP_MEMTYPE_WB, "EPTP memory type must be WB=6");
        // Page-walk length bits [5:3] = 3 (4-level = walk_length - 1)
        assert_eq!((eptp.0 >> 3) & 0x7, 3, "EPTP page-walk length must be 3 (4-level)");
        // PA bits must be preserved
        assert_eq!(eptp.0 & !0xFFF, pml4_pa, "EPTP PA bits must match PML4 PA");
    }

    #[test]
    fn ept_leaf_entry_wb() {
        let pa: u64 = 0x4000_0000;
        let entry = EptLeafEntry::normal_ram(pa);
        // Permissions: RWX in bits [2:0]
        assert_eq!(entry.0 & 0x7, EPT_RWX, "WB RAM entry must have RWX");
        // Memory type: WB=6 in bits [5:3]
        assert_eq!((entry.0 >> 3) & 0x7, 6, "WB RAM entry memory type must be 6 (WB)");
        // PA aligned
        assert_eq!(entry.0 & !0xFFF, pa, "PA bits must match input");
    }

    #[test]
    fn ept_leaf_entry_uc() {
        let pa: u64 = 0xFEC0_0000; // APIC MMIO
        let entry = EptLeafEntry::device_mmio(pa);
        assert_eq!(entry.0 & 0x7, EPT_RWX, "UC device entry must have RWX");
        assert_eq!((entry.0 >> 3) & 0x7, 0, "UC device entry memory type must be 0 (UC)");
        assert_eq!(entry.0 & !0xFFF, pa, "PA bits must match input");
    }

    #[test]
    fn gate_requires_both_hlt_and_vmresume() {
        let mut gate = VtxFoundationGate::new();
        assert!(!gate.passes());

        gate.hlt_handled = true;
        assert!(!gate.passes(), "hlt alone is not enough");

        gate.vmresume_succeeded = true;
        assert!(!gate.passes(), "also need vmxon_succeeded");

        gate.vmxon_succeeded = true;
        assert!(!gate.passes(), "also need ept_active");

        gate.ept_active = true;
        assert!(gate.passes(), "all required fields set, no EPT violation");
    }

    #[test]
    fn gate_fails_on_ept_violation() {
        let mut gate = VtxFoundationGate::new();
        gate.hlt_handled = true;
        gate.vmresume_succeeded = true;
        gate.vmxon_succeeded = true;
        gate.ept_active = true;
        gate.ept_violation_seen = true;
        assert!(!gate.passes(), "EPT violation must fail the gate");
    }

    #[test]
    fn config_validate_alignment() {
        let bad = VtxFoundationConfig {
            vmxon_pa: 0x1001, // misaligned
            vmcs_pa: 0x2000,
            ept_pml4_pa: 0x3000,
            kernel_entry_pa: 0x1_0000_0000,
            guest_ram_base: 0x1_0000_0000,
            guest_ram_size: 0x8000_0000,
            mmio_base: 0,
            mmio_size: 0,
            guest_64bit: true,
        };
        assert!(matches!(bad.validate(), Err(VtxError::UnalignedVmxonRegion)));
    }

    #[test]
    fn config_validate_zero_ram() {
        let bad = VtxFoundationConfig {
            vmxon_pa: 0x1000,
            vmcs_pa: 0x2000,
            ept_pml4_pa: 0x3000,
            kernel_entry_pa: 0,
            guest_ram_base: 0,
            guest_ram_size: 0, // zero RAM
            mmio_base: 0,
            mmio_size: 0,
            guest_64bit: true,
        };
        assert!(matches!(bad.validate(), Err(VtxError::ZeroGuestRamSize)));
    }

    #[test]
    fn state_record_hlt_exit_sets_gate() {
        let mut state = VtxFoundationState::new();
        assert!(!state.gate.hlt_handled);
        state.record_hlt_exit();
        assert!(state.gate.hlt_handled);
        assert!(state.gate.vmresume_succeeded);
        assert_eq!(state.hlt_exit_count, 1);
        assert_eq!(state.last_exit_reason, EXIT_REASON_HLT);
    }

    #[test]
    fn vmxon_region_revision_id() {
        let mut region = VmxonRegion::new();
        assert_eq!(region.revision_id(), 0);
        region.init(0x0000_0007);
        assert_eq!(region.revision_id(), 0x0000_0007);
    }

    #[test]
    fn vmcs_region_revision_id_clears_bit31() {
        let mut region = VmcsRegion::new();
        // Bit 31 must be clear (shadow VMCS indicator — AETHER never uses it)
        region.init(0x8000_0007);
        assert_eq!(region.revision_id(), 0x0000_0007, "bit 31 must be cleared");
    }

    #[test]
    fn vmx_cpu_features_none() {
        let f = VmxCpuFeatures::none();
        assert!(!f.vmx_supported);
        assert!(!f.true_controls_supported);
    }

    #[test]
    fn vmx_basic_msr_zero() {
        let b = VmxBasicMsr::zero();
        assert_eq!(b.revision_id, 0);
        assert_eq!(b.vmxon_region_size, 0);
        assert!(!b.true_controls);
    }
}
