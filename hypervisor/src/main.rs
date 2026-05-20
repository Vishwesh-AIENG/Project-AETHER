// AETHER hypervisor — UEFI entry point
//
// Two architectures, one binary name:
//   target_arch = "aarch64"  → full ARM64 EL2 hypervisor (Ch1-49)
//   target_arch = "x86_64"   → x86 root-mode hypervisor (Ch50-54), bring-up only
//
// The two entry points share Cargo.toml `[[bin]] name = "hypervisor"`; the
// active body is selected at compile time by the target triple.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// ─────────────────────────────────────────────────────────────────────────────
// Panic handler — common to both architectures.
// ─────────────────────────────────────────────────────────────────────────────
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)); }
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        core::hint::spin_loop();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ARM64 EL2 entry — chapters 1-49.  Active when building for
// aarch64-unknown-uefi.
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(target_arch = "aarch64")]
mod arm64_entry {
    use core::arch::asm;
    use core::ffi::c_void;

    use hypervisor::arm64::regs;
    use hypervisor::arm64::virt::{configure_el2_virt, hcr_el2};
    use hypervisor::boot::{acpi_find_table, AcpiRsdp, BootContext, EfiSystemTable, GuestLaunch};
    use hypervisor::cpu::Mpidr;
    use hypervisor::gic::{aether_vgic_init, discover_gic_from_madt, init_physical_gic};
    use hypervisor::irq_forward;
    use hypervisor::kernel::{AndroidDtbConfig, MAX_ANDROID_CPUS, MAX_KERNEL_CMDLINE_LEN};
    use hypervisor::linux_boot::prepare_linux_boot;
    use hypervisor::memory::{BumpAllocator, MapKind, SmmuStreamTable, Stage2Tables};
    use hypervisor::smp;
    use hypervisor::uart::Uart;

    const UART_PA: u64 = 0x0900_0000;
    const GICD_PA: u64 = 0x0800_0000;
    const GICR_PA: u64 = 0x080A_0000;
    const DRAM_BASE: u64 = 0x4000_0000;
    const ANDROID_IPA_BASE: u64 = DRAM_BASE;
    const ANDROID_RAM_SIZE: u64 = 2 * 1024 * 1024 * 1024;
    pub const KERNEL1_PA: u64 = 0x4080_0000;
    pub const DTB1_PA: u64 = 0x4400_0000;
    const SMP_CORE_COUNT: usize = 4;

    #[allow(dead_code)]
    static mut SMMU_STREAM_TABLE: SmmuStreamTable = SmmuStreamTable::new_aborted();

    #[unsafe(no_mangle)]
    pub extern "efiapi" fn efi_main(
        image_handle: *mut c_void,
        system_table: *const c_void,
    ) -> usize {
        let uart = unsafe { Uart::new(UART_PA) };

        puts(&uart, "\r\n");
        puts(&uart, "======================================\r\n");
        puts(&uart, "  AETHER Hypervisor starting...      \r\n");
        puts(&uart, "======================================\r\n");

        let el = unsafe { regs::current_el() };
        puts(&uart, "  CurrentEL: EL");
        putdec(&uart, el as usize);
        puts(&uart, "\r\n");

        if el != 2 {
            puts(&uart, "[FATAL] AETHER requires EL2. Halting.\r\n");
            hypervisor::boot::halt();
        }
        puts(&uart, "  EL2 detected\r\n");

        puts(&uart, "  ExitBootServices...\r\n");
        let boot_ctx = unsafe {
            BootContext::from_uefi(
                image_handle as *mut _,
                system_table as *const EfiSystemTable,
            )
        };
        let boot_result = unsafe { boot_ctx.run() };
        puts(&uart, "  ExitBootServices: OK\r\n");

        let total_mib = boot_result.memory_map.total_conventional_bytes() / (1024 * 1024);
        puts(&uart, "  Conventional RAM: ");
        putdec(&uart, total_mib as usize);
        puts(&uart, " MiB\r\n");

        let largest = boot_result.memory_map
            .largest_conventional()
            .unwrap_or_else(|| {
                puts(&uart, "[FATAL] No conventional RAM found.\r\n");
                hypervisor::boot::halt();
            });

        puts(&uart, "  Largest region PA: ");
        puthex64(&uart, largest.base);
        puts(&uart, "  size: ");
        putdec(&uart, (largest.size / (1024 * 1024)) as usize);
        puts(&uart, " MiB\r\n");

        let mut alloc = BumpAllocator::new(largest.base, largest.size);
        let s2 = unsafe { Stage2Tables::new(&mut alloc) }.unwrap_or_else(|| {
            puts(&uart, "[FATAL] OOM allocating Stage 2 root tables.\r\n");
            hypervisor::boot::halt();
        });

        unsafe {
            s2.map_range(ANDROID_IPA_BASE, ANDROID_IPA_BASE, ANDROID_RAM_SIZE,
                         MapKind::NormalRw, &mut alloc)
              .unwrap_or_else(|_| {
                  puts(&uart, "[FATAL] Stage 2 RAM mapping failed.\r\n");
                  hypervisor::boot::halt();
              });
        }
        unsafe {
            s2.map_range(0x0800_0000, 0x0800_0000, 0x0200_0000,
                         MapKind::DeviceRw, &mut alloc).ok();
        }
        unsafe {
            s2.map_range(UART_PA, UART_PA, 0x1000,
                         MapKind::DeviceRw, &mut alloc).ok();
        }

        puts(&uart, "  Stage 2 tables: OK\r\n");
        puts(&uart, "  S2 root PA: ");
        puthex64(&uart, s2.root_pa());
        puts(&uart, "\r\n");

        unsafe { hypervisor::arm64::vectors::install_vectors() };
        puts(&uart, "  Exception vectors: OK\r\n");

        unsafe { configure_el2_virt(s2.root_pa()) };
        let hcr   = unsafe { regs::read_hcr_el2() };
        let vttbr = unsafe { read_sysreg64("vttbr_el2") };
        let vtcr  = unsafe { read_sysreg64("vtcr_el2") };

        puts(&uart, "  HCR_EL2   = ");
        puthex64(&uart, hcr);
        puts(&uart, "\r\n");
        puts(&uart, "  VTTBR_EL2 = ");
        puthex64(&uart, vttbr);
        puts(&uart, "\r\n");
        puts(&uart, "  VTCR_EL2  = ");
        puthex64(&uart, vtcr);
        puts(&uart, "\r\n");

        if hcr & hcr_el2::VM == 0 {
            puts(&uart, "[FATAL] HCR_EL2.VM not set — Stage 2 not active.\r\n");
            hypervisor::boot::halt();
        }
        if hcr & hcr_el2::RW == 0 {
            puts(&uart, "[FATAL] HCR_EL2.RW not set — lower EL is not AArch64.\r\n");
            hypervisor::boot::halt();
        }

        let (gicd_base, gicr_base, maint_intid) = discover_gic_addresses(&uart, &boot_result);
        unsafe { init_physical_gic(gicd_base, gicr_base, SMP_CORE_COUNT) };
        puts(&uart, "  GIC: OK (GICD=");
        puthex64(&uart, gicd_base);
        puts(&uart, " GICR=");
        puthex64(&uart, gicr_base);
        puts(&uart, ")\r\n");

        unsafe { aether_vgic_init(maint_intid) };
        puts(&uart, "  VGIC: OK (maint_intid=");
        putdec(&uart, maint_intid as usize);
        puts(&uart, ")\r\n");

        unsafe { irq_forward::setup_irq_forwarding(gicd_base, gicr_base, SMP_CORE_COUNT) };
        puts(&uart, "  IRQ forwarding: timer PPIs + UART SPI enabled\r\n");

        {
            let partition = unsafe { hypervisor::cpu::aether_partition_mut() };
            for idx in 0..SMP_CORE_COUNT {
                partition.register_core(Mpidr(idx as u64));
            }
        }
        puts(&uart, "  SMP: ");
        putdec(&uart, SMP_CORE_COUNT);
        puts(&uart, " cores pre-registered\r\n");

        smp::set_s2_root_pa(s2.root_pa());
        smp::set_gicr_base(gicr_base);

        let entry_pa = smp::secondary_entry_pa();
        for idx in 1..SMP_CORE_COUNT {
            let target_mpidr = idx as u64;
            let rc = unsafe { smp::psci_cpu_on_hvc(target_mpidr, entry_pa, 0) };
            puts(&uart, "  SMP: CPU_ON core ");
            putdec(&uart, idx);
            puts(&uart, " -> ");
            putdec(&uart, rc as usize);
            puts(&uart, "\r\n");
        }

        puts(&uart, "======================================\r\n");
        puts(&uart, "  Hypervisor ready.\r\n");
        puts(&uart, "======================================\r\n");
        puts(&uart, "\r\n");

        const CMDLINE: &[u8] = b"console=ttyAMA0 earlycon rdinit=/bin/sh";
        let mut cmdline_buf = [0u8; MAX_KERNEL_CMDLINE_LEN];
        let cmdline_len = CMDLINE.len();
        cmdline_buf[..cmdline_len].copy_from_slice(CMDLINE);

        const GICR_SIZE_PER_CORE: u64 = 128 * 1024;
        let gicr_size_smp = GICR_SIZE_PER_CORE * SMP_CORE_COUNT as u64;
        const UART_SPI_INTID: u32 = 33;

        let dtb_cfg = AndroidDtbConfig {
            cpu_count: SMP_CORE_COUNT,
            cpu_mpidr: {
                let mut m = [0u64; MAX_ANDROID_CPUS];
                for i in 0..SMP_CORE_COUNT {
                    m[i] = i as u64;
                }
                m
            },
            memory_base: ANDROID_IPA_BASE,
            memory_size: ANDROID_RAM_SIZE,
            gicd_base: GICD_PA,
            gicd_size: 0x10000,
            gicr_base: GICR_PA,
            gicr_size: gicr_size_smp,
            uart_base: UART_PA,
            uart_irq_spi: UART_SPI_INTID,
            cmdline: cmdline_buf,
            cmdline_len,
        };

        puts(&uart, "  ch36: Building Android DTB (4-core SMP + IRQ forwarding)...\r\n");
        let load_cfg = unsafe {
            prepare_linux_boot(KERNEL1_PA, DTB1_PA, &dtb_cfg)
        }.unwrap_or_else(|_| {
            puts(&uart, "[FATAL] prepare_linux_boot failed\r\n");
            hypervisor::boot::halt()
        });

        let entry_ipa = load_cfg.kernel_load_ipa;
        puts(&uart, "  DTB at IPA=");
        puthex64(&uart, DTB1_PA);
        puts(&uart, "  Kernel entry IPA=");
        puthex64(&uart, entry_ipa);
        puts(&uart, "\r\n");
        puts(&uart, "  ERET to Linux kernel EL1...\r\n");

        unsafe {
            GuestLaunch { entry_pa: entry_ipa, dtb_pa: DTB1_PA }.eret_to_el1();
        }
    }

    fn discover_gic_addresses(
        uart: &Uart,
        boot_result: &hypervisor::boot::BootResult,
    ) -> (u64, u64, u32) {
        if let Some(rsdp_pa) = boot_result.rsdp_pa {
            let xsdt_pa = unsafe {
                let rsdp = rsdp_pa as *const AcpiRsdp;
                core::ptr::addr_of!((*rsdp).xsdt_address).read_unaligned()
            };
            if let Some(madt_pa) = unsafe { acpi_find_table(xsdt_pa, b"APIC") } {
                if let Some(gic) = unsafe { discover_gic_from_madt(madt_pa) } {
                    let gicr = if gic.gicr_pa != 0 && gic.gicr_pa <= 0xFF_FFFF_FFFF {
                        gic.gicr_pa
                    } else {
                        GICR_PA
                    };
                    puts(uart, "  GIC via ACPI MADT — GICD=");
                    puthex64(uart, gic.gicd_pa);
                    puts(uart, " GICR=");
                    puthex64(uart, gicr);
                    if gic.gicr_pa == 0 {
                        puts(uart, " (GICR fallback to QEMU default)");
                    }
                    puts(uart, "\r\n");
                    return (gic.gicd_pa, gicr, gic.maint_intid);
                }
            }
        }
        puts(uart, "  GIC: using QEMU virt defaults\r\n");
        (GICD_PA, GICR_PA, 25)
    }

    #[inline]
    unsafe fn read_sysreg64(reg: &str) -> u64 {
        match reg {
            "vttbr_el2" => {
                let v: u64;
                unsafe { asm!("mrs {}, vttbr_el2", out(reg) v, options(nomem, nostack)); }
                v
            }
            "vtcr_el2" => {
                let v: u64;
                unsafe { asm!("mrs {}, vtcr_el2", out(reg) v, options(nomem, nostack)); }
                v
            }
            _ => 0,
        }
    }

    #[inline]
    fn puts(uart: &Uart, s: &str) { unsafe { uart.puts(s) } }
    #[inline]
    fn puthex64(uart: &Uart, v: u64) { unsafe { uart.puthex64(v) } }
    #[inline]
    fn putdec(uart: &Uart, v: usize) { unsafe { uart.putdec(v) } }
}

// UTF-16LE NUL-terminated literal.  Inlines at compile time.
#[cfg(target_arch = "x86_64")]
macro_rules! utf16_z {
    ($s:literal) => {{
        const SRC: &[u8] = $s.as_bytes();
        const LEN: usize = SRC.len() + 1;
        const OUT: [u16; LEN] = {
            let mut out = [0u16; LEN];
            let mut i = 0;
            while i < SRC.len() {
                out[i] = SRC[i] as u16;
                i += 1;
            }
            out
        };
        OUT
    }};
}

// ═════════════════════════════════════════════════════════════════════════════
// x86_64 root-mode entry — bring-up scaffold.  Active when building for
// x86_64-unknown-uefi.
//
// At this point the firmware has already enabled long mode and identity-paged
// 4 GiB of physical memory.  We:
//   1. Print a boot banner via the UEFI ConOut text protocol (the firmware is
//      still alive — we have NOT called ExitBootServices yet).
//   2. Run CPUID leaf 0 and classify the vendor (Intel / AMD) via the existing
//      x86_hw_validation::CpuVendor::from_cpuid_string() helper.
//   3. Probe VMX / SVM support using the foundation modules (vtx::detect_vmx_
//      cpu_features for Intel; svm::SvmCpuFeatures::detect for AMD).
//   4. Hand control back to firmware (return 0).  ExitBootServices and the
//      actual VMXON / VMRUN entry path are deliberately not wired here — that
//      is the next chapter of work.
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(target_arch = "x86_64")]
mod x86_entry {
    use core::ffi::c_void;
    use hypervisor::x86_hw_validation::CpuVendor;

    // ── Minimal UEFI structure decoding ──────────────────────────────────────
    // We only need ConOut + OutputString.  Layouts are from UEFI 2.10 §4 / §12.
    #[repr(C)]
    struct EfiSimpleTextOutput {
        reset:           unsafe extern "efiapi" fn(*mut Self, bool) -> usize,
        output_string:   unsafe extern "efiapi" fn(*mut Self, *const u16) -> usize,
        // ...remaining fields unused
    }

    #[repr(C)]
    struct EfiSystemTable {
        hdr:                   [u8; 24],
        firmware_vendor:       *const u16,
        firmware_revision:     u32,
        console_in_handle:     *mut c_void,
        con_in:                *mut c_void,
        console_out_handle:    *mut c_void,
        con_out:               *mut EfiSimpleTextOutput,
        // ...remaining fields unused
    }

    /// Print a UTF-16LE NUL-terminated string via ConOut.  Embeds the string
    /// inline as `&[u16]`; callers pass `&utf16("...")` via wstr! below.
    unsafe fn puts(st: *const EfiSystemTable, s: &[u16]) {
        if st.is_null() { return; }
        let con_out = unsafe { (*st).con_out };
        if con_out.is_null() { return; }
        unsafe { ((*con_out).output_string)(con_out, s.as_ptr()); }
    }

    /// CPUID via inline asm.  LLVM owns rbx, so we save/restore around the
    /// instruction.
    unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
        let eax: u32; let ebx: u32; let ecx: u32; let edx: u32;
        unsafe {
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "mov rbx, {tmp:r}",
                tmp = out(reg) _,
                ebx_out = out(reg) ebx,
                inout("eax") leaf => eax,
                out("ecx") ecx,
                out("edx") edx,
                options(nomem, nostack),
            );
        }
        (eax, ebx, ecx, edx)
    }

    /// Encode CPUID leaf 0 vendor ID bytes (EBX, EDX, ECX) into a 12-byte
    /// string.  Matches the byte order that
    /// `CpuVendor::from_cpuid_string` expects.
    fn vendor_bytes(ebx: u32, ecx: u32, edx: u32) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&ebx.to_le_bytes());
        out[4..8].copy_from_slice(&edx.to_le_bytes());
        out[8..12].copy_from_slice(&ecx.to_le_bytes());
        out
    }

    use hypervisor::vtx::VmxCpuFeatures;
    use hypervisor::svm::SvmCpuFeatures;
    use hypervisor::boot_x86::{boot_x86_hypervisor, set_framebuffer, FramebufferInfo};

    // ── EFI GOP (Graphics Output Protocol) bindings ──────────────────────────
    // We need to capture the framebuffer base + dimensions BEFORE
    // ExitBootServices so we can paint a green/red status indicator on
    // machines without a serial port.

    #[repr(C)]
    struct EfiGuid { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }
    // EFI_GRAPHICS_OUTPUT_PROTOCOL GUID: 9042a9de-23dc-4a38-96fb-7aded080516a
    const GOP_GUID: EfiGuid = EfiGuid {
        d1: 0x9042a9de, d2: 0x23dc, d3: 0x4a38,
        d4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
    };

    #[repr(C)]
    struct EfiGopModeInfo {
        version:          u32,
        horizontal_res:   u32,
        vertical_res:     u32,
        pixel_format:     u32,  // 0=RGB888, 1=BGR888, 2=BitMask, 3=BltOnly
        pixel_mask_red:   u32,
        pixel_mask_green: u32,
        pixel_mask_blue:  u32,
        pixel_mask_reserved: u32,
        pixels_per_scan_line: u32,
    }

    #[repr(C)]
    struct EfiGopMode {
        max_mode:        u32,
        mode:            u32,
        info:            *const EfiGopModeInfo,
        size_of_info:    u64,
        framebuffer_base: u64,
        framebuffer_size: u64,
    }

    #[repr(C)]
    struct EfiGop {
        query_mode:   *const c_void,
        set_mode:     *const c_void,
        blt:          *const c_void,
        mode:         *const EfiGopMode,
    }

    // EFI_BOOT_SERVICES.LocateProtocol is at offset 320 (UEFI 2.10 Table 7-3).
    type LocateProtocolFn = unsafe extern "efiapi" fn(
        *const EfiGuid,
        *mut c_void,
        *mut *mut c_void,
    ) -> usize;

    /// Query GOP and stash the framebuffer info for the post-EBS painter.
    /// Silently does nothing if GOP can't be found.
    unsafe fn capture_framebuffer(system_table: *const c_void) {
        if system_table.is_null() { return; }
        // EFI_SYSTEM_TABLE layout: hdr(24) + fw_vendor(8) + fw_rev(4) + pad(4)
        //   + con_in_h(8) + con_in(8) + con_out_h(8) + con_out(8) + con_err_h(8)
        //   + con_err(8) + runtime_svc(8) + boot_svc(8) + ...
        // boot_services pointer at offset 96.
        let boot_svc_ptr = unsafe {
            *(system_table.cast::<u8>().add(96) as *const *const u8)
        };
        if boot_svc_ptr.is_null() { return; }
        // LocateProtocol is at offset 320 in EFI_BOOT_SERVICES.
        let lp = unsafe {
            *(boot_svc_ptr.add(320) as *const LocateProtocolFn)
        };

        let mut gop_ptr: *mut c_void = core::ptr::null_mut();
        let status = unsafe { lp(&GOP_GUID, core::ptr::null_mut(), &mut gop_ptr) };
        if status != 0 || gop_ptr.is_null() { return; }

        let gop  = gop_ptr as *const EfiGop;
        let mode = unsafe { (*gop).mode };
        if mode.is_null() { return; }
        let info = unsafe { (*mode).info };
        if info.is_null() { return; }

        let fb_base = unsafe { (*mode).framebuffer_base };
        let fb_size = unsafe { (*mode).framebuffer_size };
        let width   = unsafe { (*info).horizontal_res };
        let height  = unsafe { (*info).vertical_res };
        let pitch   = unsafe { (*info).pixels_per_scan_line };
        // pixel_format 0 = RGB (BGRA in memory? actually UEFI's RGB means red in low byte).
        // pixel_format 1 = BGR (most common: B,G,R,reserved in memory order).
        let fmt = unsafe { (*info).pixel_format };
        let bgr = fmt == 1;

        set_framebuffer(FramebufferInfo {
            base: fb_base,
            size: fb_size,
            width,
            height,
            pitch_px: pitch,
            bgr_format: bgr,
        });
    }

    // UTF-16LE banner strings (literal, NUL-terminated).
    static BANNER:        &[u16] = &utf16_z!("\r\nAETHER Hypervisor (x86_64) starting...\r\n");
    static SEP:           &[u16] = &utf16_z!("======================================\r\n");
    static MSG_INTEL:     &[u16] = &utf16_z!("  CPU vendor: Intel (GenuineIntel)\r\n");
    static MSG_AMD:       &[u16] = &utf16_z!("  CPU vendor: AMD (AuthenticAMD)\r\n");
    static MSG_OTHER:     &[u16] = &utf16_z!("  CPU vendor: unsupported (not Intel or AMD)\r\n");
    static MSG_VMX_OK:    &[u16] = &utf16_z!("  Intel VT-x supported (VMX in CPUID.1.ECX[5])\r\n");
    static MSG_VMX_NO:    &[u16] = &utf16_z!("  Intel VT-x NOT supported / disabled in BIOS\r\n");
    static MSG_SVM_OK:    &[u16] = &utf16_z!("  AMD-V (SVM) supported (CPUID.80000001h.ECX[2])\r\n");
    static MSG_SVM_NO:    &[u16] = &utf16_z!("  AMD-V (SVM) NOT supported / disabled in BIOS\r\n");
    static MSG_EPT_OK:    &[u16] = &utf16_z!("  EPT (Extended Page Tables) supported\r\n");
    static MSG_NPT_OK:    &[u16] = &utf16_z!("  NPT (Nested Page Tables) supported\r\n");
    static MSG_NPT_NO:    &[u16] = &utf16_z!("  NPT NOT supported by this AMD CPU\r\n");

    static MSG_HANDOFF:   &[u16] = &utf16_z!("  Handing off to boot_x86_hypervisor (ExitBootServices)\r\n");

    #[unsafe(no_mangle)]
    pub extern "efiapi" fn efi_main(
        image_handle: *mut c_void,
        system_table: *const c_void,
    ) -> usize {
        let st = system_table as *const EfiSystemTable;

        unsafe {
            puts(st, BANNER);
            puts(st, SEP);
        }

        // ── 1. CPU vendor detection ──────────────────────────────────────────
        let (_max_leaf, ebx, ecx, edx) = unsafe { cpuid(0) };
        let vbytes = vendor_bytes(ebx, ecx, edx);
        let vendor = CpuVendor::from_cpuid_string(&vbytes);

        unsafe {
            match vendor {
                Some(CpuVendor::Intel) => puts(st, MSG_INTEL),
                Some(CpuVendor::Amd)   => puts(st, MSG_AMD),
                None                   => puts(st, MSG_OTHER),
            }
        }

        // ── 2. Virtualization-extension probe (still in boot services) ───────
        let (_, _, ecx1, _) = unsafe { cpuid(1) };
        let vmx_supported = (ecx1 >> 5) & 1 == 1;
        let (_, _, ecx8x1, _) = unsafe { cpuid(0x8000_0001) };
        let svm_supported = (ecx8x1 >> 2) & 1 == 1;

        let vmx_features = unsafe { VmxCpuFeatures::detect() };
        let svm_features = unsafe { SvmCpuFeatures::detect() };

        unsafe {
            match vendor {
                Some(CpuVendor::Intel) => {
                    if vmx_supported && vmx_features.vmx_supported {
                        puts(st, MSG_VMX_OK);
                        puts(st, MSG_EPT_OK);
                    } else {
                        puts(st, MSG_VMX_NO);
                        halt();
                    }
                }
                Some(CpuVendor::Amd) => {
                    if svm_supported && svm_features.svm_supported {
                        puts(st, MSG_SVM_OK);
                        if svm_features.npt_supported { puts(st, MSG_NPT_OK); }
                        else { puts(st, MSG_NPT_NO); halt(); }
                    } else {
                        puts(st, MSG_SVM_NO);
                        halt();
                    }
                }
                None => {
                    puts(st, MSG_HANDOFF);
                    halt();
                }
            }
            puts(st, MSG_HANDOFF);
            capture_framebuffer(system_table);
        }

        // ── 3. Hand off to boot_x86_hypervisor ───────────────────────────────
        // From here on: ExitBootServices, EPT/NPT setup, VMXON/SVME enable,
        // VMLAUNCH/VMRUN, first VMEXIT.  Diagnostic output switches from UEFI
        // ConOut to direct COM1 (0x3F8) because firmware boot services exit
        // inside boot_x86_hypervisor.
        unsafe { boot_x86_hypervisor(image_handle, system_table, vendor); }
    }

    fn halt() -> ! {
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
        }
    }
}

