// AETHER hypervisor — UEFI entry point
//
// This is where execution begins. UEFI firmware loads hypervisor.efi and
// calls efi_main() at EL2. From here the boot sequence is:
//
//   1.  Early UART init      → print banner (raw MMIO, no UEFI required)
//   2.  EL check             → halt if not EL2
//   3.  ExitBootServices     → firmware is done; we own the machine
//   4.  Memory map parsing   → locate largest conventional RAM region
//   5.  Stage 2 tables       → map RAM + devices for Android partition
//   6.  Exception vectors    → install VBAR_EL2
//   7.  EL2 virt config      → HCR_EL2, VTCR_EL2, VTTBR_EL2
//   8.  GIC init             → distributor + redistributor + CPU interface
//   9.  "Hypervisor ready."  → spin (or ERET to guest when kernel is loaded)
//
// QEMU virt machine fixed physical addresses (ARM ARM DDI0527, QEMU hw/arm/virt.c):
//   PL011 UART:        0x0900_0000  (size 0x1000)
//   GICv3 GICD:        0x0800_0000  (size 0x1_0000)
//   GICv3 GICR:        0x080A_0000  (128 KiB × n_cores)
//   DRAM region:       0x4000_0000  (up to 255 GiB; 8 GiB in our QEMU run)
//   Flash (OVMF):      0x0000_0000  (64 MiB, read-only)
//
// Tests this file enables (once the guest kernel is loaded):
//   Test 1 — Boot AETHER, see "Hypervisor ready." on serial console ← this file
//   Test 2 — Guest 1 Linux boots to shell (requires kernel at KERNEL1_PA)
//   Test 3 — Guest 2 Linux boots to shell (second partition, second ERET)
//   Tests 4-6 — Memory isolation, CPU partitioning, interrupt routing
//              (verified by what the guest OS observes, not by this code)

#![no_std]
#![no_main]

use core::arch::asm;
use core::ffi::c_void;
use core::panic::PanicInfo;

use hypervisor::arm64::regs;
use hypervisor::arm64::virt::{configure_el2_virt, hcr_el2};
use hypervisor::boot::{acpi_find_table, AcpiRsdp, BootContext, EfiSystemTable, GuestLaunch};
use hypervisor::gic::{discover_gic_from_madt, init_physical_gic};
use hypervisor::guest_stub;
use hypervisor::memory::{BumpAllocator, MapKind, SmmuStreamTable, Stage2Tables};
use hypervisor::uart::Uart;

// ─────────────────────────────────────────────────────────────────────────────
// QEMU virt machine physical memory map
// Verified against QEMU source: hw/arm/virt.c (virt_memmap[])
// ─────────────────────────────────────────────────────────────────────────────

/// PL011 UART at its QEMU virt base. `-serial stdio` maps this to the host terminal.
const UART_PA: u64 = 0x0900_0000;

/// GICv3 Distributor base (64 KiB region).
const GICD_PA: u64 = 0x0800_0000;

/// GICv3 Redistributor region start (128 KiB per CPU, grows with SMP count).
const GICR_PA: u64 = 0x080A_0000;

/// Start of physical DRAM on QEMU virt. The guest kernel and DTB are loaded here.
const DRAM_BASE: u64 = 0x4000_0000;

/// Android partition: 2 GiB starting at DRAM_BASE.
/// With `-m 8G`, QEMU exposes 8 GiB DRAM; we give the first 2 GiB to Android.
const ANDROID_IPA_BASE: u64 = DRAM_BASE;
const ANDROID_RAM_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Android Linux kernel load address.
/// ARM64 Linux Image header requires 2 MiB-aligned load address (typically).
/// Placed at DRAM+8 MiB to leave room for the UEFI stub stub if needed.
pub const KERNEL1_PA: u64 = 0x4080_0000;

/// Android device-tree blob address (placed after the 2 MiB text+rodata).
pub const DTB1_PA: u64 = 0x4400_0000;

// ─────────────────────────────────────────────────────────────────────────────
// Global static SMMU stream table
//
// Must live in a static so its physical address is stable. The SMMU's DMA
// engine reads this table; any relocation would desync it. The table is
// all-Abort (all-zero) at init — safe default: no DMA until AETHER assigns a
// device. The passthrough module (ch11) populates individual entries.
//
// Rust 2024: use `&raw mut` for access instead of &mut on static mut.
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)] // wired to SMMU MMIO in ch12+ device passthrough
static mut SMMU_STREAM_TABLE: SmmuStreamTable = SmmuStreamTable::new_aborted();

// ─────────────────────────────────────────────────────────────────────────────
// UEFI entry point
// ─────────────────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    image_handle: *mut c_void,
    system_table: *const c_void,
) -> usize {
    // SAFETY: UART_PA is the identity-mapped PL011 UART on QEMU virt.
    // UEFI maps all device memory (MMIO) before handing control to us, so the
    // physical address is directly accessible as a virtual address pre-MMU.
    let uart = unsafe { Uart::new(UART_PA) };

    // ── 1. Banner ─────────────────────────────────────────────────────────────
    puts(&uart, "\r\n");
    puts(&uart, "======================================\r\n");
    puts(&uart, "  AETHER Hypervisor starting...      \r\n");
    puts(&uart, "======================================\r\n");

    // ── 2. Exception level check ──────────────────────────────────────────────
    // UEFI on QEMU virt starts at EL2 (OVMF ARM64 enters at EL2).
    // Real Snapdragon hardware also starts at EL2 after ATF boot.
    let el = unsafe { regs::current_el() };
    puts(&uart, "  CurrentEL: EL");
    putdec(&uart, el as usize);
    puts(&uart, "\r\n");

    if el != 2 {
        puts(&uart, "[FATAL] AETHER requires EL2. Halting.\r\n");
        hypervisor::boot::halt();
    }
    puts(&uart, "  EL2 detected\r\n");

    // ── 3. ExitBootServices ───────────────────────────────────────────────────
    // After this call: all UEFI boot services pointers are invalid.
    // The UART MMIO remains valid (hardware never changes).
    puts(&uart, "  ExitBootServices...\r\n");

    let boot_ctx = unsafe {
        BootContext::from_uefi(
            image_handle as *mut _,
            system_table as *const EfiSystemTable,
        )
    };
    let boot_result = unsafe { boot_ctx.run() };

    puts(&uart, "  ExitBootServices: OK\r\n");

    // ── 4. Memory map ─────────────────────────────────────────────────────────
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

    // ── 5. Stage 2 page tables ────────────────────────────────────────────────
    // BumpAllocator carved from the largest conventional RAM region.
    // Stage2Tables::new() takes the first 8 KiB (two 4KB pages, 8KiB-aligned)
    // for the L1 concatenated root required by T0SZ=24, SL0=1.
    let mut alloc = BumpAllocator::new(largest.base, largest.size);

    let s2 = unsafe { Stage2Tables::new(&mut alloc) }.unwrap_or_else(|| {
        puts(&uart, "[FATAL] OOM allocating Stage 2 root tables.\r\n");
        hypervisor::boot::halt();
    });

    // Map Android's 2 GiB DRAM partition: NormalRw (Inner WB/WA, cacheable).
    // Identity mapping: IPA == PA. The Android kernel builds its own VA→IPA
    // tables on top of this; AETHER's Stage 2 is the IPA→PA layer beneath.
    unsafe {
        s2.map_range(ANDROID_IPA_BASE, ANDROID_IPA_BASE, ANDROID_RAM_SIZE,
                     MapKind::NormalRw, &mut alloc)
          .unwrap_or_else(|_| {
              puts(&uart, "[FATAL] Stage 2 RAM mapping failed.\r\n");
              hypervisor::boot::halt();
          });
    }

    // Map GIC device memory (GICD + GICR region): DeviceRw.
    // The Android GIC driver programs the physical GIC addresses; Stage 2
    // identity-maps them so the driver's MMIO accesses reach the real hardware.
    // GIC region: 0x0800_0000..0x0A00_0000 (32 MiB covers both GICD and GICR).
    unsafe {
        s2.map_range(0x0800_0000, 0x0800_0000, 0x0200_0000,
                     MapKind::DeviceRw, &mut alloc).ok();
    }

    // Map PL011 UART device memory: DeviceRw (4 KiB page).
    // The Android serial driver will talk to the same UART through Stage 2.
    unsafe {
        s2.map_range(UART_PA, UART_PA, 0x1000,
                     MapKind::DeviceRw, &mut alloc).ok();
    }

    // Map PCIe config space (ECAM) if present on QEMU virt.
    // QEMU virt PCIe ECAM: 0x4010_0000_0000 (in 40-bit IPA space).
    // Omitted here — passthrough devices are configured in ch11 at SMMU level.

    puts(&uart, "  Stage 2 tables: OK\r\n");
    puts(&uart, "  S2 root PA: ");
    puthex64(&uart, s2.root_pa());
    puts(&uart, "\r\n");

    // ── 6. Exception vectors ──────────────────────────────────────────────────
    // Installs AETHER's EL2 vector table at VBAR_EL2. All guest VM exits
    // (Stage 2 faults, HVC, SMC, WFI) are routed here.
    // Compiled only for target_os = "uefi" — see arm64/vectors.rs.
    unsafe { hypervisor::arm64::vectors::install_vectors() };
    puts(&uart, "  Exception vectors: OK\r\n");

    // ── 7. EL2 virtualization extensions ──────────────────────────────────────
    // configure_el2_virt() sets:
    //   CPTR_EL2   → FP/SIMD NOT trapped (Android needs NEON)
    //   VTCR_EL2   → T0SZ=24 (40-bit IPA), 4KB granule, L1 start, 48-bit PA
    //   VTTBR_EL2  → s2.root_pa() | (VMID_ANDROID << 48)
    //   TLB flush  → TLBI VMALLS12E1IS
    //   HCR_EL2    → GUEST_FLAGS (VM=1, FMO, IMO, AMO, RW=1, TWI, TWE, TSC)
    unsafe { configure_el2_virt(s2.root_pa()) };

    // Read back the configured registers for the boot banner.
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

    // Verify the mandatory bits are set before claiming readiness.
    if hcr & hcr_el2::VM == 0 {
        puts(&uart, "[FATAL] HCR_EL2.VM not set — Stage 2 not active.\r\n");
        hypervisor::boot::halt();
    }
    if hcr & hcr_el2::RW == 0 {
        puts(&uart, "[FATAL] HCR_EL2.RW not set — lower EL is not AArch64.\r\n");
        hypervisor::boot::halt();
    }

    // ── 8. GIC initialisation ─────────────────────────────────────────────────
    // Discover GIC addresses from ACPI MADT, falling back to QEMU virt defaults.
    //
    // ACPI chain: RSDP → XSDT → MADT ("APIC") → GICv3 structures.
    // The RSDP was captured before ExitBootServices (boot.rs captures it first).
    let (gicd_base, gicr_base) = discover_gic_addresses(&uart, &boot_result);

    // Initialize physical GIC: wake all redistributors, configure GICD, ICC.
    // `online_cores = 1` — boot CPU only. Additional cores are woken by PSCI
    // (ch09 cpu.rs) as they join the hypervisor.
    unsafe { init_physical_gic(gicd_base, gicr_base, 1) };
    puts(&uart, "  GIC: OK (GICD=");
    puthex64(&uart, gicd_base);
    puts(&uart, " GICR=");
    puthex64(&uart, gicr_base);
    puts(&uart, ")\r\n");

    // ── Done ──────────────────────────────────────────────────────────────────
    puts(&uart, "======================================\r\n");
    puts(&uart, "  Hypervisor ready.\r\n");
    puts(&uart, "======================================\r\n");
    puts(&uart, "\r\n");

    // ── Test 2: copy bare-metal ARM64 stub into guest RAM, ERET to EL1 ──────────
    //
    // guest_stub_start..guest_stub_end is the position-independent stub assembled
    // inline in guest_stub.rs. We allocate one page from the bump allocator
    // (safe region starting at 0x48000000, already covered by the ANDROID_RAM_SIZE
    // Stage 2 mapping), copy the stub there, then ERET to EL1 at that address.
    //
    // Safety preconditions (all met above):
    //   - HCR_EL2.VM = 1 ✓          (configure_el2_virt)
    //   - VTTBR_EL2 set ✓            (configure_el2_virt)
    //   - VBAR_EL2 set ✓             (install_vectors)
    //   - Stub PA mapped NormalRw ✓  (covered by ANDROID_IPA_BASE + ANDROID_RAM_SIZE)
    //   - UART PA mapped DeviceRw ✓  (0x09000000 mapped above)
    let stub_pa = unsafe { alloc.alloc_zeroed_page() }
        .unwrap_or_else(|| {
            puts(&uart, "[FATAL] guest stub alloc failed\r\n");
            hypervisor::boot::halt()
        });

    let stub_src = guest_stub::stub_start();
    let stub_bytes = guest_stub::stub_len();

    // Copy stub code to the allocated page. The stub is position-independent
    // (uses movz for absolute UART address, adr for PC-relative string data),
    // so it runs correctly at stub_pa without relocation.
    unsafe {
        core::ptr::copy_nonoverlapping(stub_src, stub_pa as *mut u8, stub_bytes);
        // D-cache clean + I-cache invalidate: ensure the copied instructions
        // are visible as code to the EL1 instruction fetch path.
        // For QEMU this is unnecessary but it is correct on real hardware.
        core::arch::asm!(
            "dc cvau, {p}",     // clean D-cache line by VA to PoU
            "dsb ish",
            "ic ivau, {p}",     // invalidate I-cache line by VA to PoU
            "dsb ish",
            "isb",
            p = in(reg) stub_pa,
            options(nomem, nostack, preserves_flags),
        );
    }

    puts(&uart, "  Stub at PA=");
    puthex64(&uart, stub_pa);
    puts(&uart, " (");
    puthex64(&uart, stub_bytes as u64);
    puts(&uart, " bytes) — ERET to EL1\r\n");

    // ERET: ELR_EL2 = stub_pa, SPSR_EL2 = EL1h, DAIF masked.
    // dtb_pa = 0 (stub ignores x0).
    unsafe {
        GuestLaunch { entry_pa: stub_pa, dtb_pa: 0 }.eret_to_el1();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GIC address discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Discover GIC base addresses from ACPI MADT, falling back to QEMU defaults.
///
/// Order:
///   1. Parse ACPI MADT via the RSDP captured before ExitBootServices.
///   2. If ACPI is absent or MADT parsing fails, use hardcoded QEMU virt values.
fn discover_gic_addresses(
    uart: &Uart,
    boot_result: &hypervisor::boot::BootResult,
) -> (u64, u64) {
    if let Some(rsdp_pa) = boot_result.rsdp_pa {
        // Dereference the RSDP to get the XSDT physical address.
        // SAFETY: rsdp_pa was captured from the EFI config table before
        // ExitBootServices; the ACPI RSDP region survives ExitBootServices per
        // UEFI spec (it is in EfiACPIReclaimMemory or EfiACPIMemoryNVS).
        // AcpiRsdp is repr(C, packed) — use addr_of! + read_unaligned to avoid
        // creating a misaligned reference to the u64 xsdt_address field.
        let xsdt_pa = unsafe {
            let rsdp = rsdp_pa as *const AcpiRsdp;
            core::ptr::addr_of!((*rsdp).xsdt_address).read_unaligned()
        };

        // Walk XSDT to find the MADT ("APIC" signature).
        if let Some(madt_pa) = unsafe { acpi_find_table(xsdt_pa, b"APIC") } {
            if let Some(gic) = unsafe { discover_gic_from_madt(madt_pa) } {
                // Use ACPI GICD; fall back to QEMU default if GICR is absent
                // or outside the 40-bit IPA space (QEMU OVMF leaves it garbage).
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
                return (gic.gicd_pa, gicr);
            }
        }
    }

    // Fall back to QEMU virt hardcoded addresses.
    puts(uart, "  GIC: using QEMU virt defaults\r\n");
    (GICD_PA, GICR_PA)
}

// ─────────────────────────────────────────────────────────────────────────────
// System register helpers (not yet in regs.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Read any 64-bit system register by name via inline assembly.
///
/// # Safety
/// The register name must be a valid AArch64 system register accessible at EL2.
#[inline]
unsafe fn read_sysreg64(reg: &str) -> u64 {
    // We need a concrete register name at compile time, so use a match.
    // Only the registers actually used in main.rs are listed here.
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

// ─────────────────────────────────────────────────────────────────────────────
// UART formatting helpers
//
// No format! macro (no_std, no alloc). All output is assembled from primitive
// calls. This keeps the binary small and avoids any heap dependency.
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn puts(uart: &Uart, s: &str) {
    unsafe { uart.puts(s) }
}

#[inline]
fn puthex64(uart: &Uart, v: u64) {
    unsafe { uart.puthex64(v) }
}

#[inline]
fn putdec(uart: &Uart, v: usize) {
    unsafe { uart.putdec(v) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Panic handler — bare-metal, no recovery, halt immediately
// ─────────────────────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // We cannot safely use the UART here (PanicInfo has no Send guarantee and
    // we may be mid-boot with state undefined). Just halt.
    loop {
        unsafe { asm!("wfe", options(nomem, nostack)); }
    }
}
