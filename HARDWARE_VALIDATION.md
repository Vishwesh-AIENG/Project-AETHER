# AETHER x86_64 Hardware Validation

Validation log for the x86_64 boot pipeline introduced on the
`sandbox/x86_64-port` branch.

## Gate: Ch50 / Ch51 — first VMEXIT in VMX-root / SVM-host mode

The x86 tier reaches the same gate the ARM tier reaches in QEMU: AETHER
boots from UEFI, takes ownership of the machine via ExitBootServices,
transitions into VMX root mode (Intel) or SVM host mode (AMD), launches
a minimal guest, and observes the first VMEXIT.

## Binary

```
target/x86_64-unknown-uefi/release/hypervisor.efi
PE32+ executable for EFI (application), x86-64
```

Build:

```
cargo +nightly build \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --release --target x86_64-unknown-uefi -p hypervisor
```

## Validation 1: QEMU/TCG (software emulator)

Host:  Windows 11 / QEMU 10.x (Stefan Weil's Windows build) / edk2 OVMF.
Accel: TCG (no KVM/WHPX), q35 machine, `-cpu max -m 1G`.

QEMU presents the CPU as `AuthenticAMD`, so the AMD path of
`boot_x86.rs` runs.

Run script: `qemu/run-x86.sh`.

### Result

Serial log (`qemu/com1.log`, last lines):

```
AETHER Hypervisor (x86_64) starting...
======================================
  CPU vendor: AMD (AuthenticAMD)
  AMD-V (SVM) supported (CPUID.80000001h.ECX[2])
  NPT (Nested Page Tables) supported
  Handing off to boot_x86_hypervisor (ExitBootServices)

[x86] ExitBootServices: OK
[x86] VMXON region PA = 0x000000003de78000
[x86] VMCS region PA  = 0x000000003de76000
[x86] EPT PML4 PA     = 0x000000003de7f000
[x86] Guest RAM PA    = 0x000000003de84000
[x86] Host RIP        = 0x000000003de69278
[x86] AMD path: building NPT identity map...
[x86] Guest CR3 (PML4)= 0x000000003de73000
[x86] init_svm_foundation()...
[x86] init_svm_foundation: phase=0x0000000000000005 (NPT active)
[x86] VMRUN...
[x86] VMRUN returned (VMEXIT observed).
[x86] VMCB exit_code = 0x0000000000000078 HLT (Ch51 gate PASSED)
[x86] EXITINFO1 = 0x0000000000000000
[x86] EXITINFO2 = 0x0000000000000000
[x86] Hypervisor in SVM host mode. Halting.
```

QMP `screendump` of the 1280x800 GOP framebuffer: solid green
(center pixel = `(0, 255, 0)`).

## Validation 2: Real hardware (USB boot)

Real x86 machine, UEFI firmware, no host OS underneath (booted from a
FAT32 USB stick with `\EFI\BOOT\BOOTX64.EFI` only).

### Procedure

1. Format a USB stick FAT32.
2. Create `\EFI\BOOT\` on the USB root.
3. Copy `hypervisor.efi` to `\EFI\BOOT\BOOTX64.EFI`.
4. Save work in the host OS, then reboot.
5. At firmware splash, press the boot-menu hotkey (varies by vendor:
   F12 / F11 / F9 / Esc) and select the USB drive.
6. Read the framebuffer colour.

### Result

Screen turned solid **green** post-handoff.

That means the same sequence the QEMU log shows ran on real silicon:
ExitBootServices succeeded, EFER.SVME (or CR4.VMXE) flipped, HSAVE /
VMXON region established, NPT / EPT identity map active, guest 4-level
page table installed, VMRUN / VMLAUNCH executed, guest entered long
mode, walked its own paging through nested paging, fetched the HLT
byte at the guest entry point, executed it, VMEXIT fired with exit
code HLT, the host VMEXIT trampoline regained control, and the gate-
passed framebuffer paint ran.

The Windows boot configuration was not touched.  Power-cycling without
the USB returns the machine to its previous OS as usual.

## Framebuffer colour code (post-EBS visual diagnostic)

| Colour | Meaning |
|---|---|
| Blue   | ExitBootServices succeeded; foundation init in progress |
| Green  | Ch50 (Intel HLT_EXIT) or Ch51 (AMD HLT) gate PASSED |
| Amber  | VMRUN / VMLAUNCH succeeded but guest faulted (NPF / EPT_VIOLATION / exception); pipeline correct, guest VMCB/EPT state wrong |
| Red    | `init_vtx_foundation` / `init_svm_foundation` returned an error.  Most commonly: VT-x or SVM is disabled in BIOS — enable it and retry |

## Out of scope for this gate

- Multi-vCPU.  One VMCS/VMCB per logical CPU is required for SMP guests.
- Full VMEXIT dispatcher.  Right now we halt on the first VMEXIT.
- FEX-Emu binary translation (Ch52).  `libfex.a` is not in tree;
  `init_fex_integration` returns `FexLibNotLinked` by design.
- Booting a real guest kernel.  The 1-byte HLT payload is the gate
  surface; loading an actual Android-on-x86 kernel image is the
  Ch53/Ch54 work.
