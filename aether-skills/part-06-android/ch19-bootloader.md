# SKILL.md — Chapter 19: The Bootloader

## Confidence Disclosure

**LOW for Android Verified Boot specifics, MEDIUM for U-Boot general knowledge.** Android Verified Boot 2.0 (AVB2) has specific cryptographic structures and verification flows that Claude does not have reliable training on at the implementation level. Getting this wrong produces a bootloader that either refuses to boot a valid image or boots an unverified one silently.

## Required Primary Sources

**Android Verified Boot 2.0 (AVB2) specification** — available at:
`android.googlesource.com/platform/external/avb/+/refs/heads/master/README.md`

Also the full source at:
`android.googlesource.com/platform/external/avb`

| Document/File | Topic | Priority |
|---|---|---|
| README.md | Overview and design | Read first |
| avb_vbmeta_image.h | VBMeta image format | MANDATORY |
| avb_descriptor.h | Descriptor formats | MANDATORY |
| avb_crypto.h | Cryptographic operations | Read |
| avb_slot_verify.h | Slot verification API | Critical |

**U-Boot documentation** at u-boot.readthedocs.io — If AETHER uses U-Boot as the base for the Android bootloader.

| Section | Topic | Priority |
|---|---|---|
| Android Boot | Android-specific U-Boot features | Essential |
| FIT Images | Flattened Image Tree format | Read |
| UEFI Subsystem | U-Boot's UEFI implementation | Relevant |

**Android Boot Image format** — documented at:
`source.android.com/docs/core/architecture/bootloader/boot-image-header`

## Secondary Sources

**Android bootloader requirements** at `source.android.com/docs/core/architecture/bootloader` — Google's specification for what an Android bootloader must do.

**crosboot / depthcharge** — ChromeOS bootloader, open-source and well-documented, with AVB2 support. Good reference implementation.

**AOSP AVB tools** at `external/avb/avbtool` — Python tool for creating and verifying AVB2 images. Running this tool is the fastest way to understand the format.

## Critical Concepts

**VBMeta Structure.** AVB2 verification is anchored at a VBMeta image stored in a dedicated `vbmeta` partition. The VBMeta image contains a header, a collection of descriptors (one for each partition that needs verification), and a cryptographic signature over the header and descriptors. The bootloader reads VBMeta, verifies the signature against a known public key (embedded in the bootloader itself or stored in a trust anchor), then reads each descriptor to get the hash or hashtree of the corresponding partition.

**Partition Verification.** Each partition listed in VBMeta has either a hash descriptor (for partitions verified by hashing the entire partition — used for `boot`, `vbmeta` itself) or a hashtree descriptor (for large partitions verified by dm-verity Merkle tree — used for `system`, `vendor`). The bootloader verifies hash partitions completely at boot time. Hashtree partitions are verified lazily at runtime by the kernel's dm-verity driver. The bootloader only verifies the root hash of the Merkle tree at boot time.

**Rollback Protection.** AVB2 includes rollback protection using a Rollback Index stored in the device's secure storage (typically eMMC RPMB or similar). Each VBMeta image has a minimum rollback index encoded in it. At boot, the bootloader verifies that the image's rollback index is greater than or equal to the stored minimum. This prevents downgrading to older (potentially vulnerable) software. AETHER's bootloader must implement rollback protection using some form of secure storage — on an x86 laptop this might be the TPM's NV storage.

**Bootloader Lock State.** AVB2 defines three device states: LOCKED (verified boot enforced), UNLOCKED (verified boot skipped, orange indicator shown), and ORANGE (user-installed key, yellow indicator shown). AETHER's bootloader must be in LOCKED state and must boot images signed with AETHER's own build keys. The lock state is stored in secure persistent storage and must survive reboots. Implementing the state storage correctly is critical — if the lock state can be changed without authorization, the entire verified boot chain is compromised.

**Boot Image Format.** Android boot images follow a specific binary format with a header, kernel image, ramdisk, and optional second-stage bootloader. The header format has evolved through versions (v0 through v4). AETHER must parse the correct header version for the target Android release. The kernel image is gzip or LZ4 compressed ARM64 Linux kernel binary. The ramdisk is a gzip-compressed CPIO archive containing the initial RAM disk contents.

**Passing Parameters To The Kernel.** The bootloader passes information to the Linux kernel through three channels: the kernel command line (a string appended to the boot image's cmdline), the device tree blob (DTB) placed at a known address, and the Android boot control block (for A/B OTA updates). AETHER's bootloader must construct a correct kernel command line and a correct DTB describing the Android partition's virtual hardware.

## Common AI Mistakes In This Domain

Claude generates AVB2 signature verification code that verifies the signature format but not the public key — accepting images signed by any key rather than only the expected key.

Claude generates VBMeta parsers that don't validate the magic number (`AVB0`) and length fields before dereferencing structure pointers — a security vulnerability if a malformed image is presented.

Claude generates boot image parsers targeting the wrong header version — AOSP's boot image header format changed significantly between Android 9 (v1) and Android 12 (v3/v4).

Claude implements rollback index checking as a simple comparison without accounting for the RPMB or TPM storage mechanism needed to persist the minimum rollback index securely across reboots.

## Verification Protocol

For AVB2 implementation:
1. Use `avbtool verify_image` to verify images that your bootloader should accept — if avbtool and your bootloader disagree, your bootloader is wrong
2. Deliberately corrupt a verified partition and confirm the bootloader rejects it
3. Test rollback protection by attempting to boot an image with a lower rollback index than stored

For boot image parsing:
1. Parse a known-good boot image produced by the AOSP build system and verify your parser extracts the correct kernel load address, ramdisk address, and command line
2. Verify the kernel loads at the address specified in the boot image header, not at a hardcoded address

## Pre-Flight Checklist

- [ ] Clone the AVB repository and read README.md fully
- [ ] Run `avbtool` on a test image to understand the format before writing a parser
- [ ] Read Android bootloader requirements at source.android.com
- [ ] Study U-Boot's Android boot implementation at `boot/android_image.c` in U-Boot source
- [ ] Understand the A/B partition scheme (Android uses two sets of partitions for OTA — `boot_a`/`boot_b`, `system_a`/`system_b`) before implementing partition selection
