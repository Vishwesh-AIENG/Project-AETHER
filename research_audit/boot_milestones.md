# Boot milestones

**Rule used:** a milestone counts only if a serial log shows it. "Reproduced" means it was re-run in this audit on commit `9f34e2f`. "Old log" means a log preserved in the AETHER-FILES dump that I could read but not re-run. "Note only" means it appears only in prose (memory notes or commit messages), with no log.

## 0. Two different "boots" are being called "Android boot"

| Tier | What actually runs | Guest payload in the evidence | Environment |
|---|---|---|---|
| **ARM tier** | `hypervisor.efi` at **EL2** (Stage-2, vGIC, PSCI, trapped sysregs) → ERET → GKI 6.1.79 kernel at EL1 | A **custom static test binary** installed as `/bin/sh` in an initramfs (`qemu/initrd-src/aether_proof.c`). **No Android userspace, no `init`, no system image.** | QEMU `virt`, `-cpu max`, `virtualization=on`, **TCG** (EL2 emulated by QEMU). Never run on ARM hardware. |
| **x86 tier** | `hypervisor.efi` as a **UEFI application in host mode** (`whpx_hostmode`: no VMXON, no VMLAUNCH/VMRUN, no EPT) running the ARM64→x86 DBT with a **software MMU**. The translated GKI kernel boots Android from `system.raw`/`vendor.raw` exposed as PMEM. | Locally built AOSP `system.raw` / `vendor.raw` / `boot.img` | QEMU q35 + **WHPX** on the authors' Windows/AMD machine (old logs), and **TCG** in this audit |

The only path that touches Android's own userspace is the x86 host-mode DBT, which **is not a hypervisor in that configuration**. The only path that exercises the EL2 hypervisor boots a test binary, not Android.

## 1. ARM tier: reproduced (N=5 per configuration)

Command (repo script, unchanged): `QEMU_AARCH64=qemu-system-aarch64 AAVMF=/usr/share/AAVMF/AAVMF_CODE.fd python3 qemu/run-arm-auto.py --kernel _kernel_new --initrd qemu/initrd-proof.cpio --smp 4 --until "PROOF done"` → `rc=0`, `PROOF done` (`raw/2026-10-08_9f34e2f_arm-proof-smp4_run1_*.log`).

Milestone timing: `scripts/arm_milestones.py` launches the same QEMU command and records the host-clock time at which each regex first appears on the serial file (50 ms polling). `direct` is a QEMU direct kernel boot of the same kernel, initramfs and cmdline with **no firmware and no AETHER**, used as a baseline. Raw: `raw/arm-milestones-2026-10-08_9f34e2f*/`.

| Milestone (serial evidence) | AETHER smp4 median (min–max), s | direct smp4 | AETHER smp1 | direct smp1 |
|---|---|---|---|---|
| `AETHER Hypervisor starting` | 5.80 (5.80–6.36) | — | 5.71 | — |
| `EL2 detected` → `Stage 2 tables: OK` → `Hypervisor ready.` | 5.81 | — | 5.76 | — |
| `ERET to Linux kernel EL1` | 5.85 | — | 5.76 | — |
| Kernel entry (`Booting Linux on physical CPU`) | 5.90 (5.86–6.41) | 0.20 | 5.76 | 0.15 |
| `SMP: Total of N processors activated` | 8.38 | 1.61 | 6.41 | 0.56 |
| `Freeing unused kernel memory` | 11.72 | 4.84 | 9.79 | 4.54 |
| EL0 userspace (`PROOF ch34 userspace=1`) | 11.82 (11.16–12.56) | 5.00 | 9.84 | 4.70 |
| `PROOF ch35 online_cpus=` | 4 (5/5) | 4 | 1 | 1 |
| `PROOF done` (timer + IPI deltas > 0 on every CPU) | **12.98** (12.28–13.68) | 6.16 | **10.95** | 5.86 |

Interpretation:
- About 5.8 s is **UEFI firmware** (AAVMF), before AETHER prints anything. AETHER's own EL2 bring-up (start → ERET) is **below the 50 ms resolution**.
- Kernel entry → `PROOF done`: **7.1 s (AETHER, smp4) vs 6.0 s (direct)**, and **5.2 s vs 5.7 s at smp1**. These are not a clean "virtualisation overhead". The direct boot uses QEMU's generated DTB and devices and 2 GiB of RAM, while AETHER uses its own DTB and 4 GiB. Under TCG, EL2 trapping is emulated in software. The defensible statement is narrower: **under emulation, the AETHER EL2 layer does not change time to userspace by more than about 20%**. This says nothing about hardware.
- All 10 timed AETHER runs (2 configurations × 5), the functional run and the fault-injection control runs reached `PROOF done`. The old proof logs (`raw/old-evidence/arm-proof-smp{4,1}.log`) show the same milestone set.

**ARM-tier final milestone, reproduced:** GKI 6.1.79 boots under AETHER's EL2 to an EL0 test binary with 1 or 4 CPUs online and per-CPU timer interrupts and IPIs delivered. **Not reproduced and never evidenced on the ARM tier:** Android `init`, any Android service, a display, or Snapdragon hardware.

## 2. x86 tier

### 2a. Re-run in this audit (QEMU TCG; WHPX not available)

Command: `raw/x86-tcg-2026-10-08_9f34e2f/run.sh`. It mirrors `qemu/run-x86-auto.py`'s TCG branch: q35, `-accel tcg,tb-size=512 -cpu max -m 16G`, OVMF, an ESP with `hypervisor.efi` built `--features whpx_hostmode,qemu`, `boot.img`, and `system.raw` + `vendor.raw` loaded as PMEM. Three infrastructure workarounds were needed, none touching AETHER code:
1. QEMU 8.2's `-device loader` on Linux cannot read a 3 GiB file in one call, so `system.raw` was split into three 1 GiB loaders at consecutive addresses.
2. Container memory: overcommit was set to 1 and an 8 GiB swap file added (QEMU RSS ≈ 10.8 GiB; one attempt was memcg-OOM-killed).
3. QEMU `fat:rw:` write-back rewrote `BOOTX64.EFI` between runs, so the ESP is restored from the build output before every run (hash in `efi.sha256`).

| Milestone | Evidence (this run) | Wall time |
|---|---|---|
| OVMF → `AETHER Hypervisor (x86_64) starting...` | yes | < 15 s |
| `ExitBootServices: OK`, boot.img found and parsed, DTB built, initrd placed | yes | < 15 s |
| `WHPX host-mode: VMXON skipped, DBT runs directly` | yes | |
| Translated GKI kernel: `Booting Linux on physical CPU 0x0`, early printk, memory and RCU init | yes | about 30–400 s |
| Kernel `Run /init` | **not reached** (stopped by me at about 400 s, guest clock still at 0.000000) | — |

Dispatch rate under TCG (Δ`[dbt] #counter` / Δwall, 15 s heartbeat, 24 intervals): **median 21.8 K dispatches/s**, range 17.4 K–641 K/s (the maximum is a short burst over hot cached blocks). The overall mean over 361 s was 46.9 K/s. Projected from the old WHPX log (`Run /init` at guest t≈191 s), reaching init under TCG would take many hours, which is impractical here.

### 2b. Old evidence (WHPX, authors' Windows/AMD machine; not re-run)

`raw/old-evidence/x86-serial-com1.log.gz` (copied from `qemu/x86-serial-com1.log` in the dump; 20,012 lines; no host timestamps). Guest-kernel timestamps:

| Guest t (s) | Milestone in the log |
|---:|---|
| 0.0 | `Booting Linux` (Android GKI 6.1 under the DBT) |
| 191.06 | **`Run /init as init process`** |
| 509–570 | init parses `init.rc` and imports (`init.zygote64_32.rc`, `apexd.rc`, `surfaceflinger.rc` are **parsed**, not started) |
| 608.5 | `starting service 'apexd-bootstrap'` |
| 884–896 | `apexd-bootstrap: Found pre-installed APEX …` (20+ listed) |
| 1080.9 | `apexd-bootstrap exited with status 0`; the log contains `Activated 3 package` (bootstrap set) |
| 1337 / 1743 | `boringssl_self_test64_vendor` / `boringssl_self_test64` exit 0 |
| 1999 | `vdc checkpoint markBootAttempt` exit 0 |
| 2100–2155 | `post-fs` / `late-fs` actions |
| 2175.5 | `started service 'system_suspend'` |
| **2177.7** | **`starting service 'keystore2'`**, the last line (log ends) |

Other services started in this log: `servicemanager`, `vold`, `lmkd`, `prng_seeder`. **Not present in any preserved log:** `Activated 33 package`, `apexd.status activated`, `bpfloader` start or success, `zygote` start, `system_server`, `surfaceflinger` start.

### 2c. Claims found only in notes (no log in the dump)

From `_claude-memory/phase-g-tbl-multireg-t12187.md` (2026-06-29 → 07-02): "apexd FULLY ACTIVATED … `Activated 33 package` + `apexd.status activated` + 36 loop-mounts"; "`NetBpfLoad: done` (t8061) → `Service 'bpfloader' exited with status 0` (t8382)"; then a reboot at t8732, root-caused to `update_verifier` and worked around **in the system image** (`update_verifier.rc` → `/system/bin/true`). The notes also say the apexd fix "lives in images (/metadata+/data, uncompressed .apex w/ SELinux xattr), not the repo".

These notes are detailed, internally consistent, and include exact log lines. But **the logs are not in the dump**, and the image changes they depend on are not reproducible from the repository. Those image changes are converted APEX files, an `update_verifier` stub and a kernel `bpf_jit` sysctl patch; only the last is in git (`qemu/patches/0001-…`). **Status: unverified (note only).**

**Zygote:** no evidence anywhere that zygote was started. The latest note says "Next: confirm boot → zygote → SF". **Zygote must not be claimed.**

## 3. Furthest milestone, by evidence class

| Class | Furthest milestone |
|---|---|
| Reproduced in this audit | ARM: GKI 6.1 → EL0 test binary, 4 CPUs, IRQ/IPI (EL2, QEMU TCG). x86: OVMF → AETHER host-mode DBT → translated GKI 6.1 early kernel init (TCG). |
| Old log in the dump (WHPX) | Android `init` running (t=191 s), apexd-bootstrap (3 packages), post-fs/late-fs, `keystore2` starting (t=2177.7 s) |
| Notes only | apexd 33 APEXes activated, bpfloader exit 0 (t≈8382 s), first-boot reboot |
| Never evidenced | zygote, system_server, SurfaceFlinger, any UI, any app |
