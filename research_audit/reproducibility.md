# Reproducibility

## 1. Environment used for this audit

| Item | Value |
|---|---|
| Date | 2026-10-08 |
| Code | `Project-AETHER` `sandbox/aether-translator` @ `9f34e2f`, via the `AETHER-FILES` dump @ `1adc516` (identical for all 400 tracked files) |
| Host | Claude Code cloud container: Intel Xeon @ 2.10 GHz, 4 vCPU (AVX-512, FMA, BMI2, SHA-NI), 15.7 GiB RAM (memcg limit 14.3 GiB), **no KVM**, Ubuntu 24.04.5, kernel 6.18 |
| Rust | nightly 1.101.0 (1d81eb4ad 2026-10-07); targets `aarch64-unknown-uefi`, `x86_64-unknown-uefi` (build-std), `x86_64-pc-windows-gnu` |
| QEMU | 8.2.2 (Ubuntu): `qemu-system-aarch64`, `qemu-system-x86_64`, `qemu-aarch64` |
| Firmware | `/usr/share/AAVMF/AAVMF_CODE.fd` (ARM), `/usr/share/OVMF/OVMF_CODE_4M.fd` (x86) |
| Windows-ABI execution | Wine 9.0 + mingw-w64. The translator emits **Win64-ABI** calls to its runtime helpers (`aether_mmu_xlate`, sysreg, crypto), and the execution tests and oracle are `#![cfg(windows)]` (`VirtualAlloc`). Running them under Wine keeps the same ABI and code with no source changes. |
| Other | `aarch64-linux-gnu-gcc` 13.2 / objdump, cloc 1.98, LLVM 18 (`llvm-symbolizer`, `llvm-objdump`) |

**No AETHER source file was modified.** The fault-injection experiments patch a scratch copy of the tree, and the reference-interpreter FRINT fix was applied to a scratch copy of the oracle.

## 2. Commands (every important measurement)

Run from the AETHER tree root unless noted. `R=research_audit/raw`.

| Measurement | Command | Output | Runtime |
|---|---|---|---|
| Canonical tests (CLAUDE.md) | `cargo +nightly test -p hypervisor -p aether-translator` | `R/2026-10-08_9f34e2f_cargo-test-hv-translator.log` | 34 s |
| Windows-only exec tests | `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo +nightly test -p aether-translator --target x86_64-pc-windows-gnu` | `R/…_cargo-test-translator-win64-wine.log` | 33 s |
| Tool tests | `cargo +nightly test -p aether-install -p compat-check` | `R/…_cargo-test-tools.log` | 10 s |
| ARM EFI | `cargo +nightly build -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem --release --target aarch64-unknown-uefi -p hypervisor` | `R/…_build-arm-efi.log` | 42 s |
| x86 EFI | same with `--target x86_64-unknown-uefi --features whpx_hostmode,qemu` | `R/…_build-x86-efi-whpx_hostmode.log` | 43 s |
| Oracle self-test | `cargo +nightly build --release -p dbt-oracle --target x86_64-pc-windows-gnu && wine target/…/dbt-oracle.exe --self-test` | `R/…_oracle-selftest.log` | 2.4 s |
| Oracle sweep | `wine dbt-oracle.exe tools/dbt-oracle/corpus/<file>.txt` for each of the 16 files | `R/oracle-sweep-2026-10-08_9f34e2f/*.log` (`simd_from_framework.log` is gzipped; `gunzip` it before running the classify/adjudicate scripts) | ~8 s total |
| FAIL classification | `python3 -I research_audit/scripts/classify_oracle.py R/oracle-sweep-… tools/dbt-oracle/corpus` | `…/CLASSIFICATION.md` | 1 s |
| FAIL adjudication | `python3 -I research_audit/scripts/adjudicate_oracle.py R/oracle-sweep-… tools/dbt-oracle/corpus` | `…/ADJUDICATION.md` | 1.6 s |
| Reference-fix re-run | scratch copy of `tools/dbt-oracle` + `…/reference-frint-fix.audit.diff`, same profile | `…/refpatched/` | |
| DBT-only coverage | `aether-dbt-bench coverage <corpus…>` (native Linux build) + `scripts/classify_coverage.py` | `R/…_dbt-coverage-*.log`, `*.CLASSIFIED.md` | 2 s |
| Translation throughput / cache | `aether-dbt-bench translate tools/dbt-oracle/corpus/bb_*.txt` (and single-instruction corpora) | `R/…_bench-translate-*.log` | ~10 s |
| Execution microbenchmarks | `BENCH_K=100000 wine aether-dbt-bench.exe exec` | `R/…_bench-exec-families.log` | ~1 min |
| QEMU TCG baseline | `aarch64-linux-gnu-gcc -O2 -static -o tcgbench bench/qemu-tcg-baseline/tcgbench.c && qemu-aarch64 ./tcgbench 500000` | `R/2026-10-08_qemu-tcg-user-baseline.log` | 14 s |
| ARM proof (repo script) | `QEMU_AARCH64=qemu-system-aarch64 AAVMF=/usr/share/AAVMF/AAVMF_CODE.fd python3 qemu/run-arm-auto.py --kernel _kernel_new --initrd qemu/initrd-proof.cpio --smp 4 --until "PROOF done"` | `R/…_arm-proof-smp4_run1_*.log` | 17 s |
| ARM milestone timing | `python3 -I research_audit/scripts/arm_milestones.py <tree> R/arm-milestones-… {aether,direct} {4,1} 5` | `R/arm-milestones-2026-10-08_9f34e2f*` | ~3 min |
| EL2 fault injection | `research_audit/scripts/el2_fault_injection.sh <scratch-copy> <tree> R/el2-fault-injection-…` | `R/el2-fault-injection-…/` | ~15 min |
| x86 tier under TCG | `R/x86-tcg-2026-10-08_9f34e2f/run.sh` (needs `-m 16G`, overcommit, swap; see `boot_milestones.md` §2a) | `R/x86-tcg-…/` | stopped at ~400 s |
| Image reachability | rebuild both EFIs with `RUSTFLAGS="-C debuginfo=line-tables-only"`, then `python3 -I research_audit/scripts/attribute_image.py <efi> llvm-objdump llvm-symbolizer <tree> hypervisor/src aether-translator/src` | `R/…_image-attribution-{aarch64,x86_64}.md` | 30 s |
| LOC | `cloc` on `git archive 9f34e2f`; `python3 -I research_audit/scripts/rust_loc_split.py <tree> <dirs…>` | `R/…_rust-loc-split.md` | |

## 3. Infrastructure issues hit (not code failures)

| Issue | Classification | Workaround |
|---|---|---|
| `android_handoff::tests::dump_dtb_for_inspection` writes to `D:/AETHER/qemu/test.dtb` | infrastructure (hard-coded Windows path) | none; reported as the single failing test |
| `at_exec_proof`, `phase_e_*`, `dbt-oracle` are Windows-only | missing dependency on Linux | build `x86_64-pc-windows-gnu`, run under Wine |
| Native Linux execution of translated code that calls helpers would use the SysV ABI against Win64-emitted calls | ABI mismatch (silent wrong results, **not** reported by AETHER) | Wine; or never execute helper-calling blocks natively |
| QEMU 8.2 `-device loader` cannot read a 3 GiB file on Linux | infrastructure | split `system.raw` into 1 GiB loaders |
| QEMU `-m 16G` refused (overcommit=0), later memcg OOM kill | infrastructure | `vm.overcommit_memory=1`, 8 GiB swap |
| QEMU `fat:rw:` rewrote `BOOTX64.EFI` on the host directory | infrastructure | restore the ESP before each run |
| x86 tier under TCG far too slow to reach `init` | environment (no WHPX/KVM) | Windows runbook below |
| 3 corpus gate tests (`at3`, `at4`, `at5_system_img`) and 7 others are `#[ignore]` | missing dependency (GSI build, `simg2img`) | not run |

## 4. Gaps: what another researcher cannot reproduce from the repository

| Missing item | Impact |
|---|---|
| The images that reached apexd (33) and bpfloader. The notes say the fixes "live in images" (converted .capex → .apex with SELinux xattrs, `/metadata` + `/data` layout, `update_verifier.rc` → `/system/bin/true`). The dump's `system.raw`/`vendor.raw` may or may not contain them; there is no manifest or hash. | apexd/bpfloader claims cannot be re-derived |
| Boot logs for apexd-33 / bpfloader | claims unverified |
| Pre-fix translator states for the oracle and Fable-5 bugs: all July work is squashed into `99023be` | historical FAILs cannot be re-executed; only documented |
| Script and log behind "346K dispatches/s" | number unverified |
| AOSP build recipe (`docs/aosp-build-history.md`, `wsl-scripts/`) needs a full AOSP tree | images cannot be rebuilt by a third party |
| Kernel `_kernel_new` build (`qemu/_kbuild_step2.sh`, `qemu/kernel.config`, GKI 6.1.79 + local patch, "-dirty") | kernel provenance only partially reproducible |
| `qemu/initrd-proof.cpio` prebuilt with a Bootlin toolchain | `qemu/initrd-src/build.sh` rebuilds it (needs root for `mknod`); not re-done here |
| Checksums for large blobs | `_blobs/restore.sh` verifies non-emptiness only |
| Hardware runs (author reports a real ARM laptop and real x86 reaching the QEMU milestones) | no logs, machine models, firmware, EFI hashes or build diffs; the audited ARM build hard-codes QEMU-virt addresses, so the laptop build must differ. Add them under `raw/hardware-<date>/` |

## 5. Windows / WHPX runbook (to close the x86 gaps)

On the authors' machine (Windows, `bcdedit /set hypervisorlaunchtype auto`, WHPX enabled), from `D:\AETHER` at commit `9f34e2f`:

1. **Build:** `cargo +nightly build -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem --release --target x86_64-unknown-uefi -p hypervisor --features whpx_hostmode,qemu`. Record `Get-FileHash target\x86_64-unknown-uefi\release\hypervisor.efi`.
2. **Hash the images:** `Get-FileHash qemu\images\*.raw, qemu\efi-x86\EFI\AETHER\boot.img`, so a run can be tied to exact images.
3. **Run with host timestamps:** `WHPX=1 HARD_TIMEOUT=14400 SETTLE_S=4000 py -3 qemu\run-x86-auto.py`. In a second PowerShell, log the size and the last `[dbt] #counter` / guest timestamp of `qemu\x86-serial-com1.log` every 15 s to a TSV, as `raw/x86-tcg-…/run.sh` does. That makes the dispatch rate and time-to-milestone derivable from data rather than recalled.
4. **Milestone regexes to timestamp:** `Run /init`, `starting service 'apexd'`, `Activated \d+ package`, `apexd.status`, `starting service 'bpfloader'`, `NetBpfLoad: done`, `Service 'bpfloader' exited with status 0`, `starting service 'zygote`, `system_server`, `surfaceflinger`, `Boot is finished`, `reboot:`.
5. **Repeat 3 times.** Keep the full serial logs. Commit the TSVs and logs (gzipped) under `research_audit/raw/whpx-<date>-<commit>/`.
6. **Baseline on the same machine:** boot the same `system.raw`/`vendor.raw` with `qemu-system-aarch64 -M virt -cpu max` (TCG) and a stock GKI DTB/initramfs, recording the same milestones.
