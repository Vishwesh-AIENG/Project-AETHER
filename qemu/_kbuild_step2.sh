#!/bin/bash
# Step 2+3: apply the hypervisor-optimized config recipe to the GKI 6.1.79 base
# config and build a raw ARM64 Image. Run in WSL via:
#   wsl -d Ubuntu-24.04 -- bash -lc 'tr -d "\r" < /mnt/d/AETHER/qemu/_kbuild_step2.sh | bash'
set -e
cd ~/gki-src
export ARCH=arm64
export CROSS_COMPILE=/root/aarch64--glibc--stable-2024.02-1/bin/aarch64-buildroot-linux-gnu-

# ── Source patch: bpf_jit_enable sysctl write-sink ───────────────────────────
# With CONFIG_BPF_JIT=n (kept off because the DBT mis-translates JITed eBPF),
# /proc/sys/net/core/bpf_jit_enable does not exist. The system/bpf bpfloader
# (NetBpfLoad) UNCONDITIONALLY writes "1" to that file at boot and treats the
# ENOENT open() failure as fatal -> "reboot,bpfloader-failed" reboot loop.
# This patch adds an always-present write-sink sysctl (a private int no kernel
# code reads when BPF_JIT=n) so the write succeeds while eBPF stays INTERPRETED.
# Idempotent: skip if already applied.
PATCH=/mnt/d/AETHER/qemu/patches/0001-aether-bpf_jit_enable-sysctl-write-sink.patch
if git apply --reverse --check "$PATCH" >/dev/null 2>&1; then
  echo "[patch] bpf_jit_enable write-sink already applied — skipping"
elif git apply --check "$PATCH" >/dev/null 2>&1; then
  git apply "$PATCH" && echo "[patch] applied bpf_jit_enable write-sink"
else
  echo "[patch] !! bpf_jit_enable write-sink does NOT apply cleanly — aborting"; exit 1
fi

echo "[cfg] mrproper + copy base config (qemu/kernel.config)"
make O=out mrproper >/dev/null 2>&1
cp /mnt/d/AETHER/qemu/kernel.config out/.config
C="scripts/config --file out/.config"

echo "[cfg] applying recipe"
# A. THE FIX — kernel auto-creates /dev/null before init
$C -e DEVTMPFS -e DEVTMPFS_MOUNT
# B. Display stack — simpledrm leaf driver + framebuffer
$C -e DRM -e DRM_KMS_HELPER -e DRM_SIMPLEDRM -e SYSFB -e SYSFB_SIMPLEFB \
   -e FB -e FB_SIMPLE -e FRAMEBUFFER_CONSOLE -e DMABUF_HEAPS -e DMABUF_HEAPS_SYSTEM
# C. MINIMAL — the DBT mis-handles new kernel codegen, so EVERY config change that
#   alters hot-path instructions risks a fresh DBT spin (PREEMPT_VOLUNTARY->SLUB
#   ___slab_alloc spin; watchdog/kprobes-off->init_sd kernel-boot spin). So keep
#   the kernel as close to the PROVEN old binary as possible: base config (full
#   PREEMPT, HZ_250, watchdogs ON, kprobes ON) + ONLY devtmpfs (the fix) + the
#   forced build disables + BPF_JIT-off. Defer ALL real optimizations until the
#   DBT is hardened against arbitrary kernel codegen. RCU timeout is a value (not
#   code) so it's safe to keep raised.
$C --set-val RCU_CPU_STALL_TIMEOUT 300
# D. GCC build + openssl-cert-blocker disables
$C -d LTO_CLANG -d LTO_CLANG_FULL -d LTO_CLANG_THIN -d CFI_CLANG -d SHADOW_CALL_STACK -d RUST
$C -d UBSAN -d UBSAN_TRAP -d KASAN -d KCSAN
$C -d MODULE_SIG -d MODULE_SIG_ALL -d MODULE_SIG_FORMAT \
   -d SYSTEM_TRUSTED_KEYRING -d SYSTEM_DATA_VERIFICATION \
   -d DM_VERITY -d FS_VERITY -d CFG80211_REQUIRE_SIGNED_REGDB
# E. GKI make-build fixes — bazel/GKI build expects artifacts a plain `make` lacks:
#    TRIM_UNUSED_KSYMS wants the bazel abi_symbollist.raw whitelist; DEBUG_INFO_BTF needs pahole.
#    Both are GKI ABI-stability features irrelevant to our custom guest kernel.
$C -d TRIM_UNUSED_KSYMS
$C --set-str UNUSED_KSYMS_WHITELIST ""
$C -d DEBUG_INFO_BTF -d DEBUG_INFO_BTF_MODULES
# F. DBT workaround — disable the kernel BPF JIT. The DBT mis-translates
#    bpf_convert_filter (cBPF->eBPF) producing a malformed program; with the JIT
#    (+ALWAYS_ON) the kernel returns -ENOTSUPP and ptp_classifier_init BUG_ON()s
#    (kernel panic during sock_init). The BPF interpreter tolerates the malformed
#    program (PTP/seccomp classification is irrelevant to boot). Disable ALWAYS_ON
#    first (it depends on BPF_JIT) so olddefconfig stays consistent.
#    NOTE: BPF_JIT MUST stay off — re-enabling it would let NetBpfLoad's "1" write
#    to net.core.bpf_jit_enable turn the JIT ON, sending JITed eBPF back into the
#    DBT. The missing-sysctl side effect of BPF_JIT=n is handled by the source
#    patch above (write-sink), NOT by re-enabling the JIT.
$C -d BPF_JIT_ALWAYS_ON -d BPF_JIT

echo "[cfg] olddefconfig + verify-and-refix loop"
make O=out olddefconfig >/dev/null 2>&1
for i in 1 2 3; do
  STILL=""
  for k in MODULE_SIG SYSTEM_TRUSTED_KEYRING SYSTEM_DATA_VERIFICATION DM_VERITY FS_VERITY MODULE_SIG_FORMAT; do
    grep -q "^CONFIG_$k=y" out/.config && STILL="$STILL $k"
  done
  [ -z "$STILL" ] && break
  echo "  refix pass $i re-disabling:$STILL"
  for k in $STILL; do $C -d "$k"; done
  make O=out olddefconfig >/dev/null 2>&1
done

echo "[cfg] FINAL VERIFY:"
for k in DEVTMPFS DEVTMPFS_MOUNT DRM_SIMPLEDRM PREEMPT OF_PMEM EXT4_FS_SECURITY SERIAL_AMBA_PL011_CONSOLE; do
  grep -q "^CONFIG_$k=y" out/.config && echo "  +$k" || echo "  !!MISSING $k"
done
for k in MODULE_SIG SYSTEM_TRUSTED_KEYRING KPROBES SOFTLOCKUP_DETECTOR DETECT_HUNG_TASK LTO_CLANG BPF_JIT TRIM_UNUSED_KSYMS DEBUG_INFO_BTF; do
  grep -q "^CONFIG_$k=y" out/.config && echo "  !!STILL-ON $k" || echo "  -$k"
done
echo "  $(grep '^CONFIG_RCU_CPU_STALL_TIMEOUT' out/.config) $(grep '^CONFIG_HZ=' out/.config)"

echo "[build] make Image -j$(nproc) (this is the long step ~20-40min)"
make O=out -j"$(nproc)" Image
SZ=$(stat -c%s out/arch/arm64/boot/Image 2>/dev/null || echo 0)
echo "[build] Image = $SZ bytes ($((SZ/1048576)) MB)"
if [ "$SZ" -gt 1000000 ]; then
  cp out/arch/arm64/boot/Image /mnt/d/AETHER/_kernel_new
  # head magic for the Windows side to confirm raw "MZ"
  head -c 2 out/arch/arm64/boot/Image | od -A n -t x1
  echo "STEP2_DONE_OK"
else
  echo "STEP2_BUILD_FAILED"
fi
