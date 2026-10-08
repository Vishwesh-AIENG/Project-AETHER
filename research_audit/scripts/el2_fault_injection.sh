#!/bin/bash
# EL2 fault-injection: revert ONE documented hypervisor fix at a time in a
# scratch copy of the tree, rebuild the ARM-tier EFI, run the ARM proof, and
# record whether the boot still reaches "PROOF done". Confirms each runtime
# rule in CLAUDE.md "EL2 Runtime Rules" (commit 9f34e2f) is necessary.
#
# Usage: el2_fault_injection.sh <scratch-tree> <aether-tree> <out-dir>
#   <scratch-tree>: copy of the AETHER source (never the real checkout)
#   <aether-tree>:  real checkout (for _kernel_new, initrd-proof.cpio, run-arm-auto.py)
set -u
T=$1; A=$2; OUT=$3; mkdir -p "$OUT"
export QEMU_AARCH64=${QEMU_AARCH64:-qemu-system-aarch64} AAVMF=${AAVMF:-/usr/share/AAVMF/AAVMF_CODE.fd}
mkdir -p "$T/qemu"; cp "$A/qemu/run-arm-auto.py" "$A/qemu/initrd-proof.cpio" "$T/qemu/"; ln -sf "$A/_kernel_new" "$T/_kernel_new"
H=$T/hypervisor/src

EFI="$T/target/aarch64-unknown-uefi/release/hypervisor.efi"
build() { # deletes the old EFI first so a failed build can never be run by mistake
  rm -f "$EFI"
  (cd "$T" && cargo +nightly build -Z build-std=core,alloc,compiler_builtins \
     -Z build-std-features=compiler-builtins-mem --release --target aarch64-unknown-uefi -p hypervisor 2>&1 | tail -n 2)
}

run() { # $1 name  $2 smp
  local s e
  if [ ! -s "$EFI" ]; then
    printf "%s\tsmp=%s\tBUILD_FAILED (not run)\n" "$1" "$2" | tee -a "$OUT/SUMMARY.tsv"; return
  fi
  echo "$1 $(sha256sum "$EFI" | cut -c1-16)" >> "$OUT/efi_hashes.txt"
  s=$(date +%s)
  (cd "$T" && python3 qemu/run-arm-auto.py --kernel _kernel_new --initrd qemu/initrd-proof.cpio \
     --smp "$2" --until "PROOF done" --timeout 120 --settle 45 > "$OUT/$1.runner.log" 2>&1)
  local rc=$?; e=$(date +%s)
  cp "$T/qemu/arm-serial.log" "$OUT/$1.serial.log" 2>/dev/null
  local proof; proof=$(grep -a 'PROOF' "$OUT/$1.serial.log" 2>/dev/null | tr '\n' ' ' | tr -d '\r')
  local last; last=$(grep -av '^\s*$' "$OUT/$1.serial.log" 2>/dev/null | tail -n 1 | tr -d '\r' | cut -c1-140)
  printf "%s\tsmp=%s\trc=%s\twall=%ss\tproof=[%s]\tlast=[%s]\n" "$1" "$2" "$rc" "$((e-s))" "$proof" "$last" | tee -a "$OUT/SUMMARY.tsv"
}

inject() { # $1 name  $2 file  $3 python-replace-old  $4 new  $5 smp
  cp "$2" "$2.orig"
  python3 - "$2" "$3" "$4" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert old in s, f"patch site not found in {p}: {old!r}"
open(p, "w").write(s.replace(old, new, 1))
EOF
  diff -u "$2.orig" "$2" > "$OUT/$1.patch"
  echo "== $1: $(build | tail -n1)"
  run "$1" "$5"
  mv "$2.orig" "$2"; touch "$2"   # new mtime so cargo rebuilds the restored file
}

: > "$OUT/SUMMARY.tsv"; : > "$OUT/efi_hashes.txt"
echo "== control: $(build | tail -n1)"; run control_smp4 4; run control_smp1 1

inject FI1_eoimode0        "$H/gic.rs" '"orr {t}, {t}, #2",' '"bic {t}, {t}, #2",' 4
inject FI2_pl011_no_amba   "$H/main.rs" 'uart_clock_hz: 24_000_000,' 'uart_clock_hz: 0,' 4
inject FI3_psci_hvc        "$H/smp.rs" '"smc #0",' '"hvc #0",' 4
inject FI4_no_elr_advance  "$H/arm64/exception.rs" 'ExitReason::Emulated => ctx.elr_el2 = ctx.elr_el2.wrapping_add(4),' 'ExitReason::Emulated => {}' 4
inject FI5_no_id_sanitize  "$H/arm64/exception.rs" 'crate::sysreg_trap::sanitize_id(a.crm, a.op2, v)' 'v' 4
inject FI6_no_apk_api      "$H/arm64/virt.rs" 'TSW | RW | TLOR |
        APK | API;' 'TSW | RW | TLOR;' 4
inject FI7_hardcoded_4cpus "$H/main.rs" '        puts(&uart, "  CPUs: ");' '        for i in 1..max_cpus { cpu_mpidr[i] = i as u64; } smp_cores = max_cpus; // FI7
        puts(&uart, "  CPUs: ");' 1
echo "== restore: $(build | tail -n1)"
