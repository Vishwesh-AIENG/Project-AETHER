#!/bin/bash
# Build the Phase-0 kernels for aarch64 and x86_64 with the same AOSP clang -O2.
# Output (next to this script): k_arm64.bin, k_x86_64.bin, k_arm64.syms, k_x86_64.syms
# (.syms = "name hex_offset" per entry, offsets relative to the blob start).
set -e
HERE=${HERE:-/mnt/d/AETHER/tools/dbt-bench/kernels}
CL=/root/aosp/prebuilts/clang/host/linux-x86/clang-r510928/bin
FLAGS="-O2 -ffreestanding -fno-builtin -nostdlib -fPIC -fno-stack-protector \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions"
cat > /tmp/k.ld <<'EOF'
SECTIONS {
  . = 0;
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.* .bss .bss.*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.ARM.*) *(.llvm*) }
}
EOF
build() { # arch triple extra
  local a=$1 t=$2; shift 2
  $CL/clang --target=$t $FLAGS "$@" -c "$HERE/kernels.c" -o /tmp/k_$a.o
  $CL/ld.lld -static -nostdlib -T /tmp/k.ld -e 0 -o /tmp/k_$a.elf /tmp/k_$a.o
  $CL/llvm-objcopy -O binary /tmp/k_$a.elf "$HERE/k_$a.bin"
  $CL/llvm-nm /tmp/k_$a.elf | awk '$3 ~ /^k_/ {print $3, $1}' > "$HERE/k_$a.syms"
  # Any dynamic relocation left means the blob is not position-independent.
  if $CL/llvm-readelf -r /tmp/k_$a.elf | grep -q "R_"; then echo "RELOCS in $a"; exit 1; fi
  echo "$a: $(stat -c %s "$HERE/k_$a.bin") bytes, $(wc -l < "$HERE/k_$a.syms") entries"
}
build arm64 aarch64-linux-gnu -march=armv8-a -mno-outline-atomics
build x86_64 x86_64-linux-gnu -march=x86-64
