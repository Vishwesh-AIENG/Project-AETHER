#!/bin/bash
# x86-tier AETHER under QEMU TCG (mirrors qemu/run-x86-auto.py TCG branch), time-boxed.
S=$(dirname "$0"); IMG=/home/user/aether-files/qemu/images; LIMIT=${LIMIT:-3600}
SER=$S/serial.log; HB=$S/heartbeat.tsv; rm -f $SER
# fresh ESP every run: QEMU fat:rw write-back can rewrite files on the host dir
rm -rf $S/efi; mkdir -p $S/efi/EFI/BOOT $S/efi/EFI/AETHER
cp /home/user/aether-files/target/x86_64-unknown-uefi/release/hypervisor.efi $S/efi/EFI/BOOT/BOOTX64.EFI
cp /home/user/aether-files/qemu/efi-x86/EFI/AETHER/* $S/efi/EFI/AETHER/
sha256sum $S/efi/EFI/BOOT/BOOTX64.EFI > $S/efi.sha256
qemu-system-x86_64 -machine q35 -accel tcg,tb-size=512 -cpu max -m 16G \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive format=raw,file=fat:rw:$S/efi -serial file:$SER -vga std -no-reboot -display none \
  -device loader,file=$S/sys.part0,addr=0x300000000,force-raw=on \
  -device loader,file=$S/sys.part1,addr=0x340000000,force-raw=on \
  -device loader,file=$S/sys.part2,addr=0x380000000,force-raw=on \
  -device loader,file=$IMG/vendor.raw,addr=0x3C0000000,force-raw=on > $S/qemu.out 2>&1 &
QP=$!; T0=$(date +%s.%N); echo -e "wall_s\tserial_bytes\tlast_dbt_counter\tlast_guest_t\tqemu_rss_kb" > $HB
while kill -0 $QP 2>/dev/null; do
  sleep 15; W=$(echo "$(date +%s.%N)-$T0"|bc)
  C=$(grep -aoE '\[dbt\] #0x[0-9a-f]+' $SER 2>/dev/null | tail -n1 | sed 's/.*#//')
  G=$(grep -aoE '^\[ *[0-9]+\.[0-9]+\]' $SER 2>/dev/null | tail -n1 | tr -d '[] ')
  RSS=$(ps -o rss= -p $QP 2>/dev/null | tr -d ' ')
  echo -e "$W\t$(stat -c %s $SER 2>/dev/null)\t$C\t$G\t$RSS" >> $HB
  if (( $(echo "$W > $LIMIT"|bc) )); then kill $QP; echo "time limit $LIMIT s reached" >> $HB; fi
done
echo "qemu exited at $(echo "$(date +%s.%N)-$T0"|bc) s" >> $HB
