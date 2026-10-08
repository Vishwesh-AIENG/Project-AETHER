image=hypervisor.efi instructions=56698 code_bytes=219926

| source file | bytes in image | share |
|---|---:|---:|
| hypervisor/src/boot_x86.rs | 39380 | 17.9% |
| aether-translator/src/backend/lower_int.rs | 19282 | 8.8% |
| aether-translator/src/backend/encode.rs | 13934 | 6.3% |
| aether-translator/src/backend/lower_simd_ctx.rs | 13797 | 6.3% |
| aether-translator/src/lift/mod.rs | 11819 | 5.4% |
| aether-translator/src/decoder/dp_simd_fp.rs | 7615 | 3.5% |
| hypervisor/src/kernel.rs | 7225 | 3.3% |
| aether-translator/src/runtime/mmu.rs | 6544 | 3.0% |
| aether-translator/src/decoder/sysreg.rs | 3856 | 1.8% |
| aether-translator/src/decoder/load_store.rs | 3597 | 1.6% |
| aether-translator/src/runtime/exceptions.rs | 3576 | 1.6% |
| hypervisor/src/inflate.rs | 3088 | 1.4% |
| aether-translator/src/runtime/context.rs | 2389 | 1.1% |
| aether-translator/src/dbt.rs | 1714 | 0.8% |
| aether-translator/src/decoder/dp_register.rs | 1673 | 0.8% |
| hypervisor/src/mmio_emu.rs | 1284 | 0.6% |
| aether-translator/src/ir/mod.rs | 1223 | 0.6% |
| hypervisor/src/host_idt.rs | 1105 | 0.5% |
| aether-translator/src/runtime/crypto_rt.rs | 1098 | 0.5% |
| aether-translator/src/decoder/branch_sys.rs | 1073 | 0.5% |
| hypervisor/src/virtio_blk.rs | 1042 | 0.5% |
| aether-translator/src/regalloc/liveness.rs | 1041 | 0.5% |
| aether-translator/src/regalloc/linear_scan.rs | 748 | 0.3% |
| aether-translator/src/runtime/sysreg_rt.rs | 662 | 0.3% |
| hypervisor/src/main.rs | 660 | 0.3% |
| aether-translator/src/decoder/dp_immediate.rs | 650 | 0.3% |
| aether-translator/src/runtime/gic.rs | 619 | 0.3% |
| aether-translator/src/runtime/block_cache.rs | 611 | 0.3% |
| hypervisor/src/android_handoff.rs | 571 | 0.3% |
| hypervisor/src/boot_x86_esp.rs | 480 | 0.2% |
| hypervisor/src/lib.rs | 423 | 0.2% |
| hypervisor/src/android_runtime.rs | 398 | 0.2% |
| hypervisor/src/userspace_boot.rs | 340 | 0.2% |
| aether-translator/src/decoder/bits.rs | 305 | 0.1% |
| aether-translator/src/runtime/psci.rs | 304 | 0.1% |
| hypervisor/src/app_compat.rs | 297 | 0.1% |
| aether-translator/src/runtime/timer.rs | 228 | 0.1% |
| hypervisor/src/dbt_dispatch.rs | 209 | 0.1% |
| hypervisor/src/boot.rs | 204 | 0.1% |
| hypervisor/src/setup_wizard.rs | 197 | 0.1% |
| aether-translator/src/ir/ops.rs | 183 | 0.1% |
| aether-translator/src/backend/code_buf.rs | 122 | 0.1% |
| hypervisor/src/svm.rs | 99 | 0.0% |
| aether-translator/src/decoder/top_level.rs | 84 | 0.0% |
| hypervisor/src/vtx.rs | 81 | 0.0% |
| hypervisor/src/bootloader.rs | 80 | 0.0% |
| hypervisor/src/android_boot.rs | 66 | 0.0% |
| hypervisor/src/dbt_integration.rs | 38 | 0.0% |
| aether-translator/src/regalloc/mod.rs | 16 | 0.0% |
| aether-translator/src/decoder/mod.rs | 4 | 0.0% |
| hypervisor/src/x86_hw_validation.rs | 2 | 0.0% |
| _rust std/core/alloc/compiler_builtins_ | 63736 | 29.0% |
| _(no line info)_ | 154 | 0.1% |

### Source files under the reported dirs with ZERO bytes in this image

- `hypervisor/src/`: present only as an outer inlined frame (0): 

- `hypervisor/src/`: 22/88 files present; absent (66): acpi.rs, adreno_render.rs, aether_installer.rs, aether_manager.rs, android_x86_userspace.rs, aosp.rs, aosp_build.rs, arm64/barriers.rs, arm64/context.rs, arm64/exception.rs, arm64/mod.rs, arm64/paging.rs, arm64/regs.rs, arm64/vectors.rs, arm64/virt.rs, avb_boot.rs, bin/selector.rs, boot_x86_avb.rs, build_system.rs, configuration_app.rs, cpio.rs, cpu.rs, development_workflow.rs, el2_mmu.rs, fingerprint.rs, gic.rs, gpu.rs, gpu_sriov.rs, guest_stub.rs, hvc_paravirt_abi.rs, irq_forward.rs, kernel_defconfig.rs, linux_boot.rs, memory.rs, microg.rs, network.rs, network_passthrough.rs, nvme_namespace.rs, ota_update.rs, paravirt.rs, partition.rs, passthrough.rs, pcie_assignment.rs, performance.rs, phone_bridge.rs, play_store.rs, recovery_mode.rs, roadmap_phase1.rs, roadmap_phase2.rs, roadmap_phase3.rs, roadmap_phase4.rs, roadmap_phase5.rs, secure_boot.rs, security.rs, smp.rs, storage.rs, sysreg_trap.rs, time.rs, uart.rs, uefi_boot_selector.rs, usb.rs, usb_passthrough.rs, virtio.rs, virtio_blk_pci.rs, virtual_sensors_modem.rs, windows.rs

- `aether-translator/src/`: present only as an outer inlined frame (0): 

- `aether-translator/src/`: 29/64 files present; absent (35): backend/mod.rs, corpus/extract.rs, corpus/mod.rs, forbidden_symbols.rs, ir/flags.rs, ir/memory.rs, ir/serialize.rs, ir/value.rs, lib.rs, opt/const_fold.rs, opt/copy_prop.rs, opt/dce.rs, opt/flag_elision.rs, opt/gvn.rs, opt/mem_order.rs, opt/mod.rs, opt/redundant_load.rs, regalloc/x86_regs.rs, runtime/aot.rs, runtime/app_compat_x86.rs, runtime/bionic_libart.rs, runtime/branch_chain.rs, runtime/cache_persist.rs, runtime/dispatcher.rs, runtime/exception_forward.rs, runtime/hello_world.rs, runtime/mod.rs, runtime/perf_bench.rs, runtime/smc_handler.rs, runtime/zygote_launch.rs, ssa/cfg.rs, ssa/dom.rs, ssa/mod.rs, ssa/promote.rs, ssa/verify.rs

