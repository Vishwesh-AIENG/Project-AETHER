image=hypervisor.efi instructions=6010 code_bytes=272952

| source file | bytes in image | share |
|---|---:|---:|
| hypervisor/src/main.rs | 241012 | 88.3% |
| hypervisor/src/kernel.rs | 6108 | 2.2% |
| hypervisor/src/arm64/exception.rs | 1920 | 0.7% |
| hypervisor/src/paravirt.rs | 1720 | 0.6% |
| hypervisor/src/virtio_blk.rs | 1016 | 0.4% |
| hypervisor/src/gic.rs | 1000 | 0.4% |
| hypervisor/src/cpio.rs | 868 | 0.3% |
| hypervisor/src/boot.rs | 736 | 0.3% |
| hypervisor/src/cpu.rs | 608 | 0.2% |
| hypervisor/src/memory.rs | 496 | 0.2% |
| hypervisor/src/virtual_sensors_modem.rs | 432 | 0.2% |
| hypervisor/src/sysreg_trap.rs | 332 | 0.1% |
| hypervisor/src/uart.rs | 244 | 0.1% |
| hypervisor/src/smp.rs | 184 | 0.1% |
| hypervisor/src/arm64/virt.rs | 156 | 0.1% |
| hypervisor/src/linux_boot.rs | 148 | 0.1% |
| hypervisor/src/el2_mmu.rs | 132 | 0.0% |
| hypervisor/src/arm64/barriers.rs | 64 | 0.0% |
| hypervisor/src/arm64/regs.rs | 36 | 0.0% |
| hypervisor/src/arm64/vectors.rs | 36 | 0.0% |
| hypervisor/src/arm64/paging.rs | 8 | 0.0% |
| hypervisor/src/partition.rs | 4 | 0.0% |
| _(no line info)_ | 10836 | 4.0% |
| _rust std/core/alloc/compiler_builtins_ | 4856 | 1.8% |

### Source files under the reported dirs with ZERO bytes in this image

- `hypervisor/src/`: present only as an outer inlined frame (1): irq_forward.rs

- `hypervisor/src/`: 23/88 files present; absent (65): acpi.rs, adreno_render.rs, aether_installer.rs, aether_manager.rs, android_boot.rs, android_handoff.rs, android_runtime.rs, android_x86_userspace.rs, aosp.rs, aosp_build.rs, app_compat.rs, arm64/context.rs, arm64/mod.rs, avb_boot.rs, bin/selector.rs, boot_x86.rs, boot_x86_avb.rs, boot_x86_esp.rs, bootloader.rs, build_system.rs, configuration_app.rs, dbt_dispatch.rs, dbt_integration.rs, development_workflow.rs, fingerprint.rs, gpu.rs, gpu_sriov.rs, guest_stub.rs, host_idt.rs, hvc_paravirt_abi.rs, inflate.rs, kernel_defconfig.rs, lib.rs, microg.rs, mmio_emu.rs, network.rs, network_passthrough.rs, nvme_namespace.rs, ota_update.rs, passthrough.rs, pcie_assignment.rs, performance.rs, phone_bridge.rs, play_store.rs, recovery_mode.rs, roadmap_phase1.rs, roadmap_phase2.rs, roadmap_phase3.rs, roadmap_phase4.rs, roadmap_phase5.rs, secure_boot.rs, security.rs, setup_wizard.rs, storage.rs, svm.rs, time.rs, uefi_boot_selector.rs, usb.rs, usb_passthrough.rs, userspace_boot.rs, virtio.rs, virtio_blk_pci.rs, vtx.rs, windows.rs, x86_hw_validation.rs

- `aether-translator/src/`: present only as an outer inlined frame (0): 

- `aether-translator/src/`: 0/64 files present; absent (64): backend/code_buf.rs, backend/encode.rs, backend/lower_int.rs, backend/lower_simd_ctx.rs, backend/mod.rs, corpus/extract.rs, corpus/mod.rs, dbt.rs, decoder/bits.rs, decoder/branch_sys.rs, decoder/dp_immediate.rs, decoder/dp_register.rs, decoder/dp_simd_fp.rs, decoder/load_store.rs, decoder/mod.rs, decoder/sysreg.rs, decoder/top_level.rs, forbidden_symbols.rs, ir/flags.rs, ir/memory.rs, ir/mod.rs, ir/ops.rs, ir/serialize.rs, ir/value.rs, lib.rs, lift/mod.rs, opt/const_fold.rs, opt/copy_prop.rs, opt/dce.rs, opt/flag_elision.rs, opt/gvn.rs, opt/mem_order.rs, opt/mod.rs, opt/redundant_load.rs, regalloc/linear_scan.rs, regalloc/liveness.rs, regalloc/mod.rs, regalloc/x86_regs.rs, runtime/aot.rs, runtime/app_compat_x86.rs, runtime/bionic_libart.rs, runtime/block_cache.rs, runtime/branch_chain.rs, runtime/cache_persist.rs, runtime/context.rs, runtime/crypto_rt.rs, runtime/dispatcher.rs, runtime/exception_forward.rs, runtime/exceptions.rs, runtime/gic.rs, runtime/hello_world.rs, runtime/mmu.rs, runtime/mod.rs, runtime/perf_bench.rs, runtime/psci.rs, runtime/smc_handler.rs, runtime/sysreg_rt.rs, runtime/timer.rs, runtime/zygote_launch.rs, ssa/cfg.rs, ssa/dom.rs, ssa/mod.rs, ssa/promote.rs, ssa/verify.rs

