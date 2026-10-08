# Bug taxonomy

Two populations: **(A) DBT silent miscompiles and coverage gaps** in the ARM64→x86-64 translator, and **(B) EL2 hypervisor bugs** that blocked the ARM-tier boot. For each bug I state what kind of evidence backs it:
- **R** = reproduced or re-checked in this audit
- **T** = a regression test exists and passes now
- **D** = documented with an exact repro (encoding plus seed and values)
- **N** = narrative only

---

## A. DBT bugs

### A1. Found by the differential oracle

| ID | Instruction family | Wrong behaviour | Correct (ARM) | Root cause / site | How detected | Fixed? | Regression test | Evidence |
|---|---|---|---|---|---|---|---|---|
| C1 | `FCVT Sd, Dn` (double→single) | Left stale bits [63:32] of Vd | 32-bit FP write zeroes Vd[127:32] | `lower_simd_ctx.rs` `lower_fpcvt2` | sweep #2: 139 words, ~55 hot blocks in libhwui/SF | yes | `fcvt_narrow_zeroes_upper_bits_execute` | D, T, R (family absent from today's sweep; oracle probe "UNEXPECTED" = fixed) |
| C2 | `SCVTF/UCVTF Sd/Dd, Wn` (scalar) | W-form signed convert used the zero-extended 64-bit value (−1 → +2³²) | sign-extend W | `lift/mod.rs` dropped `sf`; `lower_int.rs` always `cvtsi2ss_r64` | sweep #2: 213 words, ~74 hot blocks (SF/libui/libgui) | yes | `scvtf_ucvtf_wform_sign_execute` | D, T, R |
| C3 | `FCVTZS/FCVTZU` + rounding variants (scalar) | Overflow, +inf and NaN produced x86 "integer indefinite" (0x8000…/0) | saturate to INT_MAX/UINT_MAX; NaN → 0 | `lower_int.rs` bare `cvtt*2si` | sweep #2: 66 words | yes | `fp_vector_fcvtzs_saturation` (+ scalar paths) | D, T, R |
| C4 | Vector `FMLA/FMLS` | Unfused `mulps`+`addps`, two roundings (1 ULP) | fused, single rounding | `lower_simd_ctx.rs` `lower_vecfp` | sweep #2: 28 words; hand-computed IEEE | yes | `fmla_4s_executes`, `fmls_4s_executes` | D, T, R (this audit: DBT matches exact fused ground truth on 38 words) |
| RSHRN | `RSHRN` (rounding narrow) | Routed through the saturating pack (0x8000 → 0xFF) | modular truncation (0x8000 → 0x00) | `lower_simd_ctx.rs` narrowing shift | oracle ("headline regression", `at_exec_proof.rs` doc comment) | yes | `rshrn_modular_narrow_no_saturation` | D, T |
| **NEW-1** | `FRINTA` scalar + vector, input in (−0.5, 0) | Returns **+0.0** | **−0.0** (sign of input preserved) | ties-away path (`lower_fpround` / `lower_vecfpround`); probably introduced by the 2026-07-03 F4/F6 fix (not root-caused) | **this audit**: oracle FAIL + exact-arithmetic adjudication | **no** | none | **R** (7 blocks, 7 words) |
| **NEW-2** | Vector `FMLS` with a NaN in Vn | NaN returned with original sign | ARM negates op1 *before* NaN propagation, so the NaN's sign flips | FMLS via `vfnmadd*`, whose NaN propagation ignores the negation | **this audit** | **no** | none | **R** (11 blocks, 11 words) |

Also found by the oracle but **reference** bugs, not DBT bugs (route to the oracle, not the translator): sweep #1's 20 words (UBFM/SBFM/BFM shift aliases, REV, bitmask MOV, CSINV); sweep #2's R1 (SSHLL/USHLL width) and R2 (FMAX/FMIN NaN); and in this audit, FRINTM/FRINTP decode swap (118 words), unfused FMLA/FMLS reference (48 words) and REV (2 words). **About 96% of today's FAILs (404/422) are reference-side.** That is the main methodological cost of an independent oracle: it needs its own oracle.

### A2. Found by AI adversarial code review (Fable-5, 2026-07-03), each proven by executing DBT output on the host

| ID | Family | Wrong behaviour | Site | Fixed | Regression test | Evidence |
|---|---|---|---|---|---|---|
| F1 | `FRECPE .4s` | Mis-decoded as SCVTF (2.0 → 1.07e9) | `decoder/dp_simd_fp.rs` | yes (now fail-loud) | `fp_frecpe_is_fail_loud_not_int_convert` | D, T |
| F2 | scalar `FMAX/FMIN` | NaN not propagated; ±0 tie wrong sign | `lower_simd_ctx.rs` | yes | `fmax_fmin_*` tests | D, T |
| F3 | vector `FCVTZS .4s` | No saturation; NaN → INT_MIN | `lower_veccvtfp` | yes | `fp_vector_fcvtzs_saturation` | D, T |
| F4 | `FCVTAS`, scalar `FRINTA` | ties-away rounded to even | `lower_int.rs`, `lower_simd_ctx.rs` | yes (but see NEW-1) | `fp_fcvtas_ties_away`, `fp_scalar_frinta_ties_away` | D, T |
| F5 | by-element `FMLA/FMLS` | Unfused | `lower_vecbyelem` | yes | `fmla_*` | D, T |
| F6 | vector `FRINTA` | Double rounding (0.49999997 → 1.0) | `lower_vecfpround` | yes (but see NEW-1) | `frint_vector_round_to_integral` | D, T |
| F7 | `FMAXNM/FMINNM` | ±0 tie wrong sign | `lower_simd_ctx.rs` | yes | `fmaxnm_fminnm_*` | D, T |
| S1 | `.8b` pairwise ADDP/UMAXP/UMINP/SMAXP/SMINP | Vn high-half garbage replaced Vm pairs | `lower_vecpair` | yes | `addp_8b_dform_uses_vm_not_vn_high_half`, `umaxp_8b_…` | D, T |
| S2 | byte `SSHR/USHR/SSRA/USRA #8` | `&7` turned #8 into #0 | `lower_simd_ctx.rs` | yes | `sshr_16b_by_8_is_pure_sign_fill`, `ushr_16b_by_8_is_zero` | D, T |
| L1 | all exclusive / acquire-release / LSE atomics with base `[SP]` (9 lift arms) | SP read as XZR → address 0 | `lift/mod.rs` `read_reg` vs `read_reg_or_sp` | yes | `lift_ldar_sp_base_reads_sp_not_xzr`, `lift_swp_sp_base_reads_sp_not_xzr` | D, T |
| L2 | `CMP SP,#imm` / `CMP SP,Xm` | Compared 0, not SP | `lift/mod.rs` | yes | `cmp_sp_imm_compares_sp_not_xzr` | D, T |
| L3 | `LDR/STR Bt/Ht` (FP byte/half) | Routed to the GPR file | `lift/mod.rs` | yes | `lift_ldr_byte_fp_lands_in_vreg_not_gpr`, `lift_str_half_fp_extracts_lane_not_gpr` | D, T |
| L4 | `AND/ORR/EOR SP, Xn, #imm` | SP write discarded | `lift/mod.rs` | yes | `lift_and_imm_sp_dest_writes_sp` | D, T |
| S3 | integer by-element MLA/MLS | Would lower as MUL (not live: decoder UD2s) | `lower_vecbyelem` | defensive UD2 added | — | D |
| D1 | `SDIV/UDIV` | Clobber RDX without saving it (latent; unreachable on the per-instruction live path) | `lower_int.rs` | **not applied** | — | D, S |

### A3. Found by booting (debugging under QEMU; documented in commits and notes)

ADR/ADRP/LDR-literal used a block-start PC (`7fcefe6`); REV 4-byte used BSWAP r64 (`74227ad`); RBIT lowered as NOP and UMULH/SMULH returned the low 64 bits (`6ddafd9`); SMADDL/UMADDL (`0e23084`); block cache not flushed on code-buffer reset (`bbe3d48`); W-form shift amount masking (`6928f6e`); LDXP/STXP pair flag dropped and CLZ/CLS W-form (`e36de11`); TBZ/TBNZ/CBZ/CBNZ clobbered NZCV (`521ea66`); EXTR operand swap; LSE SWP/CAS were silent no-ops; LDPSW imm7 scaled by 8 instead of 4; LDPSW sign-extension; `WriteGpr{sf:false}` truncated a GVN-shared register in place; `gpr()` silently substituted RAX for a spilled operand; chained blocks resumed at a stale PC slot; multi-register TBL/TBX; CMHI `.2d` unimplemented (fail-loud). Most have named regression tests (`phase_e_rbit_*`, `ldpsw_signed_pair_dest_order`, `phase_g_bhs_after_tbnz_consumes_arm_nzcv`, `write_gpr_w_form_does_not_truncate_live_source`, `tbl_tbx_multi_reg_execute`, `cmhi_cmhs_2d_4s_unsigned_execute`, `spilled_atomic_address_does_rmw_on_real_pointer`, …). Evidence: N + T. The Phase-G fixes are squashed into `99023be`.

### A4. Aggregates by instruction family (silent miscompiles with D or R evidence; A1 + A2 live)

| Family | Count | Members |
|---|---:|---|
| FP ↔ int conversion & saturation | 4 | C2, C3, F3, F1 (decode) |
| FP rounding / to-integral | 4 | F4, F6, NEW-1, C1 (precision narrowing) |
| FP NaN / signed-zero semantics | 4 | F2, F7, NEW-2, (FMAX residual noted in sweep #2) |
| FMA fusion | 2 | C4, F5 |
| SIMD integer lane/width | 3 | S1, S2, RSHRN |
| SP vs XZR register-31 aliasing (lift) | 3 | L1, L2, L4 |
| Register-file routing (lift) | 1 | L3 |
| **Total distinct live silent defects** | **20** | 5 oracle-found (fixed) + 13 review-found (fixed) + 2 oracle-found in this audit (open) |

**Pattern:** 14/20 are in FP/SIMD semantics where x86 SSE/AVX differs from ARM: NaN propagation, signed zero, saturation, rounding mode, fusion. 4/20 are in register-31 (SP/XZR) aliasing in the lifter. None of the 20 is in integer ALU or flags; the Fable-5 integer review was clean, and the boot-found bugs (A3) dominate that area instead.

### A5. Coverage gaps (fail-loud UD2 / decoder `Reserved`) on the real framework corpus today

See `oracle_results.md` §4: 1,193 distinct words emit UD2 and 729 are decoder-rejected (6.3% of 30,375). The top families are FCCMP, FABD, FCVTL/FCVTN, fixed-point SCVTF/UCVTF, widening/narrowing add/sub, SQDMULH/SQRDMULH, BIF/ORN `.8b`, and FRECPS/FRSQRTS.

---

## B. EL2 hypervisor bugs (ARM tier, all fixed in `9f34e2f`)

Bug → root cause → fix → reproduction. The fix list is from the `9f34e2f` commit message and `CLAUDE.md` "EL2 Runtime Rules". **The fault-injection column is new evidence.** `scripts/el2_fault_injection.sh` reverts ONE fix in a scratch copy, rebuilds the ARM EFI, and re-runs the ARM proof. Raw: `raw/el2-fault-injection-2026-10-08_9f34e2f/`.

| # | Bug (pre-fix behaviour) | Root cause | Fix in `9f34e2f` | Fault injection: revert only this fix → ARM proof result | Verdict |
|---|---|---|---|---|---|
| — | **Control** (no injection) | — | — | `PROOF done` at smp4 and smp1 (`control_smp{4,1}_clean.*`) | baseline |
| B1 | Virtual-timer IRQ storm right after `sched_clock` | ICC_CTLR_EL1.EOImode=0: EOIR also deactivates, so the still-asserted level vtimer re-pends and is retaken at EL2 before the guest runs one instruction | `gic.rs` sets EOImode=1 (split drop/deactivate; HW-linked LRs) | FI1 (`bic #2` = EOImode 0): **hangs** right after `sched_clock: 57 bits at 63MHz`; no userspace | **Confirmed** |
| B2 | Userspace output silently lost (`/dev/console` → ttynull) | DT PL011 node lacked the AMBA PrimeCell compatible and clocks, so `ttyAMA0` never probes; kernel printk still works through earlycon (misleading) | `kernel.rs` emits `arm,pl011`+`arm,primecell`, `uartclk`/`apb_pclk` fixed clock | FI2 (`uart_clock_hz: 0`): kernel reaches `Run /bin/sh as init process`, `console [ttynull0] enabled`, **zero PROOF lines** | **Confirmed** |
| B3 | Secondary CPUs never start | PSCI CPU_ON issued with `hvc` **at EL2**, which is taken by AETHER's own vector instead of firmware | `smp.rs` uses `smc #0` | FI3 (`hvc #0`): `[EL2] FAULT AT EL2 … EC=0x16` (HVC from EL2) before `Hypervisor ready` | **Confirmed** |
| B4 | Infinite trap loops (re-executes the trapped instruction) | Vector epilogue ERETs to `ELR_EL2`; for MSR/MRS, WFx, TSC-SMC and emulated MMIO the preferred return address is the trapped instruction itself, so the handler must step ELR | `ExitReason::Emulated` → ELR += 4 | FI4 (`Emulated` no longer advances ELR): silence after `ERET to Linux kernel EL1…`; the kernel never prints | **Confirmed** |
| B5 | Guest touches unmanaged state (SVE/SME/…) | Trapped ID registers returned the raw value, advertising features EL2 does not host | `sysreg_trap::sanitize_id` | FI5 (raw ID values): `Oops - Undefined instruction` at `sme_kernel_enable+0x4` during `init_cpu_features` | **Confirmed** |
| B6 | Pointer-auth key writes trapped → UNDEF | HCR_EL2.APK/API clear, so EL1 PAC key accesses trap to EL2 | `virt.rs` `GUEST_FLAGS |= APK | API` | FI6: `Oops - Undefined instruction` at `start_kernel+0x854` (PAC key setup) | **Confirmed** |
| B7 | Hang/fault before `Hypervisor ready` on machines with fewer CPUs | CPU count hard-coded; waking non-existent GIC redistributors faults at EL2 | Topology from MADT enabled-GICC entries | FI7 (force `max_cpus`=8 on `-smp 1`): `[EL2] FAULT AT EL2 … EC=0x25 FAR=0x080c0014` (GICR of absent CPU) | **Confirmed** |
| B8 | EL2 stack, EL2 stage-1 tables and Stage-2 tables in guest-writable RAM | Firmware-provided memory reused; the guest identity-owns 0x4000_0000+2 GiB | `largest_conventional_outside`, static `PRIMARY_EL2_STACK`, `el2_mmu::install_el2_identity_map`, launch guard | not fault-injected (a benign guest does not exploit it; the guard refuses to launch) | Code-verified (S), exercised by every run |
| B9 | Trapped sysregs (EC 0x18) not emulated → kernel loops on `MRS ID_AA64DFR0_EL1` | No emulation path | `sysreg_trap.rs` + `handle_sysreg_trap` | partly covered by FI4/FI5 | S + R (partial) |

**Validity notes.** Attempt 1 is archived as `raw/el2-fault-injection-2026-10-08_9f34e2f_attempt1_INVALID-FI1-FI2/`. It is invalid for FI1 and FI2: `orr #0` does not assemble and a transient build error occurred, so those runs used the previous binary and "passed". The driver now deletes the EFI before every build and refuses to run a failed build. In attempt 2, the leading control reused a stale artifact (restored files had old mtimes), so a clean control was re-run separately after `touch` plus a forced rebuild, with the scratch tree checked identical to the original (`diff -r`). FI1–FI7 in attempt 2 each recompiled from source (≈8 s builds; hashes in `efi_hashes.txt`).

**Reading:** every one of the seven runtime rules that could be reverted with a one-line change is **necessary** for the ARM proof on QEMU. This upgrades those bugs from "documented" to "reproduced". The fixes are QEMU-validated only; the rules (EOImode, conduit, ID sanitising) are architectural, but the Snapdragon behaviour is untested.

### Categories

| Category | Bugs |
|---|---|
| Protected-state lifetime / ownership | EL2 stack, EL2 stage-1 tables and Stage-2 tables lived in guest-writable RAM (moved outside the guest window; launch guard) |
| Stage-2 memory safety | Stage-2 tables in guest RAM (same fix); MMU-off switch of EL2 translation (never change MAIR with the MMU on) |
| Exception / exit handling | `Halt` re-entered the guest; MSR/MRS, WFx, TSC-SMC and MMIO aborts did not step past the trapped instruction (preferred return address); EL2-self faults unreported |
| Trapped system registers | EC 0x18 not emulated (kernel looped on `MRS ID_AA64DFR0_EL1`); ID registers advertised SVE/SME/MTE/…; pointer-auth key traps (HCR.APK/API) |
| Interrupt handling | GIC EOImode=0 (vtimer IRQ storm); SGIs injected HW-linked |
| PSCI | Secondary CPU_ON issued with `hvc` at EL2, taken by AETHER's own vector |
| Topology | Hard-coded 4 CPUs woke absent GIC redistributors |
| Device tree / console | PL011 without the AMBA PrimeCell node → `ttyAMA0` not probed → `/dev/console` = `ttynull` |
