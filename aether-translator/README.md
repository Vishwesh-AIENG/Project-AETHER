# aether-translator

ARM64 → x86_64 dynamic binary translator for AETHER's x86 Tier. Phase A
delivers the decoder and IR foundation; later phases add SSA, optimization,
x86 codegen, and dispatcher integration.

See [`README/PHASE_A_PLAN.md`](../README/PHASE_A_PLAN.md) for the full plan and
gates (AT-1 … AT-5). Plan file in user's planning store:
`~/.claude/plans/identify-your-weaknesses-in-wondrous-pond.md`.

## Quick layout

| Path | Purpose |
|---|---|
| `src/decoder/` | A64 instruction decoder (8 sub-modules by top-level family) |
| `src/ir/` | IR data model (`IrOp`, `IrValue`, `IrBlock`, `IrFunction`) |
| `src/lift/` | Decoded encoding → IR mapping |
| `src/corpus/` | AT-5 audit driver (bulk decode an Android system.img) |
| `tests/at1_*` | AT-1 gates: canned 1000 + Capstone diff fuzz |
| `tests/at2_*` | AT-2 gate: IR serialize/parse round-trip |
| `tests/at3_*` | AT-3 gate: NEON / FP / SIMD / crypto corpus |
| `tests/at4_*` | AT-4 gate: kernel + bionic system-instruction corpus |
| `tests/at5_*` | AT-5 gate: 21 AOT default libraries — 0 unknown, 0 unimplemented |
| `fuzz/` | `cargo-fuzz` target for AT-1 capstone diff |
| `corpus/` | gitignored binary blobs (NEON `.o`, vmlinux, GSI extract) |
| `scripts/fetch_gsi.sh` | Pinned Android GSI fetch for AT-5 corpus |

## Phase A status (filled by skeleton commit)

- AT-1 decoder: skeleton, no encodings decoded yet
- AT-2 IR: full enum variant list, serializer stubs
- AT-3 NEON: skeleton
- AT-4 system: skeleton
- AT-5 audit: skeleton

## Local toolchain prerequisites

- Rust nightly (workspace `rust-toolchain.toml`)
- `aarch64-linux-gnu-gcc` for AT-3 NEON corpus compilation
- `simg2img` and `7z` (or loopback mount) for AT-5 system.img extraction
- `cargo install cargo-fuzz` for AT-1 fuzz target

## Run gates

```bash
cargo test -p aether-translator                          # AT-1 canned + AT-2 roundtrip
(cd aether-translator/corpus && \
   aarch64-linux-gnu-gcc -O2 -march=armv8-a+crypto -c neon_compile.c)
cargo test -p aether-translator --test at3_neon_corpus
./aether-translator/scripts/fetch_gsi.sh
cargo test -p aether-translator --test at4_system_corpus
cargo test -p aether-translator --test at5_system_img -- --nocapture
cargo +nightly fuzz run decode_capstone_diff -- -runs=10000000
```

All five must exit 0. Phase A is **not** complete until they do.
