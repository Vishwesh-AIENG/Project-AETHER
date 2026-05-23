# FEX-Emu Vendoring

This directory is the drop location for the stripped-down FEX-Emu ARM64→x86_64
dynamic binary translator that links into `hypervisor.efi` on the x86 tier
(Chapter 52).

The archive itself is **not** checked into this repository — it is large,
target-specific, and built from an out-of-tree FEX fork. `*.a` and `*.lib`
are gitignored.

## Layout

```
third_party/fex/
├── README.md          ← this file
├── VERSION            ← FEX fork commit SHA pin
├── lib/               ← drop libfex.a (GNU) or fex.lib (MSVC) here
└── include/           ← optional: FFI header for cross-check against fex_integration.rs
```

## Toolchain note

The Windows nightly toolchain invokes `rust-lld` with `lld-link` flavor for
UEFI targets. That flavor follows MSVC conventions and expects a `.lib`
archive. The FEX fork should therefore produce `fex.lib` on Windows hosts;
on Linux/macOS hosts the same archive is produced as `libfex.a`. `build.rs`
accepts either filename.

## Vendoring procedure

1. Build the FEX fork for `x86_64-unknown-uefi` (PE/COFF static archive, no
   C++ stdlib, no libc). The fork must replace:
   - `malloc/calloc/realloc/free` → `FexHostBindings::alloc`
     (see [fex_integration.rs:538](../../src/fex_integration.rs))
   - `pthread_*` → `FexSpinLock`
     (see [fex_integration.rs:481](../../src/fex_integration.rs))
   - `fopen/fread/fwrite` → paravirt NVMe spill
   - `printf/abort/exit` → COM1 `dual_puts` + halt

2. Copy the archive into `lib/`:
   ```
   cp /path/to/fex/build/libfex.a hypervisor/third_party/fex/lib/libfex.a
   ```
   (or `fex.lib` on Windows.)

3. Record the source commit in `VERSION`:
   ```
   git -C /path/to/fex rev-parse HEAD > hypervisor/third_party/fex/VERSION
   ```

4. Audit the archive for forbidden symbols. Output **must be empty**:
   ```
   llvm-nm hypervisor/third_party/fex/lib/libfex.a | \
     grep -E '^[0-9a-f]+ T (malloc|calloc|realloc|free|pthread_|fopen|fclose|fread|fwrite|printf|fprintf|sprintf|open|close|read|write|mmap|munmap|mprotect|exit|abort|__libc_)'
   ```
   The list mirrors `LIBC_FORBIDDEN_SYMBOLS` at
   [fex_integration.rs:767](../../src/fex_integration.rs). Any hit means
   the FEX fork still depends on host userland — reject the archive and
   fix the fork.

## Build

After the archive is in place:

```
cargo +nightly build \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --features fex_linked \
  --target x86_64-unknown-uefi \
  -p hypervisor --release
```

## Verify the produced EFI binary

The five FEX symbols must be present:

```
llvm-nm target/x86_64-unknown-uefi/release/hypervisor.efi | \
  grep -E '(fex_init|fex_load_arm64_elf|fex_translate_block|fex_dispatch_block|fex_shutdown)'
```

No forbidden symbols must have leaked through:

```
llvm-nm target/x86_64-unknown-uefi/release/hypervisor.efi | \
  grep -E '^[0-9a-f]+ T (malloc|calloc|realloc|free|pthread_|fopen|fclose|fread|fwrite|printf|exit|abort|__libc_)'
```
