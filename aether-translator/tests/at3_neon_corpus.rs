//! AT-3 gate: decode every NEON / FP / SIMD / crypto encoding emitted by
//! `clang -O2 -march=armv8-a+crypto` on the bundled `neon_compile.c` plus
//! Android's `libcrypto.so`.

use std::path::PathBuf;

#[test]
#[cfg_attr(not(feature = "linux_corpus"),
           ignore = "AT-3 gate: needs aarch64-linux-gnu-gcc-compiled neon_compile.o; run \
                     with --features linux_corpus on a Linux host or via the corpus-gates CI lane")]
fn at3_neon_compile_o_has_zero_unknowns() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("corpus");
    p.push("neon_compile.o");
    assert!(p.exists(),
        "AT-3 corpus missing: build with `aarch64-linux-gnu-gcc -O2 -march=armv8-a+crypto -c neon_compile.c -o neon_compile.o` from aether-translator/corpus/");

    let bytes = std::fs::read(&p).expect("read neon_compile.o");
    let text = extract_text_section(&bytes).expect("ELF .text");
    let report = aether_translator::corpus::audit_text(&text, 0, &p);
    assert!(
        report.passes_at5(),
        "AT-3 coverage failure: unknown={} unimpl={} unlifted={} decode_err={}",
        report.unknown.len(),
        report.unimplemented.len(),
        report.decoded_but_unlifted,
        report.decode_errors,
    );
}

#[test]
#[cfg_attr(not(feature = "linux_corpus"),
           ignore = "AT-3 gate: needs corpus/libcrypto.so.aarch64 from a GSI extract; \
                     run with --features linux_corpus on a Linux host")]
fn at3_libcrypto_has_zero_unknowns() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("corpus");
    p.push("libcrypto.so.aarch64");
    if !p.exists() {
        eprintln!("AT-3 corpus libcrypto.so.aarch64 missing; skipping. Place a BoringSSL-built libcrypto here.");
        return;
    }
    let bytes = std::fs::read(&p).expect("read libcrypto");
    let text = extract_text_section(&bytes).expect("ELF .text");
    let report = aether_translator::corpus::audit_text(&text, 0, &p);
    assert!(report.passes_at5(), "AT-3 libcrypto coverage failure");
}

/// Minimal ELF64 `.text` extractor. Phase A skeleton — AT-3 fill replaces
/// with `goblin` if cross-section walking proves painful.
fn extract_text_section(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 /* ELF64 */ {
        return None;
    }
    let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
    let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().ok()?) as usize;
    let e_shstrndx = u16::from_le_bytes(bytes[62..64].try_into().ok()?) as usize;

    let shstr_off = e_shoff as usize + e_shstrndx * e_shentsize;
    let shstr_hdr = bytes.get(shstr_off..shstr_off + e_shentsize)?;
    let shstr_section_off =
        u64::from_le_bytes(shstr_hdr[24..32].try_into().ok()?) as usize;
    let shstr_section_size =
        u64::from_le_bytes(shstr_hdr[32..40].try_into().ok()?) as usize;
    let shstr = bytes.get(shstr_section_off..shstr_section_off + shstr_section_size)?;

    for i in 0..e_shnum {
        let off = e_shoff as usize + i * e_shentsize;
        let hdr = bytes.get(off..off + e_shentsize)?;
        let name_off = u32::from_le_bytes(hdr[0..4].try_into().ok()?) as usize;
        let name_end = shstr[name_off..].iter().position(|&b| b == 0)? + name_off;
        let name = &shstr[name_off..name_end];
        if name == b".text" {
            let s_off = u64::from_le_bytes(hdr[24..32].try_into().ok()?) as usize;
            let s_sz = u64::from_le_bytes(hdr[32..40].try_into().ok()?) as usize;
            return bytes.get(s_off..s_off + s_sz).map(<[u8]>::to_vec);
        }
    }
    None
}
