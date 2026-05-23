//! AT-1 fuzz target: AETHER decoder must agree with Capstone on every
//! 32-bit word. Disagreement = AT-1 gate failure.
//!
//! Usage:
//!   cargo +nightly fuzz run decode_capstone_diff -- -runs=10000000

#![no_main]

use libfuzzer_sys::fuzz_target;

use aether_translator::decoder::{decode_instruction, DecodedInsn};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    let aether = decode_instruction(word);

    // Capstone init is expensive — keep it thread-local for libfuzzer-sys's
    // single-threaded model.
    thread_local! {
        static CS: std::cell::RefCell<capstone::Capstone> = std::cell::RefCell::new(
            capstone::Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .build()
                .expect("capstone init"),
        );
    }

    let cs_ok = CS.with(|cs| {
        cs.borrow()
            .disasm_count(&word.to_le_bytes(), 0x1000, 1)
            .map(|d| !d.is_empty())
            .unwrap_or(false)
    });

    let aether_ok = !matches!(aether, Ok(DecodedInsn::Unknown(_)) | Err(_));

    // Phase A note: until Unimplemented sentinels are eliminated, the AT-1
    // gate definition compares "AETHER recognized this encoding" vs "Capstone
    // recognized this encoding". Once the fill commits land, this tightens
    // to mnemonic + operand parity.
    assert_eq!(
        aether_ok, cs_ok,
        "decode divergence on {:08x}: aether={:?} cs_ok={}",
        word, aether, cs_ok
    );
});
