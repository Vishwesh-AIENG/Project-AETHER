//! AT-24: AETHER DBT FFI Surface — test suite.

use aether_translator::dbt::{
    aether_dbt_dispatch_block, aether_dbt_init, aether_dbt_load_arm64_elf,
    aether_dbt_shutdown, aether_dbt_translate_block, check_dbt_symbols_present,
    check_fex_symbols_absent, init_dbt_integration, AetherDbtResult, ArmElfDescriptor,
    DbtError, DbtIntegrationConfig, DbtPhase, DBT_REQUIRED_SYMBOLS, FEX_FORBIDDEN_SYMBOLS,
    AETHER_DBT_VERSION,
};

// ── Version constant ──────────────────────────────────────────────────────────

#[test]
fn at24_version_nonzero() {
    assert_ne!(AETHER_DBT_VERSION, 0);
}

// ── Symbol lists ──────────────────────────────────────────────────────────────

#[test]
fn at24_fex_forbidden_symbols_count() {
    assert_eq!(FEX_FORBIDDEN_SYMBOLS.len(), 5, "must list exactly 5 fex_* symbols");
}

#[test]
fn at24_dbt_required_symbols_count() {
    assert_eq!(DBT_REQUIRED_SYMBOLS.len(), 5, "must list exactly 5 aether_dbt_* symbols");
}

#[test]
fn at24_fex_symbols_all_prefixed() {
    for &sym in FEX_FORBIDDEN_SYMBOLS {
        assert!(sym.starts_with("fex_"), "fex symbol must start with 'fex_': {sym}");
    }
}

#[test]
fn at24_dbt_symbols_all_prefixed() {
    for &sym in DBT_REQUIRED_SYMBOLS {
        assert!(
            sym.starts_with("aether_dbt_"),
            "dbt symbol must start with 'aether_dbt_': {sym}"
        );
    }
}

// ── Symbol audit helpers ──────────────────────────────────────────────────────

#[test]
fn at24_check_fex_absent_clean_input() {
    let nm_output = "0000 T aether_dbt_init\n0000 T aether_dbt_shutdown\n";
    let found = check_fex_symbols_absent(nm_output);
    assert!(found.is_empty(), "no fex_ symbols expected in clean output");
}

#[test]
fn at24_check_fex_absent_detects_fex_init() {
    let nm_output = "0000 T fex_init\n0000 T fex_shutdown\n";
    let found = check_fex_symbols_absent(nm_output);
    assert!(found.contains(&"fex_init"));
    assert!(found.contains(&"fex_shutdown"));
}

#[test]
fn at24_check_dbt_present_all_present() {
    let nm_output = DBT_REQUIRED_SYMBOLS.join("\n");
    let missing = check_dbt_symbols_present(&nm_output);
    assert!(missing.is_empty(), "all dbt symbols should be found");
}

#[test]
fn at24_check_dbt_present_detects_missing() {
    // Only include 4 of the 5 required symbols
    let nm_output =
        "aether_dbt_init\naether_dbt_load_arm64_elf\naether_dbt_translate_block\naether_dbt_dispatch_block";
    let missing = check_dbt_symbols_present(nm_output);
    assert!(missing.contains(&"aether_dbt_shutdown"));
}

// ── Stub FFI functions ────────────────────────────────────────────────────────

#[test]
fn at24_stub_init_returns_ok() {
    let r = aether_dbt_init(0x2_0000_0000, 16 << 20, 0x2_0100_0000, 1 << 20);
    // Step A: init is idempotent. Either Ok (this is the first call this
    // test process saw) or AlreadyInitialised (another test file's
    // ensure_init() landed first under cargo's parallel test runner) is
    // an acceptable outcome — both prove init wired through cleanly.
    assert!(
        r == AetherDbtResult::Ok || r == AetherDbtResult::AlreadyInitialised,
        "init must return Ok or AlreadyInitialised, got {:?}",
        r
    );
}

#[test]
fn at24_stub_load_elf_valid_descriptor() {
    let desc = ArmElfDescriptor {
        guest_pa: 0x4000_0000,
        size: 1024,
        entry_point: 0x4000_0100,
    };
    assert_eq!(aether_dbt_load_arm64_elf(&desc), AetherDbtResult::Ok);
}

#[test]
fn at24_stub_load_elf_rejects_zero_pa() {
    let desc = ArmElfDescriptor {
        guest_pa: 0,
        size: 1024,
        entry_point: 0,
    };
    assert_eq!(
        aether_dbt_load_arm64_elf(&desc),
        AetherDbtResult::InvalidElf
    );
}

#[test]
fn at24_stub_load_elf_rejects_zero_size() {
    let desc = ArmElfDescriptor {
        guest_pa: 0x4000_0000,
        size: 0,
        entry_point: 0x4000_0000,
    };
    assert_eq!(
        aether_dbt_load_arm64_elf(&desc),
        AetherDbtResult::InvalidElf
    );
}

// NOTE: AT-24 originally asserted these returned `Ok` for arbitrary input
// because they were stubs (Step 0 of the integration plan). Step A landed
// the real pipeline — decode + lift + lower against the supplied bytes —
// so a deterministic Ok requires a valid ARM64 encoding. We feed a single
// RET instruction (0xD65F_03C0, x30) and explicitly initialise the runtime
// first so the test does not race on the global lazy-init from other
// integration test files (e.g. at_step_a_pipeline.rs).
const VALID_RET_LE: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6];

fn at24_ensure_init() {
    let _ = aether_dbt_init(0x2_0000_0000, 16 * 1024 * 1024, 0x2_0100_0000, 1 << 20);
}

#[test]
fn at24_translate_block_returns_ok_on_valid_arm64() {
    at24_ensure_init();
    let r = aether_dbt_translate_block(0x4000_0000, &VALID_RET_LE);
    assert_eq!(r, AetherDbtResult::Ok);
}

#[test]
fn at24_dispatch_block_returns_ok_on_cached() {
    at24_ensure_init();
    // Translate first to populate the cache, then dispatch.
    assert_eq!(
        aether_dbt_translate_block(0x4000_1000, &VALID_RET_LE),
        AetherDbtResult::Ok
    );
    assert_eq!(
        aether_dbt_dispatch_block(0x4000_1000, &VALID_RET_LE),
        AetherDbtResult::Ok
    );
}

#[test]
fn at24_translate_block_fails_on_unknown_encoding() {
    at24_ensure_init();
    // Word 0x0200_0000 decodes to op0 = 0b0001 (currently Unallocated /
    // DecodeErr::Reserved per top_level::dispatch). Translator must report
    // TranslationFailed rather than silently emit garbage x86.
    let bad: [u8; 4] = 0x0200_0000u32.to_le_bytes();
    let r = aether_dbt_translate_block(0x4000_2000, &bad);
    assert_eq!(r, AetherDbtResult::TranslationFailed);
}

#[test]
fn at24_stub_shutdown_returns_ok() {
    assert_eq!(aether_dbt_shutdown(), AetherDbtResult::Ok);
}

// ── DbtIntegrationConfig ──────────────────────────────────────────────────────

#[test]
fn at24_config_aether_defaults_valid() {
    let cfg = DbtIntegrationConfig::aether_defaults();
    assert!(cfg.validate().is_ok());
}

#[test]
fn at24_config_jit_cache_too_small_invalid() {
    let mut cfg = DbtIntegrationConfig::aether_defaults();
    cfg.jit_cache_size = 1024; // < 16 MiB
    assert_eq!(cfg.validate(), Err(DbtError::JitCacheTooSmall));
}

#[test]
fn at24_config_bump_arena_too_small_invalid() {
    let mut cfg = DbtIntegrationConfig::aether_defaults();
    cfg.bump_arena_size = 512; // < 1 MiB
    assert_eq!(cfg.validate(), Err(DbtError::BumpArenaTooSmall));
}

#[test]
fn at24_config_unaligned_jit_cache_invalid() {
    let mut cfg = DbtIntegrationConfig::aether_defaults();
    cfg.jit_cache_pa = 0x2_0000_0001; // not page-aligned
    assert_eq!(cfg.validate(), Err(DbtError::UnalignedJitCache));
}

#[test]
fn at24_config_overlapping_regions_invalid() {
    let mut cfg = DbtIntegrationConfig::aether_defaults();
    // Place bump arena inside JIT cache region
    cfg.bump_arena_pa = cfg.jit_cache_pa + 0x1000;
    cfg.bump_arena_size = 1024 * 1024;
    assert_eq!(cfg.validate(), Err(DbtError::JitBumpOverlap));
}

// ── DbtState / pipeline ───────────────────────────────────────────────────────

#[test]
fn at24_init_pipeline_phase_advances() {
    let cfg = DbtIntegrationConfig::aether_defaults();
    let state = init_dbt_integration(cfg).unwrap();
    assert!(state.phase >= DbtPhase::JitCacheReady);
    assert!(state.gate().dbt_linked);
    assert!(state.gate().allocator_bound);
    assert!(state.gate().jit_cache_ready);
}

#[test]
fn at24_gate_passes_after_elf_and_audit() {
    let cfg = DbtIntegrationConfig::aether_defaults();
    let mut state = init_dbt_integration(cfg).unwrap();

    let desc = ArmElfDescriptor {
        guest_pa: 0x4000_0000,
        size: 4096,
        entry_point: 0x4000_0000,
    };
    state.process_elf_load(&desc);

    // Audit an nm output with no fex_ symbols
    let nm = "0000 T aether_dbt_init\n0000 T aether_dbt_shutdown\n";
    state.audit_symbols(nm).unwrap();

    assert!(state.gate().no_fex_symbols);
    assert!(state.gate().arm64_elf_validated);
    assert!(state.gate().passes());
    assert_eq!(state.phase, DbtPhase::GatePassed);
}

#[test]
fn at24_audit_fails_when_fex_symbol_present() {
    let cfg = DbtIntegrationConfig::aether_defaults();
    let mut state = init_dbt_integration(cfg).unwrap();

    let nm = "0000 T fex_init\n0000 T aether_dbt_init\n";
    let result = state.audit_symbols(nm);
    assert_eq!(result, Err(DbtError::FexSymbolDetected));
}
