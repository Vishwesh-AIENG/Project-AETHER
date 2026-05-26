//! AT-25: UEFI Link & Forbidden-Symbol Gate — test suite.

use aether_translator::forbidden_symbols::{
    check_forbidden_symbols, gate_passes_clean_archive, run_forbidden_symbol_gate,
    ForbiddenSymbolError, ForbiddenSymbolGate, LIBC_FORBIDDEN_SYMBOLS,
};

// ── Symbol list ───────────────────────────────────────────────────────────────

#[test]
fn at25_forbidden_list_nonempty() {
    assert!(!LIBC_FORBIDDEN_SYMBOLS.is_empty());
}

#[test]
fn at25_forbidden_list_contains_malloc() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"malloc"));
}

#[test]
fn at25_forbidden_list_contains_pthread_create() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"pthread_create"));
}

#[test]
fn at25_forbidden_list_contains_fopen() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"fopen"));
}

#[test]
fn at25_forbidden_list_contains_mmap() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"mmap"));
}

#[test]
fn at25_forbidden_list_contains_exit() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"exit"));
}

#[test]
fn at25_forbidden_list_contains_libc_start_main() {
    assert!(LIBC_FORBIDDEN_SYMBOLS.contains(&"__libc_start_main"));
}

#[test]
fn at25_forbidden_list_size_matches_ch52() {
    // ch52 specifies 28 entries (malloc/calloc/realloc/free + 9 pthread +
    // fopen/fclose/fread/fwrite/printf + open/close/read/write +
    // mmap/munmap/mprotect + exit/abort + __libc_start_main)
    assert_eq!(LIBC_FORBIDDEN_SYMBOLS.len(), 28);
}

// ── check_forbidden_symbols ───────────────────────────────────────────────────

#[test]
fn at25_clean_nm_output_no_violations() {
    let nm = "\
0000000000000000 T aether_dbt_init
0000000000000040 T aether_dbt_shutdown
0000000000000080 T aether_dbt_translate_block
";
    let found = check_forbidden_symbols(nm);
    assert!(
        found.is_empty(),
        "clean nm output must have zero violations; found: {found:?}"
    );
}

#[test]
fn at25_nm_with_malloc_detected() {
    let nm = "0000 U malloc\n0000 T aether_dbt_init\n";
    let found = check_forbidden_symbols(nm);
    assert!(found.contains(&"malloc"), "malloc must be detected");
}

#[test]
fn at25_nm_with_pthread_create_detected() {
    let nm = "0000 U pthread_create\n";
    let found = check_forbidden_symbols(nm);
    assert!(found.contains(&"pthread_create"));
}

#[test]
fn at25_nm_with_fopen_detected() {
    let nm = "0000 U fopen\n";
    let found = check_forbidden_symbols(nm);
    assert!(found.contains(&"fopen"));
}

#[test]
fn at25_nm_with_multiple_violations_detected() {
    let nm = "0000 U malloc\n0000 U fopen\n0000 U pthread_mutex_lock\n";
    let found = check_forbidden_symbols(nm);
    assert!(found.contains(&"malloc"));
    assert!(found.contains(&"fopen"));
    assert!(found.contains(&"pthread_mutex_lock"));
}

#[test]
fn at25_gate_passes_clean_archive() {
    let nm = "0000 T aether_dbt_init\n0000 T aether_bump_alloc\n";
    assert!(gate_passes_clean_archive(nm));
}

#[test]
fn at25_gate_fails_dirty_archive() {
    let nm = "0000 T aether_dbt_init\n0000 U malloc\n";
    assert!(!gate_passes_clean_archive(nm));
}

// ── ForbiddenSymbolGate ───────────────────────────────────────────────────────

#[test]
fn at25_gate_struct_passes_on_clean_output() {
    let nm = "0000 T aether_dbt_init\n0000 T aether_spinlock_lock\n";
    let mut gate = ForbiddenSymbolGate::default();
    gate.audit(nm);
    assert!(gate.archive_clean);
    assert!(gate.nvme_spill_present);
    assert!(gate.bump_allocator_present);
    assert!(gate.spinlock_present);
    assert!(gate.passes());
}

#[test]
fn at25_gate_struct_fails_on_malloc() {
    let nm = "0000 T aether_dbt_init\n0000 U malloc\n";
    let mut gate = ForbiddenSymbolGate::default();
    gate.audit(nm);
    assert!(!gate.archive_clean);
    assert!(!gate.bump_allocator_present);
    assert!(!gate.passes());
}

// ── run_forbidden_symbol_gate ─────────────────────────────────────────────────

#[test]
fn at25_run_gate_clean_succeeds() {
    let nm = "0000 T aether_dbt_init\n0000 T aether_nvme_spill\n";
    let result = run_forbidden_symbol_gate(nm);
    assert!(result.is_ok());
    assert!(result.unwrap().passes());
}

#[test]
fn at25_run_gate_dirty_fails() {
    let nm = "0000 U free\n0000 T aether_dbt_init\n";
    let result = run_forbidden_symbol_gate(nm);
    assert_eq!(result, Err(ForbiddenSymbolError::ForbiddenSymbolFound));
}

#[test]
fn at25_run_gate_empty_input_fails() {
    let result = run_forbidden_symbol_gate("");
    assert_eq!(result, Err(ForbiddenSymbolError::EmptyNmOutput));
}

// ── No-false-positive check ───────────────────────────────────────────────────

#[test]
fn at25_no_false_positive_on_malloc_trim() {
    // "malloc_trim" contains "malloc" as a prefix but is not the forbidden symbol.
    // Our checker matches whole tokens only, so this must not trigger.
    let nm = "0000 T malloc_trim\n";
    let found = check_forbidden_symbols(nm);
    assert!(
        !found.contains(&"malloc"),
        "malloc_trim must not trigger the 'malloc' violation"
    );
}

#[test]
fn at25_no_false_positive_on_aether_write() {
    // "aether_write" contains "write" as a suffix — must not match bare "write".
    let nm = "0000 T aether_write\n";
    let found = check_forbidden_symbols(nm);
    assert!(
        !found.contains(&"write"),
        "aether_write must not trigger the 'write' violation"
    );
}
