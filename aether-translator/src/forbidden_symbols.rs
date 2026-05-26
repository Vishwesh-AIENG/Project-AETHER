//! AT-25: UEFI Link & Forbidden-Symbol Gate.
//!
//! The AETHER DBT static archive must contain zero libc / pthread / file-I/O
//! symbols.  All allocation goes through the bump arena; synchronisation uses
//! the FexSpinLock / DbtSpinLock; NVMe-backed spill replaces `fopen`.
//!
//! Gate: `llvm-nm libaether_dbt.a` output contains none of the symbols listed
//! in `LIBC_FORBIDDEN_SYMBOLS` (the same set that ch52 applied to FEX-Emu).

/// The set of libc / pthread / file-I/O symbols that must never appear in
/// `libaether_dbt.a` or `hypervisor.efi` (from ch52 `LIBC_FORBIDDEN_SYMBOLS`).
pub const LIBC_FORBIDDEN_SYMBOLS: &[&str] = &[
    "malloc",
    "calloc",
    "realloc",
    "free",
    "pthread_create",
    "pthread_join",
    "pthread_mutex_init",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
    "pthread_mutex_destroy",
    "pthread_cond_init",
    "pthread_cond_wait",
    "pthread_cond_signal",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "printf",
    "open",
    "close",
    "read",
    "write",
    "mmap",
    "munmap",
    "mprotect",
    "exit",
    "abort",
    "__libc_start_main",
];

// ── Checker ───────────────────────────────────────────────────────────────────

/// Check the output of `llvm-nm` or `nm` for forbidden symbols.
///
/// Returns the subset of `LIBC_FORBIDDEN_SYMBOLS` found in `nm_output`.
/// An empty result means the archive is clean.
pub fn check_forbidden_symbols(nm_output: &str) -> alloc::vec::Vec<&'static str> {
    LIBC_FORBIDDEN_SYMBOLS
        .iter()
        .copied()
        .filter(|&sym| {
            // Match whole-word occurrences to avoid false positives
            // (e.g. "malloc_trim" must not trigger "malloc").
            nm_output
                .split_ascii_whitespace()
                .any(|token| token == sym || token.ends_with(&alloc::format!(" {sym}")))
                || nm_output.lines().any(|line| {
                    // nm output has the form:  "  offset  T  symbol_name"
                    // We check the last whitespace-delimited token on each line.
                    line.split_whitespace().last() == Some(sym)
                })
        })
        .collect()
}

/// Check that `nm_output` is completely free of forbidden symbols.
pub fn gate_passes_clean_archive(nm_output: &str) -> bool {
    check_forbidden_symbols(nm_output).is_empty()
}

// ── Gate type ─────────────────────────────────────────────────────────────────

/// Gate conditions for AT-25.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForbiddenSymbolGate {
    /// The `nm` audit ran and returned zero violations.
    pub archive_clean: bool,
    /// The NVMe spill path is present (no `fopen` / `fwrite`).
    pub nvme_spill_present: bool,
    /// The bump allocator is present (no `malloc` / `free`).
    pub bump_allocator_present: bool,
    /// The spin lock is present (no `pthread_mutex_*`).
    pub spinlock_present: bool,
}

impl ForbiddenSymbolGate {
    /// Populate all gate fields by running the symbol audit against `nm_output`.
    pub fn audit(&mut self, nm_output: &str) {
        let violations = check_forbidden_symbols(nm_output);
        self.archive_clean = violations.is_empty();

        self.nvme_spill_present = !nm_output.contains("fopen") && !nm_output.contains("fwrite");
        self.bump_allocator_present = !nm_output.contains("malloc") && !nm_output.contains("free");
        self.spinlock_present = !nm_output.contains("pthread_mutex");
    }

    pub fn passes(&self) -> bool {
        self.archive_clean
            && self.nvme_spill_present
            && self.bump_allocator_present
            && self.spinlock_present
    }
}

/// Error variants for the forbidden-symbol gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbiddenSymbolError {
    /// One or more forbidden symbols were found.
    ForbiddenSymbolFound,
    /// No `nm` output was provided (empty string).
    EmptyNmOutput,
}

/// Run the complete AT-25 gate.
pub fn run_forbidden_symbol_gate(nm_output: &str) -> Result<ForbiddenSymbolGate, ForbiddenSymbolError> {
    if nm_output.is_empty() {
        return Err(ForbiddenSymbolError::EmptyNmOutput);
    }
    let mut gate = ForbiddenSymbolGate::default();
    gate.audit(nm_output);
    if !gate.archive_clean {
        return Err(ForbiddenSymbolError::ForbiddenSymbolFound);
    }
    Ok(gate)
}
