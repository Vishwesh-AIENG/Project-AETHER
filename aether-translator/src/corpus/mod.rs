//! AT-5 audit driver — bulk decode an executable section.
//!
//! Walks `.text` 4 bytes at a time, decodes each word, lifts to IR, and
//! reports counts. Any non-zero `unknown` or `unimplemented` count fails the
//! AT-5 gate.
//!
//! This module is only built when `std` is enabled — it uses `std::path` and
//! `std::fs` for corpus IO.

use std::path::{Path, PathBuf};

use crate::decoder::{decode_instruction, DecodedInsn};
use crate::ir::IrBlock;
use crate::lift::{lift, LiftErr};

#[derive(Debug, Default)]
pub struct CoverageReport {
    pub path: PathBuf,
    pub lifted: u64,
    pub decoded_but_unlifted: u64,
    pub unknown: Vec<(usize, u32)>,
    pub unimplemented: Vec<(usize, u32)>,
    pub decode_errors: u64,
    pub total_words: u64,
}

impl CoverageReport {
    pub fn passes_at5(&self) -> bool {
        self.unknown.is_empty()
            && self.unimplemented.is_empty()
            && self.decoded_but_unlifted == 0
            && self.decode_errors == 0
    }
}

/// Scan a `.text` slice (already extracted from an ELF). The `offset_base`
/// is the start address of the section in its source file, used purely for
/// error reporting.
pub fn audit_text(text: &[u8], offset_base: usize, path: &Path) -> CoverageReport {
    let mut report = CoverageReport {
        path: path.to_path_buf(),
        ..Default::default()
    };
    let mut scratch_block = IrBlock::default();

    for (i, chunk) in text.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        report.total_words += 1;
        let off = offset_base + i * 4;

        match decode_instruction(word) {
            Ok(DecodedInsn::Unknown(w)) => report.unknown.push((off, w)),
            Ok(insn) => match lift(&insn, &mut scratch_block) {
                Ok(()) => report.lifted += 1,
                Err(LiftErr::Unimplemented(w)) => {
                    if w == 0 {
                        // Phase A: lift doesn't yet carry the raw word for
                        // most variants; treat as "decoded but unlifted" to
                        // distinguish from genuine unknowns.
                        report.decoded_but_unlifted += 1;
                    } else {
                        report.unimplemented.push((off, w));
                    }
                }
            },
            Err(_) => report.decode_errors += 1,
        }
    }
    report
}
