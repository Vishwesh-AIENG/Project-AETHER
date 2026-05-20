// memory.rs -- RAM capacity check.
//
// Minimum: 8 GiB total physical RAM.
// Uses sysinfo (no admin required on any supported OS).

use serde::Serialize;
use sysinfo::System;

pub const MINIMUM_GIB: u64 = 8;

#[derive(Debug, Clone, Serialize)]
pub struct MemoryResult {
    pub total_bytes:  u64,
    pub total_gib:    u64,
    pub minimum_gib:  u64,
    pub pass:         bool,
    pub note:         Option<String>,
}

pub fn check() -> MemoryResult {
    let mut sys = System::new();
    sys.refresh_memory();

    let total_bytes = sys.total_memory(); // sysinfo returns bytes in v0.30
    let total_gib   = total_bytes / (1024 * 1024 * 1024);
    let pass        = total_gib >= MINIMUM_GIB;

    let note = if pass {
        None
    } else {
        Some(format!(
            "Only {} GiB RAM detected. AETHER requires at least {} GiB.",
            total_gib, MINIMUM_GIB
        ))
    };

    MemoryResult {
        total_bytes,
        total_gib,
        minimum_gib: MINIMUM_GIB,
        pass,
        note,
    }
}
