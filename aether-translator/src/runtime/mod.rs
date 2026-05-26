//! Phase D — Dispatcher & Runtime (AT-16 … AT-20).
//! Phase E — Integration & AOT (AT-21 … AT-23).
//! Phase F — Validation (AT-26 … AT-30).
//!
//! | Chapter | Module               | Description                                  |
//! |---------|----------------------|----------------------------------------------|
//! | AT-16   | [`block_cache`]      | Two-generation block cache (guest PC → host) |
//! | AT-17   | [`dispatcher`]       | Hot/cold dispatch loop + RDTSC latency gate  |
//! | AT-18   | [`branch_chain`]     | Indirect-branch inline-cache chaining        |
//! | AT-19   | [`context`]          | Guest register-file save / restore           |
//! | AT-20   | [`exception_forward`]| x86 trap → ARM exception class forwarding    |
//! | AT-21   | [`aot`]              | AOT pre-translation of 21 default libraries  |
//! | AT-22   | [`cache_persist`]    | JIT cache persistence via NVMe spill/restore |
//! | AT-23   | [`smc_handler`]      | Self-modifying code W^X + write-fault handler|
//! | AT-26   | [`hello_world`]      | Static ARM64 hello-world under translator    |
//! | AT-27   | [`bionic_libart`]    | Bionic + libart bring-up; dalvikvm .dex run  |
//! | AT-28   | [`zygote_launch`]    | Zygote fork + SystemServer + boot_completed  |
//! | AT-29   | [`app_compat_x86`]   | x86-tier app-compat harness (≥950/1000)      |
//! | AT-30   | [`perf_bench`]       | Performance: int ≥70 %, SIMD ≥80 %, JS ≥60 %|

pub mod aot;
pub mod app_compat_x86;
pub mod bionic_libart;
pub mod block_cache;
pub mod branch_chain;
pub mod cache_persist;
pub mod context;
pub mod dispatcher;
pub mod exception_forward;
pub mod hello_world;
pub mod perf_bench;
pub mod smc_handler;
pub mod zygote_launch;

pub use aot::{AotConfig, AotGate, AotQueue, AotState};
pub use app_compat_x86::{AppCompatX86Config, AppCompatX86Gate, AppCompatX86State};
pub use bionic_libart::{BionicLibartConfig, BionicLibartGate, BionicLibartState};
pub use block_cache::BlockCache;
pub use branch_chain::BranchChainTable;
pub use cache_persist::{CachePersistConfig, CachePersistGate, CachePersistState};
pub use context::GuestRegisterFile;
pub use dispatcher::{DispatchOutcome, Dispatcher};
pub use exception_forward::{ArmEc, ArmFaultInfo, X86Fault};
pub use hello_world::{HelloWorldConfig, HelloWorldGate, HelloWorldState};
pub use perf_bench::{PerfBenchConfig, PerfBenchGate, PerfBenchState};
pub use smc_handler::{SmcConfig, SmcGate, SmcState, SmcWatcher};
pub use zygote_launch::{ZygoteLaunchConfig, ZygoteLaunchGate, ZygoteLaunchState};

/// Phase D version pin.
pub const PHASE_D_VERSION: u32 = 0x0000_0004;
/// Phase E version pin.
pub const PHASE_E_VERSION: u32 = 0x0000_0005;
/// Phase F version pin. Bumped on validation-layer ABI changes.
pub const PHASE_F_VERSION: u32 = 0x0000_0006;
