//! witr-platform-windows: Windows platform collectors for witr-win
//!
//! This crate provides Windows-specific data collection for process analysis,
//! including process enumeration, port mapping, service detection, and more.

#[cfg(windows)]
pub mod analyzer;
#[cfg(windows)]
pub mod ancestry;
#[cfg(windows)]
pub mod classifier;
#[cfg(windows)]
pub mod error;
#[cfg(windows)]
pub mod handles;
#[cfg(windows)]
pub mod net;
#[cfg(windows)]
pub mod perf;
#[cfg(windows)]
pub mod process_query;
#[cfg(windows)]
pub mod process_snapshot;
#[cfg(windows)]
pub mod security;
#[cfg(windows)]
pub mod services;

#[cfg(windows)]
pub use analyzer::*;
#[cfg(windows)]
pub use ancestry::*;
#[cfg(windows)]
pub use classifier::*;
#[cfg(windows)]
pub use error::*;
#[cfg(windows)]
pub use handles::*;
#[cfg(windows)]
pub use net::*;
#[cfg(windows)]
pub use perf::*;
#[cfg(windows)]
pub use process_query::*;
#[cfg(windows)]
pub use process_snapshot::*;
#[cfg(windows)]
pub use security::*;
#[cfg(windows)]
pub use services::*;

// Stub for non-Windows platforms (for cross-compilation/testing)
#[cfg(not(windows))]
pub fn list_processes() -> std::collections::HashMap<u32, ()> {
    std::collections::HashMap::new()
}
