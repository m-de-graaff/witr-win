//! Error types for Windows platform operations

use thiserror::Error;

/// Errors that can occur during Windows API calls
#[derive(Debug, Error)]
pub enum WinError {
    /// Process not found
    #[error("Process {pid} not found")]
    ProcessNotFound { pid: u32 },

    /// Access denied to process
    #[error("Access denied to process {pid}")]
    AccessDenied { pid: u32 },

    /// Windows API call failed
    #[error("Windows API {api} failed: {message}")]
    ApiError { api: &'static str, message: String },

    /// Failed to create process snapshot
    #[error("Failed to create process snapshot: {0}")]
    SnapshotFailed(String),

    /// Invalid handle
    #[error("Invalid handle for {context}")]
    InvalidHandle { context: &'static str },

    /// String conversion error
    #[error("String conversion error: {0}")]
    StringConversion(String),
}

impl WinError {
    /// Create an API error from a Windows error
    #[cfg(windows)]
    pub fn from_win32(api: &'static str) -> Self {
        let err = windows::core::Error::from_win32();
        WinError::ApiError {
            api,
            message: err.message().to_string(),
        }
    }

    /// Check if this is an access denied error
    pub fn is_access_denied(&self) -> bool {
        matches!(self, WinError::AccessDenied { .. })
    }
}

/// Result type for Windows operations
pub type WinResult<T> = Result<T, WinError>;
