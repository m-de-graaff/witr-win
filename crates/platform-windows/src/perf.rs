//! Performance metrics collection for processes
//!
//! Collects CPU usage, I/O statistics, and other performance metrics
//! using Windows Performance APIs.

use crate::error::{WinError, WinResult};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// RAII wrapper for handles
struct SafeHandle(HANDLE);

impl SafeHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// I/O counters for a process
#[derive(Debug, Clone, Default)]
pub struct IoCounters {
    /// Number of read operations
    pub read_operations: u64,
    /// Number of write operations
    pub write_operations: u64,
    /// Number of other operations (non-read/write)
    pub other_operations: u64,
    /// Bytes read
    pub read_bytes: u64,
    /// Bytes written
    pub write_bytes: u64,
    /// Bytes transferred in other operations
    pub other_bytes: u64,
}

/// CPU time information for a process
#[derive(Debug, Clone, Default)]
pub struct CpuTimes {
    /// Total kernel mode time in 100-nanosecond intervals
    pub kernel_time: u64,
    /// Total user mode time in 100-nanosecond intervals
    pub user_time: u64,
    /// Total CPU time (kernel + user) in 100-nanosecond intervals
    pub total_time: u64,
    /// Process creation time as FILETIME
    pub creation_time: u64,
}

impl CpuTimes {
    /// Get kernel time in seconds
    pub fn kernel_seconds(&self) -> f64 {
        self.kernel_time as f64 / 10_000_000.0
    }

    /// Get user time in seconds
    pub fn user_seconds(&self) -> f64 {
        self.user_time as f64 / 10_000_000.0
    }

    /// Get total CPU time in seconds
    pub fn total_seconds(&self) -> f64 {
        self.total_time as f64 / 10_000_000.0
    }
}

/// Complete performance metrics for a process
#[derive(Debug, Clone, Default)]
pub struct ProcessPerformance {
    /// CPU time information
    pub cpu: CpuTimes,
    /// I/O counters
    pub io: IoCounters,
    /// CPU usage percentage (if calculated)
    pub cpu_percent: Option<f64>,
}

// FFI for NtQueryInformationProcess to get I/O counters
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut std::ffi::c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

const PROCESS_IO_COUNTERS_CLASS: u32 = 2;

/// IO_COUNTERS structure from Windows
#[repr(C)]
struct IoCountersRaw {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

/// Get CPU times for a process
pub fn get_cpu_times(pid: u32) -> WinResult<CpuTimes> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
            } else if e.code().0 as u32 == 0x80070057 {
                WinError::ProcessNotFound { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _handle = SafeHandle::new(handle);

        let mut creation_time = Default::default();
        let mut exit_time = Default::default();
        let mut kernel_time = Default::default();
        let mut user_time = Default::default();

        GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .map_err(|e| WinError::ApiError {
            api: "GetProcessTimes",
            message: e.message().to_string(),
        })?;

        let kernel = (kernel_time.dwHighDateTime as u64) << 32 | kernel_time.dwLowDateTime as u64;
        let user = (user_time.dwHighDateTime as u64) << 32 | user_time.dwLowDateTime as u64;
        let creation =
            (creation_time.dwHighDateTime as u64) << 32 | creation_time.dwLowDateTime as u64;

        Ok(CpuTimes {
            kernel_time: kernel,
            user_time: user,
            total_time: kernel + user,
            creation_time: creation,
        })
    }
}

/// Get I/O counters for a process
pub fn get_io_counters(pid: u32) -> WinResult<IoCounters> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
            } else if e.code().0 as u32 == 0x80070057 {
                WinError::ProcessNotFound { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _handle = SafeHandle::new(handle);

        let mut io_counters: IoCountersRaw = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            PROCESS_IO_COUNTERS_CLASS,
            &mut io_counters as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<IoCountersRaw>() as u32,
            &mut return_length,
        );

        if status != 0 {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: format!("NTSTATUS: 0x{:08X}", status as u32),
            });
        }

        Ok(IoCounters {
            read_operations: io_counters.read_operation_count,
            write_operations: io_counters.write_operation_count,
            other_operations: io_counters.other_operation_count,
            read_bytes: io_counters.read_transfer_count,
            write_bytes: io_counters.write_transfer_count,
            other_bytes: io_counters.other_transfer_count,
        })
    }
}

/// Get complete performance metrics for a process
pub fn get_process_performance(pid: u32) -> WinResult<ProcessPerformance> {
    let cpu = get_cpu_times(pid)?;
    let io = get_io_counters(pid).unwrap_or_default();

    Ok(ProcessPerformance {
        cpu,
        io,
        cpu_percent: None, // Would need two samples to calculate
    })
}

/// Format bytes in human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a duration in seconds to human-readable format
pub fn format_duration(seconds: f64) -> String {
    if seconds < 0.001 {
        format!("{:.2} µs", seconds * 1_000_000.0)
    } else if seconds < 1.0 {
        format!("{:.2} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.2} s", seconds)
    } else if seconds < 3600.0 {
        let mins = seconds / 60.0;
        format!("{:.1} min", mins)
    } else if seconds < 86400.0 {
        let hours = seconds / 3600.0;
        format!("{:.1} hr", hours)
    } else {
        let days = seconds / 86400.0;
        format!("{:.1} days", days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cpu_times_current_process() {
        let pid = std::process::id();
        let result = get_cpu_times(pid);

        assert!(result.is_ok(), "Should get CPU times for current process");
        let times = result.unwrap();
        assert!(times.total_time > 0, "Should have used some CPU time");
    }

    #[test]
    fn test_get_io_counters_current_process() {
        let pid = std::process::id();
        let result = get_io_counters(pid);

        assert!(
            result.is_ok(),
            "Should get I/O counters for current process"
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.40 GB");
    }

    #[test]
    fn test_format_duration() {
        assert!(format_duration(0.0001).contains("µs"));
        assert!(format_duration(0.5).contains("ms"));
        assert!(format_duration(30.0).contains("s"));
        assert!(format_duration(120.0).contains("min"));
        assert!(format_duration(7200.0).contains("hr"));
        assert!(format_duration(172800.0).contains("days"));
    }
}
