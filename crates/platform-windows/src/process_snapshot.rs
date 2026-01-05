//! Process snapshot using CreateToolhelp32Snapshot
//!
//! Provides a point-in-time snapshot of all processes with their PIDs and PPIDs,
//! as well as module/DLL enumeration for processes.

use crate::error::{WinError, WinResult};
use std::collections::HashMap;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};

/// A process entry from the snapshot
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Executable name (not full path)
    pub exe_name: String,
    /// Number of threads
    pub thread_count: u32,
}

/// RAII wrapper for snapshot handle
struct SnapshotHandle(HANDLE);

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Create a snapshot of all running processes
///
/// Returns a HashMap mapping PID -> ProcessEntry for efficient lookup.
pub fn list_processes() -> WinResult<HashMap<u32, ProcessEntry>> {
    let mut processes = HashMap::new();

    unsafe {
        // Create snapshot of all processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| WinError::SnapshotFailed(e.message().to_string()))?;

        let _handle = SnapshotHandle(snapshot);

        // Initialize the process entry structure
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // Get first process
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = wchar_to_string(&entry.szExeFile);

                processes.insert(
                    entry.th32ProcessID,
                    ProcessEntry {
                        pid: entry.th32ProcessID,
                        ppid: entry.th32ParentProcessID,
                        exe_name,
                        thread_count: entry.cntThreads,
                    },
                );

                // Get next process
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Ok(processes)
}

/// Get a single process entry by PID
pub fn get_process_entry(pid: u32) -> WinResult<ProcessEntry> {
    let processes = list_processes()?;
    processes
        .get(&pid)
        .cloned()
        .ok_or(WinError::ProcessNotFound { pid })
}

/// Convert a null-terminated wide char array to String
fn wchar_to_string(wchars: &[u16]) -> String {
    let len = wchars.iter().position(|&c| c == 0).unwrap_or(wchars.len());
    String::from_utf16_lossy(&wchars[..len])
}

/// Information about a loaded module/DLL
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// Module name (filename only)
    pub name: String,
    /// Full path to the module
    pub path: String,
    /// Base address where module is loaded
    pub base_address: usize,
    /// Size of the module in bytes
    pub size: u32,
}

/// List all modules (DLLs) loaded by a process
///
/// Returns a vector of ModuleEntry for each loaded module.
pub fn list_modules(pid: u32) -> WinResult<Vec<ModuleEntry>> {
    let mut modules = Vec::new();

    unsafe {
        // Use TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 to get both 32-bit and 64-bit modules
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            .map_err(|e| {
                if e.code().0 as u32 == 0x80070005 {
                    WinError::AccessDenied { pid }
                } else {
                    WinError::SnapshotFailed(e.message().to_string())
                }
            })?;

        let _handle = SnapshotHandle(snapshot);

        // Initialize the module entry structure
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        // Get first module
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = wchar_to_string(&entry.szModule);
                let path = wchar_to_string(&entry.szExePath);

                modules.push(ModuleEntry {
                    name,
                    path,
                    base_address: entry.modBaseAddr as usize,
                    size: entry.modBaseSize,
                });

                // Get next module
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Ok(modules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let processes = list_processes().expect("Failed to list processes");

        // Should have at least a few processes
        assert!(!processes.is_empty(), "Process list should not be empty");

        // PID 0 (System Idle Process) or PID 4 (System) should exist
        assert!(
            processes.contains_key(&0) || processes.contains_key(&4),
            "Should contain system processes"
        );

        // Current process should be in the list
        let current_pid = std::process::id();
        assert!(
            processes.contains_key(&current_pid),
            "Current process should be in list"
        );
    }

    #[test]
    fn test_get_process_entry() {
        let current_pid = std::process::id();
        let entry = get_process_entry(current_pid).expect("Should find current process");

        assert_eq!(entry.pid, current_pid);
        assert!(!entry.exe_name.is_empty());
    }

    #[test]
    fn test_process_not_found() {
        // Use an unlikely PID
        let result = get_process_entry(u32::MAX - 1);
        assert!(matches!(result, Err(WinError::ProcessNotFound { .. })));
    }
}
