//! Process query functions for detailed process information
//!
//! These functions open individual processes to query detailed information
//! like full image path, start time, and owning user.

use crate::error::{WinError, WinResult};
use std::path::PathBuf;
use time::OffsetDateTime;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupAccountSidW, LookupPrivilegeValueW,
    TokenUser, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
};

// FFI for NtQueryInformationProcess (not exposed in windows crate)
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut std::ffi::c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

/// Process Basic Information structure returned by NtQueryInformationProcess
#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut std::ffi::c_void,
    peb_base_address: *mut std::ffi::c_void,
    reserved2: [*mut std::ffi::c_void; 2],
    unique_process_id: usize,
    reserved3: *mut std::ffi::c_void,
}

/// UNICODE_STRING structure used in PEB
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// CURDIR structure containing the working directory path
#[repr(C)]
struct CurDir {
    dos_path: UnicodeString,
    handle: HANDLE,
}

/// RAII wrapper for process/token handles
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

/// Query the full image path of a process
pub fn get_image_path(pid: u32) -> WinResult<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                // ERROR_ACCESS_DENIED
                WinError::AccessDenied { pid }
            } else if e.code().0 as u32 == 0x80070057 {
                // ERROR_INVALID_PARAMETER (process doesn't exist)
                WinError::ProcessNotFound { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _handle = SafeHandle::new(handle);

        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;

        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .map_err(|e| WinError::ApiError {
            api: "QueryFullProcessImageNameW",
            message: e.message().to_string(),
        })?;

        let path_str = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(PathBuf::from(path_str))
    }
}

/// Query the start time of a process
pub fn get_start_time(pid: u32) -> WinResult<OffsetDateTime> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
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

        // FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
        // Convert to Unix timestamp (seconds since 1970-01-01)
        let filetime_ticks =
            (creation_time.dwHighDateTime as u64) << 32 | creation_time.dwLowDateTime as u64;

        // 116444736000000000 = ticks between 1601-01-01 and 1970-01-01
        const EPOCH_DIFF: u64 = 116444736000000000;

        if filetime_ticks < EPOCH_DIFF {
            return Err(WinError::ApiError {
                api: "GetProcessTimes",
                message: "Invalid creation time".to_string(),
            });
        }

        let unix_ticks = filetime_ticks - EPOCH_DIFF;
        let unix_secs = (unix_ticks / 10_000_000) as i64;
        let nanos = ((unix_ticks % 10_000_000) * 100) as i64;

        OffsetDateTime::from_unix_timestamp(unix_secs)
            .map(|dt| dt + time::Duration::nanoseconds(nanos))
            .map_err(|e| WinError::ApiError {
                api: "GetProcessTimes",
                message: format!("Time conversion failed: {}", e),
            })
    }
}

/// Query the user (owner) of a process
pub fn get_user(pid: u32) -> WinResult<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _proc_handle = SafeHandle::new(handle);

        // Open the process token
        let mut token_handle = HANDLE::default();
        OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle).map_err(|e| {
            // Check for access denied (0x80070005 = ERROR_ACCESS_DENIED)
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcessToken",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _token_handle = SafeHandle::new(token_handle);

        // Get token user info size
        let mut token_info_len = 0u32;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut token_info_len);

        if token_info_len == 0 {
            return Err(WinError::ApiError {
                api: "GetTokenInformation",
                message: "Failed to get token info size".to_string(),
            });
        }

        // Allocate buffer and get token user
        let mut token_info: Vec<u8> = vec![0; token_info_len as usize];
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_info.as_mut_ptr() as *mut _),
            token_info_len,
            &mut token_info_len,
        )
        .map_err(|e| WinError::ApiError {
            api: "GetTokenInformation",
            message: e.message().to_string(),
        })?;

        let token_user = &*(token_info.as_ptr() as *const TOKEN_USER);

        // Look up the account name
        let mut name_buf = [0u16; 256];
        let mut domain_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut domain_len = domain_buf.len() as u32;
        let mut sid_type = SID_NAME_USE::default();

        LookupAccountSidW(
            None,
            token_user.User.Sid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut sid_type,
        )
        .map_err(|e| WinError::ApiError {
            api: "LookupAccountSidW",
            message: e.message().to_string(),
        })?;

        let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

        if domain.is_empty() {
            Ok(name)
        } else {
            Ok(format!("{}\\{}", domain, name))
        }
    }
}

/// Try to enable SeDebugPrivilege for the current process
///
/// This allows accessing more process information. Returns Ok(true) if enabled,
/// Ok(false) if we don't have the privilege, or Err on API failure.
pub fn try_enable_debug_privilege() -> WinResult<bool> {
    unsafe {
        let process = GetCurrentProcess();

        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            process,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| WinError::ApiError {
            api: "OpenProcessToken",
            message: e.message().to_string(),
        })?;

        let _token_handle = SafeHandle::new(token_handle);

        let mut luid = LUID::default();
        LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).map_err(|e| WinError::ApiError {
            api: "LookupPrivilegeValueW",
            message: e.message().to_string(),
        })?;

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // This will fail silently if we don't have the privilege
        let result = AdjustTokenPrivileges(token_handle, false, Some(&privileges), 0, None, None);

        // Check if the operation actually succeeded
        if result.is_ok() {
            // Check last error - if it's ERROR_NOT_ALL_ASSIGNED, privilege wasn't granted
            let last_error = windows::core::Error::from_win32();
            if last_error.code().0 as u32 == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }
}

/// Get session ID for a process
pub fn get_session_id(pid: u32) -> WinResult<u32> {
    let mut session_id = 0u32;
    unsafe {
        ProcessIdToSessionId(pid, &mut session_id).map_err(|e: windows::core::Error| {
            WinError::ApiError {
                api: "ProcessIdToSessionId",
                message: e.message().to_string(),
            }
        })?;
    }
    Ok(session_id)
}

/// Terminate a process by PID
///
/// This function opens the process with PROCESS_TERMINATE access and calls
/// TerminateProcess. It requires appropriate privileges to terminate the target
/// process (usually the same user or admin privileges).
///
/// # Arguments
/// * `pid` - The process ID to terminate
/// * `exit_code` - The exit code to set for the terminated process (typically 1)
///
/// # Returns
/// * `Ok(())` if the process was successfully terminated
/// * `Err(WinError::AccessDenied)` if we don't have permission to terminate
/// * `Err(WinError::ProcessNotFound)` if the process doesn't exist
pub fn terminate_process(pid: u32, exit_code: u32) -> WinResult<()> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                // ERROR_ACCESS_DENIED
                WinError::AccessDenied { pid }
            } else if e.code().0 as u32 == 0x80070057 {
                // ERROR_INVALID_PARAMETER (process doesn't exist)
                WinError::ProcessNotFound { pid }
            } else {
                WinError::ApiError {
                    api: "OpenProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        let _handle = SafeHandle::new(handle);

        TerminateProcess(handle, exit_code).map_err(|e| {
            if e.code().0 as u32 == 0x80070005 {
                WinError::AccessDenied { pid }
            } else {
                WinError::ApiError {
                    api: "TerminateProcess",
                    message: e.message().to_string(),
                }
            }
        })?;

        Ok(())
    }
}

/// Get memory usage (working set size) for a process in bytes
pub fn get_memory_usage(pid: u32) -> WinResult<u64> {
    unsafe {
        // GetProcessMemoryInfo requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        // Try with full permissions first, fall back to limited
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
            .map_err(|e| {
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

        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };

        GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .map_err(|e| WinError::ApiError {
            api: "GetProcessMemoryInfo",
            message: e.message().to_string(),
        })?;

        Ok(counters.WorkingSetSize as u64)
    }
}

/// Get the current working directory of a process
///
/// This uses NtQueryInformationProcess to read the PEB and extract the
/// CurrentDirectory from RTL_USER_PROCESS_PARAMETERS.
pub fn get_working_directory(pid: u32) -> WinResult<String> {
    unsafe {
        // Need PROCESS_QUERY_INFORMATION and PROCESS_VM_READ to read process memory
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
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

        // Get the PEB address using NtQueryInformationProcess
        let mut pbi: ProcessBasicInformation = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        );

        if status.0 != 0 {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: format!("NTSTATUS: 0x{:08X}", status.0),
            });
        }

        if pbi.peb_base_address.is_null() {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: "PEB address is null".to_string(),
            });
        }

        // Read the ProcessParameters pointer from the PEB
        // Offset of ProcessParameters in PEB is 0x20 on x64, 0x10 on x86
        #[cfg(target_pointer_width = "64")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x20;
        #[cfg(target_pointer_width = "32")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x10;

        let mut process_parameters_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut bytes_read: usize = 0;

        let peb_addr = pbi.peb_base_address as usize;
        let params_ptr_addr = peb_addr + PROCESS_PARAMETERS_OFFSET;

        ReadProcessMemory(
            handle,
            params_ptr_addr as *const std::ffi::c_void,
            &mut process_parameters_ptr as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<*mut std::ffi::c_void>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (ProcessParameters ptr)",
            message: e.message().to_string(),
        })?;

        if process_parameters_ptr.is_null() {
            return Err(WinError::ApiError {
                api: "ReadProcessMemory",
                message: "ProcessParameters is null".to_string(),
            });
        }

        // Read the CurrentDirectory from RTL_USER_PROCESS_PARAMETERS
        // CurrentDirectory (CURDIR) is at offset 0x38 on x64, 0x24 on x86
        #[cfg(target_pointer_width = "64")]
        const CURRENT_DIRECTORY_OFFSET: usize = 0x38;
        #[cfg(target_pointer_width = "32")]
        const CURRENT_DIRECTORY_OFFSET: usize = 0x24;

        let curdir_addr = process_parameters_ptr as usize + CURRENT_DIRECTORY_OFFSET;
        let mut curdir: CurDir = std::mem::zeroed();

        ReadProcessMemory(
            handle,
            curdir_addr as *const std::ffi::c_void,
            &mut curdir as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<CurDir>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (CurrentDirectory)",
            message: e.message().to_string(),
        })?;

        if curdir.dos_path.buffer.is_null() || curdir.dos_path.length == 0 {
            return Err(WinError::ApiError {
                api: "ReadProcessMemory",
                message: "CurrentDirectory buffer is null or empty".to_string(),
            });
        }

        // Read the actual path string
        let path_len = (curdir.dos_path.length / 2) as usize; // length is in bytes, we need chars
        let mut path_buffer: Vec<u16> = vec![0; path_len];

        ReadProcessMemory(
            handle,
            curdir.dos_path.buffer as *const std::ffi::c_void,
            path_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            curdir.dos_path.length as usize,
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (path string)",
            message: e.message().to_string(),
        })?;

        // Convert to String, removing trailing backslash if present
        let mut path = String::from_utf16_lossy(&path_buffer);
        if path.ends_with('\\') && path.len() > 3 {
            // Don't remove from "C:\"
            path.pop();
        }

        Ok(path)
    }
}

/// Get the command line of a process
///
/// This uses NtQueryInformationProcess to read the PEB and extract the
/// CommandLine from RTL_USER_PROCESS_PARAMETERS.
pub fn get_command_line(pid: u32) -> WinResult<String> {
    unsafe {
        // Need PROCESS_QUERY_INFORMATION and PROCESS_VM_READ to read process memory
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
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

        // Get the PEB address using NtQueryInformationProcess
        let mut pbi: ProcessBasicInformation = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        );

        if status.0 != 0 {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: format!("NTSTATUS: 0x{:08X}", status.0),
            });
        }

        if pbi.peb_base_address.is_null() {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: "PEB address is null".to_string(),
            });
        }

        // Read the ProcessParameters pointer from the PEB
        #[cfg(target_pointer_width = "64")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x20;
        #[cfg(target_pointer_width = "32")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x10;

        let mut process_parameters_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut bytes_read: usize = 0;

        let peb_addr = pbi.peb_base_address as usize;
        let params_ptr_addr = peb_addr + PROCESS_PARAMETERS_OFFSET;

        ReadProcessMemory(
            handle,
            params_ptr_addr as *const std::ffi::c_void,
            &mut process_parameters_ptr as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<*mut std::ffi::c_void>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (ProcessParameters ptr)",
            message: e.message().to_string(),
        })?;

        if process_parameters_ptr.is_null() {
            return Err(WinError::ApiError {
                api: "ReadProcessMemory",
                message: "ProcessParameters is null".to_string(),
            });
        }

        // Read the CommandLine from RTL_USER_PROCESS_PARAMETERS
        // CommandLine (UNICODE_STRING) is at offset 0x70 on x64, 0x40 on x86
        #[cfg(target_pointer_width = "64")]
        const COMMAND_LINE_OFFSET: usize = 0x70;
        #[cfg(target_pointer_width = "32")]
        const COMMAND_LINE_OFFSET: usize = 0x40;

        let cmdline_addr = process_parameters_ptr as usize + COMMAND_LINE_OFFSET;
        let mut cmdline_us: UnicodeString = std::mem::zeroed();

        ReadProcessMemory(
            handle,
            cmdline_addr as *const std::ffi::c_void,
            &mut cmdline_us as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<UnicodeString>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (CommandLine)",
            message: e.message().to_string(),
        })?;

        if cmdline_us.buffer.is_null() || cmdline_us.length == 0 {
            return Err(WinError::ApiError {
                api: "ReadProcessMemory",
                message: "CommandLine buffer is null or empty".to_string(),
            });
        }

        // Read the actual command line string
        let cmdline_len = (cmdline_us.length / 2) as usize; // length is in bytes, we need chars
        let mut cmdline_buffer: Vec<u16> = vec![0; cmdline_len];

        ReadProcessMemory(
            handle,
            cmdline_us.buffer as *const std::ffi::c_void,
            cmdline_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            cmdline_us.length as usize,
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (cmdline string)",
            message: e.message().to_string(),
        })?;

        let cmdline = String::from_utf16_lossy(&cmdline_buffer);
        Ok(cmdline.trim().to_string())
    }
}

/// Truncate a command line for display, keeping it under max_len characters
pub fn truncate_cmdline(cmdline: &str, max_len: usize) -> String {
    if cmdline.len() <= max_len {
        cmdline.to_string()
    } else {
        format!("{}...", &cmdline[..max_len - 3])
    }
}

/// Environment variable info
#[derive(Debug, Clone)]
pub struct EnvVar {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Well-known interesting environment variables to display
const INTERESTING_ENV_VARS: &[&str] = &[
    "PATH",
    "PATHEXT",
    "USERNAME",
    "USERDOMAIN",
    "USERPROFILE",
    "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE",
    "OS",
    "TEMP",
    "TMP",
    "HOME",
    "HOMEPATH",
    "HOMEDRIVE",
    "JAVA_HOME",
    "PYTHON_HOME",
    "NODE_PATH",
    "GOPATH",
    "RUST_BACKTRACE",
    "DEBUG",
    "NODE_ENV",
    "ASPNETCORE_ENVIRONMENT",
    "DOTNET_ENVIRONMENT",
];

/// Get environment variables for a process
///
/// This reads the environment block from the process's PEB.
/// Returns all environment variables, which can be filtered by the caller.
pub fn get_environment_variables(pid: u32) -> WinResult<Vec<EnvVar>> {
    unsafe {
        // Need PROCESS_QUERY_INFORMATION and PROCESS_VM_READ to read process memory
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
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

        // Get the PEB address using NtQueryInformationProcess
        let mut pbi: ProcessBasicInformation = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        );

        if status.0 != 0 {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: format!("NTSTATUS: 0x{:08X}", status.0),
            });
        }

        if pbi.peb_base_address.is_null() {
            return Err(WinError::ApiError {
                api: "NtQueryInformationProcess",
                message: "PEB address is null".to_string(),
            });
        }

        // Read the ProcessParameters pointer from the PEB
        #[cfg(target_pointer_width = "64")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x20;
        #[cfg(target_pointer_width = "32")]
        const PROCESS_PARAMETERS_OFFSET: usize = 0x10;

        let mut process_parameters_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut bytes_read: usize = 0;

        let peb_addr = pbi.peb_base_address as usize;
        let params_ptr_addr = peb_addr + PROCESS_PARAMETERS_OFFSET;

        ReadProcessMemory(
            handle,
            params_ptr_addr as *const std::ffi::c_void,
            &mut process_parameters_ptr as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<*mut std::ffi::c_void>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (ProcessParameters ptr)",
            message: e.message().to_string(),
        })?;

        if process_parameters_ptr.is_null() {
            return Err(WinError::ApiError {
                api: "ReadProcessMemory",
                message: "ProcessParameters is null".to_string(),
            });
        }

        // Read the Environment pointer from RTL_USER_PROCESS_PARAMETERS
        // Environment is at offset 0x80 on x64, 0x48 on x86
        #[cfg(target_pointer_width = "64")]
        const ENVIRONMENT_OFFSET: usize = 0x80;
        #[cfg(target_pointer_width = "32")]
        const ENVIRONMENT_OFFSET: usize = 0x48;

        // Also need EnvironmentSize at offset 0x03F0 on x64, 0x0290 on x86
        #[cfg(target_pointer_width = "64")]
        const ENVIRONMENT_SIZE_OFFSET: usize = 0x03F0;
        #[cfg(target_pointer_width = "32")]
        const ENVIRONMENT_SIZE_OFFSET: usize = 0x0290;

        let env_ptr_addr = process_parameters_ptr as usize + ENVIRONMENT_OFFSET;
        let mut environment_ptr: *mut u16 = std::ptr::null_mut();

        ReadProcessMemory(
            handle,
            env_ptr_addr as *const std::ffi::c_void,
            &mut environment_ptr as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<*mut u16>(),
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (Environment ptr)",
            message: e.message().to_string(),
        })?;

        if environment_ptr.is_null() {
            return Ok(Vec::new()); // No environment block
        }

        // Try to read environment size
        let env_size_addr = process_parameters_ptr as usize + ENVIRONMENT_SIZE_OFFSET;
        let mut env_size: usize = 0;

        let size_result = ReadProcessMemory(
            handle,
            env_size_addr as *const std::ffi::c_void,
            &mut env_size as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<usize>(),
            Some(&mut bytes_read),
        );

        // If we couldn't read the size, use a reasonable default
        if size_result.is_err() || env_size == 0 || env_size > 1024 * 1024 {
            env_size = 32768; // 32KB default, should be enough for most cases
        }

        // Read the environment block
        let env_chars = env_size / 2; // Size is in bytes, we need chars
        let mut env_buffer: Vec<u16> = vec![0; env_chars];

        ReadProcessMemory(
            handle,
            environment_ptr as *const std::ffi::c_void,
            env_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            env_size,
            Some(&mut bytes_read),
        )
        .map_err(|e| WinError::ApiError {
            api: "ReadProcessMemory (environment block)",
            message: e.message().to_string(),
        })?;

        // Parse the environment block
        // Format: VAR1=VALUE1\0VAR2=VALUE2\0...\0\0 (double null terminated)
        let mut env_vars = Vec::new();
        let mut start = 0;

        for i in 0..env_buffer.len() {
            if env_buffer[i] == 0 {
                if start == i {
                    // Double null - end of environment block
                    break;
                }

                let var_str = String::from_utf16_lossy(&env_buffer[start..i]);
                if let Some(eq_pos) = var_str.find('=') {
                    let name = var_str[..eq_pos].to_string();
                    let value = var_str[eq_pos + 1..].to_string();

                    // Skip empty names (first entry is sometimes "=C:=C:\...")
                    if !name.is_empty() {
                        env_vars.push(EnvVar { name, value });
                    }
                }

                start = i + 1;
            }
        }

        Ok(env_vars)
    }
}

/// Get only the "interesting" environment variables for display
pub fn get_interesting_env_vars(pid: u32) -> WinResult<Vec<EnvVar>> {
    let all_vars = get_environment_variables(pid)?;

    Ok(all_vars
        .into_iter()
        .filter(|v| {
            INTERESTING_ENV_VARS
                .iter()
                .any(|&name| v.name.eq_ignore_ascii_case(name))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_image_path_current_process() {
        let pid = std::process::id();
        let path = get_image_path(pid).expect("Should get image path for current process");

        assert!(path.exists(), "Image path should exist");
        assert!(
            path.to_string_lossy().to_lowercase().contains(".exe"),
            "Should be an exe"
        );
    }

    #[test]
    fn test_get_start_time_current_process() {
        let pid = std::process::id();
        let start_time = get_start_time(pid).expect("Should get start time for current process");

        // Start time should be in the past but not too far
        let now = OffsetDateTime::now_utc();
        assert!(start_time < now, "Start time should be in the past");

        let one_day_ago = now - time::Duration::days(1);
        assert!(
            start_time > one_day_ago,
            "Start time should be recent (within a day)"
        );
    }

    #[test]
    fn test_get_user_current_process() {
        let pid = std::process::id();
        let user = get_user(pid).expect("Should get user for current process");

        assert!(!user.is_empty(), "User should not be empty");
        // User typically looks like "DOMAIN\username" or just "username"
    }

    #[test]
    fn test_get_session_id_current_process() {
        let pid = std::process::id();
        let session_id = get_session_id(pid).expect("Should get session ID");

        // Session ID is typically 0 for services, 1+ for interactive
        // We just check it doesn't fail
        assert!(session_id < 100, "Session ID should be reasonable");
    }

    #[test]
    fn test_access_denied_for_system() {
        // PID 4 is System - we typically can't access its token
        let result = get_user(4);
        // This might succeed with admin privileges or fail with access denied
        match result {
            Ok(_) => (), // Admin mode
            Err(WinError::AccessDenied { .. }) => (),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
