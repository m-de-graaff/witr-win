//! Process query functions for detailed process information
//!
//! These functions open individual processes to query detailed information
//! like full image path, start time, and owning user.

use crate::error::{WinError, WinResult};
use std::path::PathBuf;
use time::OffsetDateTime;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupAccountSidW, LookupPrivilegeValueW,
    TokenUser, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

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
