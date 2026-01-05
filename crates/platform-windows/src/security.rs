//! Security information collection for processes
//!
//! This module provides functions to query security-related information:
//! - Integrity level (Low, Medium, High, System)
//! - Enabled privileges (SeDebugPrivilege, etc.)

use crate::error::{WinError, WinResult};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeNameW,
    TokenIntegrityLevel, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
};

/// Process integrity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
    Unknown,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityLevel::Untrusted => write!(f, "Untrusted"),
            IntegrityLevel::Low => write!(f, "Low"),
            IntegrityLevel::Medium => write!(f, "Medium"),
            IntegrityLevel::MediumPlus => write!(f, "Medium+"),
            IntegrityLevel::High => write!(f, "High"),
            IntegrityLevel::System => write!(f, "System"),
            IntegrityLevel::Protected => write!(f, "Protected"),
            IntegrityLevel::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Privilege information
#[derive(Debug, Clone)]
pub struct PrivilegeInfo {
    pub name: String,
    pub enabled: bool,
}

/// Complete security information for a process
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub integrity_level: IntegrityLevel,
    pub privileges: Vec<PrivilegeInfo>,
}

// Well-known integrity level RIDs
const SECURITY_MANDATORY_UNTRUSTED_RID: u32 = 0x0000;
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const SECURITY_MANDATORY_MEDIUM_PLUS_RID: u32 = 0x2100;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;
const SECURITY_MANDATORY_PROTECTED_PROCESS_RID: u32 = 0x5000;

/// Get the integrity level of a process
pub fn get_integrity_level(pid: u32) -> WinResult<IntegrityLevel> {
    unsafe {
        let is_current = pid == std::process::id();
        let process_handle = if is_current {
            GetCurrentProcess()
        } else {
            OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|_| WinError::AccessDenied { pid })?
        };

        // Note: GetCurrentProcess() returns a pseudo-handle (-1) which looks "invalid"
        // but is actually valid for the current process
        if !is_current && process_handle.is_invalid() {
            return Err(WinError::AccessDenied { pid });
        }

        let mut token_handle = HANDLE::default();
        let result = OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle);

        if !is_current {
            let _ = CloseHandle(process_handle);
        }

        if result.is_err() {
            return Err(WinError::AccessDenied { pid });
        }

        // Get required buffer size
        let mut size_needed: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut size_needed);

        if size_needed == 0 {
            let _ = CloseHandle(token_handle);
            return Ok(IntegrityLevel::Unknown);
        }

        // Allocate buffer and get the info
        let mut buffer = vec![0u8; size_needed as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size_needed,
            &mut size_needed,
        );

        let _ = CloseHandle(token_handle);

        if result.is_err() {
            return Ok(IntegrityLevel::Unknown);
        }

        let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;

        // Get the RID (last sub-authority) from the SID
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() {
            return Ok(IntegrityLevel::Unknown);
        }

        let count = *count_ptr;
        if count == 0 {
            return Ok(IntegrityLevel::Unknown);
        }

        let rid_ptr = GetSidSubAuthority(sid, (count - 1) as u32);
        if rid_ptr.is_null() {
            return Ok(IntegrityLevel::Unknown);
        }

        let integrity_rid = *rid_ptr;

        let level = match integrity_rid {
            r if r == SECURITY_MANDATORY_UNTRUSTED_RID => IntegrityLevel::Untrusted,
            r if r == SECURITY_MANDATORY_LOW_RID => IntegrityLevel::Low,
            r if r == SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel::Medium,
            r if r == SECURITY_MANDATORY_MEDIUM_PLUS_RID => IntegrityLevel::MediumPlus,
            r if r == SECURITY_MANDATORY_HIGH_RID => IntegrityLevel::High,
            r if r == SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel::System,
            r if r >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID => IntegrityLevel::Protected,
            _ => IntegrityLevel::Unknown,
        };

        Ok(level)
    }
}

/// Get enabled privileges for a process
pub fn get_privileges(pid: u32) -> WinResult<Vec<PrivilegeInfo>> {
    unsafe {
        let is_current = pid == std::process::id();
        let process_handle = if is_current {
            GetCurrentProcess()
        } else {
            OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|_| WinError::AccessDenied { pid })?
        };

        // Note: GetCurrentProcess() returns a pseudo-handle (-1) which looks "invalid"
        // but is actually valid for the current process
        if !is_current && process_handle.is_invalid() {
            return Err(WinError::AccessDenied { pid });
        }

        let mut token_handle = HANDLE::default();
        let result = OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle);

        if !is_current {
            let _ = CloseHandle(process_handle);
        }

        if result.is_err() {
            return Err(WinError::AccessDenied { pid });
        }

        // Get required buffer size
        let mut size_needed: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenPrivileges, None, 0, &mut size_needed);

        if size_needed == 0 {
            let _ = CloseHandle(token_handle);
            return Ok(Vec::new());
        }

        // Allocate buffer and get the info
        let mut buffer = vec![0u8; size_needed as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size_needed,
            &mut size_needed,
        );

        let _ = CloseHandle(token_handle);

        if result.is_err() {
            return Ok(Vec::new());
        }

        let privileges = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = privileges.PrivilegeCount as usize;

        let mut result_privs = Vec::new();

        // Get array of privileges
        let priv_array = std::slice::from_raw_parts(
            &privileges.Privileges[0] as *const LUID_AND_ATTRIBUTES,
            count,
        );

        for priv_info in priv_array {
            let enabled = priv_info.Attributes.contains(SE_PRIVILEGE_ENABLED);

            // Look up privilege name
            let mut name_len: u32 = 256;
            let mut name_buf = vec![0u16; name_len as usize];

            if LookupPrivilegeNameW(
                PCWSTR::null(),
                &priv_info.Luid,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
            )
            .is_ok()
            {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                result_privs.push(PrivilegeInfo { name, enabled });
            }
        }

        // Sort: enabled first, then alphabetically
        result_privs.sort_by(|a, b| match (a.enabled, b.enabled) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });

        Ok(result_privs)
    }
}

/// Get complete security information for a process
pub fn get_security_info(pid: u32) -> WinResult<SecurityInfo> {
    let integrity_level = get_integrity_level(pid).unwrap_or(IntegrityLevel::Unknown);
    let privileges = get_privileges(pid).unwrap_or_default();

    Ok(SecurityInfo {
        integrity_level,
        privileges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_integrity_level_current() {
        let level = get_integrity_level(std::process::id());
        assert!(level.is_ok());
        // Tests typically run at Medium or High integrity
        let level = level.unwrap();
        assert!(matches!(
            level,
            IntegrityLevel::Medium | IntegrityLevel::High
        ));
    }

    #[test]
    fn test_get_privileges_current() {
        let privs = get_privileges(std::process::id());
        assert!(privs.is_ok());
        let privs = privs.unwrap();
        // Should have at least some privileges
        assert!(!privs.is_empty());
    }

    #[test]
    fn test_integrity_level_display() {
        assert_eq!(format!("{}", IntegrityLevel::Medium), "Medium");
        assert_eq!(format!("{}", IntegrityLevel::High), "High");
        assert_eq!(format!("{}", IntegrityLevel::System), "System");
    }
}
