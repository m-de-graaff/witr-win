//! File handle enumeration for processes
//!
//! Uses NtQuerySystemInformation with SystemHandleInformation to enumerate
//! open handles (files, registry keys, etc.) for a specific process.

use crate::error::{WinError, WinResult};
use std::ffi::c_void;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, NTSTATUS, UNICODE_STRING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

// NtQuerySystemInformation and NtQueryObject are not fully exposed in the windows crate
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    fn NtQueryObject(
        Handle: HANDLE,
        ObjectInformationClass: u32,
        ObjectInformation: *mut c_void,
        ObjectInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}

// System information classes
const SYSTEM_HANDLE_INFORMATION: u32 = 16;

// Object information classes
const OBJECT_TYPE_INFORMATION: u32 = 2;
const OBJECT_NAME_INFORMATION: u32 = 1;

// Status codes
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_SUCCESS: i32 = 0;

/// Handle entry from the system handle table
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SystemHandleTableEntryInfo {
    process_id: u16,
    creator_back_trace_index: u16,
    object_type_number: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut c_void,
    granted_access: u32,
}

/// System handle information header
#[repr(C)]
struct SystemHandleInformation {
    number_of_handles: u32,
    // Followed by SystemHandleTableEntryInfo array
}

/// Object type information structure
#[repr(C)]
struct ObjectTypeInformation {
    type_name: UNICODE_STRING,
    // More fields follow but we only need the name
}

/// Object name information structure
#[repr(C)]
struct ObjectNameInformation {
    name: UNICODE_STRING,
}

/// RAII wrapper for handles
struct SafeHandle(HANDLE);

impl SafeHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn get(&self) -> HANDLE {
        self.0
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

/// Information about an open handle
#[derive(Debug, Clone)]
pub struct HandleInfo {
    /// The handle value in the target process
    pub handle_value: usize,
    /// The type of object (e.g., "File", "Key", "Event", "Mutant")
    pub object_type: String,
    /// The name/path of the object (e.g., file path, registry key path)
    pub name: Option<String>,
    /// Access mask granted to this handle
    pub access_mask: u32,
}

impl HandleInfo {
    /// Check if this is a file handle
    pub fn is_file(&self) -> bool {
        self.object_type == "File"
    }

    /// Check if this is a registry key handle
    pub fn is_registry_key(&self) -> bool {
        self.object_type == "Key"
    }

    /// Get a display-friendly name for the handle
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("<unnamed>")
    }
}

/// List all open handles for a specific process
///
/// This requires elevated privileges to work properly for most processes.
/// Returns handles filtered by type if specified.
pub fn list_handles(pid: u32) -> WinResult<Vec<HandleInfo>> {
    let mut handles = Vec::new();

    unsafe {
        // Open the target process to duplicate handles
        let target_process = OpenProcess(PROCESS_DUP_HANDLE, false, pid).map_err(|e| {
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

        let target_handle = SafeHandle::new(target_process);
        let current_process = GetCurrentProcess();

        // Get system handle information
        // Start with a reasonable buffer size and grow as needed
        let mut buffer_size: u32 = 1024 * 1024; // 1MB initial
        let mut buffer: Vec<u8>;
        let mut return_length: u32 = 0;

        loop {
            buffer = vec![0u8; buffer_size as usize];

            let status = NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buffer_size,
                &mut return_length,
            );

            if status.0 == STATUS_INFO_LENGTH_MISMATCH {
                // Buffer too small, grow it
                buffer_size = return_length + 1024 * 1024;
                if buffer_size > 512 * 1024 * 1024 {
                    // Sanity check: 512MB max
                    return Err(WinError::ApiError {
                        api: "NtQuerySystemInformation",
                        message: "Buffer size exceeded maximum".to_string(),
                    });
                }
                continue;
            }

            if status.0 != STATUS_SUCCESS {
                return Err(WinError::ApiError {
                    api: "NtQuerySystemInformation",
                    message: format!("NTSTATUS: 0x{:08X}", status.0 as u32),
                });
            }

            break;
        }

        // Parse the handle information
        let handle_info = &*(buffer.as_ptr() as *const SystemHandleInformation);
        let handle_count = handle_info.number_of_handles as usize;

        // Get pointer to the handle array, properly aligned
        // The array starts after the header, but must be aligned for the entry struct
        let header_size = std::mem::size_of::<SystemHandleInformation>();
        let entry_align = std::mem::align_of::<SystemHandleTableEntryInfo>();
        let array_offset = (header_size + entry_align - 1) & !(entry_align - 1);
        let handle_array = buffer.as_ptr().add(array_offset) as *const SystemHandleTableEntryInfo;

        // Process handles belonging to target PID
        for i in 0..handle_count {
            let entry = &*handle_array.add(i);

            // Filter by PID (note: process_id is u16, may wrap for high PIDs)
            if entry.process_id as u32 != pid {
                continue;
            }

            // Try to duplicate the handle to our process
            let mut duplicated_handle = HANDLE::default();
            let dup_result = DuplicateHandle(
                target_handle.get(),
                HANDLE(entry.handle_value as *mut c_void),
                current_process,
                &mut duplicated_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            );

            if dup_result.is_err() {
                // Skip handles we can't duplicate (protected or special handles)
                continue;
            }

            let dup_handle = SafeHandle::new(duplicated_handle);

            // Query object type
            let object_type = query_object_type(dup_handle.get()).unwrap_or_default();

            // Skip certain types that aren't useful or may hang
            if should_skip_type(&object_type) {
                continue;
            }

            // Query object name (skip for types that may block)
            let name = if may_block_on_name_query(&object_type) {
                None
            } else {
                query_object_name(dup_handle.get())
            };

            handles.push(HandleInfo {
                handle_value: entry.handle_value as usize,
                object_type,
                name,
                access_mask: entry.granted_access,
            });
        }
    }

    // Sort handles by type then name for consistent output
    handles.sort_by(|a, b| {
        a.object_type
            .cmp(&b.object_type)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(handles)
}

/// Query the type name of an object handle
fn query_object_type(handle: HANDLE) -> Option<String> {
    unsafe {
        let mut buffer = vec![0u8; 1024];
        let mut return_length: u32 = 0;

        let status = NtQueryObject(
            handle,
            OBJECT_TYPE_INFORMATION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut return_length,
        );

        if status.0 != STATUS_SUCCESS {
            return None;
        }

        let type_info = &*(buffer.as_ptr() as *const ObjectTypeInformation);
        unicode_string_to_string(&type_info.type_name)
    }
}

/// Query the name of an object handle
fn query_object_name(handle: HANDLE) -> Option<String> {
    unsafe {
        // Start with a reasonable buffer
        let mut buffer = vec![0u8; 1024];
        let mut return_length: u32 = 0;

        let status = NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut return_length,
        );

        // If buffer too small, retry with larger buffer
        if status.0 == STATUS_INFO_LENGTH_MISMATCH && return_length > 0 {
            buffer = vec![0u8; return_length as usize + 256];
            let status = NtQueryObject(
                handle,
                OBJECT_NAME_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut return_length,
            );

            if status.0 != STATUS_SUCCESS {
                return None;
            }
        } else if status.0 != STATUS_SUCCESS {
            return None;
        }

        let name_info = &*(buffer.as_ptr() as *const ObjectNameInformation);
        let name = unicode_string_to_string(&name_info.name)?;

        // Convert NT path to DOS path if possible
        Some(convert_nt_path_to_dos(&name))
    }
}

/// Convert a UNICODE_STRING to a Rust String
fn unicode_string_to_string(us: &UNICODE_STRING) -> Option<String> {
    if us.Buffer.0.is_null() || us.Length == 0 {
        return None;
    }

    unsafe {
        let len = (us.Length / 2) as usize;
        let slice = std::slice::from_raw_parts(us.Buffer.0, len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// Convert NT device path to DOS path
///
/// e.g., "\Device\HarddiskVolume3\Windows\System32\file.dll"
///    -> "C:\Windows\System32\file.dll"
fn convert_nt_path_to_dos(nt_path: &str) -> String {
    // Common device mappings (simplified)
    // In a production tool, you'd enumerate drive letters and their device names
    static DEVICE_PREFIXES: &[(&str, &str)] = &[
        (r"\Device\HarddiskVolume1", "C:"),
        (r"\Device\HarddiskVolume2", "D:"),
        (r"\Device\HarddiskVolume3", "C:"),
        (r"\Device\HarddiskVolume4", "D:"),
        (r"\Device\Mup", r"\\"), // UNC paths
    ];

    for (prefix, replacement) in DEVICE_PREFIXES {
        if let Some(stripped) = nt_path.strip_prefix(prefix) {
            return format!("{}{}", replacement, stripped);
        }
    }

    // Return as-is if no conversion possible
    nt_path.to_string()
}

/// Check if an object type should be skipped entirely
fn should_skip_type(object_type: &str) -> bool {
    matches!(
        object_type,
        "EtwRegistration"
            | "EtwConsumer"
            | "TpWorkerFactory"
            | "WaitCompletionPacket"
            | "IRTimer"
            | "DxgkSharedResource"
            | "DxgkSharedSyncObject"
    )
}

/// Check if querying the name for this type might block
fn may_block_on_name_query(object_type: &str) -> bool {
    // Named pipes and some other types can hang on NtQueryObject
    matches!(object_type, "File" | "")
}

/// List handles filtered by type (e.g., only files or registry keys)
pub fn list_handles_by_type(pid: u32, type_filter: &str) -> WinResult<Vec<HandleInfo>> {
    let handles = list_handles(pid)?;
    Ok(handles
        .into_iter()
        .filter(|h| h.object_type.eq_ignore_ascii_case(type_filter))
        .collect())
}

/// Get summary counts of handles by type
pub fn get_handle_summary(pid: u32) -> WinResult<Vec<(String, usize)>> {
    let handles = list_handles(pid)?;

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for handle in &handles {
        *counts.entry(handle.object_type.clone()).or_insert(0) += 1;
    }

    let mut result: Vec<(String, usize)> = counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_handles_current_process() {
        let pid = std::process::id();
        let result = list_handles(pid);

        // Should succeed for current process (we always have access)
        assert!(result.is_ok(), "Should be able to list own handles");

        let handles = result.unwrap();
        // Current process should have at least some handles open
        assert!(!handles.is_empty(), "Should have some handles");
    }

    #[test]
    fn test_handle_summary() {
        let pid = std::process::id();
        let result = get_handle_summary(pid);

        assert!(result.is_ok());
        let summary = result.unwrap();

        // Should have at least one type of handle
        assert!(!summary.is_empty(), "Should have handle types");
    }

    #[test]
    fn test_convert_nt_path() {
        let nt_path = r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll";
        let dos_path = convert_nt_path_to_dos(nt_path);
        assert!(
            dos_path.contains("Windows") && dos_path.contains("ntdll.dll"),
            "Should preserve path components"
        );
    }
}
