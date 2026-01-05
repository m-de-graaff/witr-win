//! Windows Service Control Manager (SCM) integration
//!
//! Enumerates services and correlates PIDs with service names.

use crate::error::{WinError, WinResult};
use std::collections::HashMap;
use windows::core::PWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};

/// Information about a Windows service
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (internal name used by SCM)
    pub name: String,
    /// Display name (human-readable)
    pub display_name: String,
    /// Process ID (0 if not running)
    pub pid: u32,
    /// Current service state
    pub state: ServiceState,
    /// Path to the service executable
    pub binary_path: Option<String>,
    /// Service description
    pub description: Option<String>,
}

/// Windows service state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

impl ServiceState {
    fn from_dword(state: u32) -> Self {
        match state {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            _ => ServiceState::Unknown,
        }
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::StartPending => write!(f, "Start Pending"),
            ServiceState::StopPending => write!(f, "Stop Pending"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::ContinuePending => write!(f, "Continue Pending"),
            ServiceState::PausePending => write!(f, "Pause Pending"),
            ServiceState::Paused => write!(f, "Paused"),
            ServiceState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// RAII wrapper for SC_HANDLE
struct ScHandle(windows::Win32::System::Services::SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// List all services with their PIDs
///
/// Returns a vector of ServiceInfo for all Win32 services.
pub fn list_services_with_pids() -> WinResult<Vec<ServiceInfo>> {
    let mut services = Vec::new();

    unsafe {
        // Open the Service Control Manager
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE).map_err(|e| {
            WinError::ApiError {
                api: "OpenSCManagerW",
                message: e.message().to_string(),
            }
        })?;
        let _scm_handle = ScHandle(scm);

        // First call to get required buffer size
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        );

        if bytes_needed == 0 {
            return Ok(services);
        }

        // Allocate buffer and enumerate
        let mut buffer: Vec<u8> = vec![0; bytes_needed as usize];
        let result = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        );

        if let Err(e) = result {
            return Err(WinError::ApiError {
                api: "EnumServicesStatusExW",
                message: e.message().to_string(),
            });
        }

        // Parse the results
        let entries = std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );

        for entry in entries {
            let name = pwstr_to_string(entry.lpServiceName);
            let display_name = pwstr_to_string(entry.lpDisplayName);
            let pid = entry.ServiceStatusProcess.dwProcessId;
            let state = ServiceState::from_dword(entry.ServiceStatusProcess.dwCurrentState.0);

            // Try to get the binary path
            let binary_path = get_service_binary_path(scm, &name);

            services.push(ServiceInfo {
                name,
                display_name,
                pid,
                state,
                binary_path,
                description: None,
            });
        }
    }

    Ok(services)
}

/// Get the binary path for a service
fn get_service_binary_path(
    scm: windows::Win32::System::Services::SC_HANDLE,
    service_name: &str,
) -> Option<String> {
    unsafe {
        let service_name_wide: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let service = OpenServiceW(
            scm,
            PWSTR(service_name_wide.as_ptr() as *mut _),
            SERVICE_QUERY_CONFIG,
        );

        let service = match service {
            Ok(s) => s,
            Err(_) => return None,
        };

        let _service_handle = ServiceHandleWrapper(service);

        // Get required buffer size
        let mut bytes_needed = 0u32;
        let _ = QueryServiceConfigW(service, None, 0, &mut bytes_needed);

        if bytes_needed == 0 {
            return None;
        }

        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0; bytes_needed as usize];
        let config = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;

        if QueryServiceConfigW(service, Some(config), bytes_needed, &mut bytes_needed).is_err() {
            return None;
        }

        let binary_path = pwstr_to_string((*config).lpBinaryPathName);
        if binary_path.is_empty() {
            None
        } else {
            Some(binary_path)
        }
    }
}

/// RAII wrapper for service handle
struct ServiceHandleWrapper(windows::Win32::System::Services::SC_HANDLE);

impl Drop for ServiceHandleWrapper {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// Build a map from PID to service info for quick lookup
pub fn build_pid_service_map() -> WinResult<HashMap<u32, ServiceInfo>> {
    let services = list_services_with_pids()?;
    let mut map = HashMap::new();

    for service in services {
        if service.pid != 0 && service.state == ServiceState::Running {
            map.insert(service.pid, service);
        }
    }

    Ok(map)
}

/// Find the service that owns a specific PID
///
/// Returns Some(ServiceInfo) if the PID is a service process, None otherwise.
pub fn service_for_pid(pid: u32) -> WinResult<Option<ServiceInfo>> {
    let services = list_services_with_pids()?;

    for service in services {
        if service.pid == pid && service.state == ServiceState::Running {
            return Ok(Some(service));
        }
    }

    Ok(None)
}

/// Find all services hosted by a svchost.exe PID
///
/// Multiple services can share a single svchost.exe process.
pub fn services_for_svchost_pid(pid: u32) -> WinResult<Vec<ServiceInfo>> {
    let services = list_services_with_pids()?;

    Ok(services
        .into_iter()
        .filter(|s| s.pid == pid && s.state == ServiceState::Running)
        .collect())
}

/// Check if a process name indicates a service host
pub fn is_service_host_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "svchost.exe" || lower == "services.exe"
}

/// Convert PWSTR to String
fn pwstr_to_string(pwstr: PWSTR) -> String {
    if pwstr.is_null() {
        return String::new();
    }

    unsafe {
        let len = (0..).take_while(|&i| *pwstr.0.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(pwstr.0, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_services() {
        let services = list_services_with_pids().expect("Should list services");

        // There should be many services on a Windows system
        assert!(!services.is_empty(), "Should have at least some services");

        println!("Found {} services", services.len());

        // Print first few running services
        for service in services
            .iter()
            .filter(|s| s.state == ServiceState::Running)
            .take(5)
        {
            println!(
                "  {} ({}) - PID {} - {}",
                service.name, service.display_name, service.pid, service.state
            );
        }
    }

    #[test]
    fn test_build_pid_service_map() {
        let map = build_pid_service_map().expect("Should build service map");

        println!("Found {} running services with PIDs", map.len());

        // Print some services
        for (pid, service) in map.iter().take(3) {
            println!(
                "  PID {} -> {} ({})",
                pid, service.name, service.display_name
            );
        }
    }

    #[test]
    fn test_service_for_pid() {
        // First get a known service PID
        let services = list_services_with_pids().expect("Should list services");

        if let Some(running_service) = services
            .iter()
            .find(|s| s.state == ServiceState::Running && s.pid != 0)
        {
            let found = service_for_pid(running_service.pid)
                .expect("Should query service")
                .expect("Should find service");

            assert_eq!(found.pid, running_service.pid);
            println!("Found service {} for PID {}", found.name, found.pid);
        }
    }

    #[test]
    fn test_service_state_display() {
        assert_eq!(format!("{}", ServiceState::Running), "Running");
        assert_eq!(format!("{}", ServiceState::Stopped), "Stopped");
    }

    #[test]
    fn test_is_service_host_process() {
        assert!(is_service_host_process("svchost.exe"));
        assert!(is_service_host_process("SVCHOST.EXE"));
        assert!(is_service_host_process("services.exe"));
        assert!(!is_service_host_process("notepad.exe"));
    }
}
