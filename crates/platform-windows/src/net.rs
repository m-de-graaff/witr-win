//! Network port to PID resolution
//!
//! Uses Windows IP Helper APIs to resolve ports to owning processes.

use crate::error::{WinError, WinResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_TCP_STATE_LISTEN, MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Information about a network binding
#[derive(Debug, Clone)]
pub struct PortBinding {
    /// Process ID owning the port
    pub pid: u32,
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,
    /// Local address
    pub local_addr: IpAddr,
    /// Local port
    pub local_port: u16,
    /// TCP state (only for TCP)
    pub state: Option<TcpState>,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

impl TcpState {
    fn from_mib_state(state: u32) -> Self {
        match state {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynReceived,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            _ => TcpState::Closed,
        }
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RCVD"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT_1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT_2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::DeleteTcb => write!(f, "DELETE_TCB"),
        }
    }
}

/// Find all PIDs listening on or bound to a specific port
///
/// Returns bindings for both TCP (LISTEN state) and UDP on the given port.
/// Checks both IPv4 and IPv6.
pub fn pids_listening_on_port(port: u16) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    // Get TCP IPv4 listeners
    bindings.extend(get_tcp4_bindings(port)?);

    // Get TCP IPv6 listeners
    bindings.extend(get_tcp6_bindings(port)?);

    // Get UDP IPv4 bindings
    bindings.extend(get_udp4_bindings(port)?);

    // Get UDP IPv6 bindings
    bindings.extend(get_udp6_bindings(port)?);

    Ok(bindings)
}

/// Find all PIDs for TCP listeners on a port (any state, not just LISTEN)
pub fn pids_on_tcp_port(port: u16) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();
    bindings.extend(get_tcp4_bindings_all_states(port)?);
    bindings.extend(get_tcp6_bindings_all_states(port)?);
    Ok(bindings)
}

/// Get unique PIDs listening on a port (convenience function)
pub fn pids_for_port(port: u16) -> WinResult<Vec<u32>> {
    let bindings = pids_listening_on_port(port)?;
    let mut pids: Vec<u32> = bindings.iter().map(|b| b.pid).collect();
    pids.sort();
    pids.dedup();
    Ok(pids)
}

/// Get TCP IPv4 bindings for a port (LISTEN state only)
fn get_tcp4_bindings(port: u16) -> WinResult<Vec<PortBinding>> {
    get_tcp4_bindings_filtered(port, true)
}

/// Get TCP IPv4 bindings for a port (all states)
fn get_tcp4_bindings_all_states(port: u16) -> WinResult<Vec<PortBinding>> {
    get_tcp4_bindings_filtered(port, false)
}

fn get_tcp4_bindings_filtered(port: u16, listen_only: bool) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    unsafe {
        // First call to get required buffer size
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return Ok(bindings);
        }

        // Allocate buffer and get the table
        let mut buffer: Vec<u8> = vec![0; size as usize];
        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result != 0 {
            return Err(WinError::ApiError {
                api: "GetExtendedTcpTable",
                message: format!("Error code: {}", result),
            });
        }

        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let state = TcpState::from_mib_state(row.dwState);

            if local_port == port {
                if listen_only && state != TcpState::Listen {
                    continue;
                }

                let local_addr = Ipv4Addr::from(row.dwLocalAddr.to_be());

                bindings.push(PortBinding {
                    pid: row.dwOwningPid,
                    protocol: Protocol::Tcp,
                    local_addr: IpAddr::V4(local_addr),
                    local_port,
                    state: Some(state),
                });
            }
        }
    }

    Ok(bindings)
}

/// Get TCP IPv6 bindings for a port (LISTEN state only)
fn get_tcp6_bindings(port: u16) -> WinResult<Vec<PortBinding>> {
    get_tcp6_bindings_filtered(port, true)
}

/// Get TCP IPv6 bindings for a port (all states)
fn get_tcp6_bindings_all_states(port: u16) -> WinResult<Vec<PortBinding>> {
    get_tcp6_bindings_filtered(port, false)
}

fn get_tcp6_bindings_filtered(port: u16, listen_only: bool) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return Ok(bindings);
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result != 0 {
            return Err(WinError::ApiError {
                api: "GetExtendedTcpTable (IPv6)",
                message: format!("Error code: {}", result),
            });
        }

        let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let state = TcpState::from_mib_state(row.dwState);

            if local_port == port {
                if listen_only && state != TcpState::Listen {
                    continue;
                }

                let local_addr = Ipv6Addr::from(row.ucLocalAddr);

                bindings.push(PortBinding {
                    pid: row.dwOwningPid,
                    protocol: Protocol::Tcp,
                    local_addr: IpAddr::V6(local_addr),
                    local_port,
                    state: Some(state),
                });
            }
        }
    }

    Ok(bindings)
}

/// Get UDP IPv4 bindings for a port
fn get_udp4_bindings(port: u16) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return Ok(bindings);
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let result = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if result != 0 {
            return Err(WinError::ApiError {
                api: "GetExtendedUdpTable",
                message: format!("Error code: {}", result),
            });
        }

        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if local_port == port {
                let local_addr = Ipv4Addr::from(row.dwLocalAddr.to_be());

                bindings.push(PortBinding {
                    pid: row.dwOwningPid,
                    protocol: Protocol::Udp,
                    local_addr: IpAddr::V4(local_addr),
                    local_port,
                    state: None,
                });
            }
        }
    }

    Ok(bindings)
}

/// Get UDP IPv6 bindings for a port
fn get_udp6_bindings(port: u16) -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return Ok(bindings);
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let result = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if result != 0 {
            return Err(WinError::ApiError {
                api: "GetExtendedUdpTable (IPv6)",
                message: format!("Error code: {}", result),
            });
        }

        let table = &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);

            if local_port == port {
                let local_addr = Ipv6Addr::from(row.ucLocalAddr);

                bindings.push(PortBinding {
                    pid: row.dwOwningPid,
                    protocol: Protocol::Udp,
                    local_addr: IpAddr::V6(local_addr),
                    local_port,
                    state: None,
                });
            }
        }
    }

    Ok(bindings)
}

/// Network connection with remote endpoint info
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    /// Process ID owning the connection
    pub pid: u32,
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,
    /// Local address
    pub local_addr: IpAddr,
    /// Local port
    pub local_port: u16,
    /// Remote address (None for UDP or LISTEN)
    pub remote_addr: Option<IpAddr>,
    /// Remote port (None for UDP or LISTEN)
    pub remote_port: Option<u16>,
    /// TCP state (only for TCP)
    pub state: Option<TcpState>,
}

/// Get all network connections for a specific PID
pub fn get_connections_for_pid(pid: u32) -> WinResult<Vec<NetworkConnection>> {
    let mut connections = Vec::new();

    // TCP IPv4
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwOwningPid == pid {
                        let state = TcpState::from_mib_state(row.dwState);
                        let local_addr = Ipv4Addr::from(row.dwLocalAddr.to_be());
                        let remote_addr = Ipv4Addr::from(row.dwRemoteAddr.to_be());
                        let local_port = u16::from_be(row.dwLocalPort as u16);
                        let remote_port = u16::from_be(row.dwRemotePort as u16);

                        connections.push(NetworkConnection {
                            pid,
                            protocol: Protocol::Tcp,
                            local_addr: IpAddr::V4(local_addr),
                            local_port,
                            remote_addr: if state == TcpState::Listen {
                                None
                            } else {
                                Some(IpAddr::V4(remote_addr))
                            },
                            remote_port: if state == TcpState::Listen {
                                None
                            } else {
                                Some(remote_port)
                            },
                            state: Some(state),
                        });
                    }
                }
            }
        }
    }

    // TCP IPv6
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwOwningPid == pid {
                        let state = TcpState::from_mib_state(row.dwState);
                        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
                        let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
                        let local_port = u16::from_be(row.dwLocalPort as u16);
                        let remote_port = u16::from_be(row.dwRemotePort as u16);

                        connections.push(NetworkConnection {
                            pid,
                            protocol: Protocol::Tcp,
                            local_addr: IpAddr::V6(local_addr),
                            local_port,
                            remote_addr: if state == TcpState::Listen {
                                None
                            } else {
                                Some(IpAddr::V6(remote_addr))
                            },
                            remote_port: if state == TcpState::Listen {
                                None
                            } else {
                                Some(remote_port)
                            },
                            state: Some(state),
                        });
                    }
                }
            }
        }
    }

    // UDP IPv4
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwOwningPid == pid {
                        let local_addr = Ipv4Addr::from(row.dwLocalAddr.to_be());
                        let local_port = u16::from_be(row.dwLocalPort as u16);

                        connections.push(NetworkConnection {
                            pid,
                            protocol: Protocol::Udp,
                            local_addr: IpAddr::V4(local_addr),
                            local_port,
                            remote_addr: None,
                            remote_port: None,
                            state: None,
                        });
                    }
                }
            }
        }
    }

    // UDP IPv6
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwOwningPid == pid {
                        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
                        let local_port = u16::from_be(row.dwLocalPort as u16);

                        connections.push(NetworkConnection {
                            pid,
                            protocol: Protocol::Udp,
                            local_addr: IpAddr::V6(local_addr),
                            local_port,
                            remote_addr: None,
                            remote_port: None,
                            state: None,
                        });
                    }
                }
            }
        }
    }

    Ok(connections)
}

/// List all listening TCP ports
pub fn list_tcp_listeners() -> WinResult<Vec<PortBinding>> {
    let mut bindings = Vec::new();

    // IPv4
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwState == MIB_TCP_STATE_LISTEN.0 as u32 {
                        bindings.push(PortBinding {
                            pid: row.dwOwningPid,
                            protocol: Protocol::Tcp,
                            local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_be())),
                            local_port: u16::from_be(row.dwLocalPort as u16),
                            state: Some(TcpState::Listen),
                        });
                    }
                }
            }
        }
    }

    // IPv6
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result == 0 {
                let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let rows =
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

                for row in rows {
                    if row.dwState == MIB_TCP_STATE_LISTEN.0 as u32 {
                        bindings.push(PortBinding {
                            pid: row.dwOwningPid,
                            protocol: Protocol::Tcp,
                            local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                            local_port: u16::from_be(row.dwLocalPort as u16),
                            state: Some(TcpState::Listen),
                        });
                    }
                }
            }
        }
    }

    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pids_listening_on_port_no_crash() {
        // Port 80 may or may not have a listener, but this shouldn't crash
        let result = pids_listening_on_port(80);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pids_for_port_no_crash() {
        let result = pids_for_port(443);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_tcp_listeners() {
        let listeners = list_tcp_listeners().expect("Should list TCP listeners");
        // There should be at least some listeners on a typical Windows system
        println!("Found {} TCP listeners", listeners.len());
        for binding in listeners.iter().take(5) {
            println!(
                "  {}:{} -> PID {} ({:?})",
                binding.local_addr, binding.local_port, binding.pid, binding.state
            );
        }
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
    }

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(format!("{}", TcpState::Listen), "LISTEN");
        assert_eq!(format!("{}", TcpState::Established), "ESTABLISHED");
    }
}
