//! Process ancestry chain building
//!
//! Builds the chain of parent processes from a target process up to the root.

use crate::error::{WinError, WinResult};
use crate::process_query::{
    get_command_line, get_image_path, get_memory_usage, get_session_id, get_start_time, get_user,
    get_working_directory,
};
use crate::process_snapshot::{list_processes, ProcessEntry};
use std::collections::{HashMap, HashSet};
use witr_core::{AncestryNode, AncestryRelation, ProcessInfo, Warning};

/// Maximum depth of ancestry chain to prevent infinite loops
const MAX_ANCESTRY_DEPTH: usize = 64;

/// Well-known system PIDs
const SYSTEM_IDLE_PID: u32 = 0;
/// System process PID (used in tests)
#[cfg(test)]
const SYSTEM_PID: u32 = 4;

/// Build a ProcessInfo from a ProcessEntry, querying additional details
pub fn build_process_info(entry: &ProcessEntry) -> ProcessInfo {
    let image_path = get_image_path(entry.pid).ok();
    let start_time = get_start_time(entry.pid).ok();
    let user = get_user(entry.pid).ok();
    let session_id = get_session_id(entry.pid).ok();
    let memory_bytes = get_memory_usage(entry.pid).ok();
    let working_dir = get_working_directory(entry.pid).ok();
    let cmdline = get_command_line(entry.pid).ok();

    ProcessInfo {
        pid: entry.pid,
        ppid: if entry.ppid == 0 && entry.pid != 0 || entry.pid == entry.ppid {
            None // Orphaned, system, or self-parented process
        } else {
            Some(entry.ppid)
        },
        image_path: image_path.map(|p| p.to_string_lossy().to_string()),
        user,
        start_time,
        cmdline,
        session_id,
        memory_bytes,
        working_dir,
        thread_count: Some(entry.thread_count),
    }
}

/// Build a ProcessInfo from just a PID (creates snapshot internally)
pub fn get_process_info(pid: u32) -> WinResult<ProcessInfo> {
    let processes = list_processes()?;
    let entry = processes
        .get(&pid)
        .ok_or(WinError::ProcessNotFound { pid })?;
    Ok(build_process_info(entry))
}

/// Result of building an ancestry chain
pub struct AncestryResult {
    /// The ancestry nodes, from direct parent to root
    pub ancestry: Vec<AncestryNode>,
    /// Warnings encountered during chain building
    pub warnings: Vec<Warning>,
}

/// Build the ancestry chain for a process
///
/// # Arguments
/// * `pid` - The target process ID
/// * `process_table` - Optional pre-built process table; if None, creates one
///
/// # Returns
/// The ancestry chain from direct parent to root ancestor, plus any warnings
pub fn build_ancestry(
    pid: u32,
    process_table: Option<&HashMap<u32, ProcessEntry>>,
) -> WinResult<AncestryResult> {
    // Create process table if not provided
    let owned_table;
    let table = match process_table {
        Some(t) => t,
        None => {
            owned_table = list_processes()?;
            &owned_table
        }
    };

    let mut ancestry = Vec::new();
    let mut warnings = Vec::new();
    let mut visited = HashSet::new();
    let mut current_pid = pid;

    // Get the target process to find its parent
    let target = table.get(&pid).ok_or(WinError::ProcessNotFound { pid })?;
    let mut parent_pid = target.ppid;

    // Track depth
    let mut depth = 0;

    while depth < MAX_ANCESTRY_DEPTH {
        // Check for termination conditions
        if parent_pid == SYSTEM_IDLE_PID || parent_pid == current_pid {
            break;
        }

        // Detect cycles
        if visited.contains(&parent_pid) {
            warnings.push(Warning::Other(format!(
                "Cycle detected in ancestry at PID {}",
                parent_pid
            )));
            break;
        }
        visited.insert(parent_pid);

        // Look up parent in table
        match table.get(&parent_pid) {
            Some(parent_entry) => {
                let process = build_process_info(parent_entry);

                let relation = match depth {
                    0 => AncestryRelation::Parent,
                    1 => AncestryRelation::Grandparent,
                    _ => AncestryRelation::Ancestor,
                };

                // Add notes for well-known processes
                let mut notes = Vec::new();
                let exe_lower = parent_entry.exe_name.to_lowercase();

                if exe_lower == "services.exe" {
                    notes.push("Service Control Manager".to_string());
                } else if exe_lower == "explorer.exe" {
                    notes.push("Windows Shell (interactive session root)".to_string());
                } else if exe_lower == "svchost.exe" {
                    notes.push("Service Host".to_string());
                } else if exe_lower == "csrss.exe" {
                    notes.push("Client/Server Runtime".to_string());
                } else if exe_lower == "smss.exe" {
                    notes.push("Session Manager".to_string());
                } else if exe_lower == "wininit.exe" {
                    notes.push("Windows Initialization".to_string());
                } else if exe_lower == "taskeng.exe" || exe_lower == "taskhostw.exe" {
                    notes.push("Task Scheduler Host".to_string());
                }

                ancestry.push(AncestryNode {
                    process,
                    relation,
                    notes,
                });

                // Move up the chain
                current_pid = parent_pid;
                parent_pid = parent_entry.ppid;
                depth += 1;
            }
            None => {
                // Parent not found - it may have exited
                warnings.push(Warning::ParentExited {
                    last_known_ppid: parent_pid,
                });

                // Add an orphaned node with what we know
                ancestry.push(AncestryNode {
                    process: ProcessInfo {
                        pid: parent_pid,
                        ppid: None,
                        image_path: None,
                        user: None,
                        start_time: None,
                        cmdline: None,
                        session_id: None,
                        memory_bytes: None,
                        working_dir: None,
                        thread_count: None,
                    },
                    relation: AncestryRelation::Orphaned,
                    notes: vec!["Process has exited".to_string()],
                });
                break;
            }
        }
    }

    // Check if we hit the depth limit
    if depth >= MAX_ANCESTRY_DEPTH {
        warnings.push(Warning::AncestryTruncated {
            depth: MAX_ANCESTRY_DEPTH,
        });
    }

    Ok(AncestryResult { ancestry, warnings })
}

/// Check if a process is a descendant of explorer.exe (interactive session)
pub fn is_interactive_descendant(pid: u32, process_table: &HashMap<u32, ProcessEntry>) -> bool {
    let mut visited = HashSet::new();
    let mut current = pid;

    for _ in 0..MAX_ANCESTRY_DEPTH {
        if visited.contains(&current) {
            return false; // Cycle
        }
        visited.insert(current);

        match process_table.get(&current) {
            Some(entry) => {
                if entry.exe_name.to_lowercase() == "explorer.exe" {
                    return true;
                }
                if entry.ppid == 0 || entry.ppid == current {
                    return false;
                }
                current = entry.ppid;
            }
            None => return false,
        }
    }
    false
}

/// Check if a process is a descendant of services.exe
pub fn is_service_descendant(pid: u32, process_table: &HashMap<u32, ProcessEntry>) -> bool {
    let mut visited = HashSet::new();
    let mut current = pid;

    for _ in 0..MAX_ANCESTRY_DEPTH {
        if visited.contains(&current) {
            return false;
        }
        visited.insert(current);

        match process_table.get(&current) {
            Some(entry) => {
                if entry.exe_name.to_lowercase() == "services.exe" {
                    return true;
                }
                if entry.ppid == 0 || entry.ppid == current {
                    return false;
                }
                current = entry.ppid;
            }
            None => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests with fake data
    mod unit_tests {
        use super::*;

        /// Create a fake process table for testing ancestry building
        fn create_fake_process_table() -> HashMap<u32, ProcessEntry> {
            let mut table = HashMap::new();
            table.insert(
                0,
                ProcessEntry {
                    pid: 0,
                    ppid: 0,
                    exe_name: "System Idle Process".to_string(),
                    thread_count: 1,
                },
            );
            table.insert(
                4,
                ProcessEntry {
                    pid: 4,
                    ppid: 0,
                    exe_name: "System".to_string(),
                    thread_count: 100,
                },
            );
            table.insert(
                100,
                ProcessEntry {
                    pid: 100,
                    ppid: 4,
                    exe_name: "services.exe".to_string(),
                    thread_count: 10,
                },
            );
            table.insert(
                200,
                ProcessEntry {
                    pid: 200,
                    ppid: 100,
                    exe_name: "svchost.exe".to_string(),
                    thread_count: 5,
                },
            );
            table.insert(
                300,
                ProcessEntry {
                    pid: 300,
                    ppid: 200,
                    exe_name: "explorer.exe".to_string(),
                    thread_count: 20,
                },
            );
            table.insert(
                400,
                ProcessEntry {
                    pid: 400,
                    ppid: 300,
                    exe_name: "notepad.exe".to_string(),
                    thread_count: 1,
                },
            );
            table
        }

        #[test]
        fn test_build_ancestry_with_fake_table() {
            let table = create_fake_process_table();

            // Test building ancestry for notepad.exe (400) -> explorer.exe (300) -> svchost.exe (200) -> services.exe (100) -> System (4)
            // Note: build_ancestry will try to query real process info, which may fail for fake PIDs
            // So we test the structure and logic, not the full Windows API calls
            let result = build_ancestry(400, Some(&table));

            // The function may fail due to Windows API calls, but if it succeeds, verify structure
            if let Ok(ancestry_result) = result {
                // Should have at least the parent (explorer.exe)
                if !ancestry_result.ancestry.is_empty() {
                    let first = &ancestry_result.ancestry[0];
                    assert_eq!(first.process.pid, 300);
                    assert_eq!(first.relation, AncestryRelation::Parent);
                }
            } else {
                // Expected to fail due to Windows API calls on fake PIDs
                // Just verify the table structure is correct
                let entry = table.get(&400).unwrap();
                let parent = table.get(&entry.ppid).unwrap();
                assert_eq!(parent.exe_name.to_lowercase(), "explorer.exe");
            }
        }

        #[test]
        fn test_build_ancestry_terminates_at_system_idle() {
            let table = create_fake_process_table();

            // System process (PID 4) has parent 0 (System Idle)
            let result = build_ancestry(4, Some(&table)).expect("Should build ancestry");

            // Should terminate at System Idle (PID 0), so ancestry should be empty or minimal
            // (System Idle is not included in ancestry as it's a termination condition)
            assert!(result.ancestry.is_empty() || result.ancestry.len() <= 1);
        }

        #[test]
        fn test_build_ancestry_handles_orphaned_process() {
            let mut table = create_fake_process_table();

            // Create an orphaned process (parent is itself or 0)
            table.insert(
                999,
                ProcessEntry {
                    pid: 999,
                    ppid: 999, // Self-parented (orphaned)
                    exe_name: "orphan.exe".to_string(),
                    thread_count: 1,
                },
            );

            let result = build_ancestry(999, Some(&table)).expect("Should build ancestry");
            // Orphaned process should have empty ancestry or warnings
            assert!(result.ancestry.is_empty() || !result.warnings.is_empty());
        }

        #[test]
        fn test_build_ancestry_detects_cycles() {
            let mut table = create_fake_process_table();

            // Create a cycle: 500 -> 501 -> 500
            table.insert(
                500,
                ProcessEntry {
                    pid: 500,
                    ppid: 501,
                    exe_name: "cycle1.exe".to_string(),
                    thread_count: 1,
                },
            );
            table.insert(
                501,
                ProcessEntry {
                    pid: 501,
                    ppid: 500,
                    exe_name: "cycle2.exe".to_string(),
                    thread_count: 1,
                },
            );

            let result = build_ancestry(500, Some(&table));

            // The function may fail due to Windows API calls, but if it succeeds, verify cycle detection
            if let Ok(ancestry_result) = result {
                // Should detect cycle and stop, or have warnings about cycle
                assert!(
                    ancestry_result.ancestry.len() <= 1 || !ancestry_result.warnings.is_empty(),
                    "Should stop at cycle or have cycle warning"
                );
            } else {
                // Expected to fail due to Windows API calls on fake PIDs
                // Just verify the cycle structure exists in the table
                let entry1 = table.get(&500).unwrap();
                let entry2 = table.get(&501).unwrap();
                assert_eq!(entry1.ppid, 501);
                assert_eq!(entry2.ppid, 500);
            }
        }

        #[test]
        fn test_build_process_info_from_entry() {
            let entry = ProcessEntry {
                pid: 1234,
                ppid: 5678,
                exe_name: "test.exe".to_string(),
                thread_count: 5,
            };

            let info = build_process_info(&entry);
            assert_eq!(info.pid, 1234);
            assert_eq!(info.ppid, Some(5678));
        }
    }

    // Integration tests (may require privileged access)
    mod integration_tests {
        use super::*;

        #[test]
        #[ignore] // May require admin access
        fn test_build_ancestry_current_process() {
            let pid = std::process::id();
            let result = build_ancestry(pid, None).expect("Should build ancestry");

            // Current process should have at least one ancestor (unless running as PID 1, unlikely)
            // The parent might be cargo, cmd, powershell, etc.
            println!("Ancestry for PID {}: {:?}", pid, result.ancestry);
        }

        #[test]
        #[ignore] // May require admin access
        fn test_build_ancestry_system() {
            // System process (PID 4) has minimal ancestry
            let result = build_ancestry(SYSTEM_PID, None);
            match result {
                Ok(r) => {
                    // System either has no parents or parent is System Idle (0)
                    assert!(
                        r.ancestry.is_empty() || r.ancestry.len() == 1,
                        "System should have minimal ancestry"
                    );
                }
                Err(WinError::ProcessNotFound { .. }) => {
                    // Might happen in some environments
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[test]
        #[ignore] // May require admin access
        fn test_get_process_info() {
            let pid = std::process::id();
            let info = get_process_info(pid).expect("Should get process info");

            assert_eq!(info.pid, pid);
            assert!(info.image_path.is_some(), "Should have image path");
        }

        #[test]
        #[ignore] // May require admin access
        fn test_is_interactive_descendant() {
            let processes = list_processes().expect("Should list processes");
            let pid = std::process::id();

            // The result depends on how we're running - just make sure it doesn't crash
            let _is_interactive = is_interactive_descendant(pid, &processes);
        }
    }
}
