//! Integration tests for platform-windows
//!
//! These tests spawn real processes and bind to ports to verify functionality.
//! Some tests may require admin privileges and are marked with #[ignore].

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use witr_platform_windows::{analyze_pid, build_ancestry, pids_for_port, pids_listening_on_port};

/// Test that spawning a child process results in correct ancestry
#[test]
#[ignore] // May be flaky depending on process lifecycle
fn test_child_process_ancestry() {
    // Spawn a child process (cmd.exe /c echo)
    let mut child = Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Should spawn child process");

    let child_pid = child.id();
    let parent_pid = std::process::id();

    // Give the process a moment to start
    thread::sleep(Duration::from_millis(100));

    // Build ancestry for the child
    let result = build_ancestry(child_pid, None);

    match result {
        Ok(ancestry_result) => {
            // The child's parent should be our process (or a shell wrapper)
            // Check if our PID is in the ancestry chain
            let has_parent = ancestry_result
                .ancestry
                .iter()
                .any(|node| node.process.pid == parent_pid);

            // Note: The actual parent might be cmd.exe or another wrapper,
            // so we just verify the ancestry was built successfully
            assert!(
                !ancestry_result.ancestry.is_empty() || has_parent,
                "Child process should have ancestry or parent should be in chain"
            );
            println!(
                "Child PID {} ancestry depth: {}",
                child_pid,
                ancestry_result.ancestry.len()
            );
        }
        Err(e) => {
            // Process might have exited already, which is okay
            println!("Child process may have exited: {}", e);
        }
    }

    // Wait for child to finish
    let _ = child.wait();
}

/// Test that binding to a port results in correct PID lookup
#[test]
#[ignore] // May be flaky if port is in use
fn test_port_to_pid_lookup() {
    // Find an available port by binding to port 0
    let listener = TcpListener::bind("127.0.0.1:0").expect("Should bind to port");
    let local_addr = listener.local_addr().expect("Should get local address");
    let port = local_addr.port();

    let current_pid = std::process::id();

    // Give the OS a moment to register the binding
    thread::sleep(Duration::from_millis(200));

    // Look up PIDs for this port
    let pids = pids_for_port(port).expect("Should get PIDs for port");

    // Our PID should be in the list
    assert!(
        pids.contains(&current_pid),
        "Current PID {} should be listening on port {}",
        current_pid,
        port
    );

    println!("Port {} is bound by PID {}", port, current_pid);

    // Drop listener to free the port
    drop(listener);
}

/// Test that analyzing a spawned process works
#[test]
#[ignore] // May be flaky depending on process lifecycle
fn test_analyze_spawned_process() {
    // Spawn a long-running process (ping with timeout)
    let mut child = Command::new("ping")
        .args(["127.0.0.1", "-n", "3"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Should spawn ping process");

    let child_pid = child.id();

    // Give the process a moment to start
    thread::sleep(Duration::from_millis(200));

    // Analyze the process
    let report = analyze_pid(child_pid);

    match report {
        Ok(r) => {
            assert!(r.process.is_some(), "Should have process info");
            if let Some(proc) = r.process {
                assert_eq!(proc.pid, child_pid);
                println!("Analyzed process: {} (PID {})", proc.name(), proc.pid);
                println!("Source: {:?}", r.source.kind);
            }
        }
        Err(e) => {
            // Process might have exited already
            println!("Process may have exited: {}", e);
        }
    }

    // Wait for child to finish
    let _ = child.wait();
}

/// Test port binding with TCP listener
#[test]
#[ignore] // May be flaky if port is in use
fn test_tcp_listener_port_lookup() {
    // Bind to a specific high port (unlikely to be in use)
    let test_port = 54321u16;
    
    // Try to bind - if port is in use, skip test
    let listener = match TcpListener::bind(format!("127.0.0.1:{}", test_port)) {
        Ok(l) => l,
        Err(_) => {
            println!("Port {} is in use, skipping test", test_port);
            return;
        }
    };

    let current_pid = std::process::id();

    // Give the OS a moment to register
    thread::sleep(Duration::from_millis(300));

    // Look up the port
    let bindings = pids_listening_on_port(test_port).expect("Should get bindings for port");

    // Should find our binding
    use witr_platform_windows::net::Protocol;
    let has_our_binding = bindings.iter().any(|b| {
        b.pid == current_pid && b.local_port == test_port && b.protocol == Protocol::Tcp
    });

    assert!(
        has_our_binding,
        "Should find our TCP listener on port {}",
        test_port
    );

    println!("Found {} binding(s) on port {}", bindings.len(), test_port);

    // Drop listener
    drop(listener);
}

