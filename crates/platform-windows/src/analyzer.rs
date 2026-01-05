//! Full process analysis and report generation
//!
//! Combines all collectors and classifiers to build a complete Report.

use crate::ancestry::{build_ancestry, build_process_info};
use crate::classifier::{classify_process, detect_warnings};
use crate::error::WinResult;
use crate::net::{pids_listening_on_port, PortBinding};
use crate::process_snapshot::{get_process_entry, list_processes};
use witr_core::{Report, Target, Warning};

/// Build a complete report for a PID
pub fn analyze_pid(pid: u32) -> WinResult<Report> {
    let mut report = Report::new(Target::Pid(pid));

    // Get process info
    match get_process_entry(pid) {
        Ok(entry) => {
            let process_info = build_process_info(&entry);

            // Detect warnings based on process info
            let info_warnings = detect_warnings(pid, Some(&process_info));
            for warning in info_warnings {
                report.add_warning(warning);
            }

            report.process = Some(process_info);
        }
        Err(e) => {
            report.add_error(format!("Could not get process info: {}", e));
            return Ok(report);
        }
    }

    // Build ancestry
    let processes = list_processes()?;
    match build_ancestry(pid, Some(&processes)) {
        Ok(ancestry_result) => {
            report.ancestry = ancestry_result.ancestry;
            for warning in ancestry_result.warnings {
                report.add_warning(warning);
            }
        }
        Err(e) => {
            report.add_error(format!("Could not build ancestry: {}", e));
        }
    }

    // Classify source
    match classify_process(pid) {
        Ok(classification_result) => {
            report.source = classification_result.classification;
            report.evidence = classification_result.evidence;
            for warning in classification_result.warnings {
                report.add_warning(warning);
            }
        }
        Err(e) => {
            report.add_error(format!("Could not classify process: {}", e));
        }
    }

    Ok(report)
}

/// Build a complete report for a port
pub fn analyze_port(port: u16) -> WinResult<PortAnalysisResult> {
    let bindings = pids_listening_on_port(port)?;

    if bindings.is_empty() {
        return Ok(PortAnalysisResult {
            port,
            bindings: Vec::new(),
            reports: Vec::new(),
            warnings: vec![Warning::Other(format!(
                "No process found listening on port {}",
                port
            ))],
        });
    }

    let mut result = PortAnalysisResult {
        port,
        bindings: bindings.clone(),
        reports: Vec::new(),
        warnings: Vec::new(),
    };

    // Check for listening on all interfaces
    for binding in &bindings {
        if binding.local_addr.is_unspecified() {
            result.warnings.push(Warning::Other(format!(
                "Port {} is listening on all interfaces ({})",
                port, binding.local_addr
            )));
        }
    }

    // Get unique PIDs
    let mut pids: Vec<u32> = bindings.iter().map(|b| b.pid).collect();
    pids.sort();
    pids.dedup();

    // Analyze each PID
    for pid in pids {
        match analyze_pid(pid) {
            Ok(mut report) => {
                // Update target to include port info
                report.target = Target::Port(port);
                result.reports.push(report);
            }
            Err(e) => {
                result.warnings.push(Warning::Other(format!(
                    "Could not analyze PID {}: {}",
                    pid, e
                )));
            }
        }
    }

    Ok(result)
}

/// Build reports for processes matching a name
pub fn analyze_name(name: &str) -> WinResult<NameAnalysisResult> {
    let processes = list_processes()?;
    let name_lower = name.to_lowercase();

    let matches: Vec<_> = processes
        .values()
        .filter(|p| p.exe_name.to_lowercase().contains(&name_lower))
        .collect();

    if matches.is_empty() {
        return Ok(NameAnalysisResult {
            name: name.to_string(),
            reports: Vec::new(),
            warnings: vec![Warning::Other(format!(
                "No process found matching '{}'",
                name
            ))],
        });
    }

    let mut result = NameAnalysisResult {
        name: name.to_string(),
        reports: Vec::new(),
        warnings: Vec::new(),
    };

    for entry in matches {
        match analyze_pid(entry.pid) {
            Ok(mut report) => {
                report.target = Target::Name(name.to_string());
                result.reports.push(report);
            }
            Err(e) => {
                result.warnings.push(Warning::Other(format!(
                    "Could not analyze PID {}: {}",
                    entry.pid, e
                )));
            }
        }
    }

    Ok(result)
}

/// Result of port analysis (may contain multiple processes)
pub struct PortAnalysisResult {
    /// The queried port
    pub port: u16,
    /// All bindings on this port
    pub bindings: Vec<PortBinding>,
    /// Reports for each unique PID
    pub reports: Vec<Report>,
    /// Warnings
    pub warnings: Vec<Warning>,
}

impl PortAnalysisResult {
    /// Get the primary report (first one)
    pub fn primary_report(&self) -> Option<&Report> {
        self.reports.first()
    }

    /// Check if multiple PIDs are bound to this port
    pub fn has_multiple_pids(&self) -> bool {
        self.reports.len() > 1
    }
}

/// Result of name analysis (may contain multiple processes)
pub struct NameAnalysisResult {
    /// The queried name
    pub name: String,
    /// Reports for each matching process
    pub reports: Vec<Report>,
    /// Warnings
    pub warnings: Vec<Warning>,
}

impl NameAnalysisResult {
    /// Get the primary report (first one)
    pub fn primary_report(&self) -> Option<&Report> {
        self.reports.first()
    }

    /// Check if multiple processes match
    pub fn has_multiple_matches(&self) -> bool {
        self.reports.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_pid_current() {
        let pid = std::process::id();
        let report = analyze_pid(pid).expect("Should analyze current process");

        assert!(report.process.is_some());
        println!("Report for current process:");
        println!("  Source: {:?}", report.source.kind);
        println!("  Evidence count: {}", report.evidence.len());
        println!("  Ancestry depth: {}", report.ancestry.len());
    }

    #[test]
    fn test_analyze_port_no_listener() {
        // Use a port that's unlikely to have a listener
        let result = analyze_port(59999).expect("Should analyze port");

        if result.reports.is_empty() {
            assert!(!result.warnings.is_empty());
            println!("No listener on port 59999 (expected)");
        }
    }

    #[test]
    fn test_analyze_name_system() {
        let result = analyze_name("System").expect("Should analyze by name");

        println!("Found {} matches for 'System'", result.reports.len());
        for report in &result.reports {
            if let Some(proc) = &report.process {
                println!("  {} (PID {})", proc.name(), proc.pid);
            }
        }
    }

    #[test]
    fn test_port_analysis_result() {
        let result = PortAnalysisResult {
            port: 80,
            bindings: vec![],
            reports: vec![],
            warnings: vec![],
        };
        assert!(!result.has_multiple_pids());
        assert!(result.primary_report().is_none());
    }
}
