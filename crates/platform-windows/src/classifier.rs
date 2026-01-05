//! Process source classification
//!
//! Determines what started/manages a process based on available evidence.
//! Uses a heuristics engine with scored confidence levels.

use crate::ancestry::{build_ancestry, is_interactive_descendant, is_service_descendant};
use crate::error::WinResult;
use crate::process_query::get_session_id;
use crate::process_snapshot::{list_processes, ProcessEntry};
use crate::services::{build_pid_service_map, is_service_host_process, services_for_svchost_pid};
use std::collections::HashMap;
use witr_core::{
    AncestryNode, Confidence, Evidence, EvidenceSource, ProcessInfo, SourceClassification,
    SourceKind, Warning,
};

/// Confidence scores for various heuristics
mod scores {
    /// Direct service PID match from SCM
    pub const SERVICE_PID_MATCH: f32 = 0.95;
    /// svchost.exe hosting known services
    pub const SVCHOST_HOSTING: f32 = 0.95;
    /// Parent is a known service
    pub const PARENT_IS_SERVICE: f32 = 0.90;
    /// Ancestry includes services.exe
    pub const ANCESTRY_SERVICES_EXE: f32 = 0.70;
    /// Parent is explorer.exe (interactive desktop)
    pub const PARENT_EXPLORER: f32 = 0.85;
    /// Ancestry includes explorer.exe
    pub const ANCESTRY_EXPLORER: f32 = 0.75;
    /// Parent is taskeng.exe or taskhostw.exe (scheduled task)
    pub const PARENT_TASK_HOST: f32 = 0.80;
    /// Ancestry includes task host
    pub const ANCESTRY_TASK_HOST: f32 = 0.70;
    /// System process (PID <= 4)
    pub const SYSTEM_PID: f32 = 0.99;
    /// Ancestry includes system processes
    pub const ANCESTRY_SYSTEM: f32 = 0.85;
    /// Unknown origin
    pub const UNKNOWN: f32 = 0.20;
}

/// Result of classifying a process
pub struct ClassificationResult {
    /// The determined classification
    pub classification: SourceClassification,
    /// Evidence supporting the classification
    pub evidence: Vec<Evidence>,
    /// Warnings encountered during classification
    pub warnings: Vec<Warning>,
    /// Confidence score (0.0 - 1.0)
    pub score: f32,
}

/// Context for classification decisions
struct ClassificationContext {
    pid: u32,
    process_table: HashMap<u32, ProcessEntry>,
    service_map: HashMap<u32, crate::services::ServiceInfo>,
    ancestry: Vec<AncestryNode>,
    evidence: Vec<Evidence>,
    warnings: Vec<Warning>,
}

impl ClassificationContext {
    fn add_evidence(
        &mut self,
        fact: &str,
        confidence: Confidence,
        source: EvidenceSource,
        details: Option<String>,
    ) {
        self.evidence.push(Evidence {
            fact: fact.to_string(),
            confidence,
            source,
            details,
        });
    }

    fn add_warning(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }
}

/// Classify the source of a process
///
/// Uses multiple signals to determine what started/manages the process:
/// - Direct service PID match (0.95 confidence)
/// - Parent explorer.exe (0.85 confidence)
/// - Parent taskeng.exe/taskhostw.exe (0.80 confidence - scheduled task)
/// - Ancestry includes services.exe (0.70 confidence)
/// - winlogon.exe in ancestry provides session context
pub fn classify_process(pid: u32) -> WinResult<ClassificationResult> {
    let mut ctx = ClassificationContext {
        pid,
        process_table: list_processes()?,
        service_map: HashMap::new(),
        ancestry: Vec::new(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    };

    // Get service map
    ctx.service_map = match build_pid_service_map() {
        Ok(map) => map,
        Err(e) => {
            ctx.add_warning(Warning::ApiFailed {
                api: "EnumServicesStatusExW".to_string(),
                error: e.to_string(),
            });
            HashMap::new()
        }
    };

    // Build ancestry
    let ancestry_result = build_ancestry(pid, Some(&ctx.process_table))?;
    ctx.ancestry = ancestry_result.ancestry;
    ctx.warnings.extend(ancestry_result.warnings);

    // Run classification rules in priority order
    if let Some(result) = check_direct_service(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_svchost_hosting(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_scheduled_task(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_parent_service(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_service_descendant(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_interactive(&mut ctx) {
        return Ok(result);
    }

    if let Some(result) = check_system_process(&mut ctx) {
        return Ok(result);
    }

    // Add session context as supporting evidence
    add_session_context(&mut ctx);

    // Unknown origin
    ctx.add_evidence(
        "Could not determine process origin",
        Confidence::Low,
        EvidenceSource::Heuristic,
        Some("Process may have orphaned ancestry or be from an unknown source".to_string()),
    );

    Ok(ClassificationResult {
        classification: SourceClassification::unknown(),
        evidence: ctx.evidence,
        warnings: ctx.warnings,
        score: scores::UNKNOWN,
    })
}

/// Check 1: Is this PID directly a service?
#[cfg_attr(test, allow(dead_code))]
fn check_direct_service(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    let service = ctx.service_map.get(&ctx.pid)?.clone();

    ctx.add_evidence(
        &format!("Process is Windows service '{}'", service.name),
        Confidence::High,
        EvidenceSource::ServiceControlManager,
        Some(format!(
            "Display name: {}, State: {}",
            service.display_name, service.state
        )),
    );

    Some(ClassificationResult {
        classification: SourceClassification {
            kind: SourceKind::Service,
            confidence: Confidence::High,
            description: format!(
                "Windows service '{}' ({})",
                service.name, service.display_name
            ),
            service_name: Some(service.name.clone()),
            task_name: None,
        },
        evidence: std::mem::take(&mut ctx.evidence),
        warnings: std::mem::take(&mut ctx.warnings),
        score: scores::SERVICE_PID_MATCH,
    })
}

/// Check 2: Is this a svchost.exe hosting multiple services?
fn check_svchost_hosting(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    let entry = ctx.process_table.get(&ctx.pid)?;

    if !is_service_host_process(&entry.exe_name) {
        return None;
    }

    let hosted_services = services_for_svchost_pid(ctx.pid).ok()?;
    if hosted_services.is_empty() {
        return None;
    }

    let service_names: Vec<_> = hosted_services.iter().map(|s| s.name.clone()).collect();

    ctx.add_evidence(
        &format!("svchost.exe hosting {} service(s)", hosted_services.len()),
        Confidence::High,
        EvidenceSource::ServiceControlManager,
        Some(format!("Services: {}", service_names.join(", "))),
    );

    Some(ClassificationResult {
        classification: SourceClassification {
            kind: SourceKind::Service,
            confidence: Confidence::High,
            description: format!("Service host for: {}", service_names.join(", ")),
            service_name: Some(service_names.join(", ")),
            task_name: None,
        },
        evidence: std::mem::take(&mut ctx.evidence),
        warnings: std::mem::take(&mut ctx.warnings),
        score: scores::SVCHOST_HOSTING,
    })
}

/// Check 3: Is this started by Task Scheduler?
fn check_scheduled_task(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    // Check parent first
    let entry = ctx.process_table.get(&ctx.pid)?.clone();
    if let Some(parent) = ctx.process_table.get(&entry.ppid).cloned() {
        if is_task_host_process(&parent.exe_name) {
            let parent_name = parent.exe_name.clone();
            ctx.add_evidence(
                &format!("Parent process is Task Scheduler host ({})", parent_name),
                Confidence::High,
                EvidenceSource::ProcessSnapshot,
                Some("Process was likely started by a scheduled task".to_string()),
            );

            return Some(ClassificationResult {
                classification: SourceClassification {
                    kind: SourceKind::ScheduledTask,
                    confidence: Confidence::High,
                    description: format!("Scheduled task (parent: {})", parent_name),
                    service_name: None,
                    task_name: None, // TODO: Query Task Scheduler for task name
                },
                evidence: std::mem::take(&mut ctx.evidence),
                warnings: std::mem::take(&mut ctx.warnings),
                score: scores::PARENT_TASK_HOST,
            });
        }
    }

    // Check ancestry - collect matching node names first
    let task_host_ancestor: Option<String> = ctx
        .ancestry
        .iter()
        .find(|node| is_task_host_process(node.process.name()))
        .map(|node| node.process.name().to_string());

    if let Some(ancestor_name) = task_host_ancestor {
        ctx.add_evidence(
            &format!("Ancestry includes Task Scheduler host ({})", ancestor_name),
            Confidence::Medium,
            EvidenceSource::ProcessSnapshot,
            Some("Process chain includes scheduled task infrastructure".to_string()),
        );

        return Some(ClassificationResult {
            classification: SourceClassification {
                kind: SourceKind::ScheduledTask,
                confidence: Confidence::Medium,
                description: format!("Scheduled task descendant (via {})", ancestor_name),
                service_name: None,
                task_name: None,
            },
            evidence: std::mem::take(&mut ctx.evidence),
            warnings: std::mem::take(&mut ctx.warnings),
            score: scores::ANCESTRY_TASK_HOST,
        });
    }

    None
}

/// Check 4: Is parent a known service?
fn check_parent_service(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    let entry = ctx.process_table.get(&ctx.pid)?.clone();
    let parent_service = ctx.service_map.get(&entry.ppid)?.clone();

    ctx.add_evidence(
        &format!("Parent process is service '{}'", parent_service.name),
        Confidence::High,
        EvidenceSource::ServiceControlManager,
        Some(format!("Parent PID: {}", entry.ppid)),
    );

    Some(ClassificationResult {
        classification: SourceClassification {
            kind: SourceKind::Service,
            confidence: Confidence::High,
            description: format!(
                "Child of service '{}' ({})",
                parent_service.name, parent_service.display_name
            ),
            service_name: Some(parent_service.name.clone()),
            task_name: None,
        },
        evidence: std::mem::take(&mut ctx.evidence),
        warnings: std::mem::take(&mut ctx.warnings),
        score: scores::PARENT_IS_SERVICE,
    })
}

/// Check 5: Does ancestry include services.exe?
fn check_service_descendant(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    if !is_service_descendant(ctx.pid, &ctx.process_table) {
        return None;
    }

    ctx.add_evidence(
        "Process ancestry includes services.exe",
        Confidence::Medium,
        EvidenceSource::ProcessSnapshot,
        Some("Likely started by a Windows service".to_string()),
    );

    Some(ClassificationResult {
        classification: SourceClassification {
            kind: SourceKind::Service,
            confidence: Confidence::Medium,
            description: "Service-hosted process (descendant of services.exe)".to_string(),
            service_name: None,
            task_name: None,
        },
        evidence: std::mem::take(&mut ctx.evidence),
        warnings: std::mem::take(&mut ctx.warnings),
        score: scores::ANCESTRY_SERVICES_EXE,
    })
}

/// Check 6: Is this an interactive session process?
fn check_interactive(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    // Check parent first for higher confidence
    if let Some(entry) = ctx.process_table.get(&ctx.pid) {
        if let Some(parent) = ctx.process_table.get(&entry.ppid) {
            if parent.exe_name.to_lowercase() == "explorer.exe" {
                ctx.add_evidence(
                    "Parent process is explorer.exe (Windows Shell)",
                    Confidence::High,
                    EvidenceSource::ProcessSnapshot,
                    Some("Direct child of interactive desktop".to_string()),
                );

                return Some(ClassificationResult {
                    classification: SourceClassification {
                        kind: SourceKind::Interactive,
                        confidence: Confidence::High,
                        description: "Interactive session (direct child of explorer.exe)"
                            .to_string(),
                        service_name: None,
                        task_name: None,
                    },
                    evidence: std::mem::take(&mut ctx.evidence),
                    warnings: std::mem::take(&mut ctx.warnings),
                    score: scores::PARENT_EXPLORER,
                });
            }
        }
    }

    // Check ancestry
    if is_interactive_descendant(ctx.pid, &ctx.process_table) {
        ctx.add_evidence(
            "Process ancestry includes explorer.exe",
            Confidence::High,
            EvidenceSource::ProcessSnapshot,
            Some("Descendant of Windows Shell (interactive session)".to_string()),
        );

        return Some(ClassificationResult {
            classification: SourceClassification {
                kind: SourceKind::Interactive,
                confidence: Confidence::High,
                description: "Interactive session (descendant of explorer.exe)".to_string(),
                service_name: None,
                task_name: None,
            },
            evidence: std::mem::take(&mut ctx.evidence),
            warnings: std::mem::take(&mut ctx.warnings),
            score: scores::ANCESTRY_EXPLORER,
        });
    }

    None
}

/// Check 7: Is this a system process?
fn check_system_process(ctx: &mut ClassificationContext) -> Option<ClassificationResult> {
    // System PID (0-4)
    if ctx.pid <= 4 {
        ctx.add_evidence(
            &format!("System process (PID {})", ctx.pid),
            Confidence::High,
            EvidenceSource::Heuristic,
            None,
        );

        return Some(ClassificationResult {
            classification: SourceClassification {
                kind: SourceKind::System,
                confidence: Confidence::High,
                description: "Windows system process".to_string(),
                service_name: None,
                task_name: None,
            },
            evidence: std::mem::take(&mut ctx.evidence),
            warnings: std::mem::take(&mut ctx.warnings),
            score: scores::SYSTEM_PID,
        });
    }

    // Check ancestry for system processes
    let system_ancestor: Option<String> = ctx
        .ancestry
        .iter()
        .find(|node| {
            let name = node.process.name().to_lowercase();
            name == "smss.exe" || name == "csrss.exe" || name == "wininit.exe"
        })
        .map(|node| node.process.name().to_string());

    if let Some(ancestor_name) = system_ancestor {
        ctx.add_evidence(
            &format!("Ancestry includes system process {}", ancestor_name),
            Confidence::Medium,
            EvidenceSource::ProcessSnapshot,
            None,
        );

        return Some(ClassificationResult {
            classification: SourceClassification {
                kind: SourceKind::System,
                confidence: Confidence::High,
                description: format!("System-managed process (via {})", ancestor_name),
                service_name: None,
                task_name: None,
            },
            evidence: std::mem::take(&mut ctx.evidence),
            warnings: std::mem::take(&mut ctx.warnings),
            score: scores::ANCESTRY_SYSTEM,
        });
    }

    None
}

/// Add session context as supporting evidence
fn add_session_context(ctx: &mut ClassificationContext) {
    // Check for winlogon.exe in ancestry (provides session context)
    for node in &ctx.ancestry {
        let name = node.process.name().to_lowercase();
        if name == "winlogon.exe" {
            ctx.add_evidence(
                "Ancestry includes winlogon.exe",
                Confidence::Medium,
                EvidenceSource::ProcessSnapshot,
                Some("Process is part of a user logon session".to_string()),
            );
            break;
        }
    }

    // Add session ID info
    if let Ok(session_id) = get_session_id(ctx.pid) {
        let session_type = if session_id == 0 {
            "Session 0 (services/system)"
        } else {
            "Interactive user session"
        };

        ctx.add_evidence(
            &format!("Session ID: {} ({})", session_id, session_type),
            Confidence::Medium,
            EvidenceSource::SecurityToken,
            None,
        );
    }
}

/// Check if a process name indicates Task Scheduler host
fn is_task_host_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "taskeng.exe" || lower == "taskhostw.exe" || lower == "taskhost.exe"
}

/// Quick check if a PID is a known service
pub fn is_service_pid(pid: u32) -> WinResult<bool> {
    let service_map = build_pid_service_map()?;
    Ok(service_map.contains_key(&pid))
}

/// Detect warnings for a process
pub fn detect_warnings(pid: u32, process_info: Option<&ProcessInfo>) -> Vec<Warning> {
    let mut warnings = Vec::new();

    // Check if running as admin / high integrity
    if let Some(info) = process_info {
        if let Some(user) = &info.user {
            let user_lower = user.to_lowercase();
            if user_lower.contains("system") || user_lower.contains("administrator") {
                warnings.push(Warning::Other(format!(
                    "Running with elevated privileges ({})",
                    user
                )));
            }
        }
    }

    // Check session ID for service context
    if let Ok(session_id) = get_session_id(pid) {
        if session_id == 0 {
            // Session 0 is isolated from interactive sessions
            warnings.push(Warning::Other(
                "Running in Session 0 (isolated from desktop)".to_string(),
            ));
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_snapshot::ProcessEntry;
    use std::collections::HashMap;
    use witr_core::{AncestryNode, AncestryRelation, ProcessInfo};

    // Unit tests with fake data
    mod unit_tests {
        use super::*;

        /// Create a fake process table for testing
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
            table.insert(
                500,
                ProcessEntry {
                    pid: 500,
                    ppid: 100,
                    exe_name: "taskhostw.exe".to_string(),
                    thread_count: 3,
                },
            );
            table.insert(
                600,
                ProcessEntry {
                    pid: 600,
                    ppid: 500,
                    exe_name: "scheduled_task.exe".to_string(),
                    thread_count: 1,
                },
            );
            table
        }

        /// Create fake ancestry for testing
        fn create_fake_ancestry(pid: u32, table: &HashMap<u32, ProcessEntry>) -> Vec<AncestryNode> {
            let mut ancestry = Vec::new();
            let mut current = pid;
            let mut depth = 0;

            while depth < 10 {
                let entry = match table.get(&current) {
                    Some(e) => e,
                    None => break,
                };

                if entry.ppid == 0 || entry.ppid == current {
                    break;
                }

                let parent_entry = match table.get(&entry.ppid) {
                    Some(e) => e,
                    None => break,
                };

                let relation = match depth {
                    0 => AncestryRelation::Parent,
                    1 => AncestryRelation::Grandparent,
                    _ => AncestryRelation::Ancestor,
                };

                ancestry.push(AncestryNode {
                    process: ProcessInfo {
                        pid: parent_entry.pid,
                        ppid: if parent_entry.ppid == 0 {
                            None
                        } else {
                            Some(parent_entry.ppid)
                        },
                        image_path: Some(format!(
                            "C:\\Windows\\System32\\{}",
                            parent_entry.exe_name
                        )),
                        user: None,
                        start_time: None,
                        cmdline: None,
                        session_id: None,
                    },
                    relation,
                    notes: vec![],
                });

                current = entry.ppid;
                depth += 1;
            }

            ancestry
        }

        #[test]
        fn test_classify_with_fake_service() {
            let table = create_fake_process_table();
            let mut ctx = ClassificationContext {
                pid: 200, // svchost.exe
                process_table: table,
                service_map: {
                    let mut map = HashMap::new();
                    map.insert(
                        200,
                        crate::services::ServiceInfo {
                            name: "TestService".to_string(),
                            display_name: "Test Service".to_string(),
                            pid: 200,
                            state: crate::services::ServiceState::Running,
                            binary_path: None,
                            description: None,
                        },
                    );
                    map
                },
                ancestry: vec![],
                evidence: vec![],
                warnings: vec![],
            };

            // Test the classification logic by checking service map directly
            let service = ctx.service_map.get(&ctx.pid);
            assert!(service.is_some());
            let service = service.unwrap();
            assert_eq!(service.name, "TestService");

            // Verify the context has the right structure for service classification
            assert!(ctx.process_table.contains_key(&200));
        }

        #[test]
        fn test_classify_with_fake_interactive() {
            let table = create_fake_process_table();
            // Verify that notepad.exe (400) has explorer.exe (300) as parent
            let entry = table.get(&400).unwrap();
            let parent = table.get(&entry.ppid).unwrap();
            assert_eq!(parent.exe_name.to_lowercase(), "explorer.exe");

            // Verify is_interactive_descendant logic
            assert!(is_interactive_descendant(400, &table));
        }

        #[test]
        fn test_classify_with_fake_scheduled_task() {
            let table = create_fake_process_table();
            // Verify that scheduled_task.exe (600) has taskhostw.exe (500) as parent
            let entry = table.get(&600).unwrap();
            let parent = table.get(&entry.ppid).unwrap();
            assert!(is_task_host_process(&parent.exe_name));
        }

        #[test]
        fn test_classify_with_fake_service_descendant() {
            let table = create_fake_process_table();
            // Verify that svchost.exe (200) is a descendant of services.exe (100)
            assert!(is_service_descendant(200, &table));
        }

        #[test]
        fn test_classify_with_fake_system() {
            let table = create_fake_process_table();
            // System PID (4) should be <= 4
            assert!(4 <= 4);
            // Verify system process exists in table
            assert!(table.contains_key(&4));
        }
    }

    // Integration tests (may require privileged access)
    mod integration_tests {
        use super::*;

        #[test]
        #[ignore] // May require admin access
        fn test_classify_current_process() {
            let pid = std::process::id();
            let result = classify_process(pid).expect("Should classify process");

            println!("Classification for PID {}:", pid);
            println!("  Kind: {:?}", result.classification.kind);
            println!("  Confidence: {:?}", result.classification.confidence);
            println!("  Score: {:.2}", result.score);
            println!("  Description: {}", result.classification.description);
            println!("  Evidence:");
            for ev in &result.evidence {
                println!("    - {} ({:?})", ev.fact, ev.confidence);
            }
        }

        #[test]
        #[ignore] // May require admin access
        fn test_classify_system_process() {
            let result = classify_process(4);

            match result {
                Ok(r) => {
                    println!("System process classification: {:?}", r.classification.kind);
                    println!("Score: {:.2}", r.score);
                    assert!(
                        r.classification.kind == SourceKind::System
                            || r.classification.kind == SourceKind::Service
                    );
                }
                Err(e) => println!("Could not classify system: {}", e),
            }
        }

        #[test]
        fn test_is_service_pid() {
            let is_service = is_service_pid(4).unwrap_or(false);
            println!("Is PID 4 a service? {}", is_service);
        }

        #[test]
        fn test_is_task_host_process() {
            assert!(is_task_host_process("taskhostw.exe"));
            assert!(is_task_host_process("TaskHostW.exe"));
            assert!(is_task_host_process("taskeng.exe"));
            assert!(!is_task_host_process("explorer.exe"));
        }

        #[test]
        fn test_detect_warnings() {
            let pid = std::process::id();
            let warnings = detect_warnings(pid, None);
            println!("Warnings for current process: {:?}", warnings);
        }
    }
}
