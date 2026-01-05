//! Text-based rendering for reports

use crate::models::{AncestryRelation, Confidence};
use crate::report::Report;

/// Render a human-readable narrative report
pub fn render_human(report: &Report) -> String {
    let mut out = String::new();

    // Header with target
    out.push_str(&format!("─── Query: {} ───\n\n", report.target));

    // Process information
    if let Some(proc) = &report.process {
        out.push_str(&format!("Process: {} (PID {})\n", proc.name(), proc.pid));

        if let Some(path) = &proc.image_path {
            out.push_str(&format!("  Path: {}\n", path));
        }

        if let Some(cmdline) = &proc.cmdline {
            let display_cmd = if cmdline.len() > 80 {
                format!("{}...", &cmdline[..77])
            } else {
                cmdline.clone()
            };
            out.push_str(&format!("  Command: {}\n", display_cmd));
        }

        if let Some(user) = &proc.user {
            out.push_str(&format!("  User: {}\n", user));
        }

        if let Some(start) = &proc.start_time {
            if let Ok(formatted) = start.format(&time::format_description::well_known::Rfc3339) {
                out.push_str(&format!("  Started: {}\n", formatted));
            }
        }

        if let Some(session) = proc.session_id {
            out.push_str(&format!("  Session: {}\n", session));
        }
    } else {
        out.push_str("Process: Not found\n");
    }

    // Source classification
    out.push_str(&format!(
        "\nSource: {} ({} confidence)\n",
        report.source.kind, report.source.confidence
    ));
    out.push_str(&format!("  {}\n", report.source.description));

    if let Some(service) = &report.source.service_name {
        out.push_str(&format!("  Service: {}\n", service));
    }
    if let Some(task) = &report.source.task_name {
        out.push_str(&format!("  Task: {}\n", task));
    }

    // Ancestry chain
    if !report.ancestry.is_empty() {
        out.push_str("\nAncestry:\n");
        for (i, node) in report.ancestry.iter().enumerate() {
            let prefix = match node.relation {
                AncestryRelation::Parent => "└─ parent:",
                AncestryRelation::Grandparent => "   └─ grandparent:",
                AncestryRelation::Ancestor => &format!("{}└─ ancestor:", "   ".repeat(i)),
                AncestryRelation::Orphaned => "   ⚠ (orphaned)",
            };
            out.push_str(&format!(
                "  {} {} (PID {})\n",
                prefix,
                node.process.name(),
                node.process.pid
            ));
            for note in &node.notes {
                out.push_str(&format!("      ↳ {}\n", note));
            }
        }
    }

    // Evidence
    if !report.evidence.is_empty() {
        out.push_str("\nEvidence:\n");
        for ev in &report.evidence {
            let conf_marker = match ev.confidence {
                Confidence::High => "●",
                Confidence::Medium => "◐",
                Confidence::Low => "○",
            };
            out.push_str(&format!(
                "  {} {} (via {})\n",
                conf_marker, ev.fact, ev.source
            ));
            if let Some(detail) = &ev.details {
                out.push_str(&format!("      {}\n", detail));
            }
        }
    }

    // Warnings
    if !report.warnings.is_empty() {
        out.push('\n');
        for warning in &report.warnings {
            out.push_str(&format!("⚠ {}\n", warning));
        }
    }

    // Errors
    if !report.errors.is_empty() {
        out.push('\n');
        for error in &report.errors {
            out.push_str(&format!("✗ Error: {}\n", error));
        }
    }

    out
}

/// Render a process ancestry tree view
pub fn render_tree(report: &Report) -> String {
    let mut out = String::new();

    // Build tree from root to target
    let mut nodes: Vec<(&str, u32, bool)> = Vec::new();

    // Add ancestors in reverse (root first)
    for node in report.ancestry.iter().rev() {
        let is_orphaned = node.relation == AncestryRelation::Orphaned;
        nodes.push((node.process.name(), node.process.pid, is_orphaned));
    }

    // Add target process
    if let Some(proc) = &report.process {
        nodes.push((proc.name(), proc.pid, false));
    }

    if nodes.is_empty() {
        return format!("No process tree available for {}\n", report.target);
    }

    // Render tree
    out.push_str(&format!("Process tree for {}:\n\n", report.target));

    for (i, (name, pid, orphaned)) in nodes.iter().enumerate() {
        let indent = "  ".repeat(i);
        let connector = if i == 0 { "" } else { "└─ " };
        let orphan_mark = if *orphaned { " [orphaned]" } else { "" };

        if i == nodes.len() - 1 {
            // Target process (highlight)
            out.push_str(&format!(
                "{}{}▶ {} (PID {}){}\n",
                indent, connector, name, pid, orphan_mark
            ));
        } else {
            out.push_str(&format!(
                "{}{}{} (PID {}){}\n",
                indent, connector, name, pid, orphan_mark
            ));
        }
    }

    // Add source annotation
    out.push_str(&format!(
        "\n  Source: {} ({} confidence)\n",
        report.source.kind, report.source.confidence
    ));

    // Warnings
    for warning in &report.warnings {
        out.push_str(&format!("  ⚠ {}\n", warning));
    }

    out
}

/// Render a single-line causal chain summary
pub fn render_short(report: &Report) -> String {
    let proc_name = report
        .process
        .as_ref()
        .map(|p| p.name())
        .unwrap_or("<not found>");

    let pid = report
        .process
        .as_ref()
        .map(|p| p.pid.to_string())
        .unwrap_or_else(|| "?".to_string());

    // Build ancestry chain string
    let ancestry_str = if report.ancestry.is_empty() {
        String::new()
    } else {
        let chain: Vec<_> = report.ancestry.iter().map(|n| n.process.name()).collect();
        format!(" ← {}", chain.join(" ← "))
    };

    // Warning indicator
    let warn_indicator = if report.has_warnings() {
        format!(" [{}⚠]", report.warnings.len())
    } else {
        String::new()
    };

    format!(
        "{} (PID {}){} → {} ({}){}",
        proc_name, pid, ancestry_str, report.source.kind, report.source.confidence, warn_indicator
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AncestryNode, AncestryRelation, Confidence, ProcessInfo, SourceClassification, SourceKind,
        Target,
    };

    fn sample_report() -> Report {
        Report {
            target: Target::Pid(1234),
            process: Some(ProcessInfo {
                pid: 1234,
                ppid: Some(5678),
                image_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
                user: Some("DESKTOP\\User".to_string()),
                start_time: None,
                cmdline: Some("notepad.exe test.txt".to_string()),
                session_id: Some(1),
                memory_bytes: None,
                working_dir: None,
                thread_count: None,
            }),
            ancestry: vec![AncestryNode {
                process: ProcessInfo {
                    pid: 5678,
                    ppid: Some(1),
                    image_path: Some("C:\\Windows\\explorer.exe".to_string()),
                    user: Some("DESKTOP\\User".to_string()),
                    start_time: None,
                    cmdline: None,
                    session_id: Some(1),
                    memory_bytes: None,
                    working_dir: None,
                    thread_count: None,
                },
                relation: AncestryRelation::Parent,
                notes: vec![],
            }],
            source: SourceClassification {
                kind: SourceKind::Interactive,
                confidence: Confidence::High,
                description: "Descendant of explorer.exe in user session".to_string(),
                service_name: None,
                task_name: None,
            },
            evidence: vec![],
            warnings: vec![],
            errors: vec![],
        }
    }

    #[test]
    fn test_render_short() {
        let report = sample_report();
        let output = render_short(&report);
        assert!(output.contains("notepad.exe"));
        assert!(output.contains("1234"));
        assert!(output.contains("Interactive"));
    }

    #[test]
    fn test_render_human_contains_process() {
        let report = sample_report();
        let output = render_human(&report);
        assert!(output.contains("notepad.exe"));
        assert!(output.contains("PID 1234"));
    }

    #[test]
    fn test_render_tree_contains_hierarchy() {
        let report = sample_report();
        let output = render_tree(&report);
        assert!(output.contains("explorer.exe"));
        assert!(output.contains("notepad.exe"));
    }
}
