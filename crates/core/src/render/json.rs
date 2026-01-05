//! JSON rendering for reports

use crate::report::Report;
use serde_json::Value;

/// Render the report as a JSON value
pub fn render_json(report: &Report) -> serde_json::Result<Value> {
    serde_json::to_value(report)
}

/// Render the report as a pretty-printed JSON string
pub fn render_json_string(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

/// Render the report as a compact JSON string (no whitespace)
pub fn render_json_compact(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, ProcessInfo, SourceClassification, SourceKind, Target};

    #[test]
    fn test_render_json_roundtrip() {
        let report = Report {
            target: Target::Pid(1234),
            process: Some(ProcessInfo {
                pid: 1234,
                ppid: Some(5678),
                image_path: Some("C:\\test.exe".to_string()),
                user: None,
                start_time: None,
                cmdline: None,
                session_id: None,
            }),
            ancestry: vec![],
            source: SourceClassification {
                kind: SourceKind::Unknown,
                confidence: Confidence::Low,
                description: "Test".to_string(),
                service_name: None,
                task_name: None,
            },
            evidence: vec![],
            warnings: vec![],
            errors: vec![],
        };

        let json_str = render_json_string(&report).unwrap();
        let parsed: Report = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.target, Target::Pid(1234));
    }
}
