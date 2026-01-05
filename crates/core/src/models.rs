//! Core domain models for witr-win
//!
//! These types are OS-agnostic and represent the causal chain analysis data.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The input target for the query
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Target {
    /// Query by process ID
    Pid(u32),
    /// Query by network port
    Port(u16),
    /// Query by process image name
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Pid(pid) => write!(f, "PID {}", pid),
            Target::Port(port) => write!(f, "port {}", port),
            Target::Name(name) => write!(f, "\"{}\"", name),
        }
    }
}

/// Information about a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID (None if orphaned or system)
    pub ppid: Option<u32>,
    /// Full path to the executable image
    pub image_path: Option<String>,
    /// User/owner of the process (e.g., "NT AUTHORITY\\SYSTEM")
    pub user: Option<String>,
    /// Process start time
    #[serde(with = "time::serde::rfc3339::option")]
    pub start_time: Option<OffsetDateTime>,
    /// Command line arguments
    pub cmdline: Option<String>,
    /// Session ID (for terminal services / user sessions)
    pub session_id: Option<u32>,
}

impl ProcessInfo {
    /// Get the process name (filename portion of image_path)
    pub fn name(&self) -> &str {
        self.image_path
            .as_ref()
            .and_then(|p| p.rsplit(['\\', '/']).next())
            .unwrap_or("<unknown>")
    }
}

/// A node in the process ancestry chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AncestryNode {
    /// Process information for this ancestor
    pub process: ProcessInfo,
    /// How this ancestor relates to the chain
    pub relation: AncestryRelation,
    /// Additional notes about this ancestor
    pub notes: Vec<String>,
}

/// The relationship of an ancestor to the target process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AncestryRelation {
    /// Direct parent
    Parent,
    /// Grandparent (parent of parent)
    Grandparent,
    /// Further ancestor
    Ancestor,
    /// The ancestry chain was broken (parent exited)
    Orphaned,
}

/// Classification of the source that started/keeps the process running
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Windows service (SCM-managed)
    Service,
    /// Interactive user session (explorer.exe descendant)
    Interactive,
    /// Scheduled task (Task Scheduler)
    ScheduledTask,
    /// Container-like isolation (Docker, WSL, sandbox)
    ContainerLike,
    /// System process (kernel, smss, csrss, etc.)
    System,
    /// Origin could not be determined
    Unknown,
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceKind::Service => write!(f, "Windows Service"),
            SourceKind::Interactive => write!(f, "Interactive Session"),
            SourceKind::ScheduledTask => write!(f, "Scheduled Task"),
            SourceKind::ContainerLike => write!(f, "Container/Sandbox"),
            SourceKind::System => write!(f, "System Process"),
            SourceKind::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Confidence level in a classification or piece of evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Low confidence - speculative or incomplete data
    Low,
    /// Medium confidence - likely correct but not verified
    Medium,
    /// High confidence - verified from authoritative source
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}

/// A piece of evidence supporting a classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// The fact or observation
    pub fact: String,
    /// Confidence in this evidence
    pub confidence: Confidence,
    /// API or source that provided this evidence
    pub source: EvidenceSource,
    /// Additional details
    pub details: Option<String>,
}

/// The API or mechanism that provided evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Process snapshot (CreateToolhelp32Snapshot)
    ProcessSnapshot,
    /// Service Control Manager
    ServiceControlManager,
    /// Task Scheduler
    TaskScheduler,
    /// TCP/UDP table (GetExtendedTcpTable, etc.)
    NetworkTable,
    /// Token/security information
    SecurityToken,
    /// WMI query
    Wmi,
    /// Process command line
    CommandLine,
    /// Heuristic/inference
    Heuristic,
    /// Other source
    Other(String),
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceSource::ProcessSnapshot => write!(f, "Process Snapshot"),
            EvidenceSource::ServiceControlManager => write!(f, "Service Control Manager"),
            EvidenceSource::TaskScheduler => write!(f, "Task Scheduler"),
            EvidenceSource::NetworkTable => write!(f, "Network Table"),
            EvidenceSource::SecurityToken => write!(f, "Security Token"),
            EvidenceSource::Wmi => write!(f, "WMI"),
            EvidenceSource::CommandLine => write!(f, "Command Line"),
            EvidenceSource::Heuristic => write!(f, "Heuristic"),
            EvidenceSource::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Warnings about limitations or potential issues in the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum Warning {
    /// Running without admin privileges limits data collection
    NoAdminPrivileges,
    /// Parent process has exited, ancestry chain is incomplete
    ParentExited { last_known_ppid: u32 },
    /// Process exited during analysis
    ProcessExited,
    /// Access denied to process information
    AccessDenied { what: String },
    /// API call failed
    ApiFailed { api: String, error: String },
    /// PID was reused (start time mismatch)
    PidReused,
    /// Ancestry chain was truncated (too deep)
    AncestryTruncated { depth: usize },
    /// Generic warning
    Other(String),
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Warning::NoAdminPrivileges => {
                write!(
                    f,
                    "Running without admin privileges; some data may be limited"
                )
            }
            Warning::ParentExited { last_known_ppid } => {
                write!(f, "Parent process (PID {}) has exited", last_known_ppid)
            }
            Warning::ProcessExited => write!(f, "Process exited during analysis"),
            Warning::AccessDenied { what } => write!(f, "Access denied: {}", what),
            Warning::ApiFailed { api, error } => write!(f, "{} failed: {}", api, error),
            Warning::PidReused => {
                write!(
                    f,
                    "PID may have been reused; results could be for different process"
                )
            }
            Warning::AncestryTruncated { depth } => {
                write!(f, "Ancestry chain truncated at depth {}", depth)
            }
            Warning::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// The source classification with confidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceClassification {
    /// The determined source kind
    pub kind: SourceKind,
    /// Confidence in this classification
    pub confidence: Confidence,
    /// Human-readable explanation
    pub description: String,
    /// The service name if SourceKind::Service
    pub service_name: Option<String>,
    /// The task name if SourceKind::ScheduledTask
    pub task_name: Option<String>,
}

impl SourceClassification {
    /// Create an unknown classification
    pub fn unknown() -> Self {
        Self {
            kind: SourceKind::Unknown,
            confidence: Confidence::Low,
            description: "Could not determine process origin".to_string(),
            service_name: None,
            task_name: None,
        }
    }
}
