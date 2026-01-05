//! Report structure for causal chain analysis results

use crate::models::{
    AncestryNode, Evidence, ProcessInfo, SourceClassification, SourceKind, Target, Warning,
};
use serde::{Deserialize, Serialize};

/// Complete analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// The target that was queried
    pub target: Target,
    /// The resolved process (if found)
    pub process: Option<ProcessInfo>,
    /// Process ancestry chain (parent → grandparent → ...)
    pub ancestry: Vec<AncestryNode>,
    /// Classified source of the process
    pub source: SourceClassification,
    /// Evidence supporting the classification
    pub evidence: Vec<Evidence>,
    /// Warnings about limitations
    pub warnings: Vec<Warning>,
    /// Errors encountered (non-fatal)
    pub errors: Vec<String>,
}

impl Report {
    /// Create an empty report for a target
    pub fn new(target: Target) -> Self {
        Self {
            target,
            process: None,
            ancestry: Vec::new(),
            source: SourceClassification::unknown(),
            evidence: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Check if the process was found
    pub fn process_found(&self) -> bool {
        self.process.is_some()
    }

    /// Check if any warnings were raised
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Check if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Get the root ancestor (furthest from target)
    pub fn root_ancestor(&self) -> Option<&AncestryNode> {
        self.ancestry.last()
    }

    /// Check if the process is a service
    pub fn is_service(&self) -> bool {
        self.source.kind == SourceKind::Service
    }

    /// Check if the process is interactive
    pub fn is_interactive(&self) -> bool {
        self.source.kind == SourceKind::Interactive
    }

    /// Add a warning to the report
    pub fn add_warning(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }

    /// Add an error to the report
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Add evidence to the report
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }
}
