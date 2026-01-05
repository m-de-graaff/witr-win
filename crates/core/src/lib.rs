//! witr-core: Core models and rendering for witr-win
//!
//! This crate contains the OS-agnostic domain models for causal chain analysis
//! and output rendering (text, JSON, tree views).
//!
//! # Modules
//!
//! - [`models`] - Core data structures (Target, ProcessInfo, Evidence, etc.)
//! - [`report`] - The Report struct that aggregates analysis results
//! - [`render`] - Output formatters (human, tree, short, JSON)
//!
//! # Example
//!
//! ```
//! use witr_core::{Report, Target, render};
//!
//! let report = Report::new(Target::Pid(1234));
//! let output = render::render_human(&report);
//! println!("{}", output);
//! ```

pub mod models;
pub mod render;
pub mod report;

// Re-export commonly used types at crate root
pub use models::{
    AncestryNode, AncestryRelation, Confidence, Evidence, EvidenceSource, ProcessInfo,
    SourceClassification, SourceKind, Target, Warning,
};
pub use report::Report;
