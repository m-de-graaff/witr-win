//! Output rendering for reports

pub mod json;
pub mod text;

pub use json::render_json;
pub use text::{render_human, render_short, render_tree};
