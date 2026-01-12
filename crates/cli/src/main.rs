//! witr: Windows-native CLI tool that explains why a process exists
//!
//! Usage:
//!   witr-win --pid 1234        # Analyze a specific PID
//!   witr-win --port 5000       # Find what's listening on port 5000
//!   witr-win node              # Find processes matching "node"
//!
//! Output formats:
//!   --json     Machine-readable JSON
//!   --short    Single-line summary
//!   --tree     Process ancestry tree
//!   (default)  Human-readable narrative

use clap::Parser;
use owo_colors::{OwoColorize, Style};
use std::io::{self, Write};
use tabled::{
    settings::{object::Columns, style::Style as TableStyle, Alignment, Modify},
    Table, Tabled,
};
use witr_core::{render, Confidence, Report, SourceKind, Target, Warning};

#[cfg(windows)]
mod tui;

/// Label width for aligned output
const LABEL_WIDTH: usize = 12;

#[cfg(windows)]
use witr_platform_windows::{
    analyze_name, analyze_pid, analyze_port, get_connections_for_pid, get_interesting_env_vars,
    get_process_performance, get_security_info, list_handles, list_modules, list_processes,
    pids_for_port, terminate_process, HandleInfo, IntegrityLevel, NameAnalysisResult,
    NetworkConnection, PortAnalysisResult, SecurityInfo,
};

/// Update checking module
mod update_check {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    const GITHUB_API_URL: &str =
        "https://api.github.com/repos/m-de-graaff/witr-win/releases/latest";
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    struct GitHubRelease {
        tag_name: String,
        html_url: String,
        assets: Vec<ReleaseAsset>,
    }

    #[derive(Deserialize)]
    struct ReleaseAsset {
        name: String,
        browser_download_url: String,
    }

    /// Check if a newer version is available
    pub fn check_for_updates() -> Option<(String, String, String)> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent("witr-win")
            .build()
            .ok()?;

        let response = client.get(GITHUB_API_URL).send().ok()?;
        if !response.status().is_success() {
            return None;
        }

        let release: GitHubRelease = response.json().ok()?;

        // Extract version from tag (e.g., "v0.2.0" -> "0.2.0")
        let latest_version = release.tag_name.trim_start_matches('v');

        // Compare versions using semver
        if let (Ok(current), Ok(latest)) = (
            semver::Version::parse(CURRENT_VERSION),
            semver::Version::parse(latest_version),
        ) {
            if latest > current {
                // Find the download URL for witr-win.exe
                let download_url = release
                    .assets
                    .iter()
                    .find(|asset| asset.name == "witr-win.exe")
                    .map(|asset| asset.browser_download_url.clone())?;

                return Some((latest_version.to_string(), release.html_url, download_url));
            }
        }

        None
    }

    /// Download and install the update
    pub fn download_and_install_update(
        colors: &Colors,
        download_url: &str,
        new_version: &str,
    ) -> Result<(), String> {
        eprintln!("{} Downloading update...", "info:".style(colors.info));

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("witr-win")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(download_url)
            .send()
            .map_err(|e| format!("Failed to download update: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Download failed with status: {}",
                response.status()
            ));
        }

        // Get current executable path
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;

        eprintln!(
            "{} Updating executable at: {}",
            "info:".style(colors.info),
            current_exe.display()
        );

        // Create temp file for download
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("witr-win-update-{}.exe", std::process::id()));

        // Download to temp file
        let mut file = fs::File::create(&temp_file)
            .map_err(|e| format!("Failed to create temp file: {}", e))?;

        let mut content = std::io::Cursor::new(
            response
                .bytes()
                .map_err(|e| format!("Failed to read response: {}", e))?,
        );

        std::io::copy(&mut content, &mut file)
            .map_err(|e| format!("Failed to write to temp file: {}", e))?;

        drop(file);

        eprintln!("{} Installing update...", "info:".style(colors.info));

        // On Windows, we can't replace a running executable directly
        // Strategy: rename current exe to .old, then copy new one
        // This works because Windows allows renaming files that are in use
        let old_exe = current_exe.with_extension("exe.old");

        // Remove old backup if it exists
        if old_exe.exists() {
            let _ = fs::remove_file(&old_exe);
        }

        // Rename current exe to .old (Windows allows this even if file is in use)
        if let Err(e) = fs::rename(&current_exe, &old_exe) {
            return Err(format!(
                "Failed to rename current executable: {}. Please close all instances of witr-win and try again.",
                e
            ));
        }

        // Verify the downloaded file size is reasonable (at least 1MB)
        let temp_metadata = fs::metadata(&temp_file)
            .map_err(|e| format!("Failed to get temp file metadata: {}", e))?;
        if temp_metadata.len() < 1_000_000 {
            // Try to restore the old exe before returning error
            let _ = fs::rename(&old_exe, &current_exe);
            return Err(format!(
                "Downloaded file seems too small ({} bytes). Update may have failed.",
                temp_metadata.len()
            ));
        }

        // Now copy the new exe to the original location
        match fs::copy(&temp_file, &current_exe) {
            Ok(bytes_copied) => {
                // Verify the copy was successful by checking file size
                if bytes_copied != temp_metadata.len() {
                    // Copy size mismatch - restore old exe
                    let _ = fs::rename(&old_exe, &current_exe);
                    return Err(format!(
                        "File copy incomplete: expected {} bytes, got {} bytes. Old version restored.",
                        temp_metadata.len(),
                        bytes_copied
                    ));
                }

                // Verify the copied file exists and has correct size
                match fs::metadata(&current_exe) {
                    Ok(metadata) => {
                        if metadata.len() != temp_metadata.len() {
                            let _ = fs::rename(&old_exe, &current_exe);
                            return Err(
                                "Copied file size mismatch. Old version restored.".to_string()
                            );
                        }
                    }
                    Err(e) => {
                        let _ = fs::rename(&old_exe, &current_exe);
                        return Err(format!(
                            "Failed to verify copied file: {}. Old version restored.",
                            e
                        ));
                    }
                }

                // Success! Clean up temp file and try to remove old exe
                let _ = fs::remove_file(&temp_file);
                // Try to remove old exe, but don't fail if it's still in use
                let _ = fs::remove_file(&old_exe);

                eprintln!(
                    "{} Update installed successfully! New version: {}",
                    "success:".style(colors.success),
                    new_version
                );
                eprintln!(
                    "{} Please close this window and run 'witr-win --version' in a new terminal to verify.",
                    "info:".style(colors.info)
                );
                Ok(())
            }
            Err(e) => {
                // If copy fails, try to restore the old exe
                let _ = fs::rename(&old_exe, &current_exe);
                Err(format!(
                    "Failed to install update: {}. The old version has been restored.",
                    e
                ))
            }
        }
    }

    /// Display update notification in pnpm style
    pub fn display_update_notification(colors: &Colors, latest_version: &str, release_url: &str) {
        eprintln!();
        eprintln!(
            "{} {} {} {}",
            "Update available!".style(colors.warning),
            CURRENT_VERSION.style(colors.dim),
            "→".style(colors.dim),
            latest_version.style(colors.success)
        );
        eprintln!(
            "{} {}",
            "Run".style(colors.dim),
            "witr-win --update".style(colors.info)
        );
        eprintln!(
            "{} {}",
            "Or visit:".style(colors.dim),
            release_url.style(colors.info)
        );
        eprintln!();
    }
}

/// Why Is This Running? - Windows Edition
///
/// A Windows-native CLI tool that explains why a process exists
/// by building a causal chain of process ancestry and system signals.
/// Exit codes for scripting
mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const ERROR_GENERAL: i32 = 1;
    pub const ERROR_NOT_FOUND: i32 = 2;
    pub const ERROR_ACCESS_DENIED: i32 = 3;
    pub const ERROR_INVALID_INPUT: i32 = 4;
}

/// Configuration file support
mod config {
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    /// User configuration from ~/.witr-win/config.toml
    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    pub struct Config {
        /// Default output settings
        pub output: OutputConfig,
        /// Default flags
        pub defaults: DefaultFlags,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    pub struct OutputConfig {
        /// Disable colored output by default
        pub no_color: bool,
        /// Use JSON output by default
        pub json: bool,
        /// Use short output by default
        pub short: bool,
        /// Use tree output by default
        pub tree: bool,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    pub struct DefaultFlags {
        /// Always show verbose output
        pub verbose: bool,
        /// Always show modules
        pub modules: bool,
        /// Always show handles
        pub handles: bool,
        /// Always show performance metrics
        pub perf: bool,
        /// Always show network connections
        pub net: bool,
    }

    /// Get the config file path
    pub fn config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".witr-win").join("config.toml"))
    }

    /// Load configuration from file
    pub fn load_config() -> Config {
        let Some(path) = config_path() else {
            return Config::default();
        };

        if !path.exists() {
            return Config::default();
        }

        match fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    /// Generate a sample config file content
    pub fn sample_config() -> &'static str {
        r#"# witr-win configuration file
# Place this file at ~/.witr-win/config.toml

[output]
# Disable colored output
no_color = false
# Use JSON output by default
json = false
# Use short (one-line) output by default
short = false
# Use tree view by default
tree = false

[defaults]
# Always show verbose output
verbose = false
# Always show loaded modules
modules = false
# Always show open handles
handles = false
# Always show performance metrics
perf = false
# Always show network connections
net = false
"#
    }
}

/// Snapshot management for historical analysis
mod snapshots {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use witr_core::Report;

    /// A saved process snapshot
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Snapshot {
        pub name: String,
        pub timestamp: String,
        pub report: Report,
    }

    /// Get snapshots directory
    pub fn snapshots_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".witr-win").join("snapshots"))
    }

    /// Save a snapshot
    pub fn save_snapshot(name: &str, report: &Report) -> Result<PathBuf, String> {
        let dir = snapshots_dir().ok_or("Could not determine home directory")?;
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create snapshots dir: {}", e))?;

        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());

        let snapshot = Snapshot {
            name: name.to_string(),
            timestamp,
            report: report.clone(),
        };

        let path = dir.join(format!("{}.json", name));
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| format!("Failed to serialize snapshot: {}", e))?;
        fs::write(&path, json).map_err(|e| format!("Failed to write snapshot: {}", e))?;

        Ok(path)
    }

    /// Load a snapshot
    pub fn load_snapshot(name: &str) -> Result<Snapshot, String> {
        let dir = snapshots_dir().ok_or("Could not determine home directory")?;
        let path = dir.join(format!("{}.json", name));

        if !path.exists() {
            return Err(format!("Snapshot '{}' not found", name));
        }

        let content =
            fs::read_to_string(&path).map_err(|e| format!("Failed to read snapshot: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse snapshot: {}", e))
    }

    /// List all snapshots
    pub fn list_snapshots() -> Result<Vec<(String, String)>, String> {
        let dir = snapshots_dir().ok_or("Could not determine home directory")?;

        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut snapshots = Vec::new();
        for entry in
            fs::read_dir(&dir).map_err(|e| format!("Failed to read snapshots dir: {}", e))?
        {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&content) {
                        snapshots.push((snapshot.name, snapshot.timestamp));
                    }
                }
            }
        }

        snapshots.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by timestamp descending
        Ok(snapshots)
    }

    /// Compare two reports and return differences
    pub fn compare_reports(old: &Report, new: &Report) -> HashMap<String, (String, String)> {
        let mut diffs = HashMap::new();

        // Compare process info
        if let (Some(old_proc), Some(new_proc)) = (&old.process, &new.process) {
            if old_proc.memory_bytes != new_proc.memory_bytes {
                diffs.insert(
                    "Memory".to_string(),
                    (
                        format_mem(old_proc.memory_bytes),
                        format_mem(new_proc.memory_bytes),
                    ),
                );
            }
            if old_proc.thread_count != new_proc.thread_count {
                diffs.insert(
                    "Threads".to_string(),
                    (
                        old_proc
                            .thread_count
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        new_proc
                            .thread_count
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                    ),
                );
            }
            if old_proc.working_dir != new_proc.working_dir {
                diffs.insert(
                    "Working Dir".to_string(),
                    (
                        old_proc.working_dir.clone().unwrap_or_default(),
                        new_proc.working_dir.clone().unwrap_or_default(),
                    ),
                );
            }
        }

        // Compare source classification
        if old.source.description != new.source.description {
            diffs.insert(
                "Source".to_string(),
                (
                    old.source.description.clone(),
                    new.source.description.clone(),
                ),
            );
        }

        diffs
    }

    fn format_mem(bytes: Option<u64>) -> String {
        match bytes {
            Some(b) if b >= 1_073_741_824 => format!("{:.1} GB", b as f64 / 1_073_741_824.0),
            Some(b) if b >= 1_048_576 => format!("{:.1} MB", b as f64 / 1_048_576.0),
            Some(b) if b >= 1024 => format!("{:.1} KB", b as f64 / 1024.0),
            Some(b) => format!("{} B", b),
            None => "N/A".to_string(),
        }
    }
}

/// Render report as DOT graph for Graphviz
fn render_dot_graph(report: &Report) -> String {
    let mut dot = String::new();
    dot.push_str("digraph process_ancestry {\n");
    dot.push_str("    rankdir=LR;\n");
    dot.push_str("    node [shape=box, style=filled, fontname=\"Arial\"];\n");
    dot.push_str("    edge [fontname=\"Arial\"];\n\n");

    // Add target process node
    if let Some(proc) = &report.process {
        dot.push_str(&format!(
            "    p{} [label=\"{}\nPID: {}\", fillcolor=\"#90EE90\"];\n",
            proc.pid,
            proc.name(),
            proc.pid
        ));
    }

    // Add ancestry nodes
    for node in &report.ancestry {
        let color = match node.relation {
            witr_core::AncestryRelation::Parent => "#ADD8E6",
            witr_core::AncestryRelation::Grandparent => "#B0C4DE",
            witr_core::AncestryRelation::Ancestor => "#D3D3D3",
            witr_core::AncestryRelation::Orphaned => "#FFB6C1",
        };
        dot.push_str(&format!(
            "    p{} [label=\"{}\nPID: {}\", fillcolor=\"{}\"];\n",
            node.process.pid,
            node.process.name(),
            node.process.pid,
            color
        ));
    }

    // Add edges (child -> parent)
    if let Some(proc) = &report.process {
        if let Some(parent) = report.ancestry.first() {
            dot.push_str(&format!("    p{} -> p{};\n", proc.pid, parent.process.pid));
        }
    }

    for i in 0..report.ancestry.len().saturating_sub(1) {
        let child = &report.ancestry[i];
        let parent = &report.ancestry[i + 1];
        dot.push_str(&format!(
            "    p{} -> p{};\n",
            child.process.pid, parent.process.pid
        ));
    }

    // Add source classification as a note
    dot.push_str(&format!(
        "\n    source [label=\"Source:\\n{}\", shape=note, fillcolor=\"#FFFACD\"];\n",
        report.source.description.replace('"', "\\\"")
    ));

    if let Some(root) = report.ancestry.last() {
        dot.push_str(&format!(
            "    p{} -> source [style=dashed];\n",
            root.process.pid
        ));
    }

    dot.push_str("}\n");
    dot
}

#[derive(Parser)]
#[command(name = "witr-win")]
#[command(version, about, long_about = None)]
#[command(after_help = "Examples:
  witr-win --pid 1234          Analyze process with PID 1234
  witr-win --port 8080         Find what's listening on port 8080
  witr-win node                Find processes matching 'node'
  witr-win --pid 1234 --json   Output as JSON for scripting
  witr-win --port 80 --tree    Show ancestry tree for port 80 owner
  witr-win --port 3000 --end   Terminate process on port 3000
  witr-win --pid 1234 --end    Terminate process by PID
  witr-win --pid 1234 --watch  Monitor process in real-time
  witr-win -P 3000 -w          Watch process on port 3000")]
struct Cli {
    /// Process ID to analyze (alias: p)
    #[arg(long, short = 'p', visible_alias = "p", value_name = "PID")]
    pid: Option<u32>,

    /// Port number to find the owning process (alias: P)
    #[arg(long, short = 'P', visible_alias = "P", value_name = "PORT")]
    port: Option<u16>,

    /// Process name to search for (supports partial matching)
    #[arg(value_name = "NAME")]
    name: Option<String>,

    /// Output as JSON (for scripting and automation)
    #[arg(long, short = 'j', conflicts_with_all = ["short", "tree"])]
    json: bool,

    /// Output single-line summary
    #[arg(long, short = 's', conflicts_with_all = ["json", "tree"])]
    short: bool,

    /// Show process ancestry tree
    #[arg(long, short = 't', conflicts_with_all = ["json", "short"])]
    tree: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Show verbose output including all evidence
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Show loaded modules/DLLs for the process
    #[arg(long, short = 'm')]
    modules: bool,

    /// Show open file handles for the process
    #[arg(long, short = 'H')]
    handles: bool,

    /// Show performance metrics (CPU time, I/O stats)
    #[arg(long)]
    perf: bool,

    /// Show network connections for the process
    #[arg(long, short = 'n')]
    net: bool,

    /// Show security info (integrity level, privileges)
    #[arg(long, short = 'S')]
    security: bool,

    /// Check for updates and display notification if available
    #[arg(long)]
    check_update: bool,

    /// Download and install the latest update
    #[arg(long)]
    update: bool,

    /// Show all details (modules, handles, perf, net)
    #[arg(long, short = 'a')]
    all: bool,

    /// Generate a sample config file at ~/.witr-win/config.toml
    #[arg(long)]
    init_config: bool,

    /// Output process ancestry as DOT graph (for Graphviz)
    #[arg(long)]
    graph: bool,

    /// Save a snapshot of the process for later comparison
    #[arg(long, value_name = "NAME")]
    snapshot: Option<String>,

    /// Compare current process state with a saved snapshot
    #[arg(long, value_name = "NAME")]
    compare: Option<String>,

    /// List all saved snapshots
    #[arg(long)]
    list_snapshots: bool,

    /// Launch interactive TUI mode
    #[arg(long, short = 'i')]
    interactive: bool,

    /// Terminate the process (use with --pid or --port)
    #[arg(long, short = 'e')]
    end: bool,

    /// Watch mode: monitor process changes in real-time
    #[arg(long, short = 'w')]
    watch: bool,

    /// Refresh interval in seconds for watch mode (default: 2)
    #[arg(long, default_value = "2", value_name = "SECONDS")]
    interval: u64,
}

/// Color configuration for output
#[allow(dead_code)]
struct Colors {
    enabled: bool,
    header: Style,
    success: Style,
    warning: Style,
    error: Style,
    info: Style,
    dim: Style,
    highlight: Style,
}

impl Colors {
    fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                enabled: true,
                header: Style::new().bold().cyan(),
                success: Style::new().green(),
                warning: Style::new().yellow(),
                error: Style::new().red().bold(),
                info: Style::new().cyan(),
                dim: Style::new().dimmed(),
                highlight: Style::new().bold().white(),
            }
        } else {
            Self {
                enabled: false,
                header: Style::new(),
                success: Style::new(),
                warning: Style::new(),
                error: Style::new(),
                info: Style::new(),
                dim: Style::new(),
                highlight: Style::new(),
            }
        }
    }
}

fn main() {
    // Load configuration file
    let cfg = config::load_config();

    let mut cli = Cli::parse();

    // Apply config defaults (CLI flags override config)
    if !cli.no_color && cfg.output.no_color {
        cli.no_color = true;
    }
    if !cli.json && cfg.output.json {
        cli.json = true;
    }
    if !cli.short && cfg.output.short {
        cli.short = true;
    }
    if !cli.tree && cfg.output.tree {
        cli.tree = true;
    }
    if !cli.verbose && cfg.defaults.verbose {
        cli.verbose = true;
    }
    if !cli.modules && cfg.defaults.modules {
        cli.modules = true;
    }
    if !cli.handles && cfg.defaults.handles {
        cli.handles = true;
    }
    if !cli.perf && cfg.defaults.perf {
        cli.perf = true;
    }
    if !cli.net && cfg.defaults.net {
        cli.net = true;
    }

    // Handle --all flag: enable all detail flags
    if cli.all {
        cli.modules = true;
        cli.handles = true;
        cli.perf = true;
        cli.net = true;
        cli.security = true;
        cli.verbose = true;
    }

    // Determine color mode
    let colors = Colors::new(!cli.no_color && supports_color());

    // Handle update flags
    if cli.update {
        handle_update(&colors);
        return;
    }

    if cli.check_update {
        handle_check_update(&colors);
        return;
    }

    if cli.init_config {
        handle_init_config(&colors);
        return;
    }

    if cli.list_snapshots {
        handle_list_snapshots(&colors);
        return;
    }

    // Handle interactive mode
    #[cfg(windows)]
    if cli.interactive {
        match tui::run_interactive_and_get_pid() {
            Ok(Some(pid)) => {
                // User selected a process, analyze it
                cli.pid = Some(pid);
            }
            Ok(None) => {
                // User quit without selecting
                return;
            }
            Err(e) => {
                print_error(&colors, &e);
                std::process::exit(exit_codes::ERROR_GENERAL);
            }
        }
    }

    // Validate input
    let target_count = [cli.pid.is_some(), cli.port.is_some(), cli.name.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();

    if target_count == 0 {
        print_error(&colors, "No target specified");
        eprintln!();
        eprintln!("Usage: witr-win [OPTIONS] [NAME]");
        eprintln!();
        eprintln!("Specify one of:");
        eprintln!("  --pid <PID>     Analyze a process by PID (short: -p)");
        eprintln!("  --port <PORT>   Find process listening on port (short: -P)");
        eprintln!("  <NAME>          Search for process by name");
        eprintln!();
        eprintln!("Quick examples:");
        eprintln!("  witr-win -p 1234          # Analyze PID 1234");
        eprintln!("  witr-win -P 3000          # What's on port 3000?");
        eprintln!("  witr-win chrome           # Find Chrome processes");
        eprintln!("  witr-win -p 1234 --all    # Show everything");
        eprintln!();
        eprintln!("Run 'witr-win --help' for more information.");
        std::process::exit(exit_codes::ERROR_INVALID_INPUT);
    }

    if target_count > 1 {
        print_error(&colors, "Only one target can be specified at a time");
        eprintln!();
        eprintln!("Use one of: --pid, --port, or <NAME>");
        std::process::exit(exit_codes::ERROR_INVALID_INPUT);
    }

    // Check for updates before executing operations (non-blocking)
    check_and_notify_updates(&colors);

    // Handle --end flag: terminate process(es) by PID or port
    #[cfg(windows)]
    if cli.end {
        let result = handle_end(&cli, &colors);
        if let Err(e) = result {
            let exit_code = if e.contains("not found") || e.contains("No process") {
                exit_codes::ERROR_NOT_FOUND
            } else if e.contains("Access denied") || e.contains("permission") {
                exit_codes::ERROR_ACCESS_DENIED
            } else {
                exit_codes::ERROR_GENERAL
            };
            print_error(&colors, &e);
            std::process::exit(exit_code);
        }
        std::process::exit(exit_codes::SUCCESS);
    }

    // Handle --watch flag: monitor process in real-time
    #[cfg(windows)]
    if cli.watch {
        let result = handle_watch(&cli, &colors);
        if let Err(e) = result {
            let exit_code = if e.contains("not found") || e.contains("No process") {
                exit_codes::ERROR_NOT_FOUND
            } else if e.contains("Access denied") || e.contains("permission") {
                exit_codes::ERROR_ACCESS_DENIED
            } else {
                exit_codes::ERROR_GENERAL
            };
            print_error(&colors, &e);
            std::process::exit(exit_code);
        }
        std::process::exit(exit_codes::SUCCESS);
    }

    // Route to appropriate handler
    let result = if let Some(pid) = cli.pid {
        handle_pid(pid, &cli, &colors)
    } else if let Some(port) = cli.port {
        handle_port(port, &cli, &colors)
    } else if let Some(ref name) = cli.name {
        handle_name(name, &cli, &colors)
    } else {
        unreachable!()
    };

    if let Err(e) = result {
        // Determine appropriate exit code based on error
        let exit_code = if e.contains("not found") || e.contains("No process") {
            exit_codes::ERROR_NOT_FOUND
        } else if e.contains("Access denied") || e.contains("permission") {
            exit_codes::ERROR_ACCESS_DENIED
        } else {
            exit_codes::ERROR_GENERAL
        };
        print_error(&colors, &e);
        std::process::exit(exit_code);
    }
}

/// Handle --check-update flag
fn handle_check_update(colors: &Colors) {
    if let Some((latest_version, release_url, _)) = update_check::check_for_updates() {
        update_check::display_update_notification(colors, &latest_version, &release_url);
        std::process::exit(exit_codes::SUCCESS);
    } else {
        eprintln!(
            "{} You are using the latest version ({})",
            "info:".style(colors.info),
            env!("CARGO_PKG_VERSION")
        );
        std::process::exit(exit_codes::SUCCESS);
    }
}

/// Handle --init-config flag
fn handle_init_config(colors: &Colors) {
    use std::fs;

    let Some(config_path) = config::config_path() else {
        print_error(colors, "Could not determine home directory");
        std::process::exit(exit_codes::ERROR_GENERAL);
    };

    // Create directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            print_error(colors, &format!("Failed to create config directory: {}", e));
            std::process::exit(exit_codes::ERROR_GENERAL);
        }
    }

    // Check if config already exists
    if config_path.exists() {
        eprintln!(
            "{} Config file already exists at: {}",
            "warning:".style(colors.warning),
            config_path.display()
        );
        eprintln!("Use a text editor to modify it, or delete it first to regenerate.");
        std::process::exit(exit_codes::SUCCESS);
    }

    // Write sample config
    match fs::write(&config_path, config::sample_config()) {
        Ok(()) => {
            eprintln!(
                "{} Created config file at: {}",
                "success:".style(colors.success),
                config_path.display()
            );
            eprintln!();
            eprintln!("Edit this file to customize default behavior.");
            std::process::exit(exit_codes::SUCCESS);
        }
        Err(e) => {
            print_error(colors, &format!("Failed to write config file: {}", e));
            std::process::exit(exit_codes::ERROR_GENERAL);
        }
    }
}

/// Handle --list-snapshots flag
fn handle_list_snapshots(colors: &Colors) {
    match snapshots::list_snapshots() {
        Ok(list) if list.is_empty() => {
            eprintln!("{} No snapshots saved yet.", "info:".style(colors.info));
            eprintln!("Use --snapshot <name> to save a snapshot.");
            std::process::exit(exit_codes::SUCCESS);
        }
        Ok(list) => {
            eprintln!("{} Saved snapshots:\n", "info:".style(colors.info));
            for (name, timestamp) in list {
                eprintln!(
                    "  {} {} ({})",
                    "•".style(colors.info),
                    name.style(colors.header),
                    timestamp.style(colors.dim)
                );
            }
            eprintln!();
            eprintln!("Use --compare <name> to compare with current state.");
            std::process::exit(exit_codes::SUCCESS);
        }
        Err(e) => {
            print_error(colors, &e);
            std::process::exit(exit_codes::ERROR_GENERAL);
        }
    }
}

/// Handle --update flag
fn handle_update(colors: &Colors) {
    if let Some((latest_version, release_url, download_url)) = update_check::check_for_updates() {
        eprintln!(
            "{} {} {} {}",
            "info:".style(colors.info),
            "Update available:".style(colors.info),
            env!("CARGO_PKG_VERSION").style(colors.dim),
            format!("→ {}", latest_version).style(colors.success)
        );
        eprintln!();
        eprintln!(
            "{} Downloading from: {}",
            "info:".style(colors.info),
            download_url
        );
        eprintln!();

        match update_check::download_and_install_update(colors, &download_url, &latest_version) {
            Ok(()) => {
                eprintln!();
                eprintln!(
                    "{} To verify the update, close this terminal and run:",
                    "info:".style(colors.info)
                );
                eprintln!("  witr-win --version");
                eprintln!();
                eprintln!(
                    "{} If it still shows the old version, you may be running a different witr-win.exe from your PATH.",
                    "warning:".style(colors.warning)
                );
                std::process::exit(exit_codes::SUCCESS);
            }
            Err(e) => {
                print_error(colors, &format!("Update failed: {}", e));
                eprintln!(
                    "{} You can manually download from: {}",
                    "info:".style(colors.info),
                    release_url
                );
                std::process::exit(exit_codes::ERROR_GENERAL);
            }
        }
    } else {
        eprintln!(
            "{} You are using the latest version ({})",
            "info:".style(colors.info),
            env!("CARGO_PKG_VERSION")
        );
        std::process::exit(exit_codes::SUCCESS);
    }
}

/// Check for updates and display notification if available (non-blocking, silent on failure)
fn check_and_notify_updates(colors: &Colors) {
    if let Some((latest_version, release_url, _)) = update_check::check_for_updates() {
        update_check::display_update_notification(colors, &latest_version, &release_url);
    }
}

/// Resolve a target to a list of PIDs
///
/// This function takes a Target enum and returns all PIDs that match it.
/// For Pid targets, returns a single-element vector.
/// For Port targets, returns all PIDs listening on that port.
/// For Name targets, returns all PIDs with matching process names.
#[cfg(windows)]
#[allow(dead_code)] // Requested function for command routing
fn resolve_target_to_pids(target: &witr_core::Target) -> Result<Vec<u32>, String> {
    match target {
        witr_core::Target::Pid(pid) => Ok(vec![*pid]),
        witr_core::Target::Port(port) => {
            pids_for_port(*port).map_err(|e| format!("Failed to resolve port {}: {}", port, e))
        }
        witr_core::Target::Name(name) => {
            let processes =
                list_processes().map_err(|e| format!("Failed to list processes: {}", e))?;
            let name_lower = name.to_lowercase();
            let mut pids: Vec<u32> = processes
                .values()
                .filter(|p| p.exe_name.to_lowercase().contains(&name_lower))
                .map(|p| p.pid)
                .collect();
            pids.sort();
            pids.dedup();
            Ok(pids)
        }
    }
}

/// Build a report for a given PID
///
/// This is a wrapper around analyze_pid that provides a cleaner interface.
#[cfg(windows)]
fn build_report(pid: u32) -> Result<witr_core::Report, String> {
    analyze_pid(pid).map_err(|e| format!("Failed to build report for PID {}: {}", pid, e))
}

/// Handle --end flag: terminate process(es) by PID, port, or name
#[cfg(windows)]
fn handle_end(cli: &Cli, colors: &Colors) -> Result<(), String> {
    // Collect PIDs to terminate
    let pids: Vec<u32> = if let Some(pid) = cli.pid {
        vec![pid]
    } else if let Some(port) = cli.port {
        let pids = pids_for_port(port)
            .map_err(|e| format!("Failed to find process on port {}: {}", port, e))?;
        if pids.is_empty() {
            return Err(format!("No process found listening on port {}", port));
        }
        pids
    } else if let Some(ref name) = cli.name {
        let processes = list_processes().map_err(|e| format!("Failed to list processes: {}", e))?;
        let name_lower = name.to_lowercase();
        let pids: Vec<u32> = processes
            .values()
            .filter(|p| p.exe_name.to_lowercase().contains(&name_lower))
            .map(|p| p.pid)
            .collect();
        if pids.is_empty() {
            return Err(format!("No process found matching '{}'", name));
        }
        pids
    } else {
        return Err("--end requires --pid, --port, or a process name".to_string());
    };

    // Show what we're about to terminate
    let processes = list_processes().unwrap_or_default();

    for &pid in &pids {
        let proc_name = processes
            .get(&pid)
            .map(|p| p.exe_name.as_str())
            .unwrap_or("Unknown");

        print_info(
            colors,
            &format!("Terminating {} (PID {})...", proc_name, pid),
        );

        match terminate_process(pid, 1) {
            Ok(()) => {
                eprintln!(
                    "{} Terminated {} (PID {})",
                    "success:".style(colors.success),
                    proc_name,
                    pid
                );
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to terminate PID {}: {}",
                    "error:".style(colors.error),
                    pid,
                    e
                );
            }
        }
    }

    Ok(())
}

/// Handle --watch flag: monitor process in real-time
#[cfg(windows)]
fn handle_watch(cli: &Cli, colors: &Colors) -> Result<(), String> {
    use crossterm::{
        cursor,
        terminal::{self, ClearType},
        ExecutableCommand,
    };
    use std::time::Duration;

    // Resolve the target PID
    let target_pid: u32 = if let Some(pid) = cli.pid {
        pid
    } else if let Some(port) = cli.port {
        let pids = pids_for_port(port)
            .map_err(|e| format!("Failed to find process on port {}: {}", port, e))?;
        if pids.is_empty() {
            return Err(format!("No process found listening on port {}", port));
        }
        if pids.len() > 1 {
            print_warning(
                colors,
                &format!(
                    "Multiple processes on port {}, watching first (PID {})",
                    port, pids[0]
                ),
            );
        }
        pids[0]
    } else if let Some(ref name) = cli.name {
        let processes = list_processes().map_err(|e| format!("Failed to list processes: {}", e))?;
        let name_lower = name.to_lowercase();
        let matching: Vec<u32> = processes
            .values()
            .filter(|p| p.exe_name.to_lowercase().contains(&name_lower))
            .map(|p| p.pid)
            .collect();
        if matching.is_empty() {
            return Err(format!("No process found matching '{}'", name));
        }
        if matching.len() > 1 {
            print_warning(
                colors,
                &format!(
                    "Multiple processes match '{}', watching first (PID {})",
                    name, matching[0]
                ),
            );
        }
        matching[0]
    } else {
        return Err("--watch requires --pid, --port, or a process name".to_string());
    };

    let interval = Duration::from_secs(cli.interval);

    // Get initial process info for header
    let initial_processes = list_processes().unwrap_or_default();
    let proc_name = initial_processes
        .get(&target_pid)
        .map(|p| p.exe_name.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    let mut stdout = io::stdout();
    let mut iteration = 0u64;

    loop {
        iteration += 1;

        // Clear screen and move cursor to top
        let _ = stdout.execute(terminal::Clear(ClearType::All));
        let _ = stdout.execute(cursor::MoveTo(0, 0));

        // Print header
        let now = time::OffsetDateTime::now_utc();
        let time_str = now
            .format(&time::format_description::parse("[hour]:[minute]:[second]").unwrap())
            .unwrap_or_else(|_| "??:??:??".to_string());

        println!(
            "{} {} (PID {}) │ {} │ iteration #{}",
            "◉".style(colors.success),
            proc_name.style(colors.highlight),
            target_pid.to_string().style(colors.dim),
            time_str.style(colors.dim),
            iteration
        );
        println!("{}", "─".repeat(60).style(colors.dim));
        println!();

        // Check if process still exists
        let processes = list_processes().unwrap_or_default();
        if !processes.contains_key(&target_pid) {
            println!(
                "{} Process {} (PID {}) has exited",
                "✖".style(colors.error),
                proc_name.style(colors.highlight),
                target_pid
            );
            return Ok(());
        }

        // Get and display metrics
        print_watch_metrics(target_pid, colors);

        // Get network connections
        if let Ok(connections) = get_connections_for_pid(target_pid) {
            if !connections.is_empty() {
                println!();
                println!("{}", "Network Connections:".style(colors.header));
                for conn in connections.iter().take(10) {
                    let local = format!("{}:{}", conn.local_addr, conn.local_port);
                    let remote = match (&conn.remote_addr, conn.remote_port) {
                        (Some(addr), Some(port)) => format!("{}:{}", addr, port),
                        _ => "-".to_string(),
                    };
                    let state = conn
                        .state
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "  {} {} → {} ({})",
                        conn.protocol.to_string().style(colors.dim),
                        local.style(colors.info),
                        remote.style(colors.dim),
                        state.style(colors.dim)
                    );
                }
                if connections.len() > 10 {
                    println!(
                        "  {} ... and {} more",
                        "".style(colors.dim),
                        connections.len() - 10
                    );
                }
            }
        }

        println!();
        println!("{} Press Ctrl+C to stop watching", "tip:".style(colors.dim));

        // Wait for interval
        std::thread::sleep(interval);
    }
}

/// Print watch mode metrics for a process
#[cfg(windows)]
fn print_watch_metrics(pid: u32, colors: &Colors) {
    use witr_platform_windows::perf::{format_bytes, format_duration};

    // Memory
    if let Ok(memory) = witr_platform_windows::get_memory_usage(pid) {
        println!(
            "{:>12} : {}",
            "Memory".style(colors.header),
            format_memory_size(memory).style(colors.info)
        );
    }

    // CPU times
    if let Ok(perf) = get_process_performance(pid) {
        println!(
            "{:>12} : {} (user: {}, kernel: {})",
            "CPU Time".style(colors.header),
            format_duration(perf.cpu.total_seconds()).style(colors.info),
            format_duration(perf.cpu.user_seconds()).style(colors.dim),
            format_duration(perf.cpu.kernel_seconds()).style(colors.dim)
        );

        // I/O
        println!(
            "{:>12} : read {} ({} ops) │ write {} ({} ops)",
            "I/O".style(colors.header),
            format_bytes(perf.io.read_bytes).style(colors.info),
            perf.io.read_operations.to_string().style(colors.dim),
            format_bytes(perf.io.write_bytes).style(colors.info),
            perf.io.write_operations.to_string().style(colors.dim)
        );
    }

    // Thread count
    if let Ok(processes) = list_processes() {
        if let Some(proc) = processes.get(&pid) {
            println!(
                "{:>12} : {}",
                "Threads".style(colors.header),
                proc.thread_count.to_string().style(colors.info)
            );
        }
    }

    // Handle count
    if let Ok(handles) = list_handles(pid) {
        println!(
            "{:>12} : {}",
            "Handles".style(colors.header),
            handles.len().to_string().style(colors.info)
        );
    }
}

/// Handle PID target
#[cfg(windows)]
fn handle_pid(pid: u32, cli: &Cli, colors: &Colors) -> Result<(), String> {
    if cli.verbose {
        print_info(colors, &format!("Analyzing PID {}...", pid));
    }

    let report = build_report(pid)?;

    if report.process.is_none() {
        return Err(format!("Process {} not found or access denied", pid));
    }

    render_report(&report, cli, colors);
    Ok(())
}

/// Handle port target
#[cfg(windows)]
fn handle_port(port: u16, cli: &Cli, colors: &Colors) -> Result<(), String> {
    if cli.verbose {
        print_info(
            colors,
            &format!("Finding process listening on port {}...", port),
        );
    }

    let result = analyze_port(port).map_err(|e| e.to_string())?;

    if result.reports.is_empty() {
        return Err(format!("No process found listening on port {}", port));
    }

    // Handle warnings about listening publicly (filter out exited process warnings)
    for warning in &result.warnings {
        if !matches!(
            warning,
            Warning::ParentExited { .. } | Warning::ProcessExited
        ) {
            print_warning(colors, &format_warning(warning));
        }
    }

    if result.has_multiple_pids() {
        print_info(
            colors,
            &format!(
                "Multiple processes ({}) bound to port {}:",
                result.reports.len(),
                port
            ),
        );
        println!();
    }

    render_port_result(&result, cli, colors);
    Ok(())
}

/// Handle name target
#[cfg(windows)]
fn handle_name(name: &str, cli: &Cli, colors: &Colors) -> Result<(), String> {
    if cli.verbose {
        print_info(
            colors,
            &format!("Searching for processes matching '{}'...", name),
        );
    }

    let result = analyze_name(name).map_err(|e| e.to_string())?;

    if result.reports.is_empty() {
        return Err(format!("No process found matching '{}'", name));
    }

    if result.has_multiple_matches() {
        print_info(
            colors,
            &format!(
                "Found {} processes matching '{}':",
                result.reports.len(),
                name
            ),
        );
        println!();

        if !cli.json {
            // List all matches first
            for report in &result.reports {
                if let Some(proc) = &report.process {
                    println!(
                        "  {} {} (PID {})",
                        "→".style(colors.info),
                        proc.name().style(colors.highlight),
                        proc.pid.to_string().style(colors.dim)
                    );
                }
            }
            println!();
            println!("Showing details for first match. Use --pid to select a specific process.");
            println!();
        }
    }

    render_name_result(&result, cli, colors);
    Ok(())
}

/// Render a single report based on output format
fn render_report(report: &Report, cli: &Cli, colors: &Colors) {
    // Handle snapshot saving
    if let Some(ref name) = cli.snapshot {
        match snapshots::save_snapshot(name, report) {
            Ok(path) => {
                eprintln!(
                    "{} Snapshot saved to: {}",
                    "success:".style(colors.success),
                    path.display()
                );
            }
            Err(e) => {
                print_error(colors, &format!("Failed to save snapshot: {}", e));
            }
        }
    }

    // Handle comparison with saved snapshot
    if let Some(ref name) = cli.compare {
        match snapshots::load_snapshot(name) {
            Ok(snapshot) => {
                let diffs = snapshots::compare_reports(&snapshot.report, report);
                if diffs.is_empty() {
                    eprintln!(
                        "{} No changes detected since snapshot '{}' ({})",
                        "info:".style(colors.info),
                        name,
                        snapshot.timestamp
                    );
                } else {
                    eprintln!(
                        "{} Changes since snapshot '{}' ({}):\n",
                        "info:".style(colors.info),
                        name,
                        snapshot.timestamp
                    );
                    for (field, (old, new)) in &diffs {
                        eprintln!(
                            "  {} {}: {} → {}",
                            "→".style(colors.warning),
                            field.style(colors.header),
                            old.style(colors.dim),
                            new.style(colors.success)
                        );
                    }
                    eprintln!();
                }
            }
            Err(e) => {
                print_error(colors, &e);
            }
        }
    }

    // Handle graph output
    if cli.graph {
        println!("{}", render_dot_graph(report));
        return;
    }

    if cli.json {
        match render::json::render_json_string(report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                print_error(colors, &format!("Failed to render JSON: {}", e));
                std::process::exit(exit_codes::ERROR_GENERAL);
            }
        }
    } else if cli.short {
        println!("{}", render::render_short(report));
    } else if cli.tree {
        print_colored_tree(report, colors);
    } else {
        print_colored_report(report, cli, colors);
    }
}

/// Render port analysis result
#[cfg(windows)]
fn render_port_result(result: &PortAnalysisResult, cli: &Cli, colors: &Colors) {
    if cli.json {
        // Collect all reports into a JSON array
        let reports: Vec<_> = result.reports.iter().collect();
        match serde_json::to_string_pretty(&reports) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                print_error(colors, &format!("Failed to render JSON: {}", e));
                std::process::exit(exit_codes::ERROR_GENERAL);
            }
        }
    } else {
        for (i, report) in result.reports.iter().enumerate() {
            if i > 0 {
                println!();
                println!("{}", "─".repeat(60).style(colors.dim));
                println!();
            }

            // Show listening interfaces for port queries
            if matches!(report.target, Target::Port(_)) {
                let bindings: Vec<_> = result
                    .bindings
                    .iter()
                    .filter(|b| b.pid == report.process.as_ref().map(|p| p.pid).unwrap_or(0))
                    .collect();

                if !bindings.is_empty() {
                    let stdout = io::stdout();
                    let mut out = stdout.lock();
                    writeln!(out, "{}: ", "Listening Interfaces".style(colors.header)).ok();
                    for binding in &bindings {
                        writeln!(
                            out,
                            "  {}:{} ({})",
                            binding.local_addr.style(colors.highlight),
                            binding.local_port.to_string().style(colors.info),
                            binding.protocol.to_string().style(colors.dim)
                        )
                        .ok();
                    }
                    writeln!(out).ok();
                }
            }

            render_report(report, cli, colors);
        }
    }
}

/// Render name analysis result
#[cfg(windows)]
fn render_name_result(result: &NameAnalysisResult, cli: &Cli, colors: &Colors) {
    if cli.json {
        // Collect all reports into a JSON array
        let reports: Vec<_> = result.reports.iter().collect();
        match serde_json::to_string_pretty(&reports) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                print_error(colors, &format!("Failed to render JSON: {}", e));
                std::process::exit(exit_codes::ERROR_GENERAL);
            }
        }
    } else if result.reports.len() > 5 {
        // Use table for many processes (like Chrome with many tabs)
        print_multi_process_table(result, cli, colors);
    } else {
        // Show details for first match, list others
        if let Some(report) = result.reports.first() {
            render_report(report, cli, colors);
        }
    }
}

/// Print a table view for multiple matching processes
#[cfg(windows)]
fn print_multi_process_table(result: &NameAnalysisResult, cli: &Cli, colors: &Colors) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    println!(
        "\n{} {} matching processes found:\n",
        "→".style(colors.info),
        result.reports.len()
    );

    // Build process rows
    let rows: Vec<ProcessRow> = result
        .reports
        .iter()
        .filter_map(|r| r.process.as_ref())
        .map(|proc| ProcessRow {
            pid: proc.pid,
            name: proc.name().to_string(),
            memory: proc
                .memory_bytes
                .map(format_memory_size)
                .unwrap_or_else(|| "-".to_string()),
            user: proc.user.clone().unwrap_or_else(|| "-".to_string()),
        })
        .collect();

    let table = Table::new(&rows)
        .with(TableStyle::rounded())
        .with(Modify::new(Columns::single(0)).with(Alignment::right()))
        .with(Modify::new(Columns::single(2)).with(Alignment::right()))
        .to_string();

    for line in table.lines() {
        writeln!(out, "  {}", line).ok();
    }

    println!(
        "\n{} Use {} to see details for a specific process.",
        "tip:".style(colors.dim),
        "--pid <PID>".style(colors.info)
    );

    // If verbose, show first process details
    if cli.verbose {
        if let Some(report) = result.reports.first() {
            println!("\n{}", "─".repeat(50).style(colors.dim));
            println!(
                "{} Showing details for first match:\n",
                "→".style(colors.info)
            );
            render_report(report, cli, colors);
        }
    }
}

#[cfg(not(windows))]
fn print_multi_process_table(result: &NameAnalysisResult, cli: &Cli, colors: &Colors) {
    // Fallback for non-Windows
    if let Some(report) = result.reports.first() {
        render_report(report, cli, colors);
    }
}

/// Format relative time (e.g., "256 days ago")
fn format_relative_time(dt: &time::OffsetDateTime) -> String {
    let now = time::OffsetDateTime::now_utc();
    let duration = now - *dt;

    let days = duration.whole_days();
    let hours = duration.whole_hours();
    let minutes = duration.whole_minutes();
    let seconds = duration.whole_seconds();

    if days > 90 {
        format!("{} days ago", days)
    } else if days > 0 {
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if hours > 0 {
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if minutes > 0 {
        format!(
            "{} minute{} ago",
            minutes,
            if minutes == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{} second{} ago",
            seconds,
            if seconds == 1 { "" } else { "s" }
        )
    }
}

/// Format absolute time for display
fn format_absolute_time(dt: &time::OffsetDateTime) -> String {
    // Try to format as "Mon 2025-04-14 15:12:56 +02:00"
    if let Ok(formatted) = dt.format(&time::format_description::well_known::Rfc3339) {
        formatted
    } else {
        // Fallback to simple format
        format!("{}", dt)
    }
}

/// Format memory size in human-readable format
fn format_memory_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format module size in human-readable format
fn format_module_size(bytes: u32) -> String {
    const KB: u32 = 1024;
    const MB: u32 = KB * 1024;

    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Print an aligned label with value
fn print_row(
    out: &mut impl Write,
    label: &str,
    value: &str,
    label_style: Style,
    value_style: Style,
) {
    writeln!(
        out,
        "{:>width$} : {}",
        label.style(label_style),
        value.style(value_style),
        width = LABEL_WIDTH
    )
    .ok();
}

/// Print an aligned label with styled value (already styled)
fn print_row_raw(out: &mut impl Write, label: &str, value: String, label_style: Style) {
    writeln!(
        out,
        "{:>width$} : {}",
        label.style(label_style),
        value,
        width = LABEL_WIDTH
    )
    .ok();
}

/// Print an aligned section header
fn print_section(out: &mut impl Write, label: &str, label_style: Style) {
    writeln!(out).ok();
    writeln!(
        out,
        "{:>width$} :",
        label.style(label_style),
        width = LABEL_WIDTH
    )
    .ok();
}

/// Print sub-items with proper indentation
fn print_sub_item(out: &mut impl Write, value: &str, value_style: Style) {
    writeln!(
        out,
        "{:>width$}   {}",
        "",
        value.style(value_style),
        width = LABEL_WIDTH
    )
    .ok();
}

/// Module table entry for tabled output
#[derive(Tabled)]
struct ModuleRow {
    #[tabled(rename = "Module")]
    name: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Path")]
    path: String,
}

/// Handle summary row for tabled output
#[derive(Tabled)]
struct HandleSummaryRow {
    #[tabled(rename = "Type")]
    object_type: String,
    #[tabled(rename = "Count")]
    count: usize,
}

/// Process row for multi-process tables
#[derive(Tabled)]
struct ProcessRow {
    #[tabled(rename = "PID")]
    pid: u32,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Memory")]
    memory: String,
    #[tabled(rename = "User")]
    user: String,
}

/// Network connection row for tables
#[derive(Tabled)]
struct ConnectionRow {
    #[tabled(rename = "Proto")]
    protocol: String,
    #[tabled(rename = "Local Address")]
    local: String,
    #[tabled(rename = "Remote Address")]
    remote: String,
    #[tabled(rename = "State")]
    state: String,
}

/// Calculate total memory usage of a process tree (target + all descendants)
#[cfg(windows)]
fn get_process_tree_memory(pid: u32) -> Option<u64> {
    use witr_platform_windows::get_memory_usage;

    let processes = list_processes().ok()?;

    // Find all descendants recursively
    let mut tree_pids = vec![pid];
    let mut i = 0;
    while i < tree_pids.len() {
        let parent_pid = tree_pids[i];
        for proc in processes.values() {
            if proc.ppid == parent_pid && !tree_pids.contains(&proc.pid) {
                tree_pids.push(proc.pid);
            }
        }
        i += 1;
    }

    // Sum memory of all processes in the tree
    let mut total: u64 = 0;
    for &child_pid in &tree_pids {
        if let Ok(mem) = get_memory_usage(child_pid) {
            total += mem;
        }
    }

    if total > 0 {
        Some(total)
    } else {
        None
    }
}

/// Print the handles section with table format
#[cfg(windows)]
fn print_handles_table(out: &mut impl Write, handles: &[HandleInfo], cli: &Cli, colors: &Colors) {
    // Group handles by type
    let mut by_type: std::collections::HashMap<&str, Vec<&HandleInfo>> =
        std::collections::HashMap::new();
    for handle in handles {
        by_type.entry(&handle.object_type).or_default().push(handle);
    }

    // Sort types by count (descending)
    let mut types: Vec<_> = by_type.into_iter().collect();
    types.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    print_section(out, "Handles", colors.header);
    print_sub_item(out, &format!("({} open)", handles.len()), colors.dim);
    writeln!(out).ok();

    // Create summary table
    let summary_rows: Vec<HandleSummaryRow> = types
        .iter()
        .map(|(type_name, type_handles)| HandleSummaryRow {
            object_type: type_name.to_string(),
            count: type_handles.len(),
        })
        .collect();

    let table = Table::new(&summary_rows)
        .with(TableStyle::rounded())
        .with(Modify::new(Columns::single(1)).with(Alignment::right()))
        .to_string();

    for line in table.lines() {
        writeln!(out, "  {}", line).ok();
    }

    // In verbose mode, show individual handles for key types
    if cli.verbose {
        writeln!(out).ok();
        for (type_name, type_handles) in &types {
            if !type_handles.is_empty() && (*type_name == "File" || *type_name == "Key") {
                writeln!(out, "  {} {}:", "▸".style(colors.info), type_name).ok();
                for handle in type_handles.iter().take(15) {
                    let name = handle.name.as_deref().unwrap_or("<unnamed>");
                    writeln!(
                        out,
                        "    {} {}",
                        format!("0x{:04X}", handle.handle_value).style(colors.dim),
                        name.style(colors.dim)
                    )
                    .ok();
                }
                if type_handles.len() > 15 {
                    writeln!(
                        out,
                        "    {} ... and {} more",
                        "".style(colors.dim),
                        type_handles.len() - 15
                    )
                    .ok();
                }
            }
        }
    }

    writeln!(out).ok();
}

/// Print performance metrics section
#[cfg(windows)]
fn print_perf_section(
    out: &mut impl Write,
    perf: &witr_platform_windows::ProcessPerformance,
    colors: &Colors,
) {
    use witr_platform_windows::perf::{format_bytes, format_duration};

    print_section(out, "Performance", colors.header);

    // CPU times
    writeln!(out).ok();
    print_sub_item(out, "CPU Time:", colors.info);
    print_sub_item(
        out,
        &format!("  User:   {}", format_duration(perf.cpu.user_seconds())),
        colors.dim,
    );
    print_sub_item(
        out,
        &format!("  Kernel: {}", format_duration(perf.cpu.kernel_seconds())),
        colors.dim,
    );
    print_sub_item(
        out,
        &format!("  Total:  {}", format_duration(perf.cpu.total_seconds())),
        colors.dim,
    );

    // I/O stats
    writeln!(out).ok();
    print_sub_item(out, "I/O Statistics:", colors.info);
    print_sub_item(
        out,
        &format!(
            "  Read:   {} ({} ops)",
            format_bytes(perf.io.read_bytes),
            perf.io.read_operations
        ),
        colors.dim,
    );
    print_sub_item(
        out,
        &format!(
            "  Write:  {} ({} ops)",
            format_bytes(perf.io.write_bytes),
            perf.io.write_operations
        ),
        colors.dim,
    );
    if perf.io.other_bytes > 0 || perf.io.other_operations > 0 {
        print_sub_item(
            out,
            &format!(
                "  Other:  {} ({} ops)",
                format_bytes(perf.io.other_bytes),
                perf.io.other_operations
            ),
            colors.dim,
        );
    }

    writeln!(out).ok();
}

/// Print security information section
#[cfg(windows)]
fn print_security_section(
    out: &mut impl Write,
    security: &SecurityInfo,
    cli: &Cli,
    colors: &Colors,
) {
    print_section(out, "Security", colors.header);

    // Integrity level with color coding
    let integrity_style = match security.integrity_level {
        IntegrityLevel::System | IntegrityLevel::Protected => colors.warning,
        IntegrityLevel::High => colors.success,
        IntegrityLevel::Low | IntegrityLevel::Untrusted => colors.error,
        _ => colors.dim,
    };
    print_sub_item(
        out,
        &format!(
            "Integrity: {}",
            security.integrity_level.to_string().style(integrity_style)
        ),
        Style::new(),
    );

    // Enabled privileges (only show if verbose or there are interesting ones)
    let enabled_privs: Vec<_> = security.privileges.iter().filter(|p| p.enabled).collect();

    if !enabled_privs.is_empty() {
        writeln!(out).ok();
        print_sub_item(
            out,
            &format!("Privileges: ({} enabled)", enabled_privs.len()),
            colors.info,
        );

        // Highlight dangerous privileges
        let dangerous = [
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLoadDriverPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeImpersonatePrivilege",
        ];

        for priv_info in &enabled_privs {
            let is_dangerous = dangerous.iter().any(|d| priv_info.name.contains(d));
            let style = if is_dangerous {
                colors.warning
            } else {
                colors.dim
            };
            let prefix = if is_dangerous { "⚠ " } else { "  " };
            print_sub_item(
                out,
                &format!("{}{}", prefix, priv_info.name.style(style)),
                Style::new(),
            );
        }

        // In verbose mode, also show disabled privileges
        if cli.verbose {
            let disabled_privs: Vec<_> =
                security.privileges.iter().filter(|p| !p.enabled).collect();
            if !disabled_privs.is_empty() {
                writeln!(out).ok();
                print_sub_item(
                    out,
                    &format!("Disabled: ({} privileges)", disabled_privs.len()),
                    colors.dim,
                );
                for priv_info in disabled_privs.iter().take(10) {
                    print_sub_item(out, &format!("  {}", priv_info.name), colors.dim);
                }
                if disabled_privs.len() > 10 {
                    print_sub_item(
                        out,
                        &format!("  ... and {} more", disabled_privs.len() - 10),
                        colors.dim,
                    );
                }
            }
        }
    }

    writeln!(out).ok();
}

/// Print network connections section
#[cfg(windows)]
fn print_network_section(out: &mut impl Write, connections: &[NetworkConnection], colors: &Colors) {
    print_section(out, "Network", colors.header);
    print_sub_item(
        out,
        &format!("({} connections)", connections.len()),
        colors.dim,
    );
    writeln!(out).ok();

    // Build table rows
    let rows: Vec<ConnectionRow> = connections
        .iter()
        .map(|conn| {
            let local = format!("{}:{}", conn.local_addr, conn.local_port);
            let remote = match (&conn.remote_addr, conn.remote_port) {
                (Some(addr), Some(port)) => format!("{}:{}", addr, port),
                _ => "-".to_string(),
            };
            let state = conn
                .state
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());

            ConnectionRow {
                protocol: conn.protocol.to_string(),
                local,
                remote,
                state,
            }
        })
        .collect();

    let table = Table::new(&rows).with(TableStyle::rounded()).to_string();

    for line in table.lines() {
        writeln!(out, "  {}", line).ok();
    }

    writeln!(out).ok();
}

/// Print a colored human-readable report
fn print_colored_report(report: &Report, cli: &Cli, colors: &Colors) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    const ONE_GB: u64 = 1024 * 1024 * 1024;

    // Process info section
    if let Some(proc) = &report.process {
        // Build flags
        let mut flags: Vec<String> = Vec::new();
        if let Some(mem) = proc.memory_bytes {
            if mem > ONE_GB {
                flags.push("high-mem".to_string());
            }
        }

        let flags_str = if flags.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                format!("[{}]", flags.join(", ")).style(colors.warning)
            )
        };

        // Process row with name, PID, and flags
        let process_value = format!(
            "{} (pid {}){}",
            proc.name().style(colors.highlight),
            proc.pid.to_string().style(colors.info),
            flags_str
        );
        print_row_raw(&mut out, "Process", process_value, colors.header);

        // User
        if let Some(user) = &proc.user {
            print_row(&mut out, "User", user, colors.header, colors.info);
        }

        // Command (image path)
        if let Some(path) = &proc.image_path {
            print_row(&mut out, "Command", path, colors.header, colors.dim);
        }

        // Command line arguments (truncated if too long)
        if let Some(cmdline) = &proc.cmdline {
            let display_cmdline = if cmdline.len() > 80 {
                format!("{}...", &cmdline[..77])
            } else {
                cmdline.clone()
            };
            print_row(
                &mut out,
                "Args",
                &display_cmdline,
                colors.header,
                colors.dim,
            );
        }

        // Started time
        if let Some(start_time) = &proc.start_time {
            let relative = format_relative_time(start_time);
            let absolute = format_absolute_time(start_time);
            let time_value = format!(
                "{} ({})",
                relative.style(colors.dim),
                absolute.style(colors.dim)
            );
            print_row_raw(&mut out, "Started", time_value, colors.header);
        }

        // Thread count
        if let Some(threads) = proc.thread_count {
            print_row(
                &mut out,
                "Threads",
                &threads.to_string(),
                colors.header,
                colors.dim,
            );
        }
    }

    // Why It Exists section
    print_section(&mut out, "Why It Exists", colors.header);

    // Ancestry chain
    if !report.ancestry.is_empty() {
        let chain: Vec<String> = report
            .ancestry
            .iter()
            .rev() // Reverse to show from root to target
            .filter(|node| node.relation != witr_core::AncestryRelation::Orphaned) // Skip exited processes
            .map(|node| {
                format!(
                    "{} (pid {})",
                    node.process.name().style(colors.info),
                    node.process.pid.to_string().style(colors.dim)
                )
            })
            .collect();

        // Add target process at the end
        if let Some(proc) = &report.process {
            let mut full_chain = chain;
            full_chain.push(format!(
                "{} (pid {})",
                proc.name().style(colors.highlight),
                proc.pid.to_string().style(colors.dim)
            ));
            print_sub_item(&mut out, &full_chain.join(" → "), Style::new());
        } else {
            print_sub_item(&mut out, &chain.join(" → "), Style::new());
        }
    }

    // Source classification
    let kind_style = match report.source.kind {
        SourceKind::Service => colors.info,
        SourceKind::Interactive => colors.success,
        SourceKind::ScheduledTask => colors.warning,
        SourceKind::System => colors.highlight,
        SourceKind::ContainerLike => colors.info,
        SourceKind::Unknown => colors.dim,
    };

    print_row(
        &mut out,
        "Source",
        &report.source.description,
        colors.header,
        kind_style,
    );

    // Working directory
    if let Some(proc) = &report.process {
        if let Some(ref cwd) = proc.working_dir {
            print_row(&mut out, "Working Dir", cwd, colors.header, colors.dim);
        }
    }

    // Memory section
    if let Some(proc) = &report.process {
        if let Some(target_mem) = proc.memory_bytes {
            print_section(&mut out, "Memory", colors.header);

            let target_label = format!("Target PID size : {}", format_memory_size(target_mem));
            print_sub_item(
                &mut out,
                &format!("- {}", target_label),
                if target_mem > ONE_GB {
                    colors.warning
                } else {
                    colors.dim
                },
            );

            #[cfg(windows)]
            if let Some(tree_mem) = get_process_tree_memory(proc.pid) {
                let tree_label = format!("Process tree    : {}", format_memory_size(tree_mem));
                print_sub_item(
                    &mut out,
                    &format!("- {}", tree_label),
                    if tree_mem > ONE_GB {
                        colors.warning
                    } else {
                        colors.dim
                    },
                );
            }
        }
    }

    // Warnings section (filter out exited process warnings - these are noise)
    let filtered_warnings: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| !matches!(w, Warning::ParentExited { .. } | Warning::ProcessExited))
        .collect();
    if !filtered_warnings.is_empty() {
        print_section(&mut out, "Warnings", colors.warning);
        for warning in filtered_warnings {
            print_sub_item(
                &mut out,
                &format!("• {}", format_warning(warning)),
                colors.warning,
            );
        }
    }

    // Evidence (verbose only)
    if cli.verbose && !report.evidence.is_empty() {
        print_section(&mut out, "Evidence", colors.header);
        for ev in &report.evidence {
            let conf_style = match ev.confidence {
                Confidence::High => colors.success,
                Confidence::Medium => colors.warning,
                Confidence::Low => colors.dim,
            };
            let evidence_line = format!(
                "• {} {}",
                ev.fact,
                format!("[{:?}]", ev.confidence).style(conf_style)
            );
            print_sub_item(&mut out, &evidence_line, Style::new());

            if let Some(details) = &ev.details {
                print_sub_item(&mut out, &format!("  {}", details), colors.dim);
            }
        }
    }

    // Modules section (with table for many modules)
    #[cfg(windows)]
    if cli.modules {
        if let Some(proc) = &report.process {
            match list_modules(proc.pid) {
                Ok(modules) => {
                    print_section(&mut out, "Modules", colors.header);
                    print_sub_item(&mut out, &format!("({} loaded)", modules.len()), colors.dim);
                    writeln!(out).ok();

                    // Use table for modules (show first 50 in table)
                    let module_rows: Vec<ModuleRow> = modules
                        .iter()
                        .take(if cli.verbose { 100 } else { 30 })
                        .map(|m| ModuleRow {
                            name: m.name.clone(),
                            size: format_module_size(m.size),
                            path: if cli.verbose {
                                m.path.clone()
                            } else {
                                // Truncate path for non-verbose
                                if m.path.len() > 50 {
                                    format!("...{}", &m.path[m.path.len() - 47..])
                                } else {
                                    m.path.clone()
                                }
                            },
                        })
                        .collect();

                    let table = Table::new(&module_rows)
                        .with(TableStyle::rounded())
                        .with(Modify::new(Columns::single(1)).with(Alignment::right()))
                        .to_string();

                    for line in table.lines() {
                        writeln!(out, "  {}", line).ok();
                    }

                    if modules.len() > if cli.verbose { 100 } else { 30 } {
                        writeln!(
                            out,
                            "  {} ... and {} more (use -v to see more)",
                            "".style(colors.dim),
                            modules.len() - if cli.verbose { 100 } else { 30 }
                        )
                        .ok();
                    }
                    writeln!(out).ok();
                }
                Err(e) => {
                    print_sub_item(
                        &mut out,
                        &format!("⚠ Could not list modules: {}", e),
                        colors.warning,
                    );
                }
            }
        }
    }

    // Handles section (with table)
    #[cfg(windows)]
    if cli.handles {
        if let Some(proc) = &report.process {
            match list_handles(proc.pid) {
                Ok(handles) => {
                    print_handles_table(&mut out, &handles, cli, colors);
                }
                Err(e) => {
                    print_sub_item(
                        &mut out,
                        &format!("⚠ Could not list handles: {}", e),
                        colors.warning,
                    );
                }
            }
        }
    }

    // Performance metrics section
    #[cfg(windows)]
    if cli.perf {
        if let Some(proc) = &report.process {
            match get_process_performance(proc.pid) {
                Ok(perf) => {
                    print_perf_section(&mut out, &perf, colors);
                }
                Err(e) => {
                    print_sub_item(
                        &mut out,
                        &format!("⚠ Could not get performance metrics: {}", e),
                        colors.warning,
                    );
                }
            }
        }
    }

    // Network connections (if --net flag is used)
    #[cfg(windows)]
    if cli.net {
        if let Some(proc) = &report.process {
            match get_connections_for_pid(proc.pid) {
                Ok(connections) if !connections.is_empty() => {
                    print_network_section(&mut out, &connections, colors);
                }
                Ok(_) => {
                    print_section(&mut out, "Network", colors.header);
                    print_sub_item(&mut out, "(no connections)", colors.dim);
                    writeln!(out).ok();
                }
                Err(e) => {
                    print_sub_item(
                        &mut out,
                        &format!("⚠ Could not get network connections: {}", e),
                        colors.warning,
                    );
                }
            }
        }
    }

    // Security information (if --security flag is used)
    #[cfg(windows)]
    if cli.security {
        if let Some(proc) = &report.process {
            match get_security_info(proc.pid) {
                Ok(security) => {
                    print_security_section(&mut out, &security, cli, colors);
                }
                Err(e) => {
                    print_sub_item(
                        &mut out,
                        &format!("⚠ Could not get security info: {}", e),
                        colors.warning,
                    );
                }
            }
        }
    }

    // Environment variables (verbose mode only)
    #[cfg(windows)]
    if cli.verbose {
        if let Some(proc) = &report.process {
            match get_interesting_env_vars(proc.pid) {
                Ok(env_vars) if !env_vars.is_empty() => {
                    print_section(&mut out, "Environment", colors.header);
                    for var in &env_vars {
                        let display_value = if var.value.len() > 60 {
                            format!("{}...", &var.value[..57])
                        } else {
                            var.value.clone()
                        };
                        print_sub_item(
                            &mut out,
                            &format!("{}: {}", var.name, display_value),
                            colors.dim,
                        );
                    }
                    writeln!(out).ok();
                }
                Ok(_) => {}  // No interesting env vars found
                Err(_) => {} // Silently ignore errors (access denied, etc.)
            }
        }
    }

    // Errors
    if !report.errors.is_empty() {
        print_section(&mut out, "Errors", colors.error);
        for error in &report.errors {
            print_sub_item(&mut out, &format!("✖ {}", error), colors.error);
        }
    }

    writeln!(out).ok();
}

/// Print a colored ancestry tree
fn print_colored_tree(report: &Report, colors: &Colors) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Start with the target process
    if let Some(proc) = &report.process {
        writeln!(
            out,
            "{} {} {}",
            "●".style(colors.success),
            proc.name().style(colors.highlight),
            format!("(PID {})", proc.pid).style(colors.dim)
        )
        .ok();
    }

    // Build tree upward
    for (i, node) in report.ancestry.iter().enumerate() {
        let is_last = i == report.ancestry.len() - 1;
        let prefix = if is_last { "└── " } else { "├── " };

        let indent = "│   ".repeat(i);

        writeln!(
            out,
            "{}{}{} {}",
            indent.style(colors.dim),
            prefix.style(colors.dim),
            node.process.name().style(colors.info),
            format!("(PID {})", node.process.pid).style(colors.dim)
        )
        .ok();
    }

    writeln!(out).ok();

    // Summary line
    writeln!(
        out,
        "{}: {}",
        "Source".style(colors.header),
        report.source.description.style(colors.highlight)
    )
    .ok();
}

/// Format a warning for display
fn format_warning(warning: &Warning) -> String {
    match warning {
        Warning::NoAdminPrivileges => "Running without admin privileges".to_string(),
        Warning::ParentExited { last_known_ppid } => {
            format!(
                "Parent process (PID {}) has exited; ancestry chain is incomplete",
                last_known_ppid
            )
        }
        Warning::ProcessExited => "Process exited during analysis".to_string(),
        Warning::AccessDenied { what } => format!("Access denied: {}", what),
        Warning::ApiFailed { api, error } => format!("{} failed: {}", api, error),
        Warning::PidReused => "PID may have been reused".to_string(),
        Warning::AncestryTruncated { depth } => {
            format!("Ancestry truncated at depth {}", depth)
        }
        Warning::Other(msg) => {
            // Format common warning patterns to match screenshot style
            if msg.contains("high memory") || msg.contains(">1GB") {
                "Process is using high memory (>1GB RSS)".to_string()
            } else if msg.contains("listening on all interfaces") || msg.contains("0.0.0.0") {
                "Process is listening on a public interface".to_string()
            } else if msg.contains("over 90 days") || msg.contains("running for") {
                "Process has been running for over 90 days".to_string()
            } else {
                msg.clone()
            }
        }
    }
}

/// Print an error message
fn print_error(colors: &Colors, message: &str) {
    eprintln!("{} {}", "error:".style(colors.error), message);
}

/// Print a warning message
fn print_warning(colors: &Colors, message: &str) {
    eprintln!("{} {}", "warning:".style(colors.warning), message);
}

/// Print an info message
fn print_info(colors: &Colors, message: &str) {
    eprintln!("{} {}", "info:".style(colors.info), message);
}

/// Check if the terminal supports color
fn supports_color() -> bool {
    // Check for common NO_COLOR convention
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check for TERM
    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }

    // On Windows, check for ENABLE_VIRTUAL_TERMINAL_PROCESSING
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::{
            GetConsoleMode, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        };

        let stdout = io::stdout();
        let handle = HANDLE(stdout.as_raw_handle() as _);

        unsafe {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                // Try to enable VT processing
                let new_mode = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if SetConsoleMode(handle, new_mode).is_ok() {
                    return true;
                }
            }
        }

        // Fallback: check if output is to a console at all
        true
    }

    #[cfg(not(windows))]
    {
        // On Unix, check if stdout is a TTY
        atty::is(atty::Stream::Stdout)
    }
}

// Stubs for non-Windows platforms
#[cfg(not(windows))]
fn handle_pid(_pid: u32, _cli: &Cli, colors: &Colors) -> Result<(), String> {
    print_error(colors, "This tool only works on Windows");
    std::process::exit(exit_codes::ERROR_GENERAL);
}

#[cfg(not(windows))]
fn handle_port(_port: u16, _cli: &Cli, colors: &Colors) -> Result<(), String> {
    print_error(colors, "This tool only works on Windows");
    std::process::exit(exit_codes::ERROR_GENERAL);
}

#[cfg(not(windows))]
fn handle_name(_name: &str, _cli: &Cli, colors: &Colors) -> Result<(), String> {
    print_error(colors, "This tool only works on Windows");
    std::process::exit(exit_codes::ERROR_GENERAL);
}
