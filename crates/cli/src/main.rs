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
use witr_core::{render, Confidence, Report, SourceKind, Target, Warning};

#[cfg(windows)]
use witr_platform_windows::{
    analyze_name, analyze_pid, analyze_port, list_processes, pids_for_port, NameAnalysisResult,
    PortAnalysisResult,
};

/// Why Is This Running? - Windows Edition
///
/// A Windows-native CLI tool that explains why a process exists
/// by building a causal chain of process ancestry and system signals.
#[derive(Parser)]
#[command(name = "witr-win")]
#[command(version, about, long_about = None)]
#[command(after_help = "Examples:
  witr-win --pid 1234          Analyze process with PID 1234
  witr-win --port 8080         Find what's listening on port 8080
  witr-win node                Find processes matching 'node'
  witr-win --pid 1234 --json   Output as JSON for scripting
  witr-win --port 80 --tree    Show ancestry tree for port 80 owner")]
struct Cli {
    /// Process ID to analyze
    #[arg(long, short = 'p', value_name = "PID")]
    pid: Option<u32>,

    /// Port number to find the owning process
    #[arg(long, short = 'P', value_name = "PORT")]
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
                info: Style::new().blue(),
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
    let cli = Cli::parse();

    // Determine color mode
    let colors = Colors::new(!cli.no_color && supports_color());

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
        eprintln!("  --pid <PID>     Analyze a process by PID");
        eprintln!("  --port <PORT>   Find process listening on port");
        eprintln!("  <NAME>          Search for process by name");
        eprintln!();
        eprintln!("Run 'witr-win --help' for more information.");
        std::process::exit(1);
    }

    if target_count > 1 {
        print_error(&colors, "Only one target can be specified at a time");
        std::process::exit(1);
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
        print_error(&colors, &format!("Error: {}", e));
        std::process::exit(1);
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

    // Handle warnings about listening publicly
    for warning in &result.warnings {
        print_warning(colors, &format!("{:?}", warning));
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
    if cli.json {
        match render::json::render_json_string(report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                print_error(colors, &format!("Failed to render JSON: {}", e));
                std::process::exit(1);
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
                std::process::exit(1);
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
                std::process::exit(1);
            }
        }
    } else {
        // Just show the first match for non-JSON output
        if let Some(report) = result.reports.first() {
            render_report(report, cli, colors);
        }
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

/// Print a colored human-readable report
fn print_colored_report(report: &Report, cli: &Cli, colors: &Colors) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Process info - compact format like screenshot
    if let Some(proc) = &report.process {
        // Process name with PID and optional flags
        let flags: Vec<String> = Vec::new();
        // TODO: Add memory check for [high-mem] flag

        let flags_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(", "))
        };

        writeln!(
            out,
            "{}: {} (PID {}){}",
            "Process".style(colors.header),
            proc.name().style(colors.highlight),
            proc.pid.to_string().style(colors.info),
            flags_str.style(colors.warning)
        )
        .ok();

        // User
        if let Some(user) = &proc.user {
            writeln!(
                out,
                "  {}: {}",
                "User".style(colors.dim),
                user.style(colors.info)
            )
            .ok();
        }

        // Command (image path)
        if let Some(path) = &proc.image_path {
            writeln!(
                out,
                "  {}: {}",
                "Command".style(colors.dim),
                path.as_str().style(colors.dim)
            )
            .ok();
        }

        // Started time (relative + absolute)
        if let Some(start_time) = &proc.start_time {
            let relative = format_relative_time(start_time);
            let absolute = format_absolute_time(start_time);
            writeln!(
                out,
                "  {}: {} ({})",
                "Started".style(colors.dim),
                relative.style(colors.dim),
                absolute.style(colors.dim)
            )
            .ok();
        }

        writeln!(out).ok();
    }

    // "Why It Exists" section - compact format
    writeln!(out, "{}", "Why It Exists".style(colors.header)).ok();

    // Ancestry (show parent chain)
    if !report.ancestry.is_empty() {
        write!(out, "  {}: ", "Ancestry".style(colors.dim)).ok();
        let chain: Vec<String> = report
            .ancestry
            .iter()
            .map(|node| format!("{} (PID {})", node.process.name(), node.process.pid))
            .collect();
        writeln!(out, "{}", chain.join(" → ").style(colors.highlight)).ok();
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

    writeln!(
        out,
        "  {}: {}",
        "Source".style(colors.dim),
        report.source.description.style(kind_style)
    )
    .ok();

    if let Some(service) = &report.source.service_name {
        writeln!(
            out,
            "    {}: {}",
            "Service".style(colors.dim),
            service.style(colors.info)
        )
        .ok();
    }

    writeln!(out).ok();

    // Evidence (verbose only)
    if cli.verbose && !report.evidence.is_empty() {
        writeln!(out, "{}", "Evidence".style(colors.header)).ok();
        writeln!(out, "{}", "─".repeat(40).style(colors.dim)).ok();

        for ev in &report.evidence {
            let conf_style = match ev.confidence {
                Confidence::High => colors.success,
                Confidence::Medium => colors.warning,
                Confidence::Low => colors.dim,
            };

            writeln!(
                out,
                "  {} {} {}",
                "•".style(conf_style),
                ev.fact,
                format!("[{:?}]", ev.confidence).style(conf_style)
            )
            .ok();

            if let Some(details) = &ev.details {
                writeln!(out, "    {}", details.style(colors.dim)).ok();
            }
        }

        writeln!(out).ok();
    }

    // Warnings - compact format like screenshot
    if !report.warnings.is_empty() {
        for warning in &report.warnings {
            writeln!(
                out,
                "{} {}",
                "⚠".style(colors.warning),
                format_warning(warning).style(colors.warning)
            )
            .ok();
        }
        writeln!(out).ok();
    }

    // Errors
    if !report.errors.is_empty() {
        writeln!(out, "{}", "Errors".style(colors.error)).ok();
        writeln!(out, "{}", "─".repeat(40).style(colors.dim)).ok();

        for error in &report.errors {
            writeln!(
                out,
                "  {} {}",
                "✖".style(colors.error),
                error.style(colors.error)
            )
            .ok();
        }
    }
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
                "Parent process exited (last known PPID: {})",
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
    std::process::exit(1);
}

#[cfg(not(windows))]
fn handle_port(_port: u16, _cli: &Cli, colors: &Colors) -> Result<(), String> {
    print_error(colors, "This tool only works on Windows");
    std::process::exit(1);
}

#[cfg(not(windows))]
fn handle_name(_name: &str, _cli: &Cli, colors: &Colors) -> Result<(), String> {
    print_error(colors, "This tool only works on Windows");
    std::process::exit(1);
}
