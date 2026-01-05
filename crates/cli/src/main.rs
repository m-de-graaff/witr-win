//! witr: Windows-native CLI tool that explains why a process exists

use clap::{Parser, ValueEnum};
use witr_core::{render, Report, SourceClassification, Target, Warning};

#[derive(Parser)]
#[command(name = "witr")]
#[command(
    version,
    about = "Why Is This Running? - Explain why a Windows process exists"
)]
struct Cli {
    /// Process ID to analyze
    #[arg(long)]
    pid: Option<u32>,

    /// Port number to find the owning process
    #[arg(long)]
    port: Option<u16>,

    /// Process name to look up
    #[arg(value_name = "NAME")]
    name: Option<String>,

    /// Output format
    #[arg(long, short, value_enum, default_value = "text")]
    output: OutputFormat,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// Human-readable narrative (default)
    Text,
    /// Machine-readable JSON
    Json,
    /// Process ancestry tree
    Tree,
    /// Single-line causal chain
    Short,
}

fn main() {
    let cli = Cli::parse();

    // Determine target
    let target = if let Some(pid) = cli.pid {
        Target::Pid(pid)
    } else if let Some(port) = cli.port {
        Target::Port(port)
    } else if let Some(name) = cli.name {
        Target::Name(name)
    } else {
        eprintln!("Error: Must specify --pid, --port, or a process name");
        std::process::exit(1);
    };

    // TODO: Build report using platform-windows collectors
    let mut report = Report::new(target);
    report.source = SourceClassification::unknown();
    report.add_warning(Warning::Other(
        "This is a placeholder implementation".to_string(),
    ));

    // Render output
    match cli.output {
        OutputFormat::Text => print!("{}", render::render_human(&report)),
        OutputFormat::Json => match render::json::render_json_string(&report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error rendering JSON: {}", e);
                std::process::exit(1);
            }
        },
        OutputFormat::Tree => print!("{}", render::render_tree(&report)),
        OutputFormat::Short => println!("{}", render::render_short(&report)),
    }
}
