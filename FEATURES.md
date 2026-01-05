# Features & Roadmap

This document tracks implemented features and planned enhancements for witr-win.

---

## 🚧 Planned Features

### High Priority

### Medium Priority

- **CPU Usage Percentage** - Calculate real-time CPU usage (requires watch mode)

### Network Enhancements

- **Port Range Queries** - `witr-win --port-range 5000-5010`
- **Protocol Filter** - `witr-win --port 80 --protocol tcp`
- **Show All Listeners** - `witr-win --list-ports` (like `netstat -an`)

### Classification Enhancements

- **Scheduled Task Names** - Show actual task name, not just "Scheduled Task"
  - Use Task Scheduler COM API

- **Service Dependencies** - Show what services depend on this service
  - Use `QueryServiceConfig2`

- **AppX/UWP Detection** - Detect Windows Store apps
- **WSL Process Detection** - Identify WSL2 processes
- **Container Detection** - Docker Desktop, Podman Desktop

### Output & UX Enhancements

- **Watch Mode** - `witr-win --watch --pid 1234` (monitor process changes)
- **Batch Mode** - `witr-win --pid 1234,5678,9012` (analyze multiple PIDs)
- **Filter Options**:
  - `--filter-service` - Only show service processes
  - `--filter-interactive` - Only show interactive processes
  - `--filter-user USER` - Filter by user
  - `--filter-memory-gt 1GB` - Filter by memory usage

- **Export to File** - `witr-win --pid 1234 --output-file report.json`
- **CSV Output** - `witr-win --port 5000 --format csv`
- **Markdown Output** - `witr-win --pid 1234 --format markdown`

- **Interactive Mode** - `witr-win --interactive` (TUI with search/filter)
  - Use `ratatui` or `crossterm` for TUI

### Advanced Features

- **Process Dependencies Graph** - Visualize all dependencies
  - `witr-win --pid 1234 --graph` (output as DOT/Graphviz)

- **Historical Analysis** - Track process changes over time
  - Store snapshots, compare changes

### Security & Compliance

- **Integrity Level Detection** - Show process integrity level (Low, Medium, High, System)
- **Privilege Detection** - Show enabled privileges (SeDebugPrivilege, etc.)
- **ASLR/DEP Status** - Show security mitigations
- **Digital Signature Verification** - Verify process image signature

### Quality of Life

- **Aliases** - `witr-win p 1234` instead of `--pid 1234`
- **Config File** - `~/.witr-win/config.toml` for defaults
- **Caching** - Cache process info for faster repeated queries
- **Better Error Messages** - More actionable error messages
- **Exit Codes** - Proper exit codes for scripting

### Integration

- **PowerShell Module** - `Import-Module witr-win`
- **VS Code Extension** - Right-click process → "Why is this running?"
- **Windows Terminal Integration** - Context menu integration

---