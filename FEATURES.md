# Features & Roadmap

This document tracks implemented features and planned enhancements for witr-win.

---

## ✅ Implemented Features

### Core Analysis
- **Multiple input modes** - Query by PID (`--pid`), port (`--port`), or process name
- **Ancestry chain** - Full parent→grandparent→root chain with classification
- **Source classification** - Services, Scheduled Tasks, Interactive sessions
- **Memory usage** - Working set size with process tree totals
- **Command line arguments** - Full command line display
- **Environment variables** - Key env vars in verbose mode
- **Thread count** - Number of threads in process
- **Working directory** - Process current directory

### Advanced Analysis
- **Loaded modules** (`--modules`) - List all DLLs loaded by process
- **Open handles** (`--handles`) - Files, registry keys, events, mutexes
- **Performance metrics** (`--perf`) - CPU time (user/kernel) and I/O statistics
- **Network connections** (`--net`) - All TCP/UDP with states (ESTABLISHED, LISTEN, etc.)
- **Security analysis** (`--security`) - Integrity level and enabled privileges

### Output Formats
- **Human-readable** - Pretty aligned output with Unicode tables
- **JSON** (`--json`) - Machine-readable output
- **Tree view** (`--tree`) - Visual ancestry tree
- **Short** (`--short`) - Single-line summary
- **DOT graph** (`--graph`) - Graphviz output for visualization

### Interactive & Historical
- **Interactive TUI** (`--interactive`) - Browse processes with search/filter
- **Snapshots** (`--snapshot`) - Save process state for comparison
- **Compare** (`--compare`) - Compare current state with saved snapshot

### Quality of Life
- **Aliases** - `-p` (pid), `-P` (port), `-a` (all), `-i` (interactive), `-S` (security)
- **Config file** - `~/.witr-win/config.toml` for persistent defaults
- **Exit codes** - Proper codes for scripting (0=success, 2=not found, etc.)
- **Better errors** - Actionable error messages with examples
- **Auto-update** - Built-in update checker and installer

---

## 🚧 Planned Features

### High Priority

- **Watch Mode** - `witr-win --watch --pid 1234` (monitor process changes in real-time)

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

- **Batch Mode** - `witr-win --pid 1234,5678,9012` (analyze multiple PIDs)
- **Filter Options**:
  - `--filter-service` - Only show service processes
  - `--filter-interactive` - Only show interactive processes
  - `--filter-user USER` - Filter by user
  - `--filter-memory-gt 1GB` - Filter by memory usage

- **Export to File** - `witr-win --pid 1234 --output-file report.json`
- **CSV Output** - `witr-win --port 5000 --format csv`
- **Markdown Output** - `witr-win --pid 1234 --format markdown`

### Security & Compliance

- **ASLR/DEP Status** - Show security mitigations (requires additional Windows features)
- **Digital Signature Verification** - Verify process image signature (requires WinTrust API)

---
