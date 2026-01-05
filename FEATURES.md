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

- ✅ **Interactive Mode** - `witr-win --interactive` or `witr-win -i`
  - TUI with process list, search, sort, and filtering
  - Navigate with arrow keys, Enter to analyze, / to search

### Advanced Features

- ✅ **Process Dependencies Graph** - Visualize ancestry as DOT/Graphviz
  - `witr-win --pid 1234 --graph` (pipe to `dot -Tpng` for image)

- ✅ **Historical Analysis** - Track process changes over time
  - `witr-win --pid 1234 --snapshot myapp` - Save snapshot
  - `witr-win --pid 1234 --compare myapp` - Compare with snapshot
  - `witr-win --list-snapshots` - List all snapshots

### Security & Compliance

- ✅ **Integrity Level Detection** - Show process integrity level (Low, Medium, High, System)
- ✅ **Privilege Detection** - Show enabled privileges (SeDebugPrivilege, etc.) with dangerous privilege warnings
- **ASLR/DEP Status** - Show security mitigations (requires additional Windows features)
- **Digital Signature Verification** - Verify process image signature (requires WinTrust API)

### Quality of Life

- ✅ **Aliases** - Short flags: `-p` for `--pid`, `-P` for `--port`, `-a` for `--all`
- ✅ **Better Error Messages** - More actionable error messages with examples
- ✅ **Exit Codes** - Proper exit codes for scripting (0=success, 1=error, 2=not found, 3=access denied, 4=invalid input)
- ✅ **Config File** - `~/.witr-win/config.toml` for defaults (`--init-config` to generate)
---