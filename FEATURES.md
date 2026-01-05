# Additional Features & Enhancements

This document outlines potential features and enhancements for witr-win beyond the current v0.2.0 release.

## 🔍 Process Information Enhancements

### High Priority
- **Memory Usage Detection** - Show RSS/working set size, flag processes using >1GB as `[high-mem]`
  - Use `GetProcessMemoryInfo` or `NtQueryInformationProcess`
  - Add to ProcessInfo model
  - Display in output with warning if high

- **Command Line Arguments** - Show full command line (currently TODO)
  - Use WMI `Win32_Process` or `NtQueryInformationProcess` with `ProcessCommandLineInformation`
  - Display truncated if too long (>80 chars)

- **Working Directory** - Show process working directory
  - Use `NtQueryInformationProcess` with `ProcessWorkingSetWatch`
  - Or WMI `Win32_Process.ExecutablePath`

- **Environment Variables** - Show key environment variables (optional, verbose mode)
  - Use `NtQueryInformationProcess` with `ProcessEnvironmentBlock`
  - Filter to show only interesting vars (PATH, USER, etc.)

### Medium Priority
- **Thread Count** - Already available in ProcessEntry, expose in ProcessInfo
- **CPU Usage** - Calculate CPU time percentage
- **Handle Count** - Number of open handles (file, registry, etc.)
- **Network Connections** - Show all TCP/UDP connections (not just listening ports)
  - Use `GetExtendedTcpTable` for all states
  - Show ESTABLISHED, TIME_WAIT, etc.

## 🌐 Network Enhancements

- **Connection Details** - For port queries, show:
  - Remote addresses (for ESTABLISHED connections)
  - Connection state
  - Protocol (TCP/UDP)
  - All listening interfaces (IPv4 + IPv6)

- **Port Range Queries** - `witr-win --port-range 5000-5010`
- **Protocol Filter** - `witr-win --port 80 --protocol tcp`
- **Show All Listeners** - `witr-win --list-ports` (like `netstat -an`)

## 🏷️ Classification Enhancements

- **Scheduled Task Names** - Currently shows "Scheduled Task" but not the task name
  - Use Task Scheduler COM API (`ITaskScheduler`, `ITaskService`)
  - Query `\Microsoft\Windows\*` tasks
  - Match by process image path or command line

- **Service Dependencies** - Show what services depend on this service
  - Use `QueryServiceConfig2` with `SERVICE_CONFIG_DESCRIPTION`
  - Show service dependencies tree

- **AppX/UWP Detection** - Detect Windows Store apps
  - Check for AppX package identity
  - Use `GetApplicationUserModelId`

- **WSL Process Detection** - Identify WSL2 processes
  - Check for `wsl.exe` ancestry
  - Detect Linux processes running under WSL

- **Container Detection** - Docker Desktop, Podman Desktop
  - Check for container runtime processes
  - Detect containerized processes

## 📊 Output & UX Enhancements

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
- **Color Themes** - `--theme dark|light|auto` (currently auto-detects)

- **Progress Indicators** - Show progress for long operations
  - Use `indicatif` crate for progress bars
  - Show "Analyzing PID 1234..." with spinner

- **Interactive Mode** - `witr-win --interactive` (TUI with search/filter)
  - Use `ratatui` or `crossterm` for TUI
  - Browse processes, filter, drill down

## 🔧 Advanced Features

- **Process Dependencies Graph** - Visualize all dependencies
  - `witr-win --pid 1234 --graph` (output as DOT/Graphviz)
  - Show service dependencies, process tree, network connections

- **Historical Analysis** - Track process changes over time
  - `witr-win --pid 1234 --history` (if process was analyzed before)
  - Store snapshots, compare changes

- **Performance Metrics** - CPU, memory, I/O stats
  - Use Performance Counters API
  - Show over time (if watch mode)

- **File Handles** - Show open files/handles
  - Use `NtQuerySystemInformation` with `SystemHandleInformation`
  - Show file paths, registry keys, etc.

- **Module/DLL List** - Show loaded modules
  - Use `CreateToolhelp32Snapshot` with `TH32CS_SNAPMODULE`
  - Useful for security analysis

## 📦 Distribution & Installation

- **Scoop Manifest** - Community-friendly package manager ✅
  - Created `witr-win.json` manifest file
  - Auto-update support via checkver
  - Ready for submission to Scoop bucket

- **Chocolatey Package** - More ceremony, but widely used ✅
  - Created `chocolatey/witr-win.nuspec`
  - Installation and uninstallation scripts
  - Auto-update support

- **MSI Installer** - Professional installation ✅
  - Created `wix.toml` for cargo-wix
  - Created `wix/main.wxs` WiX source file
  - Add to PATH automatically
  - Uninstaller support

- **Auto-update** - `witr-win --update` or `witr-win --check-update` ✅
  - Check GitHub releases API
  - Download and replace binary
  - Automatic update notifications on every run

## 🔒 Security & Compliance

- **Integrity Level Detection** - Show process integrity level (Low, Medium, High, System)
  - Use `GetTokenInformation` with `TokenIntegrityLevel`
  - Important for security analysis

- **Privilege Detection** - Show enabled privileges (SeDebugPrivilege, etc.)
- **ASLR/DEP Status** - Show security mitigations
- **Digital Signature Verification** - Verify process image signature
  - Use `WinTrust` API
  - Show if signed, by whom

## 🎯 Quality of Life

- **Aliases** - `witr-win p 1234` instead of `--pid 1234`
- **Config File** - `~/.witr-win/config.toml` for defaults
  - Default output format
  - Color preferences
  - Cache settings

- **Caching** - Cache process info for faster repeated queries
  - Store in temp directory
  - TTL-based expiration

- **Better Error Messages** - More actionable error messages
  - "Try running as administrator for full details"
  - "Process may have exited, try again"

- **Exit Codes** - Proper exit codes for scripting
  - 0 = success
  - 1 = process not found
  - 2 = access denied
  - 3 = invalid arguments

## 📈 Performance

- **Parallel Processing** - Analyze multiple PIDs in parallel
- **Lazy Loading** - Only query what's needed for requested output format
- **Streaming Output** - Start showing results as they're discovered
- **Incremental Updates** - Update display as more info is gathered

## 🧪 Testing & Reliability

- **Fuzz Testing** - Fuzz test with random PIDs, ports, names
- **Performance Benchmarks** - Track analysis time
- **Memory Leak Detection** - Ensure no leaks in long-running scenarios
- **Error Recovery** - Better handling of edge cases (PID reuse, etc.)

## 📚 Documentation

- **Man Pages** - Generate man pages from clap
- **Examples Gallery** - Real-world examples in docs
- **Video Tutorials** - Screen recordings showing usage
- **API Documentation** - Full API docs for library usage

## 🔄 Integration

- **PowerShell Module** - `Import-Module witr-win`
- **VS Code Extension** - Right-click process → "Why is this running?"
- **Process Explorer Integration** - Plugin for Process Explorer
- **Windows Terminal Integration** - Context menu integration

---

## Priority Recommendations

### v0.2.0 (Next Release)
1. ✅ Memory usage detection & [high-mem] flag
2. ✅ Command line arguments display
3. ✅ Working directory
4. ✅ Scheduled task name detection
5. ✅ Better warnings (high memory, public interface, long uptime)

### v0.3.0
1. Network connections (all states, not just listening)
2. Watch mode
3. Batch processing
4. Scoop manifest

### Future
- Container support (Docker, WSL)
- Interactive TUI mode
- MSI installer
- Auto-update

