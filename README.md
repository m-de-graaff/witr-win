# witr-win (Why Is This Running? - Windows Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows-blue.svg)](https://www.microsoft.com/windows)
[![Rust](https://img.shields.io/badge/built_with-Rust-d6t.svg)](https://www.rust-lang.org/)

**witr-win** is a powerful, native CLI tool designed exclusively for Windows to explain *why* a process exists. It goes beyond simple task listing by building a causal chain of process ancestry, analyzing system signals, and providing deep inspection capabilities—all in a convenient terminal interface.

> "It's like `ps` meets `netstat` meets `Process Explorer`, but for the command line."

---

## 🚀 Why Use witr-win?

- **🔍 Deep Causality**: Don't just see *what* is running, see *who* started it and *why* (parent process chain).
- **🛡️ Security & Integrity**: Inspect DLL modules, open file handles, security tokens, and integrity levels.
- **🌐 Network Aware**: Instantly identify what process is holding a port, or what connections a process has open.
- **⚡ Performance Metrics**: View real-time CPU, memory, and I/O statistics.
- **📸 Time Travel**: Take **snapshots** of process states and **compare** them later to detect changes.
- **🤖 Automation Ready**: Output in JSON for scripts, or visualize ancestry with Graphviz DOT format.
- **🖥️ TUI Mode**: Interactive terminal UI for exploring processes without remembering flags.

---

## 📦 Installation

Choose the method that fits your workflow.

### Option 1: Scoop (Recommended)
If you use [Scoop](https://scoop.sh/):

```powershell
scoop bucket add witr-win https://github.com/m-de-graaff/witr-win-bucket
scoop install witr-win
```

### Option 2: Chocolatey
If you use [Chocolatey](https://chocolatey.org/):

```powershell
choco install witr-win
```

### Option 3: Manual Download
1. Go to the [Releases Page](https://github.com/m-de-graaff/witr-win/releases).
2. Download the latest `witr-win.exe`.
3. Place it in a folder included in your system `PATH`.

### Option 4: Build from Source
Requires [Rust](https://rustup.rs/) installed.

```powershell
cargo install --git https://github.com/m-de-graaff/witr-win
```

---

## 📖 Usage Guide

Everything starts with `witr-win`. Run it with `--help` for a quick refresher.

### 🎯 Basic Targeting
Find out what you're looking for.

| Goal | Command | Description |
|------|---------|-------------|
| **Analyze by PID** | `witr-win --pid 1234` | Analyze a specific Process ID. |
| **Analyze by Port** | `witr-win --port 8080` | Find the process listening on port 8080. |
| **Search by Name** | `witr-win node` | Find processes matching "node". |
| **Interactive Mode** | `witr-win -i` | Launch the TUI to select a process interactively. |

### 🔍 Deep Inspection
Add flags to get more details about the target.

```powershell
# Show EVERYTHING (Modules, Handles, Network, Perf, Security)
witr-win --pid 1234 --all

# Show specific details
witr-win --pid 1234 --modules   # List loaded DLLs
witr-win --pid 1234 --handles   # List open files/registry keys
witr-win --pid 1234 --net       # List active network connections
witr-win --pid 1234 --perf      # Show CPU/RAM usage
witr-win --pid 1234 --security  # Show User, SID, Integrity Level
```

### 📊 Output Formats
Tailor the output to your needs.

```powershell
# Default (Human Readable Narrative)
witr-win --pid 1234

# Tree View (Visualize Ancestry)
witr-win --pid 1234 --tree

# JSON (For Scripts/Automation)
witr-win --pid 1234 --json

# One-Liner (For Piping/Logging)
witr-win --pid 1234 --short

# Graphviz DOT (Visual Diagram)
witr-win --pid 1234 --graph > ancestry.dot
```

---

## 🛠️ Advanced Features

### 📸 Snapshots & Comparison
Track how a process changes over time (memory leaks, handle leaks, etc.).

1. **Take a Snapshot**:
   ```powershell
   witr-win --pid 1234 --snapshot "baseline"
   ```
2. **Wait/Do work...**
3. **Compare Current State to Snapshot**:
   ```powershell
   witr-win --pid 1234 --compare "baseline"
   ```
   *This will highlight differences in memory, thread count, and configuration.*

4. **List Snapshots**:
   ```powershell
   witr-win --list-snapshots
   ```

### ⚙️ Configuration
Customize defaults so you don't have to type flags every time.

1. **Generate Config**:
   ```powershell
   witr-win --init-config
   ```
   *Creates `~/.witr-win/config.toml`*

2. **Edit Config**:
   Open that file to set preferred defaults (e.g., always enable `--tree` or `--no-color`).

### 🔄 Auto-Update
Keep your tool fresh.

```powershell
witr-win --check-update
witr-win --update
```

### 🛡️ Process Control
Need to stop a rogue process?

```powershell
# Kill the process on port 3000
witr-win --port 3000 --end
```

### 🌐 Network Scanning
Explore your network footprint.

```powershell
# Netstat-like list of all listening ports
witr-win --list-ports

# Scan a specific range
witr-win --port-range 5000-5010

# Filter by protocol
witr-win --port 80 --protocol tcp
```

---

## 🗺️ Roadmap

We are constantly improving `witr-win`. Here's what's planned:

- **Classification**: Better recognition of "Scheduled Tasks" and Service dependencies.
- **Container Awareness**: Detection of Docker/Podman processes.
- **Advanced Filtering**: Filter by user, memory usage, or interactive status.
- **Security**: ASLR/DEP status and digital signature verification.

See [FEATURES.md](./FEATURES.md) for the full roadmap.

## 🤝 Contributing

Contributions are welcome! Please check out [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the [MIT License](./LICENSE).
