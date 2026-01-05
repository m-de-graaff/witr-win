<p align="center">
  <img src="assets/logo.png" alt="witr-win logo" width="120" height="120">
</p>

<h1 align="center">witr-win</h1>

<p align="center">
  <strong>Why Is This Running? - Windows Edition</strong><br>
  A Windows-native CLI tool that explains why a process exists.
</p>

<p align="center">
  <em>Inspired by <a href="https://github.com/pranshuparmar/witr">witr</a> - bringing the same power to Windows</em>
</p>

<p align="center">
  <a href="https://github.com/m-de-graaff/witr-win/actions/workflows/ci.yml">
    <img src="https://github.com/m-de-graaff/witr-win/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/m-de-graaff/witr-win/releases">
    <img src="https://img.shields.io/github/v/release/m-de-graaff/witr-win?include_prereleases" alt="Release">
  </a>
  <a href="https://github.com/m-de-graaff/witr-win/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/m-de-graaff/witr-win" alt="License">
  </a>
  <a href="https://github.com/m-de-graaff/witr-win/stargazers">
    <img src="https://img.shields.io/github/stars/m-de-graaff/witr-win" alt="Stars">
  </a>
</p>

---

## 🎯 What is witr-win?

Ever wondered *"What started this process?"* or *"Why is something listening on port 5000?"*

**witr-win** is the Windows-native port of [witr](https://github.com/pranshuparmar/witr) ("Why Is This Running?"). While the original witr supports Linux and macOS, **witr-win** brings the same functionality to Windows using native Win32 APIs.

It answers these questions by building a **causal chain** - tracing a process back through its ancestry to identify whether it came from a Windows Service, a Scheduled Task, an interactive user session, or something else entirely.

```
$ witr-win --port 3306

     Process : mysqld (pid 483820) [high-mem]
        User : mysql
     Command : /usr/sbin/mysqld
     Started : 256 days ago (Mon 2025-04-14 15:12:56 +02:00)

Why It Exists :
               systemd (pid 1) → mysqld (pid 483820)
      Source : systemd service (supervisor)
 Working Dir : /var/lib/mysql

      Memory :
               - Target PID size : 361.1 MB
               - Process tree    : 2534.6 MB

    Warnings :
               • Process is using high memory (>1GB RSS)
               • Process is listening on a public interface
               • Process has been running for over 90 days
```

## ✨ Features

### Core Features
- 🔍 **Multiple input modes** - Query by PID, port number, or process name
- 🌳 **Ancestry chain** - See the full parent→grandparent→root chain
- 🏷️ **Source classification** - Identifies Services, Scheduled Tasks, Interactive sessions
- 📊 **Multiple output formats** - Human-readable, JSON, tree view, or one-liner
- 🔒 **Graceful degradation** - Works without admin (with reduced detail)
- ⚡ **Fast & native** - Pure Rust, no runtime dependencies

### Process Information
- 💾 **Memory usage** - Shows working set size with [high-mem] flag for >1GB processes
- 📁 **Working directory** - Display process current working directory
- 👤 **User/Owner** - Show which user account owns the process
- ⏰ **Start time** - Both relative ("256 days ago") and absolute timestamps
- 🌲 **Process tree memory** - Total memory of process and all descendants
- 📝 **Command line arguments** - Full command line (truncated if >80 chars)
- 🌍 **Environment variables** - Key env vars shown in verbose mode (PATH, USER, etc.)
- 🧵 **Thread count** - Number of threads in the process

### Advanced Analysis
- 📦 **Loaded modules** (`--modules`) - List all DLLs loaded by the process
- 📂 **Open handles** (`--handles`) - Show open files, registry keys, events, mutexes
- 📈 **Performance metrics** (`--perf`) - CPU time (user/kernel) and I/O statistics
- 🌐 **Network connections** (`--net`) - All TCP/UDP connections with state (ESTABLISHED, LISTEN, etc.)
- ⚠️ **Smart warnings** - Alerts for high memory, public listeners, long uptime

### Output & UX
- 🎨 **Pretty tables** - Aligned output with Unicode tables for modules/handles
- 🔄 **Auto-update** - Built-in update checker and installer (`--update`)
- 📋 **JSON export** - Machine-readable output for scripting
- 🌳 **Tree view** - Visual ancestry tree

## 🚀 Quick Start

### Installation

#### From GitHub Releases (Recommended)

Download the latest release from the [Releases page](https://github.com/m-de-graaff/witr-win/releases).

```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/m-de-graaff/witr-win/releases/latest/download/witr-win.exe" -OutFile "$env:LOCALAPPDATA\Programs\witr\witr-win.exe"

# Add to PATH (run in elevated PowerShell)
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "$path;$env:LOCALAPPDATA\Programs\witr", "User")
```

#### Via Scoop

```powershell
# Add the bucket (if not already added)
scoop bucket add extras

# Install witr-win
scoop install witr-win
```

#### Via Chocolatey

```powershell
choco install witr-win
```

#### From Source

```powershell
# Clone the repository
git clone https://github.com/m-de-graaff/witr-win.git
cd witr-win

# Build release binary
cargo build --release

# The binary will be at target\release\witr-win.exe
```

### Usage

```powershell
# Query by port - "What's listening on port 5000?"
witr-win --port 5000
witr-win -P 5000           # Short form

# Query by PID - "What started process 1234?"
witr-win --pid 1234
witr-win -p 1234           # Short form

# Query by name - "What's running notepad?"
witr-win notepad.exe
witr-win chrome            # Partial match, shows table for multiple results

# Output formats
witr-win --pid 1234 --json           # Machine-readable JSON
witr-win --pid 1234 --tree           # Ancestry tree view
witr-win --pid 1234 --short          # Single-line summary

# Advanced analysis
witr-win --pid 1234 --modules        # Show loaded DLLs
witr-win --pid 1234 --handles        # Show open handles
witr-win --pid 1234 --perf           # Show CPU/IO stats
witr-win --pid 1234 -v               # Verbose output

# Combine flags
witr-win --pid 1234 --modules --handles --perf -v

# Updates
witr-win --check-update              # Check for updates
witr-win --update                    # Download and install update
```

## 📖 Command Reference

| Flag | Short | Description |
|------|-------|-------------|
| `--pid <PID>` | `-p` | Analyze process by PID |
| `--port <PORT>` | `-P` | Find process listening on port |
| `<NAME>` | | Search for process by name |
| `--json` | `-j` | Output as JSON |
| `--short` | `-s` | Single-line summary |
| `--tree` | `-t` | Show ancestry tree |
| `--modules` | `-m` | Show loaded modules/DLLs |
| `--handles` | `-H` | Show open handles |
| `--perf` | | Show performance metrics |
| `--net` | `-n` | Show network connections |
| `--verbose` | `-v` | Verbose output |
| `--no-color` | | Disable colored output |
| `--check-update` | | Check for updates |
| `--update` | | Download and install update |
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |

## 📊 Example Output

### Basic Query
```
$ witr-win --port 8080

     Process : node.exe (pid 12456)
        User : DESKTOP\Developer
     Command : C:\Program Files\nodejs\node.exe
        Args : node.exe server.js --port 8080
     Threads : 12
     Started : 2 hours ago (2025-01-05T10:30:45Z)

Why It Exists :
               explorer.exe (pid 3156) → WindowsTerminal.exe (pid 4420) → node.exe (pid 12456)
      Source : Interactive Session (user shell)
 Working Dir : D:\Projects\my-app

      Memory :
               - Target PID size : 128.5 MB
               - Process tree    : 156.2 MB
```

### Network Connections (`--net`)
```
$ witr-win --pid 12456 --net

     Process : node.exe (pid 12456)
        ...

 Connections : (5 total)

  ╭────────────┬─────────────────────────┬─────────────────────────┬─────────────╮
  │ Protocol   │ Local Address           │ Remote Address          │ State       │
  ├────────────┼─────────────────────────┼─────────────────────────┼─────────────┤
  │ TCP        │ 0.0.0.0:8080            │ -                       │ LISTEN      │
  │ TCP        │ 127.0.0.1:8080          │ 127.0.0.1:52431         │ ESTABLISHED │
  │ TCP        │ 192.168.1.50:8080       │ 192.168.1.100:49234     │ ESTABLISHED │
  │ TCP        │ 192.168.1.50:52100      │ 142.250.185.46:443      │ ESTABLISHED │
  │ UDP        │ 0.0.0.0:5353            │ -                       │ -           │
  ╰────────────┴─────────────────────────┴─────────────────────────┴─────────────╯
```

### Loaded Modules (`--modules`)
```
$ witr-win --pid 1234 --modules

     Modules : (47 loaded)

  ╭─────────────────┬──────────┬────────────────────────────────────────╮
  │ Module          │     Size │ Path                                   │
  ├─────────────────┼──────────┼────────────────────────────────────────┤
  │ ntdll.dll       │  2.1 MB  │ C:\Windows\System32\ntdll.dll          │
  │ kernel32.dll    │  768 KB  │ C:\Windows\System32\kernel32.dll       │
  │ KERNELBASE.dll  │  3.2 MB  │ C:\Windows\System32\KERNELBASE.dll     │
  │ user32.dll      │  1.8 MB  │ C:\Windows\System32\user32.dll         │
  │ gdi32.dll       │  156 KB  │ C:\Windows\System32\gdi32.dll          │
  │ ...             │          │                                        │
  ╰─────────────────┴──────────┴────────────────────────────────────────╯
```

### Open Handles (`--handles`)
```
$ witr-win --pid 1234 --handles

     Handles : (312 total)

               Summary:
               - File        : 45
               - Key         : 89
               - Event       : 67
               - Mutant      : 12
               - Directory   : 8
               - Section     : 34
               - Other       : 57

$ witr-win --pid 1234 --handles -v

     Handles : (312 total)

  ╭────────────┬─────────────────────────────────────────────────────────╮
  │ Type       │ Name                                                    │
  ├────────────┼─────────────────────────────────────────────────────────┤
  │ File       │ C:\Users\Dev\Documents\project\config.json              │
  │ File       │ C:\Windows\System32\en-US\kernel32.dll.mui              │
  │ Key        │ \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentV...│
  │ Key        │ \REGISTRY\USER\S-1-5-21-...\Software\Microsoft\Windows  │
  │ Event      │ \BaseNamedObjects\Global\EventName                      │
  │ Mutant     │ \Sessions\1\BaseNamedObjects\MyAppMutex                 │
  │ Section    │ \BaseNamedObjects\SharedMemorySection                   │
  ╰────────────┴─────────────────────────────────────────────────────────╯
```

### Performance Metrics (`--perf`)
```
$ witr-win --pid 1234 --perf

 Performance :

               CPU Time:
                 User:   12.34 s
                 Kernel: 3.21 s
                 Total:  15.55 s

               I/O Statistics:
                 Read:   1.2 GB (45,123 ops)
                 Write:  256.8 MB (12,456 ops)
                 Other:  89.4 KB (1,234 ops)
```

### Verbose Mode with Environment Variables (`-v`)
```
$ witr-win --pid 1234 -v

     Process : python.exe (pid 1234)
        User : DESKTOP\Developer
     Command : C:\Python311\python.exe
        Args : python.exe manage.py runserver 0.0.0.0:8000
     Threads : 4
     Session : 1
     Started : 35 minutes ago (2025-01-05T12:00:00Z)
        ...

 Environment :
               PATH: C:\Python311;C:\Python311\Scripts;C:\Windows\system32...
               PYTHONPATH: D:\Projects\myapp
               VIRTUAL_ENV: D:\Projects\myapp\.venv
               USER: Developer
               HOME: C:\Users\Developer
               TEMP: C:\Users\Developer\AppData\Local\Temp
```

### Tree View (`--tree`)
```
$ witr-win --pid 12456 --tree

     Process : node.exe (pid 12456)
        ...

   Ancestry :
               explorer.exe (3156)
               └── WindowsTerminal.exe (4420)
                   └── pwsh.exe (8892)
                       └── node.exe (12456) ← target
```

### JSON Output (`--json`)
```
$ witr-win --pid 1234 --json

{
  "process": {
    "pid": 1234,
    "name": "node.exe",
    "command": "C:\\Program Files\\nodejs\\node.exe",
    "cmdline": "node.exe server.js --port 8080",
    "user": "DESKTOP\\Developer",
    "memory_bytes": 134742016,
    "thread_count": 12,
    "start_time": "2025-01-05T10:30:45Z",
    "working_directory": "D:\\Projects\\my-app",
    "session_id": 1
  },
  "ancestry": [
    {"pid": 3156, "name": "explorer.exe"},
    {"pid": 4420, "name": "WindowsTerminal.exe"},
    {"pid": 1234, "name": "node.exe"}
  ],
  "classification": {
    "origin": "interactive_session",
    "description": "Interactive Session (user shell)"
  },
  "listening_ports": [8080]
}
```

### Short Output (`--short`)
```
$ witr-win --pid 12456 --short

node.exe (12456) ← WindowsTerminal.exe ← explorer.exe [Interactive Session]
```

### Multi-Process Search
```
$ witr-win chrome

→ 47 matching processes found:

  ╭────────┬────────────────┬──────────┬───────────┬─────────────────╮
  │    PID │ Name           │   Memory │   Threads │ User            │
  ├────────┼────────────────┼──────────┼───────────┼─────────────────┤
  │  12345 │ chrome.exe     │  512 MB  │        42 │ DESKTOP\User    │
  │  12346 │ chrome.exe     │  128 MB  │        18 │ DESKTOP\User    │
  │  12347 │ chrome.exe     │   64 MB  │        12 │ DESKTOP\User    │
  │  12348 │ chrome.exe     │   96 MB  │        15 │ DESKTOP\User    │
  │  12349 │ chrome.exe     │   48 MB  │         8 │ DESKTOP\User    │
  │   ...  │ ...            │          │           │                 │
  ╰────────┴────────────────┴──────────┴───────────┴─────────────────╯

tip: Use --pid <PID> to see details for a specific process.
```

### Full Analysis (All Flags Combined)
```
$ witr-win --pid 1234 --modules --handles --perf --net -v

     Process : mysqld.exe (pid 1234) [high-mem]
        User : NT AUTHORITY\NETWORK SERVICE
     Command : C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe
        Args : mysqld.exe --defaults-file=C:\ProgramData\MySQL\my.ini
     Threads : 38
     Session : 0
     Started : 45 days ago (2024-11-21T08:15:30Z)

Why It Exists :
               services.exe (pid 684) → mysqld.exe (pid 1234)
      Source : Windows Service (MySQL80)
 Working Dir : C:\Program Files\MySQL\MySQL Server 8.0\bin

      Memory :
               - Target PID size : 1.2 GB
               - Process tree    : 1.2 GB

    Warnings :
               • Process is using high memory (>1GB RSS)
               • Process is listening on a public interface (0.0.0.0:3306)
               • Process has been running for over 30 days

 Environment :
               PATH: C:\Program Files\MySQL\MySQL Server 8.0\bin;C:\Windows\...
               MYSQL_HOME: C:\Program Files\MySQL\MySQL Server 8.0
               ...

 Connections : (156 total)
               ... (table output)

     Modules : (89 loaded)
               ... (table output)

     Handles : (1,247 total)
               ... (summary or table output)

 Performance :
               CPU Time:
                 User:   4h 23m 45s
                 Kernel: 1h 12m 33s

               I/O Statistics:
                 Read:   45.6 GB (12,456,789 ops)
                 Write:  23.1 GB (8,765,432 ops)
```

## 🔧 How It Works

witr-win uses native Windows APIs to gather information:

| Data | API |
|------|-----|
| Process list | `CreateToolhelp32Snapshot` |
| Port → PID | `GetExtendedTcpTable`, `GetExtendedUdpTable` |
| Image path | `QueryFullProcessImageNameW` |
| Start time | `GetProcessTimes` |
| User/Owner | `OpenProcessToken` + `LookupAccountSidW` |
| Session ID | `ProcessIdToSessionId` |
| Memory usage | `GetProcessMemoryInfo` |
| Working directory | `NtQueryInformationProcess` (PEB) |
| Command line | `NtQueryInformationProcess` (PEB) + `ReadProcessMemory` |
| Environment vars | `NtQueryInformationProcess` (PEB) + `ReadProcessMemory` |
| Loaded modules | `CreateToolhelp32Snapshot` + `Module32First/Next` |
| Open handles | `NtQuerySystemInformation` + `NtQueryObject` |
| CPU/IO stats | `GetProcessTimes` + `GetProcessIoCounters` |
| Network connections | `GetExtendedTcpTable`, `GetExtendedUdpTable` (all states) |
| Thread count | `CreateToolhelp32Snapshot` (process entry) |

### Admin vs Non-Admin

| Feature | Without Admin | With Admin |
|---------|--------------|------------|
| Process list | ✅ Full | ✅ Full |
| Port → PID | ✅ Full | ✅ Full |
| Own processes | ✅ Full detail | ✅ Full detail |
| Other user processes | ⚠️ Limited | ✅ Full detail |
| System processes | ⚠️ Limited | ✅ Full detail |
| Open handles | ⚠️ Limited | ✅ Full detail |

## 🔄 witr vs witr-win

| Feature | [witr](https://github.com/pranshuparmar/witr) | witr-win |
|---------|------|----------|
| **Platform** | Linux, macOS | Windows |
| **Language** | Go | Rust |
| **Process info** | `/proc`, `ps`, `lsof` | Win32 APIs |
| **Service detection** | systemd, launchd | Windows Services, Task Scheduler |
| **Container support** | Docker, Podman | - (planned) |
| **Install methods** | brew, go install, nix | GitHub releases, Scoop, Chocolatey |

> 💡 **Use the right tool for your platform:** [witr](https://github.com/pranshuparmar/witr) for Linux/macOS, witr-win for Windows.

## 📦 Project Structure

```
witr-win/
├── crates/
│   ├── core/              # Domain models & rendering (OS-agnostic)
│   ├── platform-windows/  # Windows API collectors
│   │   ├── analyzer.rs    # Main analysis orchestration
│   │   ├── ancestry.rs    # Process ancestry chain
│   │   ├── classifier.rs  # Source classification
│   │   ├── handles.rs     # Open handle enumeration
│   │   ├── net.rs         # Network/port queries
│   │   ├── perf.rs        # Performance metrics
│   │   ├── process_query.rs   # Process details
│   │   ├── process_snapshot.rs # Process/module listing
│   │   └── services.rs    # Windows service detection
│   └── cli/               # CLI binary
├── chocolatey/            # Chocolatey package files
├── .github/workflows/     # CI/CD pipelines
└── assets/                # Logo, demo GIF
```

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Good First Issues

Looking to contribute? Check out issues labeled [`good first issue`](https://github.com/m-de-graaff/witr-win/labels/good%20first%20issue).

### Development Setup

```powershell
# Clone and build
git clone https://github.com/m-de-graaff/witr-win.git
cd witr-win
cargo build

# Run tests
cargo test

# Run lints
cargo clippy -- -D warnings
cargo fmt --check

# Setup git hooks (optional, but recommended)
.\setup-git-hooks.ps1
```

**Git Hooks**: The repository includes pre-commit and pre-push hooks that automatically run `cargo fmt`, `cargo clippy`, and `cargo test`. Run `.\setup-git-hooks.ps1` to install them.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[witr](https://github.com/pranshuparmar/witr)** by [@pranshuparmar](https://github.com/pranshuparmar) - the original "Why Is This Running?" for Linux/macOS that inspired this Windows port
- Inspired by tools like `lsof`, `ss`, and Process Explorer
- Built with the excellent [windows-rs](https://github.com/microsoft/windows-rs) crate
- CLI powered by [clap](https://github.com/clap-rs/clap)
- Tables powered by [tabled](https://github.com/zhiburt/tabled)

---

<p align="center">
  <sub>Made with ❤️ for Windows power users</sub>
</p>
