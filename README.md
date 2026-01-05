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

<p align="center">
  <img src="assets/demo.gif" alt="witr-win demo" width="700">
</p>

---

## 🎯 What is witr-win?

Ever wondered *"What started this process?"* or *"Why is something listening on port 5000?"*

**witr-win** is the Windows-native port of [witr](https://github.com/pranshuparmar/witr) ("Why Is This Running?"). While the original witr supports Linux and macOS, **witr-win** brings the same functionality to Windows using native Win32 APIs.

It answers these questions by building a **causal chain** - tracing a process back through its ancestry to identify whether it came from a Windows Service, a Scheduled Task, an interactive user session, or something else entirely.

```
$ witr-win --port 5000

─── Query: port 5000 ───

Process: node.exe (PID 12456)
  Path: C:\Program Files\nodejs\node.exe
  User: DESKTOP\Developer
  Started: 2024-01-15T10:30:45Z

Source: Interactive Session (high confidence)
  Descendant of explorer.exe in user session

Ancestry:
  └─ parent: cmd.exe (PID 8832)
     └─ grandparent: WindowsTerminal.exe (PID 4420)
        └─ ancestor: explorer.exe (PID 3156)
           ↳ Windows Shell (interactive session root)
```

## ✨ Features

- 🔍 **Multiple input modes** - Query by PID, port number, or process name
- 🌳 **Ancestry chain** - See the full parent→grandparent→root chain  
- 🏷️ **Source classification** - Identifies Services, Scheduled Tasks, Interactive sessions
- 📊 **Multiple output formats** - Human-readable, JSON, tree view, or one-liner
- 🔒 **Graceful degradation** - Works without admin (with reduced detail)
- ⚡ **Fast & native** - Pure Rust, no runtime dependencies

## 🚀 Quick Start

### Installation

#### From GitHub Releases (Recommended)

Download the latest release from the [Releases page](https://github.com/m-de-graaff/witr-win/releases).

```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/m-de-graaff/witr-win/releases/latest/download/witr-x86_64-pc-windows-msvc.zip" -OutFile witr.zip
Expand-Archive witr.zip -DestinationPath "$env:LOCALAPPDATA\Programs\witr"

# Verify checksum (optional but recommended)
Invoke-WebRequest -Uri "https://github.com/m-de-graaff/witr-win/releases/latest/download/witr-x86_64-pc-windows-msvc.zip.sha256" -OutFile witr.zip.sha256
$expectedHash = (Get-Content witr.zip.sha256).Split(' ')[0]
$actualHash = (Get-FileHash -Path witr.zip -Algorithm SHA256).Hash
if ($expectedHash -eq $actualHash) {
    Write-Host "Checksum verified successfully"
} else {
    Write-Error "Checksum verification failed!"
}

# Add to PATH (run in elevated PowerShell)
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "$path;$env:LOCALAPPDATA\Programs\witr", "User")
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

# Query by PID - "What started process 1234?"
witr-win --pid 1234

# Query by name - "What's running notepad?"
witr-win notepad.exe

# Different output formats
witr-win --pid 1234 --json           # Machine-readable JSON
witr-win --pid 1234 --tree           # Ancestry tree view  
witr-win --pid 1234 --short          # Single-line summary
```

## 📖 Why witr-win?

### The Problem

The excellent [witr](https://github.com/pranshuparmar/witr) project answers "Why is this running?" on Linux and macOS - but Windows users were left out. On Windows, understanding *why* a process is running is surprisingly difficult:

- Task Manager shows processes but not their origin
- `netstat` shows ports but requires manual PID lookup
- Process Explorer is powerful but heavyweight
- PowerShell one-liners get unwieldy fast

### The Solution

**witr-win** provides a single command that:

1. Resolves your query (port → PID, name → PID)
2. Gathers process metadata (path, user, start time)
3. Walks the ancestry chain (parent → grandparent → ...)
4. Classifies the source (Service? Scheduled Task? Interactive?)
5. Presents everything in a clear, actionable format

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

### Admin vs Non-Admin

| Feature | Without Admin | With Admin |
|---------|--------------|------------|
| Process list | ✅ Full | ✅ Full |
| Port → PID | ✅ Full | ✅ Full |
| Own processes | ✅ Full detail | ✅ Full detail |
| Other user processes | ⚠️ Limited | ✅ Full detail |
| System processes | ⚠️ Limited | ✅ Full detail |

## 🔄 witr vs witr-win

| Feature | [witr](https://github.com/pranshuparmar/witr) | witr-win |
|---------|------|----------|
| **Platform** | Linux, macOS | Windows |
| **Language** | Go | Rust |
| **Process info** | `/proc`, `ps`, `lsof` | Win32 APIs |
| **Service detection** | systemd, launchd | Windows Services, Task Scheduler |
| **Container support** | Docker, Podman | - (planned) |
| **Install methods** | brew, go install, nix | GitHub releases, cargo |

> 💡 **Use the right tool for your platform:** [witr](https://github.com/pranshuparmar/witr) for Linux/macOS, witr-win for Windows.

## 📦 Project Structure

```
witr-win/
├── crates/
│   ├── core/              # Domain models & rendering (OS-agnostic)
│   ├── platform-windows/  # Windows API collectors
│   └── cli/               # CLI binary
├── .github/
│   └── workflows/         # CI/CD pipelines
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

---

<p align="center">
  <sub>Made with ❤️ for Windows power users</sub>
</p>

