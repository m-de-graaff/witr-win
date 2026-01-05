# Distribution & Installation Methods

This document describes the various distribution methods available for witr-win.

## 📦 Available Distribution Methods

### 1. GitHub Releases (Direct Download)

The simplest method - download the executable directly from GitHub releases.

**Download:** https://github.com/m-de-graaff/witr-win/releases

1. Download `witr-win.exe` from the latest release
2. Place it in a directory in your PATH (e.g., `C:\Program Files\witr-win\`)
3. Run `witr-win --help` to verify installation

### 2. Scoop (Windows Package Manager)

Scoop is a command-line installer for Windows that makes it easy to install and update applications.

**Installation:**

```powershell
# Add the bucket (if using a custom bucket)
scoop bucket add witr-win https://github.com/m-de-graaff/witr-win-bucket

# Install witr-win
scoop install witr-win
```

**Update:**

```powershell
scoop update witr-win
```

**Manifest:** See `witr-win.json` in this repository. To submit to the main Scoop bucket, follow the [Scoop contribution guidelines](https://github.com/ScoopInstaller/Scoop/wiki/App-Manifests).

### 3. Chocolatey

Chocolatey is a Windows package manager that provides a centralized way to manage software.

**Installation:**

```powershell
# Install Chocolatey first (if not already installed)
# See: https://chocolatey.org/install

# Install witr-win
choco install witr-win
```

**Update:**

```powershell
choco upgrade witr-win
```

**Package Files:** See the `chocolatey/` directory in this repository.

### 4. MSI Installer

A traditional Windows installer that provides a GUI installation experience.

**Installation:**

1. Download the `.msi` file from GitHub releases
2. Double-click to run the installer
3. Follow the installation wizard
4. The installer will add `witr-win.exe` to your PATH automatically

**Uninstallation:**

Use "Add or Remove Programs" in Windows Settings, or run:
```powershell
msiexec /x witr-win.msi
```

**Build MSI from source:**

```powershell
# Install cargo-wix
cargo install cargo-wix

# Build MSI
cargo wix
```

### 5. Cargo (Build from Source)

For developers or users who want to build from source:

```powershell
# Clone the repository
git clone https://github.com/m-de-graaff/witr-win.git
cd witr-win

# Build
cargo build --release

# The executable will be at: target/release/witr-win.exe
```

## 🔄 Auto-Update

witr-win includes built-in auto-update functionality:

```powershell
# Check for updates
witr-win --check-update

# Download and install updates
witr-win --update
```

The tool also automatically checks for updates on every run and displays a notification if a newer version is available.

## 📝 Notes

- **PATH Configuration:** After installation, ensure `witr-win.exe` is in your system PATH to use it from any directory.
- **Administrator Rights:** Some features require administrator privileges. Run PowerShell/CMD as Administrator when needed.
- **Version Information:** Check the installed version with `witr-win --version`

## 🤝 Contributing Distribution Methods

If you'd like to add support for additional package managers (winget, Nix, etc.), please open an issue or submit a pull request!

