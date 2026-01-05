# Contributing to witr-win

First off, thank you for considering contributing to witr-win! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Prerequisites

- **Windows 10/11** - witr-win is Windows-native
- **Rust stable** (MSVC toolchain) - Install from [rustup.rs](https://rustup.rs)
- **Git** - For version control

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```powershell
   git clone https://github.com/YOUR_USERNAME/witr-win.git
   cd witr-win
   ```

3. **Add upstream remote**:
   ```powershell
   git remote add upstream https://github.com/m-de-graaff/witr-win.git
   ```

4. **Build the project**:
   ```powershell
   cargo build
   ```

5. **Run tests**:
   ```powershell
   cargo test
   ```

## Development Workflow

### Branch Naming

- `feature/short-description` - New features
- `fix/issue-number-description` - Bug fixes
- `docs/what-changed` - Documentation updates
- `refactor/what-changed` - Code refactoring

### Before You Start Coding

1. **Check existing issues** - Someone may already be working on it
2. **Create or claim an issue** - Discuss your approach before diving in
3. **Keep changes focused** - One feature/fix per PR

### Running Checks Locally

Before submitting a PR, ensure all checks pass:

```powershell
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run tests
cargo test

# Build release (optional, to catch release-only issues)
cargo build --release
```

### Git Hooks (Automatic Checks)

This repository includes git hooks that automatically run checks before commits and pushes:

**Setup (one-time):**
```powershell
.\setup-git-hooks.ps1
```

**What the hooks do:**
- **Pre-commit**: Runs `cargo fmt --all --check` and `cargo clippy` to ensure code quality
- **Pre-push**: Runs `cargo test` to ensure all tests pass

**To skip hooks temporarily** (use sparingly):
```powershell
git commit --no-verify
git push --no-verify
```

## Submitting Changes

### Pull Request Process

1. **Update your fork**:
   ```powershell
   git fetch upstream
   git rebase upstream/master
   ```

2. **Create a feature branch**:
   ```powershell
   git checkout -b feature/your-feature
   ```

3. **Make your changes** with clear, atomic commits

4. **Push to your fork**:
   ```powershell
   git push origin feature/your-feature
   ```

5. **Open a Pull Request** against `master`

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Formatting, no code change
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `test` - Adding or updating tests
- `chore` - Maintenance tasks

**Examples:**
```
feat(cli): add --all flag to show all matching processes
fix(net): handle IPv6 localhost correctly
docs(readme): add installation instructions for winget
```

### PR Checklist

- [ ] Code follows the project's style guidelines
- [ ] All tests pass locally
- [ ] New code includes tests where applicable
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventional commits
- [ ] PR description explains what and why

## Style Guidelines

### Rust Style

- Follow `rustfmt` defaults - run `cargo fmt` before committing
- Follow `clippy` recommendations - run `cargo clippy -- -D warnings`
- Write documentation for public APIs
- Prefer explicit types in function signatures
- Use meaningful variable names

### Code Organization

```
crates/
├── core/              # OS-agnostic domain models
│   ├── models.rs      # Data structures
│   ├── report.rs      # Report type
│   └── render/        # Output formatters
├── platform-windows/  # Windows-specific code
│   ├── process_*.rs   # Process APIs
│   ├── net.rs         # Network APIs
│   └── ancestry.rs    # Chain building
└── cli/               # CLI application
    └── main.rs        # Entry point
```

### Adding Windows API Calls

When adding new Windows API functionality:

1. Add the required feature to `Cargo.toml`:
   ```toml
   windows = { version = "0.58", features = ["Win32_Your_Feature"] }
   ```

2. Create proper error handling:
   ```rust
   .map_err(|e| WinError::ApiError {
       api: "YourApiName",
       message: e.message().to_string(),
   })
   ```

3. Handle both admin and non-admin scenarios gracefully

## Reporting Bugs

### Before Submitting

1. **Check existing issues** - It may already be reported
2. **Try the latest version** - The bug may be fixed
3. **Gather information** - OS version, Rust version, steps to reproduce

### Bug Report Template

Use the issue template, or include:

- **Summary** - Brief description
- **Environment** - Windows version, Rust version
- **Steps to Reproduce** - Minimal steps to trigger the bug
- **Expected Behavior** - What should happen
- **Actual Behavior** - What actually happens
- **Additional Context** - Logs, screenshots, etc.

## Suggesting Features

### Feature Request Process

1. **Search existing issues** - It may already be suggested
2. **Open a new issue** using the feature request template
3. **Describe the use case** - Why is this feature needed?
4. **Propose a solution** - How might it work?

### Feature Scope (v1)

Currently in scope:
- Process ancestry chain
- Port → PID resolution
- Service/Task/Interactive classification
- JSON/text/tree output

Out of scope for v1:
- Kernel driver integration
- Real-time monitoring
- GUI interface
- Cross-platform support

---

Thank you for contributing to witr-win! 🚀

