# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in witr, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainer directly or use GitHub's private vulnerability reporting
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity, typically within 30 days

### Scope

Security issues we're interested in:

- Privilege escalation vulnerabilities
- Information disclosure beyond intended scope
- Denial of service via crafted input
- Memory safety issues

Out of scope:

- Issues requiring physical access to the machine
- Issues in dependencies (report to the dependency maintainer)
- Social engineering attacks

## Security Considerations

### Process Information Access

witr accesses Windows process information. By design:

- It can see all processes visible to the current user
- With admin privileges, it can see all system processes
- It does **not** modify any processes or system state
- It does **not** require or use network access

### Running with Elevated Privileges

When run as Administrator:

- witr gains access to more process details
- It can query information about system processes
- No special permissions are retained after exit

### Third-Party Dependencies

We regularly audit our dependencies:

- `windows-rs` - Microsoft's official Windows API bindings
- `clap` - CLI argument parsing (no unsafe code)
- `serde`/`serde_json` - Serialization (widely audited)
- `time` - Date/time handling
- `thiserror`/`anyhow` - Error handling

