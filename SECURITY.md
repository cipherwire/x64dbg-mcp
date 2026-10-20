# Security Policy

## Supported Versions

We provide security updates and patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of `x64dbg-mcp` seriously. Because this project provides deep debugging, memory inspection, and execution control over processes on Windows systems, secure communication over local IPC is paramount.

If you believe you have found a security vulnerability in `x64dbg-mcp`:

1. **Do not open a public GitHub issue.**
2. Send an advisory report via GitHub Private Vulnerability Reporting at:
   https://github.com/cipherwire/x64dbg-mcp/security/advisories/new
3. Alternatively, report the vulnerability directly to security maintainers at:
   `security@cipherwire.org`

### What to include in your report

Please include as much detail as possible to help us understand and resolve the issue quickly:
- Target architecture and Windows version
- Step-by-step reproduction instructions or Proof of Concept (PoC)
- Potential impact (e.g. unauthorized named pipe access, memory corruption, privilege escalation)
- Any proposed mitigations or fixes

### Response Timeline

- **Initial Response**: Within 48 hours acknowledging receipt of your report.
- **Triage & Status Update**: Within 5 business days with assessment and mitigation plan.
- **Public Disclosure**: Coordinated after a fix has been released and verified.
