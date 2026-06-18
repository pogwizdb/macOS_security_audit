# 🔒 macOS Security Audit

A Bash-based security auditing toolkit for macOS that checks system hardening settings against CIS Benchmark recommendations and generates JSON/HTML reports.

> Created by **Bartłomiej Pogwizd** · https://www.youtube.com/@pTech-pl

---

## Overview

This toolkit consists of two scripts:

- **`auditMAC.sh`** — runs the full security audit and outputs results to the terminal and a TSV data file
- **`generate_reports.sh`** — converts the TSV data file into a JSON report and a styled HTML report

---

## Requirements

- macOS 11 (Big Sur) or newer — tested up to macOS 15 Sequoia
- Bash 3.2+ (pre-installed on macOS)
- `sudo` access (required for several checks)

---

## Usage

### Step 1 — Run the audit

```bash
chmod +x auditMAC.sh
./auditMAC.sh
```

The script will:
- prompt for your `sudo` password (used locally only, never stored)
- run ~50 security checks across 10 categories
- print colour-coded results to the terminal
- save raw results to a temporary TSV file (path shown at the end)
- automaticly repair failures, you need to confirm with y or n with no
- show auto-fix summary

### Step 2 — Generate reports

Put files ( auditMAC.sh and generate_reports.sh ) in same folder
json and html files will show in the folder, they are generate automatically

This produces two files in the current directory:
- `macos_security_report.json`
- `macos_security_report.html`

---

## What Gets Checked

| Category | Checks |
|---|---|
| **System Security** | Firewall, SIP, Secure Boot, Gatekeeper, FileVault, Firmware Password, Authenticated Root |
| **Privacy** | Diagnostic uploads, Siri data sharing, Location Services, AirPlay Receiver, Screen Lock, Guest Account, Autologin |
| **Updates & Time** | Pending updates, Auto-download, Critical updates, Network Time, Wake-on-Network |
| **Sharing & Remote Access** | Screen Sharing, SMB, Printer Sharing, Remote Login, Remote Management, AirDrop, Handoff |
| **System Services** | tftpd, nfsd, httpd, uucp, sshd |
| **Users & Privileges** | Admin accounts, current user role, Root account status |
| **Network & Ports** | Open listening ports (IPv4/IPv6) |
| **Startup Items** | LaunchAgents and LaunchDaemons (system and user) |
| **SSH Hardening** | PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, AllowUsers |
| **System Extensions** | Active/waiting/terminated kernel extensions |

---

## Output Example

```
========================================
macOS Security / Audit Report
Author: Bartłomiej Pogwizd / youtube.com/pTech
Version: 2.5
========================================

System Security
----------------------------------------
Firewall                       OK       Enabled
SIP                            OK       Enabled
FileVault                      FAIL     Disabled
Gatekeeper                     OK       Enabled
...

Security Score                 72/100
Risk Level:       Medium
Passed                         31
Warnings                       4
Failures                       8
```

Status legend:

| Status | Meaning |
|---|---|
| `OK` | Setting meets the recommended value |
| `WARN` | Setting could not be determined or is a grey area |
| `FAIL` | Setting does not meet the recommendation |
| `INFO` | Informational only, no pass/fail judgement |

---

## Security Score

The score is calculated as:

```
score = (passed × 100 + warnings × 50) / total_checks
```

| Score | Risk Level |
|---|---|
| 80–100 | 🟢 Low |
| 50–79 | 🟡 Medium |
| 0–49 | 🔴 High |

---

## CIS Benchmark Mapping

Every check in the HTML/JSON report is tagged with a CIS macOS Benchmark ID (e.g. `2.1.1` for Firewall, `2.2.1` for FileVault). This makes it easy to cross-reference the official CIS documentation for remediation guidance.

---

## Notes

- The audit is **read-only** — it never modifies any system settings
- `sudo` is used only for commands that require elevated privileges (e.g. `fdesetup`, `systemsetup`, `launchctl`)
- Temporary files are created under `/tmp` with `umask 077` and are always cleaned up on exit, even on error or Ctrl+C
- Some checks (e.g. Touch ID) cannot be automated and are flagged as `INFO` with instructions to verify manually

---

## License

MIT — feel free to use, modify, and share.

---

## Contributing

Pull requests and issues are welcome. If a check produces incorrect results on your macOS version, please open an issue and include the output of `sw_vers`.
