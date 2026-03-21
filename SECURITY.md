# Security Policy

## Reporting a Vulnerability

FreeGPGMail is a security-sensitive project that handles PGP encryption and signing. We take security issues seriously.

**Do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email:

**Email:** security@freegpgmail.ru

** RIGHT NOW THIS EMAIL ADDRESS DOESN'T WORK **

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix release:** As soon as possible, depending on severity

## Scope

The following are in scope:
- Key material exposure or leakage
- Signature bypass or forgery
- Encryption bypass
- IPC tampering (e.g., `/tmp/freegpgmail-ipc/` manipulation)
- Sandbox escape via the extension
- Arbitrary code execution

The following are out of scope:
- Vulnerabilities in GnuPG itself (report to [GnuPG](https://gnupg.org/))
- Vulnerabilities in Apple Mail or MailKit
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No       |
