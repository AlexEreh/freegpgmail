<div align="center">

# FreeGPGMail

**Free GPG encryption & signing for Apple Mail**

[![Build](https://github.com/alexereh/freegpgmail/actions/workflows/build.yml/badge.svg)](https://github.com/alexereh/freegpgmail/actions/workflows/build.yml)
[![Lint](https://github.com/alexereh/freegpgmail/actions/workflows/lint.yml/badge.svg)](https://github.com/alexereh/freegpgmail/actions/workflows/lint.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![macOS 12+](https://img.shields.io/badge/macOS-12%2B-brightgreen.svg)](https://developer.apple.com/macos/)
[![Swift 5.9](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![GitHub release](https://img.shields.io/github/v/release/alexereh/freegpgmail)](https://github.com/alexereh/freegpgmail/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/alexereh/freegpgmail/total)](https://github.com/alexereh/freegpgmail/releases)

<img src="FreeGPGMail/Assets.xcassets/AppIcon.appiconset/icon_128x128.png" width="128" alt="FreeGPGMail Icon">

A free, open-source alternative to [GPGMail](https://gpgtools.org/) (GPG Suite).<br>
Sign, encrypt, decrypt, and verify PGP emails directly in Apple Mail.

[Installation](#installation) · [Features](#features) · [Building](#building-from-source) · [Contributing](CONTRIBUTING.md)

</div>

---

## Screenshots

<details>
<summary>Click to expand</summary>

| Compose window | Key management |
|:-:|:-:|
| Compose with sign/encrypt toggles and key selector | Import, export, search keyservers |

| Address annotations | Settings |
|:-:|:-:|
| Green = key found, Yellow = no key | Auto-sign, auto-encrypt, key cache |

</details>

## Features

- **PGP/MIME signing & encryption** (RFC 3156) — messages are readable by any PGP-compatible client
- **Automatic key discovery** via WKD (Web Key Directory)
- **Autocrypt** header support — automatic key exchange with compatible clients
- **Protected Headers** — encrypts the email subject line
- **Compose UI** — sign/encrypt toggles and key selector right in Mail's compose window
- **Address annotations** — shows which recipients have GPG keys and which don't
- **Key management** — import, export, search keyservers, set trust levels
- **Multiple identities** — select different signing keys for different accounts
- **Background key sync** — the app runs in the menu bar and keeps extension key cache fresh
- **Localization** — English and Russian

## Requirements

- macOS 12.0 (Monterey) or later
- [GnuPG](https://gnupg.org/) installed (`brew install gnupg`)
- Xcode 15+ (for building from source)

## Installation

### From Release (recommended)

1. Download the latest `.dmg` from [Releases](https://github.com/alexereh/freegpgmail/releases)
2. Drag `FreeGPGMail.app` to `/Applications/`
3. Open `FreeGPGMail.app`
4. Go to **System Settings → Extensions → Mail** and enable **FreeGPGMail**
5. Restart Mail

### Using Make

```bash
git clone https://github.com/alexereh/freegpgmail.git
cd freegpgmail
make install
```

This builds the app, copies it to `/Applications/`, registers the extension, and launches the app.

### Building from Source

```bash
# Prerequisites
brew install xcodegen gnupg

# Build
make build

# Or open in Xcode
make open
```

## Usage

1. **Launch FreeGPGMail.app** — it runs in the menu bar and syncs GPG keys for the Mail extension
2. **Open Mail** — you'll see the FreeGPGMail icon in the compose toolbar
3. **Click the extension icon** to toggle signing/encryption and select a key
4. **Recipients** are annotated with key status (green = key found, yellow = no key)

### Key Management

Open FreeGPGMail.app → **Keys** tab:
- Search and import keys from keyservers
- Import keys from clipboard, file, or text
- Export public keys
- Set owner trust levels
- Delete keys

### Settings

Open FreeGPGMail.app → **Settings** tab:
- Auto-sign / auto-encrypt defaults
- Default signing key
- Pinentry mode
- Key cache TTL
- Key sync interval
- Logging

## Architecture

```
FreeGPGMail.app              (main app, not sandboxed)
├── Menu bar agent            (background key sync + IPC server)
├── Settings UI               (SwiftUI)
└── FreeGPGMailExtension.appex (Mail extension, sandboxed)
    ├── MEComposeSessionHandler
    ├── MEMessageSecurityHandler
    └── Reads keys from /tmp/freegpgmail-keycache.json
```

The extension runs in Apple's sandbox and cannot call GPG directly. Instead:
- The **main app** runs GPG, caches keys to a shared file, and processes crypto operations via file-based IPC
- The **extension** reads cached keys and sends sign/encrypt requests to the main app

## Security

This project takes security seriously. See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

All releases include [SLSA Level 3](https://slsa.dev) provenance attestations. Verify with:

```bash
slsa-verifier verify-artifact FreeGPGMail-v1.0.0.dmg \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/alexereh/freegpgmail
```

## Development

```bash
# Setup
brew install xcodegen gnupg swiftlint lefthook
lefthook install

# Build
make build

# Lint
make lint

# All checks
make check

# Install locally
make install
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development guide.

## Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=alexereh/freegpgmail&type=Date)](https://star-history.com/#alexereh/freegpgmail&Date)

</div>

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [GnuPG](https://gnupg.org/) — the GPG implementation used under the hood
- [MailKit](https://developer.apple.com/documentation/mailkit) — Apple's Mail extension framework
- Inspired by [GPGMail](https://gpgtools.org/) from GPG Suite
