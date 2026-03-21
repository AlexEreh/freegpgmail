<div align="center">

# FreeGPGMail

**Free GPG encryption & signing for Apple Mail**

[![Build](https://github.com/alexereh/freegpgmail/actions/workflows/build.yml/badge.svg)](https://github.com/alexereh/freegpgmail/actions/workflows/build.yml)
[![Lint](https://github.com/alexereh/freegpgmail/actions/workflows/lint.yml/badge.svg)](https://github.com/alexereh/freegpgmail/actions/workflows/lint.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![macOS 12+](https://img.shields.io/badge/macOS-12%2B-brightgreen.svg)](https://developer.apple.com/macos/)
[![Swift 5.9](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)

<img src="FreeGPGMail/Assets.xcassets/AppIcon.appiconset/icon_128x128.png" width="128" alt="FreeGPGMail Icon">

A free, open-source alternative to GPGMail (GPG Suite).
Sign, encrypt, decrypt, and verify PGP emails directly in Apple Mail.

[Installation](#installation) · [Features](#features) · [Building](#building-from-source) · [Contributing](#contributing)

</div>

---

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

This builds the app and copies it to `/Applications/FreeGPGMail.app`, registers the extension, and opens the app.

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
4. **Recipients** are annotated with key status (green checkmark = key found, yellow warning = no key)

### Key Management

Open FreeGPGMail.app → **Keys** tab to:
- Search and import keys from keyservers
- Import keys from clipboard, file, or text
- Export public keys
- Set owner trust levels
- Delete keys

### Settings

Open FreeGPGMail.app → **Settings** tab to configure:
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

## Development

```bash
# Generate Xcode project
make generate

# Build debug
make build

# Build release
make release

# Run linter
make lint

# Run all checks (lint + build)
make check

# Clean
make clean
```

### Project Structure

| Directory | Description |
|-----------|-------------|
| `FreeGPGMail/` | Main app (SwiftUI, AppDelegate, key management UI) |
| `FreeGPGMailExtension/` | Mail extension (MailKit handlers, compose/security VCs) |
| `Shared/` | Shared code (GPGHelper, MIMEHelper, KeyCache, Settings, CryptoIPC) |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure `make check` passes before submitting.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [GnuPG](https://gnupg.org/) — the GPG implementation used under the hood
- [MailKit](https://developer.apple.com/documentation/mailkit) — Apple's Mail extension framework
- Inspired by [GPGMail](https://gpgtools.org/) from GPG Suite
