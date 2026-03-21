# Contributing to FreeGPGMail

Thank you for your interest in contributing!

## Getting Started

### Prerequisites

```bash
brew install xcodegen gnupg swiftlint lefthook
```

### Setup

```bash
git clone https://github.com/alexereh/freegpgmail.git
cd freegpgmail
lefthook install
make build
```

### Running

```bash
make install   # Build, install to /Applications, launch
```

Then enable the extension in **System Settings → Extensions → Mail** and restart Mail.

## Development Workflow

1. Fork the repo and create a feature branch from `master`
2. Make your changes
3. Run `make check` (lint + build)
4. Test manually in Mail.app
5. Commit and push
6. Open a Pull Request

## Code Style

- We use **SwiftLint** (`.swiftlint.yml`) — `make lint` to check, `make lint-fix` to auto-fix
- Follow existing code conventions
- Comments in Russian or English are both fine
- Keep commits focused — one logical change per commit

## Architecture Notes

The project has two targets:

| Target | Sandbox | Purpose |
|--------|---------|---------|
| `FreeGPGMail` (app) | No | Main app: settings UI, menu bar agent, GPG operations, key sync |
| `FreeGPGMailExtension` (appex) | Yes | Mail extension: compose UI, message security handlers |

**Key constraint:** The extension runs in Apple's sandbox and **cannot call GPG directly**. All GPG operations go through file-based IPC (`/tmp/freegpgmail-ipc/`). The main app processes requests and returns results.

## Localization

Localization files are in `*/en.lproj/Localizable.strings` and `*/ru.lproj/Localizable.strings`.

To add a new language:
1. Create `FreeGPGMail/<lang>.lproj/Localizable.strings`
2. Create `FreeGPGMailExtension/<lang>.lproj/Localizable.strings`
3. Translate all strings

## Reporting Issues

- **Bugs:** Use the [bug report template](https://github.com/alexereh/freegpgmail/issues/new?template=bug_report.yml)
- **Features:** Use the [feature request template](https://github.com/alexereh/freegpgmail/issues/new?template=feature_request.md)
- **Security:** See [SECURITY.md](SECURITY.md) — do **not** open a public issue

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
