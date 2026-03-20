import Foundation
import os.log

/// Централизованное логирование для FreeGPGMail
enum Log {
    private static let subsystem = "com.freegpgmail.app"

    static let general = Logger(subsystem: subsystem, category: "general")
    static let gpg = Logger(subsystem: subsystem, category: "gpg")
    static let security = Logger(subsystem: subsystem, category: "security")
    static let keys = Logger(subsystem: subsystem, category: "keys")
    static let settings = Logger(subsystem: subsystem, category: "settings")
    static let mime = Logger(subsystem: subsystem, category: "mime")

    /// Записывает диагностическую информацию в файл
    static func exportDiagnostics() -> URL? {
        let tempDir = FileManager.default.temporaryDirectory
        let diagFile = tempDir.appendingPathComponent("FreeGPGMail-diagnostics.txt")

        var lines: [String] = []
        lines.append("FreeGPGMail Diagnostics")
        lines.append("=======================")
        lines.append("Date: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("")

        // GPG info
        lines.append("GPG Status:")
        if let gpgPath = GPGHelper.gpgPath() {
            lines.append("  Path: \(gpgPath)")
            if let version = gpgVersion(path: gpgPath) {
                lines.append("  Version: \(version)")
            }
        } else {
            lines.append("  NOT INSTALLED")
        }
        lines.append("")

        // gpg-agent
        lines.append("GPG Agent:")
        let agentRunning = isGPGAgentRunning()
        lines.append("  Running: \(agentRunning)")
        lines.append("")

        // Keys
        let secretKeys = GPGHelper.listSecretKeys()
        lines.append("Secret Keys: \(secretKeys.count)")
        for key in secretKeys {
            lines.append("  \(key.fingerprint.suffix(16)) \(key.userID)")
        }
        lines.append("")

        let publicKeys = GPGHelper.listPublicKeys()
        lines.append("Public Keys: \(publicKeys.count)")
        for key in publicKeys {
            lines.append("  \(key.fingerprint.suffix(16)) \(key.userID)")
        }
        lines.append("")

        // Settings
        let settings = Settings.shared
        lines.append("Settings:")
        lines.append("  Auto-sign: \(settings.autoSign)")
        lines.append("  Auto-encrypt: \(settings.autoEncrypt)")
        lines.append("  Default key: \(settings.defaultKeyFingerprint ?? "none")")
        lines.append("  Pinentry mode: \(settings.pinentryMode.rawValue)")
        lines.append("")

        // Cache stats
        lines.append("Key Cache:")
        lines.append("  Secret keys cached: \(KeyCache.shared.secretKeysCount)")
        lines.append("  Public keys cached: \(KeyCache.shared.publicKeysCount)")

        let content = lines.joined(separator: "\n")
        do {
            try content.write(to: diagFile, atomically: true, encoding: .utf8)
            general.info("Diagnostics exported to \(diagFile.path)")
            return diagFile
        } catch {
            general.error("Failed to export diagnostics: \(error.localizedDescription)")
            return nil
        }
    }

    private static func gpgVersion(path: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                return output.components(separatedBy: "\n").first
            }
        } catch {}
        return nil
    }

    private static func isGPGAgentRunning() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "gpg-agent"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}
