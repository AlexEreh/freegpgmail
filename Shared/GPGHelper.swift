import Foundation

/// Информация о GPG-ключе
struct GPGKeyInfo: Sendable {
    let fingerprint: String
    let userID: String
    let email: String
}

/// Обёртка над CLI gpg для выполнения криптографических операций
enum GPGHelper {
    /// Возможные пути к gpg
    private static let gpgPaths = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
        "/opt/local/bin/gpg",
    ]

    /// Возможные пути к gpgconf
    private static let gpgconfPaths = [
        "/opt/homebrew/bin/gpgconf",
        "/usr/local/bin/gpgconf",
        "/usr/bin/gpgconf",
        "/opt/local/bin/gpgconf",
    ]

    /// Находит исполняемый файл gpg
    static func gpgPath() -> String? {
        for path in gpgPaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    /// Находит gpgconf
    static func gpgconfPath() -> String? {
        for path in gpgconfPaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    /// Проверяет, установлен ли GPG
    static func isGPGInstalled() -> Bool {
        gpgPath() != nil
    }

    // MARK: - GPG Agent

    /// Запускает gpg-agent если он не запущен
    static func ensureAgentRunning() {
        guard let confPath = gpgconfPath() else {
            Log.gpg.warning("gpgconf not found, cannot ensure agent is running")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: confPath)
        process.arguments = ["--launch", "gpg-agent"]
        process.environment = gpgEnvironment()
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                Log.gpg.info("gpg-agent launched successfully")
            } else {
                Log.gpg.warning("gpg-agent launch returned status \(process.terminationStatus)")
            }
        } catch {
            Log.gpg.error("Failed to launch gpg-agent: \(error.localizedDescription)")
        }
    }

    /// Перезапускает gpg-agent
    static func restartAgent() {
        guard let confPath = gpgconfPath() else { return }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: confPath)
        process.arguments = ["--kill", "gpg-agent"]
        process.environment = gpgEnvironment()
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
            Log.gpg.info("gpg-agent killed, relaunching...")
            ensureAgentRunning()
        } catch {
            Log.gpg.error("Failed to kill gpg-agent: \(error.localizedDescription)")
        }
    }

    /// Аргументы pinentry в зависимости от настроек
    private static func pinentryArgs() -> [String] {
        let mode = Settings.shared.pinentryMode
        switch mode {
        case .default:
            return []
        case .loopback:
            return ["--pinentry-mode", "loopback"]
        case .ask:
            return ["--pinentry-mode", "ask"]
        case .cancel:
            return ["--pinentry-mode", "cancel"]
        case .error:
            return ["--pinentry-mode", "error"]
        }
    }

    // MARK: - Key Management

    /// Список секретных ключей
    static func listSecretKeys() -> [GPGKeyInfo] {
        guard let output = run(["--list-secret-keys", "--with-colons", "--batch"]) else {
            return []
        }
        return parseKeyListing(output)
    }

    /// Список публичных ключей
    static func listPublicKeys() -> [GPGKeyInfo] {
        guard let output = run(["--list-keys", "--with-colons", "--batch"]) else {
            return []
        }
        return parseKeyListing(output)
    }

    /// Поиск ключа по email
    static func findKey(for email: String) -> GPGKeyInfo? {
        let keys = listPublicKeys()
        return keys.first { $0.email.lowercased() == email.lowercased() }
    }

    /// Поиск секретного ключа по email
    static func findSecretKey(for email: String) -> GPGKeyInfo? {
        let keys = listSecretKeys()
        return keys.first { $0.email.lowercased() == email.lowercased() }
    }

    // MARK: - Sign

    /// Подписывает данные (detached signature, armor)
    static func sign(data: Data, signer email: String) -> Data? {
        Log.gpg.info("Signing message as \(email, privacy: .public)")
        ensureAgentRunning()

        var args = ["--batch", "--yes", "--armor"]
        args.append(contentsOf: pinentryArgs())
        args.append(contentsOf: ["--local-user", email, "--detach-sign"])

        let result = runWithIO(args: args, input: data)
        if result != nil {
            Log.gpg.info("Message signed successfully")
        } else {
            Log.gpg.error("Signing failed for \(email, privacy: .public)")
        }
        return result
    }

    // MARK: - Verify

    /// Результат проверки подписи
    struct VerifyResult: Sendable {
        let isValid: Bool
        let signerEmail: String?
        let signerKeyID: String?
        let statusMessage: String
        let trustLevel: TrustLevel

        enum TrustLevel: String, Sendable {
            case ultimate, full, marginal, undefined, never, expired, unknown
        }
    }

    /// Проверяет отделённую подпись
    static func verify(signature: Data, signedData: Data) -> VerifyResult {
        Log.security.info("Verifying signature")

        let tempDir = FileManager.default.temporaryDirectory
        let sigFile = tempDir.appendingPathComponent(UUID().uuidString + ".sig")
        let dataFile = tempDir.appendingPathComponent(UUID().uuidString + ".dat")

        defer {
            try? FileManager.default.removeItem(at: sigFile)
            try? FileManager.default.removeItem(at: dataFile)
        }

        do {
            try signature.write(to: sigFile)
            try signedData.write(to: dataFile)
        } catch {
            Log.security.error("Failed to write temp files for verification")
            return VerifyResult(isValid: false, signerEmail: nil, signerKeyID: nil,
                              statusMessage: "Ошибка записи временных файлов", trustLevel: .unknown)
        }

        let (exitCode, _, stderr) = runFull(args: [
            "--batch", "--status-fd", "2",
            "--verify", sigFile.path, dataFile.path,
        ])

        let stderrStr = stderr ?? ""
        Log.security.debug("Verify stderr: \(stderrStr, privacy: .public)")

        let isGoodSig = stderrStr.contains("[GNUPG:] GOODSIG") || stderrStr.contains("Good signature")
        let signerEmail = extractEmail(from: stderrStr)
        let signerKeyID = extractKeyID(from: stderrStr)
        let trustLevel = extractTrustLevel(from: stderrStr)

        if exitCode == 0 && isGoodSig {
            Log.security.info("Signature valid from \(signerEmail ?? "unknown", privacy: .public)")
            return VerifyResult(isValid: true, signerEmail: signerEmail, signerKeyID: signerKeyID,
                              statusMessage: "Подпись верна", trustLevel: trustLevel)
        } else {
            Log.security.warning("Signature invalid")
            return VerifyResult(isValid: false, signerEmail: signerEmail, signerKeyID: signerKeyID,
                              statusMessage: "Подпись недействительна", trustLevel: .unknown)
        }
    }

    // MARK: - Clear Sign (inline PGP)

    /// Создаёт clearsigned сообщение (inline PGP)
    static func clearSign(data: Data, signer email: String) -> Data? {
        Log.gpg.info("Clear-signing message as \(email, privacy: .public)")
        ensureAgentRunning()

        var args = ["--batch", "--yes", "--armor"]
        args.append(contentsOf: pinentryArgs())
        args.append(contentsOf: ["--local-user", email, "--clearsign"])

        let result = runWithIO(args: args, input: data)
        if result != nil {
            Log.gpg.info("Clear-sign successful")
        } else {
            Log.gpg.error("Clear-sign failed for \(email, privacy: .public)")
        }
        return result
    }

    /// Проверяет множество подписей и возвращает результаты для каждой
    static func verifyMultiple(signatures: [Data], signedData: Data) -> [VerifyResult] {
        return signatures.map { sig in
            verify(signature: sig, signedData: signedData)
        }
    }

    // MARK: - Encrypt

    /// Шифрует данные для указанных получателей
    static func encrypt(data: Data, recipients: [String], sign signer: String? = nil) -> Data? {
        Log.gpg.info("Encrypting for \(recipients.count) recipients")
        ensureAgentRunning()

        var args = ["--batch", "--yes", "--armor", "--trust-model", "always"]
        args.append(contentsOf: pinentryArgs())

        for recipient in recipients {
            args.append(contentsOf: ["--recipient", recipient])
        }

        if let signer = signer {
            args.append(contentsOf: ["--local-user", signer, "--sign"])
        }

        args.append("--encrypt")

        let result = runWithIO(args: args, input: data)
        if result != nil {
            Log.gpg.info("Encryption successful")
        } else {
            Log.gpg.error("Encryption failed")
        }
        return result
    }

    // MARK: - Decrypt

    /// Результат расшифровки
    struct DecryptResult: Sendable {
        let data: Data?
        let success: Bool
        let statusMessage: String
        let wasSignedBy: String?
        let signatureValid: Bool
    }

    /// Расшифровывает данные
    static func decrypt(data: Data) -> DecryptResult {
        Log.gpg.info("Decrypting message")
        ensureAgentRunning()

        var args = ["--batch", "--yes", "--status-fd", "2"]
        args.append(contentsOf: pinentryArgs())
        args.append("--decrypt")

        let (exitCode, stdout, stderr) = runFullWithIO(args: args, input: data)

        let stderrStr = stderr ?? ""
        Log.security.debug("Decrypt stderr: \(stderrStr, privacy: .public)")

        if exitCode == 0, let output = stdout {
            let sigValid = stderrStr.contains("[GNUPG:] GOODSIG")
            let signerEmail = sigValid ? extractEmail(from: stderrStr) : nil
            let message = sigValid ? "Расшифровано и подпись верна" : "Расшифровано"
            Log.gpg.info("Decryption successful, signature: \(sigValid)")
            return DecryptResult(data: output, success: true, statusMessage: message,
                               wasSignedBy: signerEmail, signatureValid: sigValid)
        } else {
            Log.gpg.error("Decryption failed: \(stderrStr, privacy: .public)")
            return DecryptResult(data: nil, success: false, statusMessage: "Ошибка расшифровки",
                               wasSignedBy: nil, signatureValid: false)
        }
    }

    // MARK: - Import Key

    /// Импортирует публичный ключ
    static func importKey(data: Data) -> Bool {
        Log.keys.info("Importing key")
        let result = runWithIO(args: ["--batch", "--import"], input: data)
        let success = result != nil
        if success {
            Log.keys.info("Key imported successfully")
            KeyCache.shared.invalidateAll()
        } else {
            Log.keys.error("Key import failed")
        }
        return success
    }

    // MARK: - Export Key

    /// Экспортирует публичный ключ в ASCII Armor
    static func exportKey(fingerprint: String) -> String? {
        Log.keys.info("Exporting key \(fingerprint.suffix(8), privacy: .public)")
        return run(["--batch", "--armor", "--export", fingerprint])
    }

    // MARK: - Keyserver

    /// Ищет и импортирует ключ с keyserver
    static func searchAndImportFromKeyserver(query: String, server: String = "keys.openpgp.org") -> Bool {
        Log.keys.info("Searching keyserver \(server) for \(query, privacy: .public)")

        let (exitCode, _, stderr) = runFull(args: [
            "--batch", "--keyserver", server,
            "--search-keys", query,
        ])

        if exitCode != 0 {
            // search-keys может не работать в batch mode, пробуем recv-keys напрямую
            let (recvExit, _, _) = runFull(args: [
                "--batch", "--keyserver", server,
                "--recv-keys", query,
            ])
            if recvExit == 0 {
                Log.keys.info("Key received from keyserver")
                KeyCache.shared.invalidateAll()
                return true
            }
            Log.keys.warning("Keyserver search failed: \(stderr ?? "", privacy: .public)")
            return false
        }

        KeyCache.shared.invalidateAll()
        return true
    }

    /// Отправляет ключ на keyserver
    static func sendToKeyserver(fingerprint: String, server: String = "keys.openpgp.org") -> Bool {
        Log.keys.info("Sending key \(fingerprint.suffix(8), privacy: .public) to \(server)")
        let (exitCode, _, _) = runFull(args: [
            "--batch", "--keyserver", server,
            "--send-keys", fingerprint,
        ])
        return exitCode == 0
    }

    /// Обновляет ключи с keyserver
    static func refreshKeysFromKeyserver(server: String = "keys.openpgp.org") -> Bool {
        Log.keys.info("Refreshing keys from \(server)")
        let (exitCode, _, _) = runFull(args: [
            "--batch", "--keyserver", server,
            "--refresh-keys",
        ])
        if exitCode == 0 {
            KeyCache.shared.invalidateAll()
        }
        return exitCode == 0
    }

    // MARK: - Trust

    /// Устанавливает уровень доверия ключу (1-5)
    static func setOwnerTrust(fingerprint: String, level: String) -> Bool {
        Log.keys.info("Setting trust level \(level) for \(fingerprint.suffix(8), privacy: .public)")
        let trustLine = "\(fingerprint):\(level):\n"
        guard let data = trustLine.data(using: .utf8) else { return false }
        let result = runWithIO(args: ["--batch", "--import-ownertrust"], input: data)
        if result != nil {
            KeyCache.shared.invalidateAll()
        }
        return result != nil
    }

    // MARK: - Delete Key

    /// Удаляет публичный ключ
    static func deletePublicKey(fingerprint: String) -> Bool {
        Log.keys.info("Deleting public key \(fingerprint.suffix(8), privacy: .public)")
        let (exitCode, _, _) = runFull(args: [
            "--batch", "--yes", "--delete-keys", fingerprint,
        ])
        if exitCode == 0 {
            KeyCache.shared.invalidateAll()
        }
        return exitCode == 0
    }

    // MARK: - Process Execution

    private static func run(_ args: [String]) -> String? {
        guard let path = gpgPath() else {
            Log.gpg.error("gpg binary not found")
            return nil
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = gpgEnvironment()

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            Log.gpg.error("Failed to run gpg: \(error.localizedDescription)")
            return nil
        }
    }

    private static func runWithIO(args: [String], input: Data) -> Data? {
        let (exitCode, stdout, _) = runFullWithIO(args: args, input: input)
        return exitCode == 0 ? stdout : nil
    }

    private static func runFull(args: [String]) -> (Int32, String?, String?) {
        guard let path = gpgPath() else { return (-1, nil, nil) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = gpgEnvironment()

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
            let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            return (
                process.terminationStatus,
                String(data: stdoutData, encoding: .utf8),
                String(data: stderrData, encoding: .utf8)
            )
        } catch {
            Log.gpg.error("Failed to run gpg: \(error.localizedDescription)")
            return (-1, nil, nil)
        }
    }

    private static func runFullWithIO(args: [String], input: Data) -> (Int32, Data?, String?) {
        guard let path = gpgPath() else { return (-1, nil, nil) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = gpgEnvironment()

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            stdinPipe.fileHandleForWriting.write(input)
            stdinPipe.fileHandleForWriting.closeFile()
            process.waitUntilExit()
            let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            return (
                process.terminationStatus,
                stdoutData,
                String(data: stderrData, encoding: .utf8)
            )
        } catch {
            Log.gpg.error("Failed to run gpg: \(error.localizedDescription)")
            return (-1, nil, nil)
        }
    }

    private static func gpgEnvironment() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        // Настраиваем для работы с gpg-agent
        if let home = env["HOME"] {
            env["GNUPGHOME"] = env["GNUPGHOME"] ?? "\(home)/.gnupg"
        }
        // GPG_TTY нужен для pinentry-tty, но в non-TTY среде ставим пустое
        if env["GPG_TTY"] == nil {
            env["GPG_TTY"] = ""
        }
        // Добавляем Homebrew пути
        if let path = env["PATH"] {
            env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + path
        }
        return env
    }

    // MARK: - Parsing

    private static func parseKeyListing(_ output: String) -> [GPGKeyInfo] {
        var keys: [GPGKeyInfo] = []
        var currentFingerprint: String?
        var currentKeyValid = true

        for line in output.components(separatedBy: "\n") {
            let fields = line.components(separatedBy: ":")

            // pub/sec — основная строка ключа, поле [1] = validity
            if fields.count >= 2 && (fields[0] == "pub" || fields[0] == "sec") {
                let validity = fields[1]
                // r=revoked, e=expired, d=disabled, n=not valid
                currentKeyValid = !["r", "e", "d", "n"].contains(validity)
                if !currentKeyValid {
                    Log.keys.debug("Skipping invalid key (validity=\(validity, privacy: .public))")
                }
            }

            if fields.count >= 10 && fields[0] == "fpr" {
                currentFingerprint = fields[9]
            }

            if fields.count >= 10 && fields[0] == "uid" && currentKeyValid {
                let uidValidity = fields[1]
                // Пропускаем отозванные uid
                if uidValidity == "r" { continue }

                let uid = fields[9]
                    .removingPercentEncoding ?? fields[9]
                if let fingerprint = currentFingerprint {
                    let email = extractEmailFromUID(uid)
                    keys.append(GPGKeyInfo(
                        fingerprint: fingerprint,
                        userID: uid,
                        email: email
                    ))
                }
            }
        }

        return keys
    }

    private static func extractEmailFromUID(_ uid: String) -> String {
        guard let start = uid.lastIndex(of: "<"),
              let end = uid.lastIndex(of: ">") else {
            return uid
        }
        return String(uid[uid.index(after: start)..<end])
    }

    private static func extractEmail(from gpgOutput: String) -> String? {
        for line in gpgOutput.components(separatedBy: "\n") {
            if line.contains("GOODSIG") || line.contains("Good signature from") {
                return extractEmailFromUID(line)
            }
        }
        return nil
    }

    private static func extractKeyID(from gpgOutput: String) -> String? {
        for line in gpgOutput.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") || line.contains("[GNUPG:] BADSIG") {
                let parts = line.components(separatedBy: " ")
                if parts.count >= 3 {
                    return parts[2]
                }
            }
        }
        return nil
    }

    private static func extractTrustLevel(from gpgOutput: String) -> VerifyResult.TrustLevel {
        for line in gpgOutput.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] TRUST_ULTIMATE") { return .ultimate }
            if line.contains("[GNUPG:] TRUST_FULLY") { return .full }
            if line.contains("[GNUPG:] TRUST_MARGINAL") { return .marginal }
            if line.contains("[GNUPG:] TRUST_UNDEFINED") { return .undefined }
            if line.contains("[GNUPG:] TRUST_NEVER") { return .never }
        }
        return .unknown
    }
}
