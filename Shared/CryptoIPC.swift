import Foundation

/// IPC между расширением (sandbox) и основным приложением для крипто-операций.
/// Расширение записывает запрос в /tmp/, основное приложение обрабатывает и записывает результат.
enum CryptoIPC {

    private static let requestDir = "/tmp/freegpgmail-ipc"
    private static let timeout: TimeInterval = 15

    struct Request: Codable {
        let id: String
        let operation: String  // "sign", "encrypt", "sign+encrypt", "verify", "decrypt"
        let data: Data
        let signer: String?
        let recipients: [String]?
        let signatureData: Data?  // Для verify: отдельная подпись

        init(id: String, operation: String, data: Data, signer: String?, recipients: [String]?, signatureData: Data? = nil) {
            self.id = id
            self.operation = operation
            self.data = data
            self.signer = signer
            self.recipients = recipients
            self.signatureData = signatureData
        }
    }

    struct Response: Codable {
        let id: String
        let success: Bool
        let data: Data?
        let error: String?
        let isSigned: Bool
        let isEncrypted: Bool
        let signerEmail: String?
        let signatureValid: Bool?
        // Расширенная информация о подписи
        let signerKeyID: String?
        let trustLevel: String?          // ultimate, full, marginal, undefined, never, expired, unknown
        let keyFingerprint: String?
        let keyCreationDate: Date?
        let keyExpirationDate: Date?
        let signerUserID: String?
        let verificationDetail: String?  // Детали верификации (причина ошибки или статус GPG)

        init(id: String, success: Bool, data: Data?, error: String?, isSigned: Bool, isEncrypted: Bool,
             signerEmail: String? = nil, signatureValid: Bool? = nil,
             signerKeyID: String? = nil, trustLevel: String? = nil,
             keyFingerprint: String? = nil, keyCreationDate: Date? = nil,
             keyExpirationDate: Date? = nil, signerUserID: String? = nil,
             verificationDetail: String? = nil) {
            self.id = id
            self.success = success
            self.data = data
            self.error = error
            self.isSigned = isSigned
            self.isEncrypted = isEncrypted
            self.signerEmail = signerEmail
            self.signatureValid = signatureValid
            self.signerKeyID = signerKeyID
            self.trustLevel = trustLevel
            self.keyFingerprint = keyFingerprint
            self.keyCreationDate = keyCreationDate
            self.keyExpirationDate = keyExpirationDate
            self.signerUserID = signerUserID
            self.verificationDetail = verificationDetail
        }
    }

    /// Вызывается из расширения: отправляет запрос и ждёт ответ
    static func sendRequest(operation: String, data: Data, signer: String?, recipients: [String]?, signatureData: Data? = nil) -> Response? {
        let requestID = UUID().uuidString
        let request = Request(id: requestID, operation: operation, data: data, signer: signer, recipients: recipients, signatureData: signatureData)

        // Создаём директорию если нет
        try? FileManager.default.createDirectory(atPath: requestDir, withIntermediateDirectories: true)

        // Записываем запрос
        let requestFile = "\(requestDir)/req-\(requestID).json"
        let responseFile = "\(requestDir)/resp-\(requestID).json"

        guard let json = try? JSONEncoder().encode(request) else {
            NSLog("[FreeGPGMail] IPC: failed to encode request")
            return nil
        }
        try? json.write(to: URL(fileURLWithPath: requestFile))
        NSLog("[FreeGPGMail] IPC: sent request %@ (%@)", requestID, operation)

        // Ждём ответ с polling
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let responseData = try? Data(contentsOf: URL(fileURLWithPath: responseFile)),
               let response = try? JSONDecoder().decode(Response.self, from: responseData) {
                // Удаляем файлы
                try? FileManager.default.removeItem(atPath: requestFile)
                try? FileManager.default.removeItem(atPath: responseFile)
                NSLog("[FreeGPGMail] IPC: got response for %@ (success=%d)", requestID, response.success ? 1 : 0)
                return response
            }
            Thread.sleep(forTimeInterval: 0.1)
        }

        NSLog("[FreeGPGMail] IPC: timeout waiting for response %@", requestID)
        try? FileManager.default.removeItem(atPath: requestFile)
        return nil
    }

    /// Вызывается из основного приложения: обрабатывает запросы
    static func processRequests() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: requestDir) else { return }

        for file in files where file.hasPrefix("req-") && file.hasSuffix(".json") {
            let requestFile = "\(requestDir)/\(file)"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: requestFile)),
                  let request = try? JSONDecoder().decode(Request.self, from: data) else {
                continue
            }

            let responseFile = "\(requestDir)/resp-\(request.id).json"

            // Если ответ уже есть — пропускаем
            if fm.fileExists(atPath: responseFile) { continue }

            NSLog("[FreeGPGMail] IPC: processing request %@ (%@)", request.id, request.operation)

            var response: Response

            switch request.operation {
            case "sign":
                // Разделяем raw email на заголовки и тело
                guard let parts = MIMEHelper.splitRawEmail(request.data) else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось разобрать письмо.", isSigned: false, isEncrypted: false)
                    break
                }
                // Подписываем тело с Content-Type заголовком (RFC 3156)
                let bodyToSign = "Content-Type: \(parts.contentType)\r\nContent-Transfer-Encoding: 8bit\r\n\r\n".data(using: .utf8)! + parts.body
                if let signer = request.signer,
                   let signatureData = GPGHelper.sign(data: bodyToSign, signer: signer) {
                    let boundary = MIMEHelper.generateBoundary()
                    if let mimeData = MIMEHelper.buildSignedEmail(rawEmail: request.data, signature: signatureData, boundary: boundary) {
                        response = Response(id: request.id, success: true, data: mimeData, error: nil, isSigned: true, isEncrypted: false)
                    } else {
                        response = Response(id: request.id, success: false, data: nil, error: "Ошибка построения PGP/MIME.", isSigned: false, isEncrypted: false)
                    }
                } else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось подписать письмо. Проверьте GPG-ключ и gpg-agent.", isSigned: false, isEncrypted: false)
                }

            case "encrypt":
                guard let parts = MIMEHelper.splitRawEmail(request.data) else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось разобрать письмо.", isSigned: false, isEncrypted: false)
                    break
                }
                let bodyToEncrypt = "Content-Type: \(parts.contentType)\r\n\r\n".data(using: .utf8)! + parts.body
                if let recipients = request.recipients,
                   let encrypted = GPGHelper.encrypt(data: bodyToEncrypt, recipients: recipients, sign: nil) {
                    let boundary = MIMEHelper.generateBoundary()
                    if let mimeData = MIMEHelper.buildEncryptedEmail(rawEmail: request.data, encryptedData: encrypted, boundary: boundary) {
                        response = Response(id: request.id, success: true, data: mimeData, error: nil, isSigned: false, isEncrypted: true)
                    } else {
                        response = Response(id: request.id, success: false, data: nil, error: "Ошибка построения PGP/MIME.", isSigned: false, isEncrypted: false)
                    }
                } else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось зашифровать письмо. Проверьте GPG-ключи получателей.", isSigned: false, isEncrypted: false)
                }

            case "sign+encrypt":
                guard let parts = MIMEHelper.splitRawEmail(request.data) else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось разобрать письмо.", isSigned: false, isEncrypted: false)
                    break
                }
                let bodyToEncrypt = "Content-Type: \(parts.contentType)\r\n\r\n".data(using: .utf8)! + parts.body
                if let signer = request.signer,
                   let recipients = request.recipients,
                   let encrypted = GPGHelper.encrypt(data: bodyToEncrypt, recipients: recipients, sign: signer) {
                    let boundary = MIMEHelper.generateBoundary()
                    if let mimeData = MIMEHelper.buildEncryptedEmail(rawEmail: request.data, encryptedData: encrypted, boundary: boundary) {
                        response = Response(id: request.id, success: true, data: mimeData, error: nil, isSigned: true, isEncrypted: true)
                    } else {
                        response = Response(id: request.id, success: false, data: nil, error: "Ошибка построения PGP/MIME.", isSigned: false, isEncrypted: false)
                    }
                } else {
                    response = Response(id: request.id, success: false, data: nil, error: "Не удалось подписать и зашифровать письмо.", isSigned: false, isEncrypted: false)
                }

            case "verify":
                // request.data = signed data, request.signatureData = detached signature
                let verifyResult: GPGHelper.VerifyResult
                if let sigData = request.signatureData {
                    verifyResult = GPGHelper.verify(signature: sigData, signedData: request.data)
                } else {
                    verifyResult = GPGHelper.verify(signature: request.data, signedData: request.data)
                }
                // Подтягиваем расширенную информацию о ключе подписанта
                let keyInfo: GPGKeyInfo?
                if let email = verifyResult.signerEmail {
                    keyInfo = GPGHelper.findKey(for: email)
                } else {
                    keyInfo = nil
                }
                response = Response(id: request.id, success: true, data: request.data, error: nil,
                                   isSigned: true, isEncrypted: false,
                                   signerEmail: verifyResult.signerEmail, signatureValid: verifyResult.isValid,
                                   signerKeyID: verifyResult.signerKeyID,
                                   trustLevel: verifyResult.trustLevel.rawValue,
                                   keyFingerprint: keyInfo?.fingerprint,
                                   keyCreationDate: keyInfo?.creationDate,
                                   keyExpirationDate: keyInfo?.expirationDate,
                                   signerUserID: keyInfo?.userID,
                                   verificationDetail: verifyResult.statusMessage)

            case "decrypt":
                let result = GPGHelper.decrypt(data: request.data)
                if result.success, let decData = result.data {
                    response = Response(id: request.id, success: true, data: decData, error: nil,
                                       isSigned: result.wasSignedBy != nil, isEncrypted: true,
                                       signerEmail: result.wasSignedBy, signatureValid: result.signatureValid)
                } else {
                    response = Response(id: request.id, success: false, data: nil,
                                       error: result.statusMessage, isSigned: false, isEncrypted: true)
                }

            default:
                response = Response(id: request.id, success: false, data: nil, error: "Неизвестная операция: \(request.operation)", isSigned: false, isEncrypted: false)
            }

            if let json = try? JSONEncoder().encode(response) {
                try? json.write(to: URL(fileURLWithPath: responseFile))
            }

            // Удаляем файл запроса
            try? fm.removeItem(atPath: requestFile)
        }
    }
}
