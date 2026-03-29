import MailKit

/// Обработчик безопасности сообщений — расшифровка и верификация входящих,
/// шифрование и подпись исходящих.
class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    // MARK: - Decoding (Incoming Messages)

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        Log.security.info("Decoding message (\(data.count) bytes)")

        guard let rawString = String(data: data, encoding: .utf8) else {
            Log.security.error("Cannot decode message as UTF-8")
            return nil
        }

        let contentType = extractContentType(from: rawString)

        // Обработка Autocrypt заголовков (импорт ключей из входящих)
        if let headerEnd = rawString.range(of: "\r\n\r\n") ?? rawString.range(of: "\n\n") {
            let headers = String(rawString[rawString.startIndex..<headerEnd.lowerBound])
            if headers.lowercased().contains("autocrypt:") {
                _ = AutocryptHelper.processIncoming(rawHeaders: headers)
            }
        }

        switch MIMEHelper.detectPGPMIMEType(contentType: contentType) {
        case .encrypted:
            return handleEncryptedMessage(data: data, contentType: contentType)
        case .signed:
            return handleSignedMessage(data: data, contentType: contentType)
        case .none:
            if rawString.contains("-----BEGIN PGP MESSAGE-----") {
                return handleInlinePGPEncrypted(data: data)
            }
            if rawString.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
                return handleInlinePGPSigned(data: data)
            }
            return nil
        }
    }

    // MARK: - Encoding (Outgoing Messages)

    func getEncodingStatus(
        for message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void
    ) {
        let sender = message.fromAddress.addressString ?? message.fromAddress.rawString
        let signingKey = KeyCache.shared.findSigningKey(for: sender)
        let canSign = signingKey != nil

        let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
        let canEncrypt = canSign && !allRecipients.isEmpty && allRecipients.allSatisfy { addr in
            let email = addr.addressString ?? addr.rawString
            return KeyCache.shared.findPublicKey(for: email) != nil
        }

        Log.security.info("Encoding status: canSign=\(canSign), canEncrypt=\(canEncrypt), recipients=\(allRecipients.count)")

        let status = MEOutgoingMessageEncodingStatus(
            canSign: canSign,
            canEncrypt: canEncrypt,
            securityError: nil,
            addressesFailingEncryption: []
        )
        completionHandler(status)
    }

    func encode(
        _ message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEMessageEncodingResult) -> Void
    ) {
        let sender = message.fromAddress.addressString ?? message.fromAddress.rawString
        let settings = Settings.shared

        let shouldSign = composeContext.shouldSign || settings.autoSign
        let shouldEncrypt = composeContext.shouldEncrypt || settings.autoEncrypt

        NSLog("[FreeGPGMail] encode: sign=%d, encrypt=%d, sender=%@", shouldSign ? 1 : 0, shouldEncrypt ? 1 : 0, sender)

        // Ничего не делаем — отправляем как есть
        if !shouldSign && !shouldEncrypt {
            NSLog("[FreeGPGMail] encode: no sign/encrypt requested, passing through")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        guard let rawData = message.rawData else {
            NSLog("[FreeGPGMail] encode: no rawData, passing through")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        // Определяем ключ для подписи
        let signingEmail: String
        if let key = KeyCache.shared.findSigningKey(for: sender) {
            signingEmail = key.email
        } else {
            signingEmail = sender
        }

        // Определяем операцию
        let operation: String
        var recipients: [String]?

        if shouldEncrypt && shouldSign {
            operation = "sign+encrypt"
            let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            recipients = allRecipients.map { $0.addressString ?? $0.rawString }
        } else if shouldEncrypt {
            operation = "encrypt"
            let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            recipients = allRecipients.map { $0.addressString ?? $0.rawString }
        } else {
            operation = "sign"
        }

        // Отправляем запрос через IPC к основному приложению
        NSLog("[FreeGPGMail] encode: sending IPC request (%@)", operation)
        guard let response = CryptoIPC.sendRequest(
            operation: operation,
            data: rawData,
            signer: shouldSign ? signingEmail : nil,
            recipients: recipients
        ) else {
            // IPC таймаут — отправляем без подписи/шифрования, не крашим Mail
            NSLog("[FreeGPGMail] encode: IPC timeout, sending without protection")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        if response.success, let mimeData = response.data {
            NSLog("[FreeGPGMail] encode: success, %d bytes", mimeData.count)
            let encoded = MEEncodedOutgoingMessage(rawData: mimeData, isSigned: response.isSigned, isEncrypted: response.isEncrypted)
            completionHandler(MEMessageEncodingResult(encodedMessage: encoded, signingError: nil, encryptionError: nil))
        } else {
            // Ошибка GPG — отправляем без подписи, не крашим Mail
            NSLog("[FreeGPGMail] encode: GPG error: %@, sending without protection", response.error ?? "unknown")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
        }
    }

    // MARK: - Extension View Controllers

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        Log.general.debug("extensionViewController(signers:) called with \(messageSigners.count) signers")
        guard let signer = messageSigners.first else {
            return nil
        }
        let vc = SecurityInfoViewController()
        vc.configure(with: signer.context)
        return vc
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        Log.general.debug("extensionViewController(messageContext:) called")
        let vc = SecurityInfoViewController()
        vc.configure(with: context)
        return vc
    }

    func primaryActionClicked(forMessageContext context: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        // ViewBridge/XPC не может сериализовать MEExtensionViewController из primaryActionClicked —
        // Mail крашится с _swift_stdlib_bridgeErrorToNSError. Возвращаем nil.
        // Детали подписи доступны через клик на подпись в заголовке (extensionViewController(signers:)).
        completionHandler(nil)
    }

    // MARK: - Private: Encrypted Message Handling

    private func handleEncryptedMessage(data: Data, contentType: String) -> MEDecodedMessage? {
        Log.security.info("Handling PGP/MIME encrypted message")

        guard let boundary = MIMEHelper.extractBoundary(from: contentType),
              let encryptedData = MIMEHelper.parseEncryptedMessage(data: data, boundary: boundary) else {
            Log.security.error("Failed to parse encrypted MIME structure")
            return nil
        }

        var ctx = SecurityContext()
        ctx.isEncrypted = true

        // Расшифровка через IPC (sandbox не может запустить gpg)
        guard let response = CryptoIPC.sendRequest(
            operation: "decrypt",
            data: encryptedData,
            signer: nil,
            recipients: nil
        ) else {
            // IPC недоступен — показываем ошибку
            NSLog("[FreeGPGMail] decrypt IPC unavailable")
            ctx.decryptionError = "FreeGPGMail.app не запущен"
            let banner = MEDecodedMessageBanner(
                title: "Не удалось расшифровать (запустите FreeGPGMail.app)",
                primaryActionTitle: "",
                dismissable: true
            )
            let securityInfo = MEMessageSecurityInformation(
                signers: [], isEncrypted: true, signingError: nil, encryptionError: GPGMailError.decryptionFailed
            )
            return MEDecodedMessage(data: nil, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        guard response.success, let decryptedData = response.data else {
            Log.security.error("Decryption failed: \(response.error ?? "unknown")")
            ctx.decryptionError = response.error ?? "Ошибка расшифровки"

            let banner = MEDecodedMessageBanner(
                title: "Не удалось расшифровать сообщение",
                primaryActionTitle: "",
                dismissable: true
            )
            let securityInfo = MEMessageSecurityInformation(
                signers: [], isEncrypted: true, signingError: nil, encryptionError: GPGMailError.decryptionFailed
            )
            return MEDecodedMessage(data: nil, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        // Собираем информацию о подписи если была
        var signers: [MEMessageSigner] = []
        let signatureValid = response.signatureValid ?? false
        let signerEmail = response.signerEmail

        if signatureValid, let email = signerEmail {
            ctx.signatureStatus = .valid(email: email, trust: "unknown")
            let signer = MEMessageSigner(
                emailAddresses: [MEEmailAddress(rawString: email)],
                signatureLabel: email,
                context: ctx.encode()
            )
            signers = [signer]
        }

        let banner = MEDecodedMessageBanner(
            title: signatureValid
                ? "Зашифровано и подписано (\(signerEmail ?? ""))"
                : "Зашифрованное сообщение расшифровано",
            primaryActionTitle: "",
            dismissable: true
        )

        let securityInfo = MEMessageSecurityInformation(
            signers: signers,
            isEncrypted: true,
            signingError: nil,
            encryptionError: nil,
            shouldBlockRemoteContent: Settings.shared.blockRemoteContentForEncrypted,
            localizedRemoteContentBlockingReason: Settings.shared.blockRemoteContentForEncrypted
                ? "Удалённый контент заблокирован для зашифрованных сообщений" : nil
        )

        return MEDecodedMessage(
            data: decryptedData,
            securityInformation: securityInfo,
            context: ctx.encode(),
            banner: banner
        )
    }

    // MARK: - Private: Signed Message Handling

    private func handleSignedMessage(data: Data, contentType: String) -> MEDecodedMessage? {
        Log.security.info("Handling PGP/MIME signed message")

        guard let boundary = MIMEHelper.extractBoundary(from: contentType) else {
            Log.security.error("Failed to extract boundary")
            return nil
        }

        guard let parsed = MIMEHelper.parseSignedMessage(data: data, boundary: boundary) else {
            Log.security.error("Failed to parse signed MIME structure")
            return nil
        }

        // Отображаемый контент — тело подписанной части (MIME entity без обёртки multipart/signed)
        // MEDecodedMessage(data:) ожидает именно MIME-контент, а не полный RFC822 с заголовками From/To/Subject.
        let displayData = parsed.body

        // Верификация через IPC (sandbox не может запустить gpg)
        if let response = CryptoIPC.sendRequest(
            operation: "verify",
            data: parsed.body,
            signer: nil,
            recipients: nil,
            signatureData: parsed.signature
        ) {
            let isValid = response.signatureValid ?? false
            let signerEmail = response.signerEmail

            var ctx = SecurityContext()
            let trustLevel = response.trustLevel ?? "unknown"
            if isValid {
                ctx.signatureStatus = .valid(email: signerEmail ?? "Неизвестный", trust: trustLevel)
            } else {
                ctx.signatureStatus = .invalid(email: signerEmail)
            }
            ctx.signerKeyID = response.signerKeyID
            ctx.trustLevel = trustLevel
            ctx.keyFingerprint = response.keyFingerprint
            ctx.keyCreationDate = response.keyCreationDate
            ctx.keyExpirationDate = response.keyExpirationDate
            ctx.signerUserID = response.signerUserID
            ctx.verificationDetail = response.verificationDetail

            let signerLabel = signerEmail ?? "Неизвестный"
            let signers: [MEMessageSigner]
            let signingError: Error?

            if isValid {
                signers = [MEMessageSigner(
                    emailAddresses: [MEEmailAddress(rawString: signerLabel)],
                    signatureLabel: "PGP: \(signerLabel)",
                    context: ctx.encode()
                )]
                signingError = nil
            } else {
                // Пустой signers + signingError → Mail покажет предупреждающую иконку вместо галочки
                // Для просмотра деталей используется extensionViewController(messageContext:) через баннер
                signers = []
                signingError = GPGMailError.verificationFailed
            }

            let banner = MEDecodedMessageBanner(
                title: isValid ? "PGP подпись верна: \(signerLabel)" : "⚠️ PGP подпись недействительна: \(signerLabel)",
                primaryActionTitle: "",
                dismissable: isValid
            )

            let securityInfo = MEMessageSecurityInformation(
                signers: signers,
                isEncrypted: false,
                signingError: signingError,
                encryptionError: nil
            )

            return MEDecodedMessage(data: displayData, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        // IPC недоступен — показываем тело, помечаем как подписанное но непроверенное
        NSLog("[FreeGPGMail] verify IPC unavailable, showing body without verification")

        var ctx = SecurityContext()
        ctx.signatureStatus = .valid(email: "Не проверено (FreeGPGMail.app не запущен)", trust: "unknown")

        let signers = [MEMessageSigner(
            emailAddresses: [],
            signatureLabel: "PGP: Подпись не проверена (запустите FreeGPGMail.app)",
            context: ctx.encode()
        )]

        let banner = MEDecodedMessageBanner(
            title: "PGP подписанное сообщение (подпись не проверена — запустите FreeGPGMail.app)",
            primaryActionTitle: "",
            dismissable: true
        )

        let securityInfo = MEMessageSecurityInformation(
            signers: signers, isEncrypted: false, signingError: nil, encryptionError: nil
        )

        return MEDecodedMessage(data: displayData, securityInformation: securityInfo,
                               context: ctx.encode(), banner: banner)
    }

    // MARK: - Private: Inline PGP

    private func handleInlinePGPEncrypted(data: Data) -> MEDecodedMessage? {
        Log.security.info("Handling inline PGP encrypted message")

        guard let rawString = String(data: data, encoding: .utf8),
              let pgpStart = rawString.range(of: "-----BEGIN PGP MESSAGE-----"),
              let pgpEnd = rawString.range(of: "-----END PGP MESSAGE-----") else {
            return nil
        }

        let pgpBlock = String(rawString[pgpStart.lowerBound...pgpEnd.upperBound])
        guard let pgpData = pgpBlock.data(using: .utf8) else { return nil }

        var ctx = SecurityContext()
        ctx.isEncrypted = true

        guard let response = CryptoIPC.sendRequest(
            operation: "decrypt",
            data: pgpData,
            signer: nil,
            recipients: nil
        ), response.success, let decryptedData = response.data else {
            ctx.decryptionError = "Не удалось расшифровать"
            let banner = MEDecodedMessageBanner(
                title: "Не удалось расшифровать сообщение",
                primaryActionTitle: "",
                dismissable: true
            )
            let securityInfo = MEMessageSecurityInformation(
                signers: [], isEncrypted: true, signingError: nil, encryptionError: GPGMailError.decryptionFailed
            )
            return MEDecodedMessage(data: nil, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        let decryptedText = String(data: decryptedData, encoding: .utf8) ?? ""
        let replacedString = rawString.replacingCharacters(
            in: pgpStart.lowerBound...pgpEnd.upperBound,
            with: decryptedText
        )

        if response.signatureValid ?? false {
            ctx.signatureStatus = .valid(email: response.signerEmail ?? "", trust: "unknown")
        }

        let banner = MEDecodedMessageBanner(
            title: "Зашифрованное сообщение расшифровано",
            primaryActionTitle: "",
            dismissable: true
        )

        let securityInfo = MEMessageSecurityInformation(
            signers: [], isEncrypted: true, signingError: nil, encryptionError: nil,
            shouldBlockRemoteContent: Settings.shared.blockRemoteContentForEncrypted,
            localizedRemoteContentBlockingReason: Settings.shared.blockRemoteContentForEncrypted
                ? "Удалённый контент заблокирован для зашифрованных сообщений" : nil
        )

        return MEDecodedMessage(
            data: replacedString.data(using: .utf8) ?? data,
            securityInformation: securityInfo,
            context: ctx.encode(),
            banner: banner
        )
    }

    private func handleInlinePGPSigned(data: Data) -> MEDecodedMessage? {
        Log.security.info("Handling inline PGP signed message")

        var ctx = SecurityContext()
        let signers: [MEMessageSigner]
        let banner: MEDecodedMessageBanner

        if let response = CryptoIPC.sendRequest(
            operation: "verify",
            data: data,
            signer: nil,
            recipients: nil
        ) {
            let isValid = response.signatureValid ?? false
            let email = response.signerEmail ?? "Неизвестный"

            if isValid {
                ctx.signatureStatus = .valid(email: email, trust: "unknown")
                let signer = MEMessageSigner(
                    emailAddresses: [MEEmailAddress(rawString: email)],
                    signatureLabel: email,
                    context: ctx.encode()
                )
                signers = [signer]
                banner = MEDecodedMessageBanner(
                    title: "Подписано: \(email)",
                    primaryActionTitle: "",
                    dismissable: true
                )
            } else {
                ctx.signatureStatus = .invalid(email: response.signerEmail)
                signers = []
                banner = MEDecodedMessageBanner(
                    title: "Недействительная подпись",
                    primaryActionTitle: "",
                    dismissable: false
                )
            }

            let securityInfo = MEMessageSecurityInformation(
                signers: signers,
                isEncrypted: false,
                signingError: isValid ? nil : GPGMailError.verificationFailed,
                encryptionError: nil
            )

            return MEDecodedMessage(data: data, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        // IPC недоступен — показываем без верификации
        NSLog("[FreeGPGMail] inline verify IPC unavailable")
        ctx.signatureStatus = .valid(email: "Не проверено (FreeGPGMail.app не запущен)", trust: "unknown")
        signers = []
        banner = MEDecodedMessageBanner(
            title: "Подписанное сообщение (подпись не проверена)",
            primaryActionTitle: "",
            dismissable: true
        )

        let securityInfo = MEMessageSecurityInformation(
            signers: [], isEncrypted: false, signingError: nil, encryptionError: nil
        )

        return MEDecodedMessage(data: data, securityInformation: securityInfo,
                               context: ctx.encode(), banner: banner)
    }

    // MARK: - Helpers

    private func extractContentType(from rawMessage: String) -> String {
        let headerEnd = rawMessage.range(of: "\r\n\r\n") ?? rawMessage.range(of: "\n\n")
        let headerSection = headerEnd.map { String(rawMessage[rawMessage.startIndex..<$0.lowerBound]) } ?? rawMessage

        var contentType = ""
        var capturing = false

        for line in headerSection.components(separatedBy: "\n") {
            if line.lowercased().hasPrefix("content-type:") {
                contentType = String(line.dropFirst("content-type:".count)).trimmingCharacters(in: .whitespaces)
                capturing = true
            } else if capturing {
                let trimmed = line.trimmingCharacters(in: .init(charactersIn: "\r"))
                if trimmed.hasPrefix(" ") || trimmed.hasPrefix("\t") {
                    contentType += " " + trimmed.trimmingCharacters(in: .whitespaces)
                } else {
                    capturing = false
                }
            }
        }

        return contentType
    }
}

// MARK: - Errors

enum GPGMailError: Error, LocalizedError {
    case signingFailed
    case encryptionFailed
    case decryptionFailed
    case verificationFailed
    case gpgNotFound

    var errorDescription: String? {
        switch self {
        case .signingFailed: return "Не удалось подписать сообщение"
        case .encryptionFailed: return "Не удалось зашифровать сообщение"
        case .decryptionFailed: return "Не удалось расшифровать сообщение"
        case .verificationFailed: return "Подпись недействительна"
        case .gpgNotFound: return "GPG не найден. Установите: brew install gnupg"
        }
    }
}
