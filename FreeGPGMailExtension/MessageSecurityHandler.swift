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

        if !shouldSign && !shouldEncrypt {
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        guard let rawData = message.rawData else {
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: shouldSign ? GPGMailError.signingFailed : nil,
                encryptionError: shouldEncrypt ? GPGMailError.encryptionFailed : nil
            ))
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
            let errorMsg = "FreeGPGMail.app не отвечает. Убедитесь что приложение запущено."
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: shouldSign ? NSError(domain: MEComposeSessionErrorDomain, code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg]) : nil,
                encryptionError: shouldEncrypt ? NSError(domain: MEComposeSessionErrorDomain, code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg]) : nil
            ))
            return
        }

        if response.success, let mimeData = response.data {
            let encoded = MEEncodedOutgoingMessage(rawData: mimeData, isSigned: response.isSigned, isEncrypted: response.isEncrypted)
            completionHandler(MEMessageEncodingResult(encodedMessage: encoded, signingError: nil, encryptionError: nil))
        } else {
            let errorMsg = response.error ?? "Неизвестная ошибка"
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil,
                signingError: shouldSign ? NSError(domain: MEComposeSessionErrorDomain, code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg]) : nil,
                encryptionError: shouldEncrypt ? NSError(domain: MEComposeSessionErrorDomain, code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg]) : nil
            ))
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
        Log.general.debug("primaryActionClicked called")
        let vc = SecurityInfoViewController()
        vc.configure(with: context)
        completionHandler(vc)
    }

    // MARK: - Private: Encrypted Message Handling

    private func handleEncryptedMessage(data: Data, contentType: String) -> MEDecodedMessage? {
        Log.security.info("Handling PGP/MIME encrypted message")

        guard let boundary = MIMEHelper.extractBoundary(from: contentType),
              let encryptedData = MIMEHelper.parseEncryptedMessage(data: data, boundary: boundary) else {
            Log.security.error("Failed to parse encrypted MIME structure")
            return nil
        }

        let result = GPGHelper.decrypt(data: encryptedData)

        var ctx = SecurityContext()
        ctx.isEncrypted = true

        guard result.success, let decryptedData = result.data else {
            Log.security.error("Decryption failed: \(result.statusMessage)")
            ctx.decryptionError = result.statusMessage

            let banner = MEDecodedMessageBanner(
                title: "Не удалось расшифровать сообщение",
                primaryActionTitle: "Подробнее",
                dismissable: true
            )

            let securityInfo = MEMessageSecurityInformation(
                signers: [],
                isEncrypted: true,
                signingError: nil,
                encryptionError: GPGMailError.decryptionFailed
            )
            return MEDecodedMessage(data: nil, securityInformation: securityInfo,
                                   context: ctx.encode(), banner: banner)
        }

        // Собираем информацию о подписи если была
        var signers: [MEMessageSigner] = []
        if result.signatureValid, let signerEmail = result.wasSignedBy {
            ctx.signatureStatus = .valid(email: signerEmail, trust: "unknown")
            let signer = MEMessageSigner(
                emailAddresses: [MEEmailAddress(rawString: signerEmail)],
                signatureLabel: signerEmail,
                context: ctx.encode()
            )
            signers = [signer]
        }

        let banner = MEDecodedMessageBanner(
            title: result.signatureValid
                ? "Зашифровано и подписано (\(result.wasSignedBy ?? ""))"
                : "Зашифрованное сообщение расшифровано",
            primaryActionTitle: "Подробнее",
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

        // Пробуем извлечь множественные подписи
        if let parsed = MIMEHelper.parseSignedMessageMultiple(data: data, boundary: boundary) {
            let verifyResults = GPGHelper.verifyMultiple(signatures: parsed.signatures, signedData: parsed.body)
            return buildSignedDecodedMessage(body: parsed.body, verifyResults: verifyResults)
        }

        // Fallback на одну подпись
        guard let parsed = MIMEHelper.parseSignedMessage(data: data, boundary: boundary) else {
            Log.security.error("Failed to parse signed MIME structure")
            return nil
        }

        let verifyResult = GPGHelper.verify(signature: parsed.signature, signedData: parsed.body)
        return buildSignedDecodedMessage(body: parsed.body, verifyResults: [verifyResult])
    }

    /// Строит MEDecodedMessage из результатов верификации (поддерживает множественные подписи)
    private func buildSignedDecodedMessage(body: Data, verifyResults: [GPGHelper.VerifyResult]) -> MEDecodedMessage {
        var ctx = SecurityContext()
        var signers: [MEMessageSigner] = []
        var allValid = true
        var signerNames: [String] = []

        for result in verifyResults {
            if result.isValid {
                let email = result.signerEmail ?? "Неизвестный"
                signerNames.append(email)

                let signer = MEMessageSigner(
                    emailAddresses: result.signerEmail.map {
                        [MEEmailAddress(rawString: $0)]
                    } ?? [],
                    signatureLabel: email,
                    context: ctx.encode()
                )
                signers.append(signer)
                Log.security.info("Valid signature from \(email, privacy: .public)")
            } else {
                allValid = false
                Log.security.warning("Invalid signature")
            }
        }

        if let first = verifyResults.first {
            if first.isValid {
                ctx.signatureStatus = .valid(
                    email: first.signerEmail ?? "Неизвестный",
                    trust: first.trustLevel.rawValue
                )
                ctx.signerKeyID = first.signerKeyID
            } else {
                ctx.signatureStatus = .invalid(email: first.signerEmail)
            }
        }

        let banner: MEDecodedMessageBanner
        if allValid && !signerNames.isEmpty {
            let names = signerNames.joined(separator: ", ")
            banner = MEDecodedMessageBanner(
                title: signerNames.count > 1
                    ? "Подписано (\(signerNames.count)): \(names)"
                    : "Подписано: \(names)",
                primaryActionTitle: "Подробнее",
                dismissable: true
            )
        } else {
            banner = MEDecodedMessageBanner(
                title: "Недействительная подпись",
                primaryActionTitle: "Подробнее",
                dismissable: false
            )
        }

        let securityInfo = MEMessageSecurityInformation(
            signers: signers,
            isEncrypted: false,
            signingError: allValid ? nil : GPGMailError.verificationFailed,
            encryptionError: nil
        )

        return MEDecodedMessage(
            data: body,
            securityInformation: securityInfo,
            context: ctx.encode(),
            banner: banner
        )
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

        let result = GPGHelper.decrypt(data: pgpData)

        var ctx = SecurityContext()
        ctx.isEncrypted = true

        guard result.success, let decryptedData = result.data else {
            ctx.decryptionError = result.statusMessage
            let banner = MEDecodedMessageBanner(
                title: "Не удалось расшифровать сообщение",
                primaryActionTitle: "Подробнее",
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

        if result.signatureValid {
            ctx.signatureStatus = .valid(email: result.wasSignedBy ?? "", trust: "unknown")
        }

        let banner = MEDecodedMessageBanner(
            title: "Зашифрованное сообщение расшифровано",
            primaryActionTitle: "Подробнее",
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

        let result = GPGHelper.verify(signature: data, signedData: data)

        var ctx = SecurityContext()
        let signers: [MEMessageSigner]
        let banner: MEDecodedMessageBanner

        if result.isValid {
            let email = result.signerEmail ?? "Неизвестный"
            ctx.signatureStatus = .valid(email: email, trust: result.trustLevel.rawValue)
            let signer = MEMessageSigner(
                emailAddresses: result.signerEmail.map {
                    [MEEmailAddress(rawString: $0)]
                } ?? [],
                signatureLabel: email,
                context: ctx.encode()
            )
            signers = [signer]
            banner = MEDecodedMessageBanner(
                title: "Подписано: \(email)",
                primaryActionTitle: "Подробнее",
                dismissable: true
            )
        } else {
            ctx.signatureStatus = .invalid(email: result.signerEmail)
            signers = []
            banner = MEDecodedMessageBanner(
                title: "Недействительная подпись",
                primaryActionTitle: "Подробнее",
                dismissable: false
            )
        }

        let securityInfo = MEMessageSecurityInformation(
            signers: signers,
            isEncrypted: false,
            signingError: result.isValid ? nil : GPGMailError.verificationFailed,
            encryptionError: nil
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
