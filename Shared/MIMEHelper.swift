import Foundation

/// Работа с PGP/MIME форматом (RFC 3156)
enum MIMEHelper {

    /// Генерирует уникальный boundary
    static func generateBoundary() -> String {
        "----FreeGPGMail-\(UUID().uuidString)"
    }

    // MARK: - PGP/MIME Signed Message (RFC 3156 §5)

    /// Оборачивает тело письма в PGP/MIME signed multipart
    static func buildSignedMessage(body: Data, signature: Data, boundary: String) -> Data {
        var result = Data()

        let header = "Content-Type: multipart/signed; micalg=pgp-sha256;\r\n protocol=\"application/pgp-signature\";\r\n boundary=\"\(boundary)\"\r\n\r\n"
        result.append(header.data(using: .utf8)!)

        // Part 1: Original message body
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append(body)
        result.append("\r\n".data(using: .utf8)!)

        // Part 2: PGP signature
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n".data(using: .utf8)!)
        result.append("Content-Description: OpenPGP digital signature\r\n".data(using: .utf8)!)
        result.append("Content-Disposition: attachment; filename=\"signature.asc\"\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)
        result.append(signature)
        result.append("\r\n".data(using: .utf8)!)

        // Closing boundary
        result.append("--\(boundary)--\r\n".data(using: .utf8)!)

        return result
    }

    // MARK: - PGP/MIME Encrypted Message (RFC 3156 §4)

    /// Оборачивает зашифрованные данные в PGP/MIME encrypted multipart
    static func buildEncryptedMessage(encryptedData: Data, boundary: String) -> Data {
        var result = Data()

        let header = "Content-Type: multipart/encrypted;\r\n protocol=\"application/pgp-encrypted\";\r\n boundary=\"\(boundary)\"\r\n\r\n"
        result.append(header.data(using: .utf8)!)

        // Part 1: PGP/MIME version identification
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append("Content-Type: application/pgp-encrypted\r\n".data(using: .utf8)!)
        result.append("Content-Description: PGP/MIME version identification\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)
        result.append("Version: 1\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        // Part 2: Encrypted content
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n".data(using: .utf8)!)
        result.append("Content-Description: OpenPGP encrypted message\r\n".data(using: .utf8)!)
        result.append("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)
        result.append(encryptedData)
        result.append("\r\n".data(using: .utf8)!)

        // Closing boundary
        result.append("--\(boundary)--\r\n".data(using: .utf8)!)

        return result
    }

    // MARK: - Inline PGP

    /// Оборачивает текст в inline PGP signed формат (clearsign)
    static func buildInlinePGPSigned(text: String, signer: String) -> Data? {
        guard let textData = text.data(using: .utf8) else { return nil }
        return GPGHelper.clearSign(data: textData, signer: signer)
    }

    /// Оборачивает текст в inline PGP encrypted формат
    static func buildInlinePGPEncrypted(text: String, recipients: [String], signer: String?) -> Data? {
        guard let textData = text.data(using: .utf8) else { return nil }
        return GPGHelper.encrypt(data: textData, recipients: recipients, sign: signer)
    }

    // MARK: - Attachment Handling

    /// Информация о MIME-вложении
    struct MIMEAttachment {
        let filename: String
        let contentType: String
        let data: Data
        let isInline: Bool
    }

    /// Извлекает вложения из multipart MIME-сообщения
    static func extractAttachments(from data: Data, boundary: String) -> [MIMEAttachment] {
        guard let str = String(data: data, encoding: .utf8) else { return [] }

        let parts = str.components(separatedBy: "--\(boundary)")
        var attachments: [MIMEAttachment] = []

        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed == "--" { continue }

            // Разделяем заголовки и тело
            let separator = trimmed.contains("\r\n\r\n") ? "\r\n\r\n" : "\n\n"
            guard let sepRange = trimmed.range(of: separator) else { continue }

            let headers = String(trimmed[trimmed.startIndex..<sepRange.lowerBound])
            let body = String(trimmed[sepRange.upperBound...])

            // Проверяем Content-Disposition
            let headersLower = headers.lowercased()
            guard headersLower.contains("content-disposition: attachment") ||
                  headersLower.contains("content-disposition: inline") else {
                continue
            }

            let contentType = extractHeaderValue(from: headers, header: "content-type") ?? "application/octet-stream"
            let filename = extractFilename(from: headers) ?? "attachment"
            let isInline = headersLower.contains("content-disposition: inline")

            // Декодируем тело (base64 или plain)
            let attachData: Data
            if headersLower.contains("content-transfer-encoding: base64") {
                let cleaned = body.replacingOccurrences(of: "\r\n", with: "")
                    .replacingOccurrences(of: "\n", with: "")
                    .trimmingCharacters(in: .whitespaces)
                attachData = Data(base64Encoded: cleaned) ?? body.data(using: .utf8) ?? Data()
            } else {
                attachData = body.data(using: .utf8) ?? Data()
            }

            attachments.append(MIMEAttachment(
                filename: filename,
                contentType: contentType,
                data: attachData,
                isInline: isInline
            ))
        }

        return attachments
    }

    /// Собирает multipart/mixed сообщение с вложениями
    static func buildMultipartMixed(textBody: Data, attachments: [MIMEAttachment], boundary: String) -> Data {
        var result = Data()

        let header = "Content-Type: multipart/mixed;\r\n boundary=\"\(boundary)\"\r\n\r\n"
        result.append(header.data(using: .utf8)!)

        // Text body part
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append("Content-Type: text/plain; charset=utf-8\r\n".data(using: .utf8)!)
        result.append("Content-Transfer-Encoding: quoted-printable\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)
        result.append(textBody)
        result.append("\r\n".data(using: .utf8)!)

        // Attachment parts
        for attachment in attachments {
            result.append("--\(boundary)\r\n".data(using: .utf8)!)
            result.append("Content-Type: \(attachment.contentType); name=\"\(attachment.filename)\"\r\n".data(using: .utf8)!)
            result.append("Content-Transfer-Encoding: base64\r\n".data(using: .utf8)!)
            let disposition = attachment.isInline ? "inline" : "attachment"
            result.append("Content-Disposition: \(disposition); filename=\"\(attachment.filename)\"\r\n".data(using: .utf8)!)
            result.append("\r\n".data(using: .utf8)!)

            // Base64 encode
            let base64 = attachment.data.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
            result.append(base64.data(using: .utf8)!)
            result.append("\r\n".data(using: .utf8)!)
        }

        result.append("--\(boundary)--\r\n".data(using: .utf8)!)
        return result
    }

    // MARK: - Parsing

    /// Извлекает части PGP/MIME signed сообщения
    static func parseSignedMessage(data: Data, boundary: String) -> (body: Data, signature: Data)? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }

        let parts = str.components(separatedBy: "--\(boundary)")
        guard parts.count >= 3 else { return nil }

        let bodyPart = parts[1]
        let sigPart = parts[2]

        // Для верификации подписи тело должно быть точным (включая CRLF после boundary delimiter)
        let bodyContent: String
        if bodyPart.hasPrefix("\r\n") {
            bodyContent = String(bodyPart.dropFirst(2))
        } else if bodyPart.hasPrefix("\n") {
            bodyContent = String(bodyPart.dropFirst(1))
        } else {
            bodyContent = bodyPart
        }

        // Убираем trailing CRLF перед boundary
        let bodyTrimmed: String
        if bodyContent.hasSuffix("\r\n") {
            bodyTrimmed = String(bodyContent.dropLast(2))
        } else if bodyContent.hasSuffix("\n") {
            bodyTrimmed = String(bodyContent.dropLast(1))
        } else {
            bodyTrimmed = bodyContent
        }

        guard let sigRange = sigPart.range(of: "-----BEGIN PGP SIGNATURE-----"),
              let sigEnd = sigPart.range(of: "-----END PGP SIGNATURE-----") else {
            return nil
        }
        let sigContent = String(sigPart[sigRange.lowerBound...sigEnd.upperBound])

        guard let bodyData = bodyTrimmed.data(using: .utf8),
              let sigData = sigContent.data(using: .utf8) else {
            return nil
        }

        return (bodyData, sigData)
    }

    /// Парсит PGP/MIME signed сообщение с множественными подписями
    static func parseSignedMessageMultiple(data: Data, boundary: String) -> (body: Data, signatures: [Data])? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }

        let parts = str.components(separatedBy: "--\(boundary)")
        guard parts.count >= 3 else { return nil }

        // Первая часть — тело
        let bodyPart = parts[1]
        let bodyContent: String
        if bodyPart.hasPrefix("\r\n") {
            bodyContent = String(bodyPart.dropFirst(2))
        } else if bodyPart.hasPrefix("\n") {
            bodyContent = String(bodyPart.dropFirst(1))
        } else {
            bodyContent = bodyPart
        }
        let bodyTrimmed: String
        if bodyContent.hasSuffix("\r\n") {
            bodyTrimmed = String(bodyContent.dropLast(2))
        } else if bodyContent.hasSuffix("\n") {
            bodyTrimmed = String(bodyContent.dropLast(1))
        } else {
            bodyTrimmed = bodyContent
        }

        guard let bodyData = bodyTrimmed.data(using: .utf8) else { return nil }

        // Остальные части — подписи
        var signatures: [Data] = []
        for i in 2..<parts.count {
            let sigPart = parts[i]
            if sigPart.trimmingCharacters(in: .whitespacesAndNewlines) == "--" { continue }

            if let sigRange = sigPart.range(of: "-----BEGIN PGP SIGNATURE-----"),
               let sigEnd = sigPart.range(of: "-----END PGP SIGNATURE-----") {
                let sigContent = String(sigPart[sigRange.lowerBound...sigEnd.upperBound])
                if let sigData = sigContent.data(using: .utf8) {
                    signatures.append(sigData)
                }
            }
        }

        return signatures.isEmpty ? nil : (bodyData, signatures)
    }

    /// Извлекает зашифрованные данные из PGP/MIME сообщения
    static func parseEncryptedMessage(data: Data, boundary: String) -> Data? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }

        let parts = str.components(separatedBy: "--\(boundary)")
        guard parts.count >= 3 else { return nil }

        let encPart = parts[2]

        guard let pgpStart = encPart.range(of: "-----BEGIN PGP MESSAGE-----"),
              let pgpEnd = encPart.range(of: "-----END PGP MESSAGE-----") else {
            return nil
        }

        let pgpContent = String(encPart[pgpStart.lowerBound...pgpEnd.upperBound])
        return pgpContent.data(using: .utf8)
    }

    /// Извлекает boundary из Content-Type заголовка
    static func extractBoundary(from contentType: String) -> String? {
        let parts = contentType.components(separatedBy: ";")
        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("boundary=") {
                var boundary = String(trimmed.dropFirst("boundary=".count))
                boundary = boundary.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                return boundary
            }
        }
        return nil
    }

    /// Определяет тип PGP/MIME сообщения
    enum PGPMIMEType {
        case signed
        case encrypted
        case none
    }

    static func detectPGPMIMEType(contentType: String) -> PGPMIMEType {
        let lower = contentType.lowercased()
        if lower.contains("multipart/signed") && lower.contains("application/pgp-signature") {
            return .signed
        }
        if lower.contains("multipart/encrypted") && lower.contains("application/pgp-encrypted") {
            return .encrypted
        }
        return .none
    }

    // MARK: - Header Parsing Helpers

    private static func extractHeaderValue(from headers: String, header: String) -> String? {
        let headerLower = header.lowercased() + ":"
        for line in headers.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .init(charactersIn: "\r"))
            if trimmed.lowercased().hasPrefix(headerLower) {
                let value = String(trimmed.dropFirst(headerLower.count)).trimmingCharacters(in: .whitespaces)
                // Берём только основное значение (до ;)
                return value.components(separatedBy: ";").first?.trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    private static func extractFilename(from headers: String) -> String? {
        let patterns = ["filename=\"", "name=\""]
        for pattern in patterns {
            if let range = headers.range(of: pattern) {
                let rest = headers[range.upperBound...]
                if let endQuote = rest.firstIndex(of: "\"") {
                    return String(rest[rest.startIndex..<endQuote])
                }
            }
        }
        return nil
    }
}
