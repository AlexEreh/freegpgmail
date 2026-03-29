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

    // MARK: - Protected Headers (Subject Encryption)

    /// Оборачивает тело письма с protected headers (шифрует тему)
    /// Добавляет внутренний MIME-слой с оригинальной темой, заменяя внешнюю на "..."
    static func wrapWithProtectedHeaders(body: Data, subject: String) -> Data {
        let innerBoundary = generateBoundary()
        var result = Data()

        // Inner MIME message with protected headers
        result.append("Content-Type: multipart/mixed;\r\n protected-headers=\"v1\";\r\n boundary=\"\(innerBoundary)\"\r\n".data(using: .utf8)!)
        result.append("Subject: \(subject)\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        result.append("--\(innerBoundary)\r\n".data(using: .utf8)!)
        result.append(body)
        result.append("\r\n--\(innerBoundary)--\r\n".data(using: .utf8)!)

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
        // ВАЖНО: работаем на уровне байтов, а не Swift String,
        // потому что Swift считает \r\n одним Character и dropFirst(2) удаляет 2 символа, а не 2 байта.
        let delimiter = "--\(boundary)".data(using: .utf8)!

        // Находим первое вхождение delimiter (начало тела)
        guard let firstRange = data.range(of: delimiter) else { return nil }
        let afterFirst = firstRange.upperBound

        // Пропускаем \r\n после delimiter
        var bodyStart = afterFirst
        if bodyStart < data.count && data[bodyStart] == 0x0D { bodyStart += 1 } // \r
        if bodyStart < data.count && data[bodyStart] == 0x0A { bodyStart += 1 } // \n

        // Находим второе вхождение delimiter (начало подписи)
        guard let secondRange = data[bodyStart...].range(of: delimiter) else { return nil }

        // Тело — от bodyStart до secondRange, без trailing \r\n
        var bodyEnd = secondRange.lowerBound
        if bodyEnd > bodyStart && data[bodyEnd - 1] == 0x0A { bodyEnd -= 1 } // \n
        if bodyEnd > bodyStart && data[bodyEnd - 1] == 0x0D { bodyEnd -= 1 } // \r

        let bodyData = data[bodyStart..<bodyEnd]

        // Подпись — после второго delimiter
        let sigSection = data[secondRange.upperBound...]
        guard let sigStr = String(data: sigSection, encoding: .utf8) else { return nil }
        guard let sigBegin = sigStr.range(of: "-----BEGIN PGP SIGNATURE-----"),
              let sigEnd = sigStr.range(of: "-----END PGP SIGNATURE-----") else {
            return nil
        }
        let sigContent = String(sigStr[sigBegin.lowerBound...sigEnd.upperBound])
        guard let sigData = sigContent.data(using: .utf8) else { return nil }

        return (Data(bodyData), sigData)
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

    // MARK: - Raw Email Splitting

    /// Разделяет raw email на заголовки и тело
    /// Возвращает (headers без Content-Type, originalContentType, body)
    static func splitRawEmail(_ data: Data) -> (headers: String, contentType: String, body: Data)? {
        guard let raw = String(data: data, encoding: .utf8) else { return nil }

        // Находим разделитель заголовков и тела
        let separator: String
        let sepRange: Range<String.Index>
        if let r = raw.range(of: "\r\n\r\n") {
            separator = "\r\n"
            sepRange = r
        } else if let r = raw.range(of: "\n\n") {
            separator = "\n"
            sepRange = r
        } else {
            return nil
        }

        let headerSection = String(raw[raw.startIndex..<sepRange.lowerBound])
        let bodySection = raw[sepRange.upperBound...]

        // Извлекаем Content-Type (с учётом continuation lines)
        var contentType = ""
        var otherHeaders: [String] = []
        var lines = headerSection.components(separatedBy: separator)
        var i = 0
        while i < lines.count {
            let line = lines[i]
            if line.lowercased().hasPrefix("content-type:") {
                contentType = String(line.dropFirst("content-type:".count)).trimmingCharacters(in: .whitespaces)
                // Собираем continuation lines
                while i + 1 < lines.count {
                    let next = lines[i + 1]
                    if next.hasPrefix(" ") || next.hasPrefix("\t") {
                        contentType += " " + next.trimmingCharacters(in: .whitespaces)
                        i += 1
                    } else {
                        break
                    }
                }
            } else if line.lowercased().hasPrefix("content-transfer-encoding:") {
                // Пропускаем — будет заменён
            } else if line.lowercased().hasPrefix("mime-version:") {
                // Пропускаем — добавим свой
            } else {
                otherHeaders.append(line)
            }
            i += 1
        }

        if contentType.isEmpty {
            contentType = "text/plain; charset=utf-8"
        }

        let headersStr = otherHeaders.joined(separator: separator)
        let bodyData = bodySection.data(using: .utf8) ?? Data()

        return (headersStr, contentType, bodyData)
    }

    /// Убирает multipart/signed обёртку, возвращает email без подписи.
    /// Просто заменяет Content-Type: multipart/signed на содержимое подписанной части.
    /// signedBody уже содержит свой Content-Type (например multipart/alternative) и тело.
    static func extractDisplayContent(from signedBody: Data, originalEmail: Data) -> Data? {
        guard let rawStr = String(data: originalEmail, encoding: .utf8) else {
            NSLog("[FreeGPGMail] extractDisplayContent: cannot decode original email as UTF-8")
            return nil
        }

        // Находим конец заголовков
        let sep: String
        guard let headerEnd = rawStr.range(of: "\r\n\r\n") ?? rawStr.range(of: "\n\n") else {
            NSLog("[FreeGPGMail] extractDisplayContent: no header/body separator")
            return nil
        }
        sep = rawStr.range(of: "\r\n\r\n") != nil ? "\r\n" : "\n"

        let headerSection = String(rawStr[rawStr.startIndex..<headerEnd.lowerBound])

        // Фильтруем заголовки — убираем Content-Type, CTE, MIME-Version
        var filteredHeaders: [String] = []
        let lines = headerSection.components(separatedBy: sep)
        var idx = 0
        while idx < lines.count {
            let line = lines[idx]
            let lower = line.lowercased()
            if lower.hasPrefix("content-type:") || lower.hasPrefix("content-transfer-encoding:") || lower.hasPrefix("mime-version:") {
                idx += 1
                // Пропускаем continuation lines
                while idx < lines.count && (lines[idx].hasPrefix(" ") || lines[idx].hasPrefix("\t")) {
                    idx += 1
                }
                continue
            }
            filteredHeaders.append(line)
            idx += 1
        }

        // Собираем: отфильтрованные заголовки + MIME-Version + signedBody (содержит Content-Type и тело)
        var result = Data()
        let headersJoined = filteredHeaders.joined(separator: sep)
        result.append(headersJoined.data(using: .utf8)!)
        result.append("\(sep)MIME-Version: 1.0\(sep)".data(using: .utf8)!)
        result.append(signedBody)

        if let preview = String(data: result, encoding: .utf8) {
            NSLog("[FreeGPGMail] extractDisplayContent: result size=%d, first 300: %@",
                  result.count, String(preview.prefix(300)))
        }

        return result
    }

    /// Извлекает лучшую часть из multipart (предпочитает text/html)
    /// Возвращает декодированный контент
    private static func extractBestContentPart(from content: String, boundary: String) -> (contentType: String, decodedContent: Data)? {
        let parts = content.components(separatedBy: "--\(boundary)")

        var htmlPart: (contentType: String, decodedContent: Data)?
        var plainPart: (contentType: String, decodedContent: Data)?

        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed == "--" { continue }

            // Разделяем заголовки и тело
            let sep = trimmed.contains("\r\n\r\n") ? "\r\n\r\n" : "\n\n"
            guard let sepRange = trimmed.range(of: sep) else { continue }

            let headers = String(trimmed[trimmed.startIndex..<sepRange.lowerBound])
            let body = String(trimmed[sepRange.upperBound...])

            let ct = extractHeaderValue(from: headers, header: "content-type") ?? "text/plain"
            let cte = extractHeaderValue(from: headers, header: "content-transfer-encoding")?.lowercased()

            guard let decoded = decodeContent(body, encoding: cte) else { continue }

            if ct.lowercased().contains("text/html") {
                htmlPart = (ct, decoded)
            } else if ct.lowercased().contains("text/plain") {
                plainPart = (ct, decoded)
            }
        }

        return htmlPart ?? plainPart
    }

    /// Декодирует контент из base64 или quoted-printable
    private static func decodeContent(_ content: String, encoding: String?) -> Data? {
        switch encoding {
        case "base64":
            let cleaned = content
                .replacingOccurrences(of: "\r\n", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return Data(base64Encoded: cleaned)
        case "quoted-printable":
            return decodeQuotedPrintable(content)
        default:
            return content.data(using: .utf8)
        }
    }

    /// Декодирует quoted-printable строку
    private static func decodeQuotedPrintable(_ input: String) -> Data? {
        var result = Data()
        var i = input.startIndex

        while i < input.endIndex {
            let ch = input[i]
            if ch == "=" {
                let next1 = input.index(after: i)
                if next1 < input.endIndex {
                    // Soft line break (=\r\n or =\n)
                    if input[next1] == "\r" {
                        let next2 = input.index(after: next1)
                        if next2 < input.endIndex && input[next2] == "\n" {
                            i = input.index(after: next2)
                        } else {
                            i = input.index(after: next1)
                        }
                        continue
                    } else if input[next1] == "\n" {
                        i = input.index(after: next1)
                        continue
                    }

                    // Hex encoded byte
                    let next2 = input.index(after: next1)
                    if next2 < input.endIndex {
                        let hex = String(input[next1...next2])
                        if let byte = UInt8(hex, radix: 16) {
                            result.append(byte)
                            i = input.index(after: next2)
                            continue
                        }
                    }
                }
                // Malformed — keep as is
                result.append(contentsOf: "=".utf8)
                i = input.index(after: i)
            } else {
                result.append(contentsOf: String(ch).utf8)
                i = input.index(after: i)
            }
        }

        return result
    }

    /// Извлекает значение заголовка (с учётом continuation lines)
    private static func extractHeaderValue(from headers: String, header: String) -> String? {
        let lines = headers.components(separatedBy: headers.contains("\r\n") ? "\r\n" : "\n")
        let headerLower = header.lowercased() + ":"

        for (i, line) in lines.enumerated() {
            if line.lowercased().hasPrefix(headerLower) {
                var value = String(line.dropFirst(headerLower.count)).trimmingCharacters(in: .whitespaces)
                // Собираем continuation lines
                var j = i + 1
                while j < lines.count {
                    let next = lines[j]
                    if next.hasPrefix(" ") || next.hasPrefix("\t") {
                        value += " " + next.trimmingCharacters(in: .whitespaces)
                        j += 1
                    } else {
                        break
                    }
                }
                return value
            }
        }
        return nil
    }

    /// Строит полный PGP/MIME signed email из raw email data
    static func buildSignedEmail(rawEmail: Data, signature: Data, boundary: String) -> Data? {
        guard let parts = splitRawEmail(rawEmail) else { return nil }

        var result = Data()

        // Оригинальные заголовки (From, To, Subject, etc.)
        result.append(parts.headers.data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        // Новый Content-Type: multipart/signed
        result.append("Content-Type: multipart/signed; micalg=pgp-sha256;\r\n protocol=\"application/pgp-signature\";\r\n boundary=\"\(boundary)\"\r\n".data(using: .utf8)!)
        result.append("MIME-Version: 1.0\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        // Part 1: тело с оригинальным Content-Type
        let bodyPart = "Content-Type: \(parts.contentType)\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append(bodyPart.data(using: .utf8)!)
        result.append(parts.body)
        result.append("\r\n".data(using: .utf8)!)

        // Part 2: подпись
        result.append("--\(boundary)\r\n".data(using: .utf8)!)
        result.append("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n".data(using: .utf8)!)
        result.append("Content-Description: OpenPGP digital signature\r\n".data(using: .utf8)!)
        result.append("Content-Disposition: attachment; filename=\"signature.asc\"\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)
        result.append(signature)
        result.append("\r\n".data(using: .utf8)!)

        // Закрытие
        result.append("--\(boundary)--\r\n".data(using: .utf8)!)

        return result
    }

    /// Строит полный PGP/MIME encrypted email из raw email data
    static func buildEncryptedEmail(rawEmail: Data, encryptedData: Data, boundary: String) -> Data? {
        guard let parts = splitRawEmail(rawEmail) else { return nil }

        var result = Data()

        // Оригинальные заголовки
        result.append(parts.headers.data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        // Новый Content-Type: multipart/encrypted
        result.append("Content-Type: multipart/encrypted;\r\n protocol=\"application/pgp-encrypted\";\r\n boundary=\"\(boundary)\"\r\n".data(using: .utf8)!)
        result.append("MIME-Version: 1.0\r\n".data(using: .utf8)!)
        result.append("\r\n".data(using: .utf8)!)

        // Part 1: PGP/MIME version
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

        result.append("--\(boundary)--\r\n".data(using: .utf8)!)

        return result
    }

    // MARK: - Header Parsing Helpers

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
