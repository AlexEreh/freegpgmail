import Foundation

/// Поддержка Autocrypt (RFC draft) — автоматический обмен ключами через заголовки email
enum AutocryptHelper {

    /// Данные из Autocrypt заголовка
    struct AutocryptHeader {
        let addr: String
        let preferEncrypt: Bool
        let keydata: Data
    }

    /// Парсит Autocrypt заголовок из сырого email
    /// Формат: Autocrypt: addr=user@example.com; [prefer-encrypt=mutual;] keydata=<base64>
    static func parseHeader(from rawHeaders: String) -> AutocryptHeader? {
        // Ищем строку Autocrypt:
        var autocryptValue = ""
        var foundAutocrypt = false

        for line in rawHeaders.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("autocrypt:") {
                foundAutocrypt = true
                autocryptValue = String(line.dropFirst("autocrypt:".count)).trimmingCharacters(in: .whitespaces)
            } else if foundAutocrypt && (line.hasPrefix(" ") || line.hasPrefix("\t")) {
                // Continuation line
                autocryptValue += line.trimmingCharacters(in: .whitespaces)
            } else if foundAutocrypt {
                break
            }
        }

        guard !autocryptValue.isEmpty else { return nil }

        // Парсим параметры
        var addr: String?
        var preferEncrypt = false
        var keydataBase64 = ""

        let parts = autocryptValue.components(separatedBy: ";")
        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("addr=") {
                addr = String(trimmed.dropFirst("addr=".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.lowercased() == "prefer-encrypt=mutual" {
                preferEncrypt = true
            } else if trimmed.lowercased().hasPrefix("keydata=") {
                keydataBase64 = String(trimmed.dropFirst("keydata=".count)).trimmingCharacters(in: .whitespaces)
            } else if !trimmed.contains("=") && !keydataBase64.isEmpty {
                // Continuation of base64 data
                keydataBase64 += trimmed
            }
        }

        // Если keydata не нашли по ключу, ищем последний длинный base64 блок
        if keydataBase64.isEmpty {
            // Берём всё после последнего параметра с = как keydata
            if let lastSemicolon = autocryptValue.lastIndex(of: ";") {
                let remainder = String(autocryptValue[autocryptValue.index(after: lastSemicolon)...])
                    .trimmingCharacters(in: .whitespaces)
                if remainder.count > 100 { // Похоже на base64 ключа
                    keydataBase64 = remainder
                }
            }
        }

        guard let address = addr,
              let keydata = Data(base64Encoded: keydataBase64.replacingOccurrences(of: " ", with: "")
                  .replacingOccurrences(of: "\n", with: "")
                  .replacingOccurrences(of: "\r", with: "")) else {
            return nil
        }

        return AutocryptHeader(addr: address, preferEncrypt: preferEncrypt, keydata: keydata)
    }

    /// Генерирует Autocrypt заголовок для исходящего письма
    static func generateHeader(senderEmail: String, publicKeyData: Data, preferEncrypt: Bool = false) -> String {
        let base64Key = publicKeyData.base64EncodedString(options: [.lineLength76Characters])
        var header = "addr=\(senderEmail)"
        if preferEncrypt {
            header += "; prefer-encrypt=mutual"
        }
        header += "; keydata=\(base64Key)"
        return header
    }

    /// Обрабатывает входящий Autocrypt заголовок — импортирует ключ если новый
    static func processIncoming(rawHeaders: String) -> Bool {
        guard let autocrypt = parseHeader(from: rawHeaders) else { return false }

        // Проверяем, есть ли уже ключ для этого адреса
        let existingKey = KeyCache.shared.findPublicKey(for: autocrypt.addr)
        if existingKey != nil {
            Log.keys.debug("Autocrypt: key already exists for \(autocrypt.addr, privacy: .public)")
            return false
        }

        // Импортируем новый ключ
        Log.keys.info("Autocrypt: importing key for \(autocrypt.addr, privacy: .public)")
        let success = GPGHelper.importKey(data: autocrypt.keydata)
        if success {
            KeyCache.shared.invalidatePublicKeys()
        }
        return success
    }
}
