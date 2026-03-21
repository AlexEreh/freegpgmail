import MailKit

/// Обработчик сеансов композиции — управляет окном написания письма
class ComposeSessionHandler: NSObject, MEComposeSessionHandler {

    private var composeViewControllers: [UUID: ComposeViewController] = [:]

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        Log.general.info("Compose session began: \(session.sessionID)")
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        Log.general.info("Compose session ended: \(session.sessionID)")
        composeViewControllers.removeValue(forKey: session.sessionID)
    }

    /// Возвращает view controller для окна композиции
    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        let vc = ComposeViewController()

        let sender = session.mailMessage.fromAddress.addressString ?? session.mailMessage.fromAddress.rawString
        NSLog("[FreeGPGMail] viewController(for:) sender=%@", sender)

        // KeyCache в sandbox будет читать из файла, не вызывая gpg
        let signingKey = KeyCache.shared.findSigningKey(for: sender)
        NSLog("[FreeGPGMail] signingKey=%@, secretKeys=%d, publicKeys=%d",
              signingKey?.fingerprint ?? "nil",
              KeyCache.shared.secretKeysCount,
              KeyCache.shared.publicKeysCount)

        let allRecipients = session.mailMessage.toAddresses + session.mailMessage.ccAddresses + session.mailMessage.bccAddresses
        let canEncrypt = signingKey != nil && !allRecipients.isEmpty && allRecipients.allSatisfy {
            let email = $0.addressString ?? $0.rawString
            return KeyCache.shared.findPublicKey(for: email) != nil
        }

        vc.updateStatus(canSign: signingKey != nil, canEncrypt: canEncrypt, senderEmail: sender)

        composeViewControllers[session.sessionID] = vc
        return vc
    }

    /// Аннотирует адреса получателей (показывает наличие/отсутствие ключей)
    func annotateAddressesForSession(_ session: MEComposeSession, completion: @escaping ([MEEmailAddress: MEAddressAnnotation]) -> Void) {
        var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]

        let allRecipients = session.mailMessage.toAddresses + session.mailMessage.ccAddresses + session.mailMessage.bccAddresses

        for address in allRecipients {
            let email = address.addressString ?? address.rawString
            if KeyCache.shared.findPublicKey(for: email) != nil {
                annotations[address] = MEAddressAnnotation.success(withLocalizedDescription: "GPG-ключ найден")
            } else {
                annotations[address] = MEAddressAnnotation.warning(withLocalizedDescription: "GPG-ключ не найден — шифрование недоступно")
            }
        }

        // Обновляем compose VC
        if let vc = composeViewControllers[session.sessionID] {
            let sender = session.mailMessage.fromAddress.addressString ?? session.mailMessage.fromAddress.rawString
            let signingKey = KeyCache.shared.findSigningKey(for: sender)
            let canEncrypt = signingKey != nil && !allRecipients.isEmpty && allRecipients.allSatisfy {
                let email = $0.addressString ?? $0.rawString
                return KeyCache.shared.findPublicKey(for: email) != nil
            }
            vc.updateStatus(canSign: signingKey != nil, canEncrypt: canEncrypt, senderEmail: sender)
        }

        completion(annotations)
    }

    /// Возвращает дополнительные заголовки для сообщения
    func additionalHeaders(for session: MEComposeSession) -> [String: [String]] {
        // В sandbox нельзя вызывать gpg — Autocrypt заголовки добавятся на этапе encode()
        return [
            "x-pgp-agent": ["FreeGPGMail/1.0"],
        ]
    }

    /// Проверяет, допустимо ли отправить сообщение
    func allowMessageSendForSession(_ session: MEComposeSession, completion: @escaping (Error?) -> Void) {
        // В sandbox не вызываем gpg — проверяем только наличие кэшированных ключей
        if session.composeContext.shouldSign {
            let sender = session.mailMessage.fromAddress.addressString ?? session.mailMessage.fromAddress.rawString
            let signingKey = KeyCache.shared.findSigningKey(for: sender)
            if signingKey == nil {
                let error = NSError(
                    domain: MEComposeSessionErrorDomain,
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Не найден секретный ключ для подписи.\nОтправитель: \(sender)\nОткройте FreeGPGMail.app для обновления ключей."]
                )
                completion(error)
                return
            }
        }

        if session.composeContext.shouldEncrypt {
            let allRecipients = session.mailMessage.toAddresses + session.mailMessage.ccAddresses + session.mailMessage.bccAddresses
            let missingKeys = allRecipients.filter { addr in
                let email = addr.addressString ?? addr.rawString
                return KeyCache.shared.findPublicKey(for: email) == nil
            }
            if !missingKeys.isEmpty {
                let emails = missingKeys.map { $0.addressString ?? $0.rawString }.joined(separator: ", ")
                let error = NSError(
                    domain: MEComposeSessionErrorDomain,
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Нет GPG-ключей для шифрования.\nПолучатели без ключей: \(emails)"]
                )
                completion(error)
                return
            }
        }

        completion(nil)
    }
}
