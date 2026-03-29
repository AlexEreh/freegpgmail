import AppKit
import MailKit

/// Контроллер для отображения информации о подписи/шифровании в Mail
class SecurityInfoViewController: MEExtensionViewController {

    private var context: SecurityContext?

    override func viewDidLoad() {
        super.viewDidLoad()
        self.preferredContentSize = NSSize(width: 380, height: 300)
    }

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 300))
        self.view = container

        guard let ctx = context else {
            addLabel(to: container, text: "Нет данных о безопасности", icon: "questionmark.circle", color: .secondaryLabelColor)
            return
        }

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 12),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: container.bottomAnchor, constant: -12),
        ])

        // === Заголовок ===
        let title = NSTextField(labelWithString: "Информация о безопасности PGP")
        title.font = .boldSystemFont(ofSize: 14)
        title.textColor = .labelColor
        stack.addArrangedSubview(title)
        stack.addArrangedSubview(makeSeparator())

        // === Шифрование ===
        if ctx.isEncrypted {
            stack.addArrangedSubview(makeRow(
                icon: "lock.fill", text: "Зашифровано", color: .systemGreen
            ))
        }

        // === Статус подписи ===
        switch ctx.signatureStatus {
        case .valid(let email, _):
            let trustLevel = ctx.trustLevel.flatMap { GPGHelper.VerifyResult.TrustLevel(rawValue: $0) } ?? .unknown
            let trustText = trustDescription(trustLevel)
            let trustColor = trustColor(trustLevel)

            stack.addArrangedSubview(makeRow(
                icon: "checkmark.shield.fill",
                text: "Подпись верна",
                color: .systemGreen
            ))
            stack.addArrangedSubview(makeRow(
                icon: "person.fill",
                text: "Подписант: \(email)",
                color: .labelColor
            ))
            if !trustText.isEmpty {
                stack.addArrangedSubview(makeRow(
                    icon: "person.badge.shield.checkmark.fill",
                    text: "Уровень доверия: \(trustText)",
                    color: trustColor
                ))
            }

        case .invalid(let email):
            stack.addArrangedSubview(makeRow(
                icon: "xmark.shield.fill",
                text: "Подпись недействительна",
                color: .systemRed
            ))
            if let email = email, !email.isEmpty {
                stack.addArrangedSubview(makeRow(
                    icon: "person.fill",
                    text: "Подписант: \(email)",
                    color: .labelColor
                ))
            }
            let trustLevel = ctx.trustLevel.flatMap { GPGHelper.VerifyResult.TrustLevel(rawValue: $0) } ?? .unknown
            let trustText = trustDescription(trustLevel)
            if !trustText.isEmpty {
                stack.addArrangedSubview(makeRow(
                    icon: "person.badge.shield.checkmark.fill",
                    text: "Уровень доверия: \(trustText)",
                    color: trustColor(trustLevel)
                ))
            }
            // Причина ошибки для невалидной подписи
            if let detail = ctx.verificationDetail, !detail.isEmpty {
                stack.addArrangedSubview(makeSeparator())
                let reasonTitle = NSTextField(labelWithString: "Причина")
                reasonTitle.font = .boldSystemFont(ofSize: 12)
                reasonTitle.textColor = .systemRed
                stack.addArrangedSubview(reasonTitle)
                let reasonLabel = NSTextField(wrappingLabelWithString: detail)
                reasonLabel.font = .systemFont(ofSize: 11)
                reasonLabel.textColor = .secondaryLabelColor
                reasonLabel.preferredMaxLayoutWidth = 340
                stack.addArrangedSubview(reasonLabel)
            }

        case .none:
            break
        }

        // === UserID ===
        if let userID = ctx.signerUserID, !userID.isEmpty {
            stack.addArrangedSubview(makeRow(
                icon: "person.text.rectangle",
                text: "UserID: \(userID)",
                color: .secondaryLabelColor
            ))
        }

        // === Key ID ===
        if let keyID = ctx.signerKeyID, !keyID.isEmpty {
            stack.addArrangedSubview(makeRow(
                icon: "key.fill",
                text: "Key ID: \(keyID)",
                color: .secondaryLabelColor
            ))
        }

        // === Fingerprint ===
        if let fp = ctx.keyFingerprint, !fp.isEmpty {
            let formatted = formatFingerprint(fp)
            stack.addArrangedSubview(makeRow(
                icon: "textformat.123",
                text: "Отпечаток: \(formatted)",
                color: .secondaryLabelColor
            ))
        }

        // === Даты ключа ===
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .none
        dateFormatter.locale = Locale(identifier: "ru_RU")

        if let created = ctx.keyCreationDate {
            stack.addArrangedSubview(makeRow(
                icon: "calendar.badge.plus",
                text: "Ключ создан: \(dateFormatter.string(from: created))",
                color: .secondaryLabelColor
            ))
        }

        if let expires = ctx.keyExpirationDate {
            let isExpired = expires < Date()
            stack.addArrangedSubview(makeRow(
                icon: isExpired ? "calendar.badge.exclamationmark" : "calendar.badge.clock",
                text: isExpired
                    ? "Ключ истёк: \(dateFormatter.string(from: expires))"
                    : "Действителен до: \(dateFormatter.string(from: expires))",
                color: isExpired ? .systemRed : .secondaryLabelColor
            ))
        } else if ctx.keyFingerprint != nil {
            stack.addArrangedSubview(makeRow(
                icon: "calendar.badge.clock",
                text: "Срок действия: бессрочный",
                color: .secondaryLabelColor
            ))
        }

        // === Ошибка расшифровки ===
        if let error = ctx.decryptionError {
            stack.addArrangedSubview(makeRow(
                icon: "lock.slash.fill",
                text: "Ошибка расшифровки: \(error)",
                color: .systemRed
            ))
        }

        // === Web of Trust пояснение ===
        let showWoT: Bool
        switch ctx.signatureStatus {
        case .valid, .invalid: showWoT = true
        case .none: showWoT = false
        }

        if showWoT {
            stack.addArrangedSubview(makeSeparator())

            let wotTitle = NSTextField(labelWithString: "PGP Web of Trust")
            wotTitle.font = .boldSystemFont(ofSize: 12)
            wotTitle.textColor = .labelColor
            stack.addArrangedSubview(wotTitle)

            let trustLevel = ctx.trustLevel.flatMap { GPGHelper.VerifyResult.TrustLevel(rawValue: $0) } ?? .unknown
            let explanation = wotExplanation(trustLevel)
            let explanationLabel = NSTextField(wrappingLabelWithString: explanation)
            explanationLabel.font = .systemFont(ofSize: 11)
            explanationLabel.textColor = .secondaryLabelColor
            explanationLabel.preferredMaxLayoutWidth = 340
            stack.addArrangedSubview(explanationLabel)
        }
    }

    /// Настраивает контроллер из данных контекста
    func configure(with data: Data) {
        self.context = SecurityContext.decode(from: data)
    }

    // MARK: - UI Helpers

    private func makeRow(icon: String, text: String, color: NSColor) -> NSView {
        let imageView = NSImageView()
        if let image = NSImage(systemSymbolName: icon, accessibilityDescription: nil) {
            imageView.image = image
            imageView.contentTintColor = color
        }
        imageView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            imageView.widthAnchor.constraint(equalToConstant: 16),
            imageView.heightAnchor.constraint(equalToConstant: 16),
        ])

        let label = NSTextField(labelWithString: text)
        label.textColor = color
        label.font = .systemFont(ofSize: 12)
        label.lineBreakMode = .byTruncatingTail

        let row = NSStackView(views: [imageView, label])
        row.orientation = .horizontal
        row.spacing = 6
        return row
    }

    private func addLabel(to container: NSView, text: String, icon: String, color: NSColor) {
        let row = makeRow(icon: icon, text: text, color: color)
        row.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(row)
        NSLayoutConstraint.activate([
            row.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            row.centerYAnchor.constraint(equalTo: container.centerYAnchor),
        ])
    }

    private func makeSeparator() -> NSView {
        let sep = NSBox()
        sep.boxType = .separator
        return sep
    }

    private func formatFingerprint(_ fp: String) -> String {
        // Форматируем как XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
        var result = ""
        for (i, ch) in fp.enumerated() {
            if i > 0 && i % 4 == 0 {
                result += i == 20 ? "  " : " "
            }
            result.append(ch)
        }
        return result
    }

    private func trustDescription(_ trust: GPGHelper.VerifyResult.TrustLevel) -> String {
        switch trust {
        case .ultimate: return "Полное доверие (Ultimate)"
        case .full: return "Доверенный (Full)"
        case .marginal: return "Частичное доверие (Marginal)"
        case .undefined: return "Доверие не задано (Undefined)"
        case .never: return "Не доверенный (Never)"
        case .expired: return "Ключ истёк (Expired)"
        case .unknown: return ""
        }
    }

    private func trustColor(_ trust: GPGHelper.VerifyResult.TrustLevel) -> NSColor {
        switch trust {
        case .ultimate: return .systemGreen
        case .full: return .systemGreen
        case .marginal: return .systemYellow
        case .undefined: return .systemOrange
        case .never: return .systemRed
        case .expired: return .systemRed
        case .unknown: return .secondaryLabelColor
        }
    }

    private func wotExplanation(_ trust: GPGHelper.VerifyResult.TrustLevel) -> String {
        let base = "Web of Trust — это децентрализованная модель доверия PGP. Вместо центрального удостоверяющего центра (CA), пользователи сами подписывают ключи друг друга, формируя «сеть доверия»."
        let specific: String
        switch trust {
        case .ultimate:
            specific = "\n\nУровень «Ultimate» — это ваш собственный ключ. Вы полностью доверяете этому ключу, так как владеете его секретной частью."
        case .full:
            specific = "\n\nУровень «Full» — ключ подписан достаточным количеством доверенных ключей. GPG считает его подлинным."
        case .marginal:
            specific = "\n\nУровень «Marginal» — ключ подписан частично доверенными ключами. Для полного доверия нужны дополнительные подписи."
        case .undefined:
            specific = "\n\nУровень «Undefined» — ключ есть в связке, но его подлинность не подтверждена подписями доверенных ключей. Рекомендуется проверить отпечаток напрямую."
        case .never:
            specific = "\n\nУровень «Never» — ключ явно помечен как недоверенный. Подпись может быть подделана."
        case .expired:
            specific = "\n\nКлюч подписанта истёк. Подпись могла быть сделана до истечения срока, но рекомендуется обновить ключ."
        case .unknown:
            specific = "\n\nУровень доверия не определён. Ключ подписанта может отсутствовать в вашей связке."
        }
        return base + specific
    }
}

// MARK: - Security Context (serializable context data)

/// Контекст безопасности, передаётся между декодером и view controller
struct SecurityContext: Codable {
    var isEncrypted: Bool = false
    var signatureStatus: SignatureStatus = .none
    var signerKeyID: String?
    var decryptionError: String?
    // Расширенная информация о PGP подписи
    var keyFingerprint: String?
    var keyCreationDate: Date?
    var keyExpirationDate: Date?
    var signerUserID: String?
    var trustLevel: String?  // ultimate, full, marginal, undefined, never, expired, unknown
    var verificationDetail: String?  // Подробная причина ошибки верификации

    enum SignatureStatus: Codable {
        case valid(email: String, trust: String)
        case invalid(email: String?)
        case none
    }

    func encode() -> Data? {
        try? JSONEncoder().encode(self)
    }

    static func decode(from data: Data) -> SecurityContext? {
        try? JSONDecoder().decode(SecurityContext.self, from: data)
    }
}
