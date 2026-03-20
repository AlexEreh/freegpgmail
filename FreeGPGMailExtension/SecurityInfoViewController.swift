import AppKit
import MailKit

/// Контроллер для отображения информации о подписи/шифровании в Mail
class SecurityInfoViewController: MEExtensionViewController {

    private var context: SecurityContext?

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 120))
        self.view = container

        guard let ctx = context else {
            addLabel(to: container, text: "Нет данных о безопасности", icon: "questionmark.circle", color: .secondaryLabelColor)
            return
        }

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 12),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: container.bottomAnchor, constant: -12),
        ])

        // Encryption status
        if ctx.isEncrypted {
            let row = makeRow(
                icon: "lock.fill",
                text: "Зашифровано",
                color: .systemGreen
            )
            stack.addArrangedSubview(row)
        }

        // Signature status
        switch ctx.signatureStatus {
        case .valid(let email, let trust):
            let trustLevel = GPGHelper.VerifyResult.TrustLevel(rawValue: trust) ?? .unknown
            let trustText = trustDescription(trustLevel)
            let row = makeRow(
                icon: "checkmark.shield.fill",
                text: "Подписано: \(email)\(trustText)",
                color: .systemGreen
            )
            stack.addArrangedSubview(row)

        case .invalid(let email):
            let text = email.map { "Недействительная подпись: \($0)" } ?? "Недействительная подпись"
            let row = makeRow(
                icon: "xmark.shield.fill",
                text: text,
                color: .systemRed
            )
            stack.addArrangedSubview(row)

        case .none:
            break
        }

        // Key ID
        if let keyID = ctx.signerKeyID {
            let row = makeRow(
                icon: "key.fill",
                text: "Ключ: \(keyID)",
                color: .secondaryLabelColor
            )
            stack.addArrangedSubview(row)
        }

        // Decryption error
        if let error = ctx.decryptionError {
            let row = makeRow(
                icon: "lock.slash.fill",
                text: "Ошибка расшифровки: \(error)",
                color: .systemRed
            )
            stack.addArrangedSubview(row)
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

    private func trustDescription(_ trust: GPGHelper.VerifyResult.TrustLevel) -> String {
        switch trust {
        case .ultimate: return " (полное доверие)"
        case .full: return " (доверенный)"
        case .marginal: return " (частичное доверие)"
        case .undefined: return " (доверие не задано)"
        case .never: return " (не доверенный!)"
        case .expired: return " (ключ истёк!)"
        case .unknown: return ""
        }
    }
}

// MARK: - Security Context (serializable context data)

/// Контекст безопасности, передаётся между декодером и view controller
struct SecurityContext: Codable {
    var isEncrypted: Bool = false
    var signatureStatus: SignatureStatus = .none
    var signerKeyID: String?
    var decryptionError: String?

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
