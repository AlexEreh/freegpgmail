import AppKit
import MailKit

/// View controller для окна композиции — показывает статус подписи/шифрования и позволяет выбрать ключ
class ComposeViewController: MEExtensionViewController {

    private var statusLabel: NSTextField!
    private var signIcon: NSImageView!
    private var encryptIcon: NSImageView!
    private var keyPopup: NSPopUpButton!

    private var availableKeys: [GPGKeyInfo] = []

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 36))
        self.view = container

        // Основной горизонтальный стек
        let stack = NSStackView()
        stack.orientation = .horizontal
        stack.spacing = 10
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
            stack.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -4),
        ])

        // Иконка подписи
        signIcon = NSImageView()
        signIcon.image = NSImage(systemSymbolName: "signature", accessibilityDescription: "Подпись")
        signIcon.contentTintColor = .secondaryLabelColor
        signIcon.toolTip = "Подпись"
        signIcon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            signIcon.widthAnchor.constraint(equalToConstant: 16),
            signIcon.heightAnchor.constraint(equalToConstant: 16),
        ])

        // Иконка шифрования
        encryptIcon = NSImageView()
        encryptIcon.image = NSImage(systemSymbolName: "lock", accessibilityDescription: "Шифрование")
        encryptIcon.contentTintColor = .secondaryLabelColor
        encryptIcon.toolTip = "Шифрование"
        encryptIcon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            encryptIcon.widthAnchor.constraint(equalToConstant: 16),
            encryptIcon.heightAnchor.constraint(equalToConstant: 16),
        ])

        // Статус
        statusLabel = NSTextField(labelWithString: "FreeGPGMail")
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor

        // Разделитель
        let separator = NSBox()
        separator.boxType = .separator
        separator.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            separator.widthAnchor.constraint(equalToConstant: 1),
            separator.heightAnchor.constraint(equalToConstant: 16),
        ])

        // Выбор ключа
        keyPopup = NSPopUpButton(frame: .zero, pullsDown: false)
        keyPopup.font = .systemFont(ofSize: 11)
        keyPopup.controlSize = .small
        keyPopup.target = self
        keyPopup.action = #selector(keySelected(_:))

        stack.addArrangedSubview(signIcon)
        stack.addArrangedSubview(encryptIcon)
        stack.addArrangedSubview(statusLabel)
        stack.addArrangedSubview(separator)
        stack.addArrangedSubview(keyPopup)

        loadKeys()
    }

    // MARK: - State Updates

    /// Обновляет UI на основе текущей сессии композиции
    func updateStatus(canSign: Bool, canEncrypt: Bool, senderEmail: String) {
        signIcon.contentTintColor = canSign ? .systemGreen : .secondaryLabelColor
        signIcon.toolTip = canSign ? "Подпись доступна" : "Нет ключа для подписи"

        encryptIcon.contentTintColor = canEncrypt ? .systemGreen : .secondaryLabelColor
        encryptIcon.image = NSImage(
            systemSymbolName: canEncrypt ? "lock.fill" : "lock.open",
            accessibilityDescription: nil
        )
        encryptIcon.toolTip = canEncrypt
            ? "Шифрование доступно (ключи всех получателей найдены)"
            : "Шифрование недоступно (не все ключи найдены)"

        var parts: [String] = []
        if canSign { parts.append("подпись") }
        if canEncrypt { parts.append("шифрование") }

        if parts.isEmpty {
            statusLabel.stringValue = "GPG недоступен"
            statusLabel.textColor = .secondaryLabelColor
        } else {
            statusLabel.stringValue = parts.joined(separator: " + ")
            statusLabel.textColor = .labelColor
        }

        // Выделяем текущий ключ отправителя в popup
        selectKey(for: senderEmail)
    }

    // MARK: - Key Management

    private func loadKeys() {
        availableKeys = KeyCache.shared.getSecretKeys()

        keyPopup.removeAllItems()
        keyPopup.addItem(withTitle: "Авто (по email)")

        for key in availableKeys {
            let title = "\(key.email) (\(key.fingerprint.suffix(8)))"
            keyPopup.addItem(withTitle: title)
        }

        // Выбираем текущий дефолтный ключ
        if let defaultFP = Settings.shared.defaultKeyFingerprint,
           let idx = availableKeys.firstIndex(where: { $0.fingerprint == defaultFP }) {
            keyPopup.selectItem(at: idx + 1) // +1 из-за "Авто" пункта
        } else {
            keyPopup.selectItem(at: 0)
        }
    }

    private func selectKey(for email: String) {
        if let idx = availableKeys.firstIndex(where: { $0.email.lowercased() == email.lowercased() }) {
            keyPopup.selectItem(at: idx + 1)
        }
    }

    @objc private func keySelected(_ sender: NSPopUpButton) {
        let idx = sender.indexOfSelectedItem
        if idx == 0 {
            Settings.shared.defaultKeyFingerprint = nil
        } else if idx - 1 < availableKeys.count {
            Settings.shared.defaultKeyFingerprint = availableKeys[idx - 1].fingerprint
        }
        Log.settings.info("Default key changed via compose UI")
    }
}
