import AppKit
import MailKit

/// View controller для окна композиции — показывает статус и позволяет переключать подпись/шифрование
class ComposeViewController: MEExtensionViewController {

    private var signButton: NSButton!
    private var encryptButton: NSButton!
    private var statusLabel: NSTextField!
    private var keyPopup: NSPopUpButton!

    private var canSign = false
    private var canEncrypt = false
    private var isSignEnabled = false
    private var isEncryptEnabled = false

    private var availableKeys: [GPGKeyInfo] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        self.preferredContentSize = NSSize(width: 280, height: 160)
    }

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 160))
        self.view = container

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 10
        stack.alignment = .leading
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 12),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: container.bottomAnchor, constant: -12),
        ])

        // Заголовок
        let titleLabel = NSTextField(labelWithString: "FreeGPGMail")
        titleLabel.font = .boldSystemFont(ofSize: 13)
        titleLabel.textColor = .labelColor

        // Кнопки подписи и шифрования в ряд
        let buttonsRow = NSStackView()
        buttonsRow.orientation = .horizontal
        buttonsRow.spacing = 8

        signButton = NSButton(checkboxWithTitle: " Подписать", target: self, action: #selector(toggleSign(_:)))
        signButton.font = .systemFont(ofSize: 12)
        signButton.imagePosition = .imageLeading

        encryptButton = NSButton(checkboxWithTitle: " Шифровать", target: self, action: #selector(toggleEncrypt(_:)))
        encryptButton.font = .systemFont(ofSize: 12)
        encryptButton.imagePosition = .imageLeading

        buttonsRow.addArrangedSubview(signButton)
        buttonsRow.addArrangedSubview(encryptButton)

        // Статус
        statusLabel = NSTextField(labelWithString: "")
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor

        // Ключ
        let keyRow = NSStackView()
        keyRow.orientation = .horizontal
        keyRow.spacing = 6

        let keyLabel = NSTextField(labelWithString: "Ключ:")
        keyLabel.font = .systemFont(ofSize: 11)
        keyLabel.textColor = .secondaryLabelColor

        keyPopup = NSPopUpButton(frame: .zero, pullsDown: false)
        keyPopup.font = .systemFont(ofSize: 11)
        keyPopup.controlSize = .small
        keyPopup.target = self
        keyPopup.action = #selector(keySelected(_:))

        keyRow.addArrangedSubview(keyLabel)
        keyRow.addArrangedSubview(keyPopup)

        stack.addArrangedSubview(titleLabel)
        stack.addArrangedSubview(buttonsRow)
        stack.addArrangedSubview(statusLabel)
        stack.addArrangedSubview(keyRow)

        loadKeys()
        syncButtonsFromSettings()
    }

    // MARK: - State Updates

    func updateStatus(canSign: Bool, canEncrypt: Bool, senderEmail: String) {
        self.canSign = canSign
        self.canEncrypt = canEncrypt

        if !canSign { isSignEnabled = false }
        if !canEncrypt { isEncryptEnabled = false }

        updateUI()
        selectKey(for: senderEmail)
    }

    private func syncButtonsFromSettings() {
        isSignEnabled = Settings.shared.autoSign
        isEncryptEnabled = Settings.shared.autoEncrypt
        updateUI()
    }

    private func updateUI() {
        guard signButton != nil else { return }

        // Подпись
        signButton.isEnabled = canSign
        signButton.state = (canSign && isSignEnabled) ? .on : .off

        if !canSign {
            signButton.toolTip = "Нет секретного ключа для подписи"
        } else if isSignEnabled {
            signButton.toolTip = "Письмо будет подписано"
        } else {
            signButton.toolTip = "Нажмите чтобы подписать"
        }

        // Шифрование
        encryptButton.isEnabled = canEncrypt
        encryptButton.state = (canEncrypt && isEncryptEnabled) ? .on : .off

        if !canEncrypt {
            encryptButton.toolTip = "Не найдены ключи всех получателей"
        } else if isEncryptEnabled {
            encryptButton.toolTip = "Письмо будет зашифровано"
        } else {
            encryptButton.toolTip = "Нажмите чтобы зашифровать"
        }

        // Статус
        var parts: [String] = []
        if canSign && isSignEnabled { parts.append("подпись") }
        if canEncrypt && isEncryptEnabled { parts.append("шифрование") }

        if !canSign && !canEncrypt {
            statusLabel.stringValue = "GPG-ключи не найдены"
            statusLabel.textColor = .systemOrange
        } else if parts.isEmpty {
            statusLabel.stringValue = "Письмо будет отправлено без защиты"
            statusLabel.textColor = .secondaryLabelColor
        } else {
            statusLabel.stringValue = "Включено: " + parts.joined(separator: " + ")
            statusLabel.textColor = .systemGreen
        }

        Settings.shared.autoSign = isSignEnabled
        Settings.shared.autoEncrypt = isEncryptEnabled
    }

    // MARK: - Actions

    @objc private func toggleSign(_ sender: NSButton) {
        isSignEnabled = sender.state == .on
        Log.settings.info("Sign toggled: \(self.isSignEnabled)")
        updateUI()
    }

    @objc private func toggleEncrypt(_ sender: NSButton) {
        isEncryptEnabled = sender.state == .on
        Log.settings.info("Encrypt toggled: \(self.isEncryptEnabled)")
        updateUI()
    }

    // MARK: - Key Management

    private func loadKeys() {
        availableKeys = KeyCache.shared.getSecretKeys()

        keyPopup.removeAllItems()
        keyPopup.addItem(withTitle: "Авто (по email)")

        for key in availableKeys {
            let short = String(key.fingerprint.suffix(8))
            keyPopup.addItem(withTitle: "\(key.email) (\(short))")
        }

        if let defaultFP = Settings.shared.defaultKeyFingerprint,
           let idx = availableKeys.firstIndex(where: { $0.fingerprint == defaultFP }) {
            keyPopup.selectItem(at: idx + 1)
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
