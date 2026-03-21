import SwiftUI
import CoreImage

/// Управление ключами: импорт, экспорт, keyserver, доверие
struct KeyManagementView: View {
    @State private var publicKeys: [GPGKeyInfo] = []
    @State private var secretKeys: [GPGKeyInfo] = []
    @State private var importText = ""
    @State private var keyserverQuery = ""
    @State private var statusMessage = ""
    @State private var isLoading = false
    @State private var showImportSheet = false
    @State private var showGenerateSheet = false
    @State private var showQRSheet = false
    @State private var qrKeyFingerprint = ""
    @State private var genName = ""
    @State private var genEmail = ""
    @State private var genAlgorithm = "ed25519"
    @State private var genExpiry = "2y"

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "key.2.on.ring")
                    .font(.system(size: 24))
                    .foregroundColor(.accentColor)
                Text("Управление ключами")
                    .font(.title3.bold())
                Spacer()
                Button("Обновить") {
                    refresh()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding(16)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    generateKeySection
                    keyserverSection
                    importSection
                    secretKeysSection
                    publicKeysSection
                }
                .padding(20)
            }

            if !statusMessage.isEmpty {
                Divider()
                HStack {
                    Text(statusMessage)
                        .font(.callout)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("OK") { statusMessage = "" }
                        .buttonStyle(.borderless)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(.ultraThinMaterial)
            }
        }
        .task { refresh() }
    }

    // MARK: - Generate Key

    private var generateKeySection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Создать ключ")
                    .font(.headline)
                Spacer()
                Button("Создать...") {
                    showGenerateSheet = true
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }

            Text("Создаёт новую пару GPG-ключей прямо из приложения")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
        .sheet(isPresented: $showGenerateSheet) {
            generateKeySheet
        }
        .sheet(isPresented: $showQRSheet) {
            qrCodeSheet
        }
    }

    private var generateKeySheet: some View {
        VStack(spacing: 16) {
            Text("Создать GPG-ключ")
                .font(.headline)

            TextField("Имя", text: $genName)
                .textFieldStyle(.roundedBorder)

            TextField("Email", text: $genEmail)
                .textFieldStyle(.roundedBorder)

            HStack {
                Text("Алгоритм:")
                Picker("", selection: $genAlgorithm) {
                    Text("Ed25519 (рекомендуется)").tag("ed25519")
                    Text("RSA 4096").tag("rsa4096")
                    Text("RSA 3072").tag("rsa3072")
                }
                .labelsHidden()
            }

            HStack {
                Text("Срок действия:")
                Picker("", selection: $genExpiry) {
                    Text("1 год").tag("1y")
                    Text("2 года").tag("2y")
                    Text("5 лет").tag("5y")
                    Text("Бессрочно").tag("0")
                }
                .labelsHidden()
            }

            HStack {
                Button("Отмена") {
                    showGenerateSheet = false
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Создать") {
                    generateKey()
                    showGenerateSheet = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(genName.isEmpty || genEmail.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 450)
    }

    private var qrCodeSheet: some View {
        VStack(spacing: 16) {
            Text("QR-код публичного ключа")
                .font(.headline)

            if let keyText = GPGHelper.exportMinimalKey(fingerprint: qrKeyFingerprint),
               let qrImage = generateQRCode(from: keyText) {
                Image(nsImage: qrImage)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .frame(width: 250, height: 250)

                Text("Отсканируйте для импорта ключа")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Text("Не удалось сгенерировать QR-код")
                    .foregroundColor(.red)
            }

            Button("Закрыть") {
                showQRSheet = false
            }
            .keyboardShortcut(.cancelAction)
        }
        .padding(20)
        .frame(width: 350)
    }

    // MARK: - Keyserver

    private var keyserverSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Поиск на сервере ключей")
                .font(.headline)

            HStack {
                TextField("Email или ID ключа", text: $keyserverQuery)
                    .textFieldStyle(.roundedBorder)

                Button("Keyserver") {
                    searchKeyserver()
                }
                .buttonStyle(.bordered)
                .disabled(keyserverQuery.isEmpty || isLoading)

                Button("WKD") {
                    searchWKD()
                }
                .buttonStyle(.bordered)
                .disabled(keyserverQuery.isEmpty || isLoading || !keyserverQuery.contains("@"))
            }

            Text("Keyserver: keys.openpgp.org • WKD: автопоиск по домену email")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    // MARK: - Import

    private var importSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Импорт ключа")
                .font(.headline)

            HStack(spacing: 8) {
                Button("Из буфера обмена") {
                    importFromClipboard()
                }
                .buttonStyle(.bordered)

                Button("Из файла...") {
                    importFromFile()
                }
                .buttonStyle(.bordered)

                Button("Вставить текст...") {
                    showImportSheet = true
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
        .sheet(isPresented: $showImportSheet) {
            importSheet
        }
    }

    private var importSheet: some View {
        VStack(spacing: 12) {
            Text("Вставьте GPG-ключ")
                .font(.headline)

            TextEditor(text: $importText)
                .font(.system(.caption, design: .monospaced))
                .frame(height: 200)
                .border(Color.secondary.opacity(0.3))

            HStack {
                Button("Отмена") {
                    showImportSheet = false
                    importText = ""
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Импортировать") {
                    importKeyFromText()
                    showImportSheet = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(importText.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 500)
    }

    // MARK: - Key Lists

    private var secretKeysSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Секретные ключи (\(secretKeys.count))")
                .font(.headline)

            if secretKeys.isEmpty {
                Text("Нет секретных ключей")
                    .foregroundColor(.secondary)
                    .font(.callout)
            } else {
                ForEach(secretKeys, id: \.fingerprint) { key in
                    keyDetailRow(key, isSecret: true)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private var publicKeysSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Публичные ключи (\(publicKeys.count))")
                .font(.headline)

            if publicKeys.isEmpty {
                Text("Нет публичных ключей")
                    .foregroundColor(.secondary)
                    .font(.callout)
            } else {
                ForEach(publicKeys, id: \.fingerprint) { key in
                    keyDetailRow(key, isSecret: false)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private func keyDetailRow(_ key: GPGKeyInfo, isSecret: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Image(systemName: isSecret ? "key.fill" : "key")
                        .font(.caption)
                        .foregroundColor(isSecret ? .orange : .secondary)
                    Text(key.userID)
                        .font(.callout.bold())

                    // Предупреждение об истечении
                    if key.isExpired {
                        Text("ИСТЁК")
                            .font(.caption2.bold())
                            .foregroundColor(.white)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(.red))
                    } else if key.expiresWithin(days: Settings.shared.keyExpiryWarningDays) {
                        let days = Int((key.expirationDate!.timeIntervalSinceNow / 86400).rounded(.up))
                        Text("⚠ \(days)д")
                            .font(.caption2.bold())
                            .foregroundColor(.orange)
                    }
                }
                HStack(spacing: 8) {
                    Text(key.fingerprint)
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                    if let exp = key.expirationDate {
                        Text("до \(formatDate(exp))")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
            Spacer()

            Menu {
                Button("Копировать fingerprint") {
                    copyToClipboard(key.fingerprint)
                }
                Button("Экспорт (ASCII)") {
                    exportKey(key)
                }
                Button("QR-код") {
                    qrKeyFingerprint = key.fingerprint
                    showQRSheet = true
                }
                if !isSecret {
                    Divider()
                    Button("Установить доверие: полное") {
                        setTrust(key, level: "5")
                    }
                    Button("Установить доверие: частичное") {
                        setTrust(key, level: "3")
                    }
                    Divider()
                    Button("Удалить ключ", role: .destructive) {
                        deleteKey(key)
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .frame(width: 30)
        }
        .padding(.vertical, 4)
    }

    private func formatDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .short
        return f.string(from: date)
    }

    // MARK: - Actions

    private func refresh() {
        KeyCache.shared.invalidateAll()
        secretKeys = KeyCache.shared.getSecretKeys(forceRefresh: true)
        publicKeys = KeyCache.shared.getPublicKeys(forceRefresh: true)
    }

    private func searchKeyserver() {
        isLoading = true
        statusMessage = "Ищу ключ на сервере..."

        DispatchQueue.global().async {
            let success = GPGHelper.searchAndImportFromKeyserver(query: keyserverQuery)
            DispatchQueue.main.async {
                isLoading = false
                if success {
                    statusMessage = "Ключ импортирован с сервера"
                    refresh()
                } else {
                    statusMessage = "Ключ не найден на сервере"
                }
            }
        }
    }

    private func searchWKD() {
        isLoading = true
        statusMessage = "WKD: ищу ключ для \(keyserverQuery)..."

        DispatchQueue.global().async {
            let success = GPGHelper.importFromWKD(email: keyserverQuery)
            DispatchQueue.main.async {
                isLoading = false
                if success {
                    statusMessage = "WKD: ключ импортирован"
                    refresh()
                } else {
                    statusMessage = "WKD: ключ не найден для этого домена"
                }
            }
        }
    }

    private func importFromClipboard() {
        guard let string = NSPasteboard.general.string(forType: .string),
              let data = string.data(using: .utf8) else {
            statusMessage = "Буфер обмена пуст или не содержит текст"
            return
        }
        if GPGHelper.importKey(data: data) {
            statusMessage = "Ключ импортирован из буфера обмена"
            refresh()
        } else {
            statusMessage = "Не удалось импортировать ключ"
        }
    }

    private func importFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.data]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Выберите файл с GPG-ключом"

        if panel.runModal() == .OK, let url = panel.url {
            do {
                let data = try Data(contentsOf: url)
                if GPGHelper.importKey(data: data) {
                    statusMessage = "Ключ импортирован из \(url.lastPathComponent)"
                    refresh()
                } else {
                    statusMessage = "Не удалось импортировать ключ"
                }
            } catch {
                statusMessage = "Ошибка чтения файла: \(error.localizedDescription)"
            }
        }
    }

    private func importKeyFromText() {
        guard let data = importText.data(using: .utf8) else { return }
        if GPGHelper.importKey(data: data) {
            statusMessage = "Ключ импортирован"
            refresh()
        } else {
            statusMessage = "Не удалось импортировать ключ"
        }
        importText = ""
    }

    private func copyToClipboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
        statusMessage = "Скопировано в буфер обмена"
    }

    private func exportKey(_ key: GPGKeyInfo) {
        if let exported = GPGHelper.exportKey(fingerprint: key.fingerprint) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(exported, forType: .string)
            statusMessage = "Ключ скопирован в буфер обмена (ASCII Armor)"
        } else {
            statusMessage = "Не удалось экспортировать ключ"
        }
    }

    private func setTrust(_ key: GPGKeyInfo, level: String) {
        if GPGHelper.setOwnerTrust(fingerprint: key.fingerprint, level: level) {
            statusMessage = "Доверие установлено"
            refresh()
        } else {
            statusMessage = "Не удалось установить доверие"
        }
    }

    private func deleteKey(_ key: GPGKeyInfo) {
        if GPGHelper.deletePublicKey(fingerprint: key.fingerprint) {
            statusMessage = "Ключ удалён"
            refresh()
        } else {
            statusMessage = "Не удалось удалить ключ"
        }
    }

    private func generateKey() {
        isLoading = true
        statusMessage = "Генерирую ключ..."

        DispatchQueue.global().async {
            let success = GPGHelper.generateKey(
                name: genName,
                email: genEmail,
                algorithm: genAlgorithm,
                expiry: genExpiry
            )
            DispatchQueue.main.async {
                isLoading = false
                if success {
                    statusMessage = "Ключ создан для \(genEmail)"
                    genName = ""
                    genEmail = ""
                    refresh()
                } else {
                    statusMessage = "Не удалось создать ключ"
                }
            }
        }
    }

    private func generateQRCode(from string: String) -> NSImage? {
        guard let data = string.data(using: .utf8) else { return nil }
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")

        guard let ciImage = filter.outputImage else { return nil }
        let scale = CGAffineTransform(scaleX: 10, y: 10)
        let scaledImage = ciImage.transformed(by: scale)

        let rep = NSCIImageRep(ciImage: scaledImage)
        let nsImage = NSImage(size: rep.size)
        nsImage.addRepresentation(rep)
        return nsImage
    }
}
