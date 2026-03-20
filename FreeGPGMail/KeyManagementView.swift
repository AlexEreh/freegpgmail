import SwiftUI

/// Управление ключами: импорт, экспорт, keyserver, доверие
struct KeyManagementView: View {
    @State private var publicKeys: [GPGKeyInfo] = []
    @State private var secretKeys: [GPGKeyInfo] = []
    @State private var importText = ""
    @State private var keyserverQuery = ""
    @State private var statusMessage = ""
    @State private var isLoading = false
    @State private var showImportSheet = false

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

    // MARK: - Keyserver

    private var keyserverSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Поиск на сервере ключей")
                .font(.headline)

            HStack {
                TextField("Email или ID ключа", text: $keyserverQuery)
                    .textFieldStyle(.roundedBorder)

                Button("Найти") {
                    searchKeyserver()
                }
                .buttonStyle(.bordered)
                .disabled(keyserverQuery.isEmpty || isLoading)
            }

            Text("Сервер: keys.openpgp.org")
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
                }
                Text(key.fingerprint)
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()

            if !isSecret {
                Menu {
                    Button("Копировать fingerprint") {
                        copyToClipboard(key.fingerprint)
                    }
                    Button("Экспорт (ASCII)") {
                        exportKey(key)
                    }
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
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .frame(width: 30)
            }
        }
        .padding(.vertical, 4)
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
}
