import SwiftUI

struct ContentView: View {
    @State private var gpgStatus: GPGInstallStatus = .checking
    @State private var keys: [GPGKeyInfo] = []
    @State private var selectedTab = 0

    enum GPGInstallStatus {
        case checking, installed, notInstalled
    }

    var body: some View {
        VStack(spacing: 0) {
            headerView
            Divider()
            TabView(selection: $selectedTab) {
                statusTab.tag(0).tabItem { Label("Статус", systemImage: "info.circle") }
                keyManagementTab.tag(1).tabItem { Label("Ключи", systemImage: "key.2.on.ring") }
                settingsTab.tag(2).tabItem { Label("Настройки", systemImage: "gear") }
                diagnosticsTab.tag(3).tabItem { Label("Диагностика", systemImage: "stethoscope") }
            }
            .padding(0)
        }
        .frame(width: 600, height: 600)
        .task {
            await checkStatus()
        }
    }

    // MARK: - Header

    private var headerView: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield")
                .font(.system(size: 32))
                .foregroundColor(.accentColor)
            VStack(alignment: .leading) {
                Text("FreeGPGMail")
                    .font(.title2.bold())
                Text("Бесплатное GPG-шифрование для Apple Mail")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(20)
        .background(.ultraThinMaterial)
    }

    // MARK: - Key Management Tab

    private var keyManagementTab: some View {
        KeyManagementView()
    }

    // MARK: - Status Tab

    private var statusTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusSection
                setupInstructionsSection
                keysSection
            }
            .padding(24)
        }
    }

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Статус")
                .font(.headline)

            HStack(spacing: 8) {
                statusDot(ok: gpgStatus == .installed)
                switch gpgStatus {
                case .checking: Text("Проверяю GPG...")
                case .installed: Text("GPG установлен")
                case .notInstalled: Text("GPG не найден")
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private func statusDot(ok: Bool) -> some View {
        Circle()
            .fill(ok ? Color.green : Color.red)
            .frame(width: 8, height: 8)
    }

    private var setupInstructionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Настройка")
                .font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                instructionRow(number: 1, text: "Установите GPG: brew install gnupg")
                instructionRow(number: 2, text: "Создайте ключ: gpg --full-generate-key")
                instructionRow(number: 3, text: "Откройте Системные настройки → Расширения → Mail")
                instructionRow(number: 4, text: "Включите FreeGPGMail")
                instructionRow(number: 5, text: "Перезапустите Mail")
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private func instructionRow(number: Int, text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(number).")
                .foregroundColor(.secondary)
                .frame(width: 20, alignment: .trailing)
            Text(text)
                .textSelection(.enabled)
        }
    }

    private var keysSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("GPG-ключи")
                    .font(.headline)
                Spacer()
                Button("Обновить") {
                    KeyCache.shared.invalidateAll()
                    Task { await loadKeys() }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            if keys.isEmpty {
                Text("Ключи не найдены. Создайте ключ командой gpg --full-generate-key")
                    .foregroundColor(.secondary)
                    .font(.callout)
            } else {
                ForEach(keys, id: \.fingerprint) { key in
                    keyRow(key)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private func keyRow(_ key: GPGKeyInfo) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(key.userID)
                    .font(.callout.bold())
                Text(key.fingerprint.suffix(16))
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
            }
            Spacer()
            if Settings.shared.defaultKeyFingerprint == key.fingerprint {
                Text("По умолчанию")
                    .font(.caption)
                    .foregroundColor(.accentColor)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(Color.accentColor.opacity(0.15)))
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - Settings Tab

    private var settingsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                signingSettingsSection
                encryptionSettingsSection
                defaultKeySection
                agentSettingsSection
            }
            .padding(24)
        }
    }

    private var signingSettingsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Подпись")
                .font(.headline)

            Toggle("Автоматически подписывать исходящие письма", isOn: Binding(
                get: { Settings.shared.autoSign },
                set: { Settings.shared.autoSign = $0 }
            ))
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private var encryptionSettingsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Шифрование")
                .font(.headline)

            Toggle("Автоматически шифровать (если есть ключи всех получателей)", isOn: Binding(
                get: { Settings.shared.autoEncrypt },
                set: { Settings.shared.autoEncrypt = $0 }
            ))

            Toggle("Блокировать удалённый контент в зашифрованных письмах", isOn: Binding(
                get: { Settings.shared.blockRemoteContentForEncrypted },
                set: { Settings.shared.blockRemoteContentForEncrypted = $0 }
            ))
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private var defaultKeySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Ключ по умолчанию")
                .font(.headline)

            if keys.isEmpty {
                Text("Нет доступных ключей")
                    .foregroundColor(.secondary)
            } else {
                Picker("Ключ для подписи", selection: Binding(
                    get: { Settings.shared.defaultKeyFingerprint ?? "" },
                    set: { Settings.shared.defaultKeyFingerprint = $0.isEmpty ? nil : $0 }
                )) {
                    Text("Автоматически (по email отправителя)")
                        .tag("")
                    ForEach(keys, id: \.fingerprint) { key in
                        Text("\(key.email) (\(key.fingerprint.suffix(8)))")
                            .tag(key.fingerprint)
                    }
                }
                .labelsHidden()
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    private var agentSettingsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("GPG Agent")
                .font(.headline)

            Picker("Режим pinentry", selection: Binding(
                get: { Settings.shared.pinentryMode },
                set: { Settings.shared.pinentryMode = $0 }
            )) {
                Text("По умолчанию").tag(Settings.PinentryMode.default)
                Text("Всегда спрашивать").tag(Settings.PinentryMode.ask)
                Text("Loopback").tag(Settings.PinentryMode.loopback)
            }

            HStack {
                Text("TTL кэша ключей:")
                Picker("", selection: Binding(
                    get: { Settings.shared.keyCacheTTL },
                    set: { Settings.shared.keyCacheTTL = $0 }
                )) {
                    Text("1 мин").tag(60.0)
                    Text("5 мин").tag(300.0)
                    Text("15 мин").tag(900.0)
                    Text("1 час").tag(3600.0)
                }
                .labelsHidden()
                .frame(width: 120)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    // MARK: - Diagnostics Tab

    private var diagnosticsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                loggingSection
                actionsSection
            }
            .padding(24)
        }
    }

    private var loggingSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Логирование")
                .font(.headline)

            Toggle("Включить логирование", isOn: Binding(
                get: { Settings.shared.loggingEnabled },
                set: { Settings.shared.loggingEnabled = $0 }
            ))

            Text("Логи доступны через Console.app (подсистема com.freegpgmail.app)")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    @State private var diagnosticsExported = false

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Действия")
                .font(.headline)

            HStack(spacing: 12) {
                Button("Экспорт диагностики") {
                    if let url = Log.exportDiagnostics() {
                        NSWorkspace.shared.selectFile(url.path, inFileViewerRootedAtPath: "")
                        diagnosticsExported = true
                    }
                }
                .buttonStyle(.bordered)

                Button("Сбросить кэш ключей") {
                    KeyCache.shared.invalidateAll()
                    Task { await loadKeys() }
                }
                .buttonStyle(.bordered)

                Button("Перезапустить gpg-agent") {
                    GPGHelper.restartAgent()
                }
                .buttonStyle(.bordered)
            }

            if diagnosticsExported {
                Text("Диагностика экспортирована в /tmp/FreeGPGMail-diagnostics.txt")
                    .font(.caption)
                    .foregroundColor(.green)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))
    }

    // MARK: - Actions

    private func checkStatus() async {
        gpgStatus = GPGHelper.isGPGInstalled() ? .installed : .notInstalled
        await loadKeys()
    }

    private func loadKeys() async {
        keys = KeyCache.shared.getSecretKeys(forceRefresh: true)
    }
}
