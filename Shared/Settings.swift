import Foundation

/// Настройки FreeGPGMail, хранятся в UserDefaults (с App Group)
final class Settings: @unchecked Sendable {
    static let shared = Settings()

    private let defaults: UserDefaults
    private let lock = NSLock()

    private enum Keys {
        static let autoSign = "autoSign"
        static let autoEncrypt = "autoEncrypt"
        static let defaultKeyFingerprint = "defaultKeyFingerprint"
        static let pinentryMode = "pinentryMode"
        static let keyCacheTTL = "keyCacheTTL"
        static let loggingEnabled = "loggingEnabled"
        static let blockRemoteContentForEncrypted = "blockRemoteContentForEncrypted"
        static let keySyncInterval = "keySyncInterval"
        static let wkdAutoLookup = "wkdAutoLookup"
        static let autocryptEnabled = "autocryptEnabled"
        static let protectedHeaders = "protectedHeaders"
        static let encryptDrafts = "encryptDrafts"
        static let preferredPGPFormat = "preferredPGPFormat"
        static let autoGenerateKey = "autoGenerateKey"
        static let keyExpiryWarningDays = "keyExpiryWarningDays"
    }

    /// Режим pinentry для gpg-agent
    enum PinentryMode: String, CaseIterable, Sendable {
        case `default` = "default"   // gpg-agent решает сам
        case ask = "ask"             // всегда спрашивать
        case cancel = "cancel"       // отклонять запросы пароля
        case error = "error"         // возвращать ошибку
        case loopback = "loopback"   // pinentry через приложение
    }

    private init() {
        if let groupDefaults = UserDefaults(suiteName: "group.com.freegpgmail") {
            self.defaults = groupDefaults
        } else {
            self.defaults = UserDefaults.standard
        }
        registerDefaults()
    }

    private func registerDefaults() {
        defaults.register(defaults: [
            Keys.autoSign: true,
            Keys.autoEncrypt: true,
            Keys.pinentryMode: PinentryMode.default.rawValue,
            Keys.keyCacheTTL: 300.0,  // 5 минут
            Keys.keySyncInterval: 60.0,  // 1 минута
            Keys.wkdAutoLookup: true,
            Keys.autocryptEnabled: true,
            Keys.protectedHeaders: true,
            Keys.encryptDrafts: false,
            Keys.preferredPGPFormat: "pgpmime",
            Keys.keyExpiryWarningDays: 30,
            Keys.loggingEnabled: true,
            Keys.blockRemoteContentForEncrypted: true,
        ])
    }

    // MARK: - Properties

    /// Автоматически подписывать исходящие письма
    var autoSign: Bool {
        get { locked { defaults.bool(forKey: Keys.autoSign) } }
        set { locked { defaults.set(newValue, forKey: Keys.autoSign) } }
    }

    /// Автоматически шифровать если есть ключи всех получателей
    var autoEncrypt: Bool {
        get { locked { defaults.bool(forKey: Keys.autoEncrypt) } }
        set { locked { defaults.set(newValue, forKey: Keys.autoEncrypt) } }
    }

    /// Fingerprint ключа по умолчанию для подписи
    var defaultKeyFingerprint: String? {
        get { locked { defaults.string(forKey: Keys.defaultKeyFingerprint) } }
        set { locked { defaults.set(newValue, forKey: Keys.defaultKeyFingerprint) } }
    }

    /// Режим pinentry
    var pinentryMode: PinentryMode {
        get {
            locked {
                let raw = defaults.string(forKey: Keys.pinentryMode) ?? PinentryMode.default.rawValue
                return PinentryMode(rawValue: raw) ?? .default
            }
        }
        set { locked { defaults.set(newValue.rawValue, forKey: Keys.pinentryMode) } }
    }

    /// TTL кэша ключей в секундах
    var keyCacheTTL: TimeInterval {
        get { locked { defaults.double(forKey: Keys.keyCacheTTL) } }
        set { locked { defaults.set(newValue, forKey: Keys.keyCacheTTL) } }
    }

    /// Включено ли логирование
    var loggingEnabled: Bool {
        get { locked { defaults.bool(forKey: Keys.loggingEnabled) } }
        set { locked { defaults.set(newValue, forKey: Keys.loggingEnabled) } }
    }

    /// Блокировать удалённый контент в зашифрованных письмах
    var blockRemoteContentForEncrypted: Bool {
        get { locked { defaults.bool(forKey: Keys.blockRemoteContentForEncrypted) } }
        set { locked { defaults.set(newValue, forKey: Keys.blockRemoteContentForEncrypted) } }
    }

    /// Интервал синхронизации ключей с расширением (секунды)
    var keySyncInterval: TimeInterval {
        get { locked { defaults.double(forKey: Keys.keySyncInterval) } }
        set { locked { defaults.set(newValue, forKey: Keys.keySyncInterval) } }
    }

    /// Автоматический поиск ключей через WKD
    var wkdAutoLookup: Bool {
        get { locked { defaults.bool(forKey: Keys.wkdAutoLookup) } }
        set { locked { defaults.set(newValue, forKey: Keys.wkdAutoLookup) } }
    }

    /// Включить Autocrypt (обмен ключами через заголовки)
    var autocryptEnabled: Bool {
        get { locked { defaults.bool(forKey: Keys.autocryptEnabled) } }
        set { locked { defaults.set(newValue, forKey: Keys.autocryptEnabled) } }
    }

    /// Шифровать тему письма (Protected Headers)
    var protectedHeaders: Bool {
        get { locked { defaults.bool(forKey: Keys.protectedHeaders) } }
        set { locked { defaults.set(newValue, forKey: Keys.protectedHeaders) } }
    }

    /// Шифровать черновики
    var encryptDrafts: Bool {
        get { locked { defaults.bool(forKey: Keys.encryptDrafts) } }
        set { locked { defaults.set(newValue, forKey: Keys.encryptDrafts) } }
    }

    /// Формат PGP: pgpmime или inline
    var preferredPGPFormat: String {
        get { locked { defaults.string(forKey: Keys.preferredPGPFormat) ?? "pgpmime" } }
        set { locked { defaults.set(newValue, forKey: Keys.preferredPGPFormat) } }
    }

    /// За сколько дней предупреждать об истечении ключа
    var keyExpiryWarningDays: Int {
        get { locked { defaults.integer(forKey: Keys.keyExpiryWarningDays) } }
        set { locked { defaults.set(newValue, forKey: Keys.keyExpiryWarningDays) } }
    }

    /// Email ключа по умолчанию (вычисляется из fingerprint)
    var defaultKeyEmail: String? {
        guard let fp = defaultKeyFingerprint else { return nil }
        return KeyCache.shared.getSecretKeys().first { $0.fingerprint == fp }?.email
    }

    // MARK: - Thread safety

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
