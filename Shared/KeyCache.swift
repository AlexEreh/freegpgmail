import Foundation

/// Кэш GPG-ключей с TTL для избежания частых вызовов gpg CLI
final class KeyCache: @unchecked Sendable {
    static let shared = KeyCache()

    private let lock = NSLock()
    private var secretKeys: [GPGKeyInfo] = []
    private var publicKeys: [GPGKeyInfo] = []
    private var secretKeysTimestamp: Date = .distantPast
    private var publicKeysTimestamp: Date = .distantPast

    /// Определяем, запущены ли мы в sandbox (расширение)
    private let isSandboxed: Bool = {
        let home = NSHomeDirectory()
        return home.contains("/Library/Containers/")
    }()

    /// Количество закэшированных секретных ключей
    var secretKeysCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return secretKeys.count
    }

    /// Количество закэшированных публичных ключей
    var publicKeysCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return publicKeys.count
    }

    private init() {}

    // MARK: - Secret Keys

    /// Получает секретные ключи (из кэша или свежие)
    func getSecretKeys(forceRefresh: Bool = false) -> [GPGKeyInfo] {
        lock.lock()
        defer { lock.unlock() }

        let ttl = Settings.shared.keyCacheTTL
        if !forceRefresh && Date().timeIntervalSince(secretKeysTimestamp) < ttl && !secretKeys.isEmpty {
            Log.keys.debug("Secret keys: cache hit (\(self.secretKeys.count) keys)")
            return secretKeys
        }

        if isSandboxed {
            // В sandbox-расширении читаем из файла, записанного основным приложением
            NSLog("[FreeGPGMail] KeyCache: sandboxed, reading from shared file")
            if let shared = SharedKeyFile.read() {
                secretKeys = shared.secretKeys
                publicKeys = shared.publicKeys
                secretKeysTimestamp = Date()
                publicKeysTimestamp = Date()
                return secretKeys
            }
            NSLog("[FreeGPGMail] KeyCache: no shared file, returning empty")
            return []
        }

        Log.keys.info("Secret keys: refreshing from gpg")
        let keys = GPGHelper.listSecretKeys()
        secretKeys = keys
        secretKeysTimestamp = Date()
        Log.keys.info("Secret keys: found \(keys.count)")

        // Основное приложение: записываем ключи в файл для расширения
        let pubKeys = publicKeys.isEmpty ? GPGHelper.listPublicKeys() : publicKeys
        if publicKeys.isEmpty {
            publicKeys = pubKeys
            publicKeysTimestamp = Date()
        }
        SharedKeyFile.write(secretKeys: keys, publicKeys: pubKeys)

        return keys
    }

    // MARK: - Public Keys

    /// Получает публичные ключи (из кэша или свежие)
    func getPublicKeys(forceRefresh: Bool = false) -> [GPGKeyInfo] {
        lock.lock()
        defer { lock.unlock() }

        let ttl = Settings.shared.keyCacheTTL
        if !forceRefresh && Date().timeIntervalSince(publicKeysTimestamp) < ttl && !publicKeys.isEmpty {
            Log.keys.debug("Public keys: cache hit (\(self.publicKeys.count) keys)")
            return publicKeys
        }

        if isSandboxed {
            NSLog("[FreeGPGMail] KeyCache: sandboxed, reading from shared file")
            if let shared = SharedKeyFile.read() {
                secretKeys = shared.secretKeys
                publicKeys = shared.publicKeys
                secretKeysTimestamp = Date()
                publicKeysTimestamp = Date()
                return publicKeys
            }
            NSLog("[FreeGPGMail] KeyCache: no shared file, returning empty")
            return []
        }

        Log.keys.info("Public keys: refreshing from gpg")
        let keys = GPGHelper.listPublicKeys()
        publicKeys = keys
        publicKeysTimestamp = Date()
        Log.keys.info("Public keys: found \(keys.count)")

        // Основное приложение: записываем ключи в файл для расширения
        let secKeys = secretKeys.isEmpty ? GPGHelper.listSecretKeys() : secretKeys
        if secretKeys.isEmpty {
            secretKeys = secKeys
            secretKeysTimestamp = Date()
        }
        SharedKeyFile.write(secretKeys: secKeys, publicKeys: keys)

        return keys
    }

    // MARK: - Lookups

    /// Поиск публичного ключа по email (через кэш, затем WKD)
    func findPublicKey(for email: String) -> GPGKeyInfo? {
        let keys = getPublicKeys()
        if let key = keys.first(where: { $0.email.lowercased() == email.lowercased() }) {
            return key
        }

        // Если не в sandbox — пробуем WKD
        if !isSandboxed {
            if GPGHelper.importFromWKD(email: email) {
                Log.keys.info("WKD: imported key for \(email, privacy: .public), refreshing cache")
                invalidatePublicKeys()
                let refreshed = getPublicKeys(forceRefresh: true)
                return refreshed.first { $0.email.lowercased() == email.lowercased() }
            }
        }

        return nil
    }

    /// Поиск секретного ключа по email (через кэш)
    func findSecretKey(for email: String) -> GPGKeyInfo? {
        let keys = getSecretKeys()
        return keys.first { $0.email.lowercased() == email.lowercased() }
    }

    /// Поиск секретного ключа: сначала дефолтный, потом по email
    func findSigningKey(for email: String) -> GPGKeyInfo? {
        let keys = getSecretKeys()

        // Если задан ключ по умолчанию, используем его
        if let defaultFP = Settings.shared.defaultKeyFingerprint,
           let key = keys.first(where: { $0.fingerprint == defaultFP }) {
            return key
        }

        // Иначе ищем по email
        return keys.first { $0.email.lowercased() == email.lowercased() }
    }

    // MARK: - Invalidation

    /// Сбрасывает весь кэш
    func invalidateAll() {
        lock.lock()
        defer { lock.unlock() }
        secretKeys = []
        publicKeys = []
        secretKeysTimestamp = .distantPast
        publicKeysTimestamp = .distantPast
        Log.keys.info("Key cache invalidated")
    }

    /// Сбрасывает только секретные ключи
    func invalidateSecretKeys() {
        lock.lock()
        defer { lock.unlock() }
        secretKeys = []
        secretKeysTimestamp = .distantPast
    }

    /// Сбрасывает только публичные ключи
    func invalidatePublicKeys() {
        lock.lock()
        defer { lock.unlock() }
        publicKeys = []
        publicKeysTimestamp = .distantPast
    }
}
