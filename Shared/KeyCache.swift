import Foundation

/// Кэш GPG-ключей с TTL для избежания частых вызовов gpg CLI
final class KeyCache: @unchecked Sendable {
    static let shared = KeyCache()

    private let lock = NSLock()
    private var secretKeys: [GPGKeyInfo] = []
    private var publicKeys: [GPGKeyInfo] = []
    private var secretKeysTimestamp: Date = .distantPast
    private var publicKeysTimestamp: Date = .distantPast

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

        Log.keys.info("Secret keys: refreshing from gpg")
        let keys = GPGHelper.listSecretKeys()
        secretKeys = keys
        secretKeysTimestamp = Date()
        Log.keys.info("Secret keys: found \(keys.count)")
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

        Log.keys.info("Public keys: refreshing from gpg")
        let keys = GPGHelper.listPublicKeys()
        publicKeys = keys
        publicKeysTimestamp = Date()
        Log.keys.info("Public keys: found \(keys.count)")
        return keys
    }

    // MARK: - Lookups

    /// Поиск публичного ключа по email (через кэш)
    func findPublicKey(for email: String) -> GPGKeyInfo? {
        let keys = getPublicKeys()
        return keys.first { $0.email.lowercased() == email.lowercased() }
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
