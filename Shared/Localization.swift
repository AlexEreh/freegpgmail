import Foundation

/// Локализованные строки для FreeGPGMail
enum L10n {
    // MARK: - General
    static let appName = NSLocalizedString("app.name", value: "FreeGPGMail", comment: "App name")
    static let appSubtitle = NSLocalizedString("app.subtitle", value: "Бесплатное GPG-шифрование для Apple Mail", comment: "App subtitle")

    // MARK: - Status
    static let statusChecking = NSLocalizedString("status.checking", value: "Проверяю GPG...", comment: "")
    static let statusInstalled = NSLocalizedString("status.installed", value: "GPG установлен", comment: "")
    static let statusNotInstalled = NSLocalizedString("status.not_installed", value: "GPG не найден", comment: "")
    static let statusTitle = NSLocalizedString("status.title", value: "Статус", comment: "")

    // MARK: - Setup
    static let setupTitle = NSLocalizedString("setup.title", value: "Настройка", comment: "")
    static let setupStep1 = NSLocalizedString("setup.step1", value: "Установите GPG: brew install gnupg", comment: "")
    static let setupStep2 = NSLocalizedString("setup.step2", value: "Создайте ключ: gpg --full-generate-key", comment: "")
    static let setupStep3 = NSLocalizedString("setup.step3", value: "Откройте Системные настройки → Расширения → Mail", comment: "")
    static let setupStep4 = NSLocalizedString("setup.step4", value: "Включите FreeGPGMail", comment: "")
    static let setupStep5 = NSLocalizedString("setup.step5", value: "Перезапустите Mail", comment: "")

    // MARK: - Keys
    static let keysTitle = NSLocalizedString("keys.title", value: "GPG-ключи", comment: "")
    static let keysNone = NSLocalizedString("keys.none", value: "Ключи не найдены. Создайте ключ командой gpg --full-generate-key", comment: "")
    static let keysRefresh = NSLocalizedString("keys.refresh", value: "Обновить", comment: "")
    static let keysDefault = NSLocalizedString("keys.default", value: "По умолчанию", comment: "")
    static let keysSecretTitle = NSLocalizedString("keys.secret_title", value: "Секретные ключи", comment: "")
    static let keysPublicTitle = NSLocalizedString("keys.public_title", value: "Публичные ключи", comment: "")

    // MARK: - Settings
    static let settingsTitle = NSLocalizedString("settings.title", value: "Настройки", comment: "")
    static let settingsAutoSign = NSLocalizedString("settings.auto_sign", value: "Автоматически подписывать исходящие письма", comment: "")
    static let settingsAutoEncrypt = NSLocalizedString("settings.auto_encrypt", value: "Автоматически шифровать (если есть ключи всех получателей)", comment: "")
    static let settingsBlockRemote = NSLocalizedString("settings.block_remote", value: "Блокировать удалённый контент в зашифрованных письмах", comment: "")
    static let settingsDefaultKey = NSLocalizedString("settings.default_key", value: "Ключ по умолчанию", comment: "")
    static let settingsDefaultKeyAuto = NSLocalizedString("settings.default_key.auto", value: "Автоматически (по email отправителя)", comment: "")
    static let settingsSignTitle = NSLocalizedString("settings.sign.title", value: "Подпись", comment: "")
    static let settingsEncryptTitle = NSLocalizedString("settings.encrypt.title", value: "Шифрование", comment: "")
    static let settingsAgentTitle = NSLocalizedString("settings.agent.title", value: "GPG Agent", comment: "")
    static let settingsPinentryMode = NSLocalizedString("settings.pinentry_mode", value: "Режим pinentry", comment: "")
    static let settingsPinentryDefault = NSLocalizedString("settings.pinentry.default", value: "По умолчанию", comment: "")
    static let settingsPinentryAsk = NSLocalizedString("settings.pinentry.ask", value: "Всегда спрашивать", comment: "")
    static let settingsPinentryLoopback = NSLocalizedString("settings.pinentry.loopback", value: "Loopback", comment: "")
    static let settingsCacheTTL = NSLocalizedString("settings.cache_ttl", value: "TTL кэша ключей:", comment: "")

    // MARK: - Diagnostics
    static let diagTitle = NSLocalizedString("diag.title", value: "Диагностика", comment: "")
    static let diagLogging = NSLocalizedString("diag.logging", value: "Логирование", comment: "")
    static let diagLoggingEnable = NSLocalizedString("diag.logging.enable", value: "Включить логирование", comment: "")
    static let diagLoggingHint = NSLocalizedString("diag.logging.hint", value: "Логи доступны через Console.app (подсистема com.freegpgmail.app)", comment: "")
    static let diagActionsTitle = NSLocalizedString("diag.actions.title", value: "Действия", comment: "")
    static let diagExport = NSLocalizedString("diag.export", value: "Экспорт диагностики", comment: "")
    static let diagResetCache = NSLocalizedString("diag.reset_cache", value: "Сбросить кэш ключей", comment: "")
    static let diagRestartAgent = NSLocalizedString("diag.restart_agent", value: "Перезапустить gpg-agent", comment: "")

    // MARK: - Key Management
    static let keyMgmtTitle = NSLocalizedString("keymgmt.title", value: "Управление ключами", comment: "")
    static let keyMgmtSearch = NSLocalizedString("keymgmt.search", value: "Поиск на сервере ключей", comment: "")
    static let keyMgmtSearchPlaceholder = NSLocalizedString("keymgmt.search.placeholder", value: "Email или ID ключа", comment: "")
    static let keyMgmtSearchButton = NSLocalizedString("keymgmt.search.button", value: "Найти", comment: "")
    static let keyMgmtImport = NSLocalizedString("keymgmt.import", value: "Импорт ключа", comment: "")
    static let keyMgmtFromClipboard = NSLocalizedString("keymgmt.from_clipboard", value: "Из буфера обмена", comment: "")
    static let keyMgmtFromFile = NSLocalizedString("keymgmt.from_file", value: "Из файла...", comment: "")
    static let keyMgmtPasteText = NSLocalizedString("keymgmt.paste_text", value: "Вставить текст...", comment: "")

    // MARK: - Security Banners
    static let bannerEncrypted = NSLocalizedString("banner.encrypted", value: "Зашифрованное сообщение расшифровано", comment: "")
    static let bannerDecryptFailed = NSLocalizedString("banner.decrypt_failed", value: "Не удалось расшифровать сообщение", comment: "")
    static let bannerSignedValid = NSLocalizedString("banner.signed_valid", value: "Подписано: %@", comment: "")
    static let bannerSignedInvalid = NSLocalizedString("banner.signed_invalid", value: "Недействительная подпись", comment: "")
    static let bannerSignedMultiple = NSLocalizedString("banner.signed_multiple", value: "Подписано (%d): %@", comment: "")
    static let bannerDetails = NSLocalizedString("banner.details", value: "Подробнее", comment: "")
    static let bannerEncryptedAndSigned = NSLocalizedString("banner.encrypted_signed", value: "Зашифровано и подписано (%@)", comment: "")

    // MARK: - Compose
    static let composeAuto = NSLocalizedString("compose.auto", value: "Авто (по email)", comment: "")
    static let composeSignAvailable = NSLocalizedString("compose.sign_available", value: "Подпись доступна", comment: "")
    static let composeSignUnavailable = NSLocalizedString("compose.sign_unavailable", value: "Нет ключа для подписи", comment: "")
    static let composeEncryptAvailable = NSLocalizedString("compose.encrypt_available", value: "Шифрование доступно (ключи всех получателей найдены)", comment: "")
    static let composeEncryptUnavailable = NSLocalizedString("compose.encrypt_unavailable", value: "Шифрование недоступно (не все ключи найдены)", comment: "")
    static let composeGPGUnavailable = NSLocalizedString("compose.gpg_unavailable", value: "GPG недоступен", comment: "")

    // MARK: - Address Annotations
    static let annotationKeyFound = NSLocalizedString("annotation.key_found", value: "GPG-ключ найден", comment: "")
    static let annotationKeyNotFound = NSLocalizedString("annotation.key_not_found", value: "GPG-ключ не найден — шифрование недоступно", comment: "")

    // MARK: - Errors
    static let errorSigningFailed = NSLocalizedString("error.signing_failed", value: "Не удалось подписать сообщение", comment: "")
    static let errorEncryptionFailed = NSLocalizedString("error.encryption_failed", value: "Не удалось зашифровать сообщение", comment: "")
    static let errorDecryptionFailed = NSLocalizedString("error.decryption_failed", value: "Не удалось расшифровать сообщение", comment: "")
    static let errorVerificationFailed = NSLocalizedString("error.verification_failed", value: "Подпись недействительна", comment: "")
    static let errorGPGNotFound = NSLocalizedString("error.gpg_not_found", value: "GPG не найден. Установите: brew install gnupg", comment: "")

    // MARK: - Security Info
    static let secInfoEncrypted = NSLocalizedString("secinfo.encrypted", value: "Зашифровано", comment: "")
    static let secInfoSigned = NSLocalizedString("secinfo.signed", value: "Подписано: %@", comment: "")
    static let secInfoInvalidSig = NSLocalizedString("secinfo.invalid_sig", value: "Недействительная подпись", comment: "")
    static let secInfoInvalidSigFrom = NSLocalizedString("secinfo.invalid_sig_from", value: "Недействительная подпись: %@", comment: "")
    static let secInfoKey = NSLocalizedString("secinfo.key", value: "Ключ: %@", comment: "")
    static let secInfoDecryptError = NSLocalizedString("secinfo.decrypt_error", value: "Ошибка расшифровки: %@", comment: "")
    static let secInfoNoData = NSLocalizedString("secinfo.no_data", value: "Нет данных о безопасности", comment: "")

    // MARK: - Trust Levels
    static let trustUltimate = NSLocalizedString("trust.ultimate", value: "полное доверие", comment: "")
    static let trustFull = NSLocalizedString("trust.full", value: "доверенный", comment: "")
    static let trustMarginal = NSLocalizedString("trust.marginal", value: "частичное доверие", comment: "")
    static let trustUndefined = NSLocalizedString("trust.undefined", value: "доверие не задано", comment: "")
    static let trustNever = NSLocalizedString("trust.never", value: "не доверенный!", comment: "")
    static let trustExpired = NSLocalizedString("trust.expired", value: "ключ истёк!", comment: "")
}
