import Foundation

/// Фоновый сервис: синхронизация ключей + обработка IPC-запросов от расширения
final class KeySyncService {
    static let shared = KeySyncService()

    private var syncTimer: Timer?
    private var ipcTimer: Timer?
    private let syncQueue = DispatchQueue(label: "com.freegpgmail.keysync", qos: .utility)
    private let ipcQueue = DispatchQueue(label: "com.freegpgmail.ipc", qos: .userInitiated)

    private init() {}

    /// Запускает синхронизацию ключей и IPC-обработку
    func start() {
        stop()
        let interval = Settings.shared.keySyncInterval
        NSLog("[FreeGPGMail] KeySync: starting with interval %.0f sec", interval)

        syncNow()

        DispatchQueue.main.async { [weak self] in
            // Таймер синхронизации ключей
            self?.syncTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
                self?.syncNow()
            }

            // Таймер обработки IPC-запросов (каждые 0.3 сек)
            self?.ipcTimer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
                self?.processIPC()
            }
        }
    }

    func stop() {
        syncTimer?.invalidate()
        syncTimer = nil
        ipcTimer?.invalidate()
        ipcTimer = nil
    }

    func restart() {
        start()
    }

    func syncNow() {
        syncQueue.async {
            let secretKeys = GPGHelper.listSecretKeys()
            let publicKeys = GPGHelper.listPublicKeys()
            SharedKeyFile.write(secretKeys: secretKeys, publicKeys: publicKeys)
            NSLog("[FreeGPGMail] KeySync: synced %d secret, %d public keys", secretKeys.count, publicKeys.count)
        }
    }

    private func processIPC() {
        ipcQueue.async {
            CryptoIPC.processRequests()
        }
    }
}
