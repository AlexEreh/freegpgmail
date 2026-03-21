import SwiftUI

@main
struct FreeGPGMailApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    init() {
        KeySyncService.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

/// AppDelegate: меню-бар иконка + не завершаем при закрытии окна
class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenuBar()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    /// При повторном запуске приложения — показываем окно
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            for window in sender.windows {
                window.makeKeyAndOrderFront(self)
            }
        }
        return true
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "FreeGPGMail")
            button.image?.size = NSSize(width: 18, height: 18)
            button.image?.isTemplate = true
        }

        let menu = NSMenu()

        menu.addItem(withTitle: "Открыть FreeGPGMail", action: #selector(openSettings), keyEquivalent: ",")
            .target = self

        menu.addItem(NSMenuItem.separator())

        menu.addItem(withTitle: "Синхронизировать ключи", action: #selector(syncKeys), keyEquivalent: "")
            .target = self

        let countItem = NSMenuItem(title: "Ключей: \(KeyCache.shared.secretKeysCount)", action: nil, keyEquivalent: "")
        countItem.isEnabled = false
        countItem.tag = 100
        menu.addItem(countItem)

        menu.addItem(NSMenuItem.separator())

        menu.addItem(withTitle: "Выйти", action: #selector(quitApp), keyEquivalent: "q")
            .target = self

        menu.delegate = self
        statusItem?.menu = menu
    }

    @objc private func openSettings() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        if let window = NSApplication.shared.windows.first(where: { $0.contentView != nil }) {
            window.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func syncKeys() {
        KeySyncService.shared.syncNow()
    }

    @objc private func quitApp() {
        NSApplication.shared.terminate(nil)
    }
}

extension AppDelegate: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        // Обновляем количество ключей при открытии меню
        if let item = menu.item(withTag: 100) {
            item.title = "Ключей: \(KeyCache.shared.secretKeysCount)"
        }
    }
}
