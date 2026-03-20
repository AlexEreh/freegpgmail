import MailKit

/// Точка входа Mail-расширения
class FreeGPGMailExtension: NSObject, MEExtension {

    func handler(for session: MEComposeSession) -> MEComposeSessionHandler {
        return ComposeSessionHandler()
    }

    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        return MessageSecurityHandler()
    }
}
