.PHONY: generate build release clean open run install uninstall lint check

APP_NAME = FreeGPGMail
APP_BUNDLE = $(APP_NAME).app
INSTALL_DIR = /Applications
EXTENSION_ID = com.freegpgmail.app.mail-extension
BUILD_DIR = build
DERIVED_DATA = $(BUILD_DIR)
CONFIGURATION_DEBUG = Debug
CONFIGURATION_RELEASE = Release

# --- Build ---

# Generate Xcode project via xcodegen
generate:
	@command -v xcodegen >/dev/null 2>&1 || { echo "Install xcodegen: brew install xcodegen"; exit 1; }
	xcodegen generate

# Debug build
build: generate
	xcodebuild -project $(APP_NAME).xcodeproj \
		-scheme $(APP_NAME) \
		-configuration $(CONFIGURATION_DEBUG) \
		-derivedDataPath $(DERIVED_DATA) \
		build

# Release build
release: generate
	xcodebuild -project $(APP_NAME).xcodeproj \
		-scheme $(APP_NAME) \
		-configuration $(CONFIGURATION_RELEASE) \
		-derivedDataPath $(DERIVED_DATA) \
		build

# --- Install / Uninstall ---

# Build, install to /Applications, register extension, launch app
install: build
	@echo "Installing $(APP_BUNDLE) to $(INSTALL_DIR)..."
	@rm -rf "$(INSTALL_DIR)/$(APP_BUNDLE)"
	@cp -R "$(DERIVED_DATA)/Build/Products/$(CONFIGURATION_DEBUG)/$(APP_BUNDLE)" "$(INSTALL_DIR)/$(APP_BUNDLE)"
	@echo "Registering extension..."
	@pluginkit -e use -i $(EXTENSION_ID) 2>/dev/null || true
	@echo "Launching $(APP_NAME)..."
	@open "$(INSTALL_DIR)/$(APP_BUNDLE)"
	@echo ""
	@echo "Done! Enable the extension in System Settings -> Extensions -> Mail"
	@echo "Then restart Mail."

# Uninstall from /Applications
uninstall:
	@echo "Uninstalling $(APP_BUNDLE)..."
	@pkill -f $(APP_NAME) 2>/dev/null || true
	@rm -rf "$(INSTALL_DIR)/$(APP_BUNDLE)"
	@echo "Done."

# --- Lint ---

# Run SwiftLint
lint:
	@command -v swiftlint >/dev/null 2>&1 || { echo "Install swiftlint: brew install swiftlint"; exit 1; }
	swiftlint lint --config .swiftlint.yml

# Run SwiftLint with auto-fix
lint-fix:
	@command -v swiftlint >/dev/null 2>&1 || { echo "Install swiftlint: brew install swiftlint"; exit 1; }
	swiftlint lint --fix --config .swiftlint.yml

# --- Checks ---

# Run all checks (lint + build)
check: lint build
	@echo "All checks passed."

# --- Utilities ---

# Open in Xcode
open: generate
	open $(APP_NAME).xcodeproj

# Build and run
run: build
	open "$(DERIVED_DATA)/Build/Products/$(CONFIGURATION_DEBUG)/$(APP_BUNDLE)"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(APP_NAME).xcodeproj
