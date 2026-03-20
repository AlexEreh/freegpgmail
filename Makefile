.PHONY: generate build clean install run

# Генерация Xcode-проекта через xcodegen
generate:
	@command -v xcodegen >/dev/null 2>&1 || { echo "Установите xcodegen: brew install xcodegen"; exit 1; }
	xcodegen generate

# Сборка проекта
build: generate
	xcodebuild -project FreeGPGMail.xcodeproj \
		-scheme FreeGPGMail \
		-configuration Debug \
		-derivedDataPath build \
		build

# Сборка Release
release: generate
	xcodebuild -project FreeGPGMail.xcodeproj \
		-scheme FreeGPGMail \
		-configuration Release \
		-derivedDataPath build \
		build

# Очистка
clean:
	rm -rf build
	rm -rf FreeGPGMail.xcodeproj

# Открыть в Xcode
open: generate
	open FreeGPGMail.xcodeproj

# Запуск приложения
run: build
	open build/Build/Products/Debug/FreeGPGMail.app
