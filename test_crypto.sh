#!/bin/bash
set -e

GPG="/opt/homebrew/bin/gpg"
TMPDIR=$(mktemp -d)
echo "=== FreeGPGMail Crypto Test ==="
echo "Temp dir: $TMPDIR"
echo ""

# Определяем email отправителя
SENDER=$($GPG --list-secret-keys --with-colons 2>/dev/null | grep '^uid' | head -1 | cut -d: -f10 | grep -oE '<[^>]+>' | tr -d '<>')
if [ -z "$SENDER" ]; then
    echo "❌ Нет секретных ключей!"
    exit 1
fi
echo "Отправитель: $SENDER"

# Ищем fingerprint
FP=$($GPG --list-secret-keys --with-colons "$SENDER" 2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
echo "Fingerprint: $FP"
echo ""

# === Тест 1: Подпись ===
echo "--- Тест 1: PGP/MIME подпись ---"

# Создаём тело письма (как это делает CryptoIPC)
BODY_PART="Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nПривет! Это тестовое подписанное письмо."
printf "$BODY_PART" > "$TMPDIR/body.txt"

# Подписываем (detach-sign, как GPGHelper.sign)
$GPG --batch --yes --armor --detach-sign --default-key "$SENDER" \
    --pinentry-mode loopback \
    -o "$TMPDIR/signature.asc" "$TMPDIR/body.txt" 2>"$TMPDIR/sign_err.txt" && {
    echo "✅ Подпись создана"

    # Строим PGP/MIME
    BOUNDARY="----FreeGPGMail-TEST-$(date +%s)"
    cat > "$TMPDIR/signed_email.eml" << EOFMAIL
From: Test <$SENDER>
To: Test <$SENDER>
Subject: FreeGPGMail Test - Signed
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="$BOUNDARY"

--$BOUNDARY
$(cat "$TMPDIR/body.txt")
--$BOUNDARY
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="signature.asc"

$(cat "$TMPDIR/signature.asc")
--$BOUNDARY--
EOFMAIL

    echo "✅ PGP/MIME signed email создан: $TMPDIR/signed_email.eml"
    echo "   Размер: $(wc -c < "$TMPDIR/signed_email.eml") байт"

    # Верифицируем
    $GPG --verify "$TMPDIR/signature.asc" "$TMPDIR/body.txt" 2>"$TMPDIR/verify_out.txt" && {
        echo "✅ Подпись верифицирована!"
        grep -iE "Good signature|Действительная подпись" "$TMPDIR/verify_out.txt" && true
    } || {
        echo "❌ Подпись НЕ верифицирована!"
        cat "$TMPDIR/verify_out.txt"
    }
} || {
    echo "❌ Не удалось подписать!"
    cat "$TMPDIR/sign_err.txt"
}

echo ""

# === Тест 2: Шифрование ===
echo "--- Тест 2: PGP/MIME шифрование ---"

PLAIN_BODY="Content-Type: text/plain; charset=utf-8\r\n\r\nСекретное сообщение! 🔐"
printf "$PLAIN_BODY" > "$TMPDIR/plain.txt"

$GPG --batch --yes --armor --encrypt --recipient "$SENDER" \
    --trust-model always \
    -o "$TMPDIR/encrypted.asc" "$TMPDIR/plain.txt" 2>"$TMPDIR/enc_err.txt" && {
    echo "✅ Шифрование успешно"
    echo "   Размер шифротекста: $(wc -c < "$TMPDIR/encrypted.asc") байт"

    # Расшифровываем
    $GPG --batch --yes --decrypt --pinentry-mode loopback \
        "$TMPDIR/encrypted.asc" > "$TMPDIR/decrypted.txt" 2>"$TMPDIR/dec_err.txt" && {
        echo "✅ Расшифровка успешна"
        echo "   Содержимое: $(cat "$TMPDIR/decrypted.txt")"
    } || {
        echo "❌ Расшифровка не удалась!"
        cat "$TMPDIR/dec_err.txt"
    }
} || {
    echo "❌ Шифрование не удалось!"
    cat "$TMPDIR/enc_err.txt"
}

echo ""

# === Тест 3: Подпись + Шифрование ===
echo "--- Тест 3: Подпись + Шифрование ---"

$GPG --batch --yes --armor --encrypt --sign \
    --default-key "$SENDER" --recipient "$SENDER" \
    --trust-model always --pinentry-mode loopback \
    -o "$TMPDIR/sign_enc.asc" "$TMPDIR/plain.txt" 2>"$TMPDIR/se_err.txt" && {
    echo "✅ Подпись+Шифрование успешно"

    $GPG --batch --yes --decrypt --pinentry-mode loopback \
        "$TMPDIR/sign_enc.asc" > "$TMPDIR/se_dec.txt" 2>"$TMPDIR/se_dec_err.txt" && {
        echo "✅ Расшифровка+Верификация успешна"
        grep -qiE "Good signature|Действительная подпись" "$TMPDIR/se_dec_err.txt" && echo "✅ Подпись в зашифрованном сообщении верна" || echo "⚠️  Подпись не проверена (может быть OK)"
    } || {
        echo "❌ Расшифровка не удалась!"
        cat "$TMPDIR/se_dec_err.txt"
    }
} || {
    echo "❌ Подпись+Шифрование не удалось!"
    cat "$TMPDIR/se_err.txt"
}

echo ""

# === Тест 4: IPC (если приложение запущено) ===
echo "--- Тест 4: IPC через CryptoIPC ---"

IPC_DIR="/tmp/freegpgmail-ipc"
mkdir -p "$IPC_DIR"

REQ_ID="test-$(date +%s)"
RAW_EMAIL="From: Test <$SENDER>\r\nTo: Test <$SENDER>\r\nSubject: IPC Test\r\nContent-Type: text/plain; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\nТестовое письмо через IPC."

# Base64-кодируем данные для JSON
RAW_B64=$(printf "$RAW_EMAIL" | base64)

# Создаём JSON запрос (используем python для корректного JSON)
python3 -c "
import json, base64
data = '$RAW_EMAIL'.encode().replace(b'\\\\r\\\\n', b'\r\n')
req = {
    'id': '$REQ_ID',
    'operation': 'sign',
    'data': base64.b64encode(data).decode(),
    'signer': '$SENDER',
    'recipients': None
}
# CryptoIPC использует Codable, Data кодируется как base64
print(json.dumps(req))
" > "$IPC_DIR/req-$REQ_ID.json"

echo "IPC запрос записан: req-$REQ_ID.json"
echo "Ожидание ответа (5 сек)..."

for i in $(seq 1 50); do
    if [ -f "$IPC_DIR/resp-$REQ_ID.json" ]; then
        echo "✅ IPC ответ получен!"
        python3 -c "
import json, base64
with open('$IPC_DIR/resp-$REQ_ID.json') as f:
    resp = json.load(f)
print(f'  Success: {resp[\"success\"]}')
print(f'  Signed: {resp[\"isSigned\"]}')
print(f'  Encrypted: {resp[\"isEncrypted\"]}')
if resp.get('error'):
    print(f'  Error: {resp[\"error\"]}')
if resp.get('data'):
    data = base64.b64decode(resp['data'])
    print(f'  Data size: {len(data)} bytes')
    text = data.decode('utf-8', errors='replace')
    # Показываем первые 500 символов
    print(f'  Data preview:')
    for line in text[:500].split('\n'):
        print(f'    {line}')
    if len(text) > 500:
        print(f'    ... ({len(text)-500} more bytes)')
"
        rm -f "$IPC_DIR/resp-$REQ_ID.json"
        break
    fi
    sleep 0.1
done

if [ ! -f "$IPC_DIR/resp-$REQ_ID.json" ] && [ $i -eq 50 ]; then
    echo "⚠️  IPC таймаут. Убедитесь что FreeGPGMail.app запущен."
    rm -f "$IPC_DIR/req-$REQ_ID.json"
fi

echo ""

# === Тест 5: Проверка кэш-файла ===
echo "--- Тест 5: Кэш ключей ---"
CACHE="/tmp/freegpgmail-keycache.json"
if [ -f "$CACHE" ]; then
    python3 -c "
import json
with open('$CACHE') as f:
    data = json.load(f)
print(f'✅ Кэш найден')
print(f'  Secret keys: {len(data.get(\"secretKeys\", []))}')
print(f'  Public keys: {len(data.get(\"publicKeys\", []))}')
print(f'  Timestamp: {data.get(\"timestamp\", \"?\")}')
for k in data.get('secretKeys', [])[:5]:
    print(f'    🔑 {k[\"email\"]} ({k[\"fingerprint\"][-8:]})')
"
else
    echo "❌ Кэш-файл не найден: $CACHE"
    echo "   Запустите FreeGPGMail.app для создания кэша."
fi

echo ""

# Очистка
rm -rf "$TMPDIR"
echo "=== Тесты завершены ==="
