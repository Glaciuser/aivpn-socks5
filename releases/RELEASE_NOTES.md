# AIVPN Client Releases - March 30, 2026

## 📦 Обновлённые Клиенты

Все клиенты обновлены с исправлениями для предотвращения разрывов соединения.

### Изменения:
- ✅ Исправлен Ctrl+C handler (отдельная задача вместо блокировки)
- ✅ Исправлен MutexGuard deadlock при отправке control сообщений
- ✅ Добавлена обработка consecutive errors для UDP socket
- ✅ Улучшена обработка shutdown сигналов
- ✅ Исправлен borrow checker в main.rs

---

## 🖥️ macOS

**Файл:** `aivpn-macos.dmg`  
**Размер:** 2.2 MB  
**Архитектура:** Universal Binary (arm64 + x86_64)  
**Минимальная версия:** macOS 13.0+

### Установка:
1. Откройте `aivpn-macos.dmg`
2. Перетащите **Aivpn.app** в Applications
3. Запустите из Applications folder

### Быстрый старт:
```bash
# Или запустить напрямую из терминала
open /Applications/Aivpn.app
```

---

## 🪟 Windows

**Файл:** `aivpn-client.exe`  
**Размер:** 6.4 MB  
**Архитектура:** x86_64  
**Требования:** Windows 10/11, [wintun.dll](https://www.wintun.net/)

### Установка:
1. Скачайте [wintun.dll](https://www.wintun.net/)
2. Положите `wintun.dll` рядом с `aivpn-client.exe`
3. Запустите PowerShell **от имени Администратора**

### Быстрый старт:
```powershell
.\aivpn-client.exe -k "aivpn://eyJp..."
```

---

## 🤖 Android

**Файл:** `aivpn-client.apk`  
**Размер:** 6.5 MB  
**Минимальная версия:** Android 8.0+  
**Разрешения:** VPN, Internet, Foreground Service

### Установка:
1. Включите "Install from Unknown Sources" в настройках
2. Установите APK
3. Откройте приложение и вставьте connection key

### Быстрый старт:
1. Откройте приложение
2. Вставьте `aivpn://...` ключ подключения
3. Нажмите **Connect**

---

## 🔧 Linux (CLI)

**Файл:** `aivpn-client-macos` (переименуйте для вашей платформы)  
**Размер:** 3.2 MB  
**Требования:** sudo права для TUN устройства

### Сборка из исходников:
```bash
cargo build --release
sudo ./target/release/aivpn-client -k "aivpn://..."
```

### Full tunnel mode:
```bash
sudo ./target/release/aivpn-client -k "aivpn://..." --full-tunnel
```

---

## 📝 Connection Key

Все клиенты используют единый формат connection key:

```
aivpn://BASE64({"s":"server:port","k":"server_pubkey","p":"psk","i":"vpn_ip"})
```

Получить key можно от сервера:
```bash
docker exec aivpn-server aivpn-server \
  --add-client "My Phone" \
  --key-file /etc/aivpn/server.key \
  --server-ip YOUR_PUBLIC_IP
```

---

## 🐛 Известные Проблемы

- ⚠️ Windows: Требуется wintun.dll отдельно
- ⚠️ macOS: Может потребоваться `xattr -cr` для снятия карантина
- ⚠️ Android: На некоторых устройствах требуется ручное разрешение VPN

---

## 📊 Статистика Релиза

| Платформа | Файл | Размер | Статус |
|-----------|------|--------|--------|
| macOS DMG | aivpn-macos.dmg | 2.2 MB | ✅ Готово |
| Windows EXE | aivpn-client.exe | 6.4 MB | ✅ Готово |
| Android APK | aivpn-client.apk | 6.5 MB | ✅ Готово |
| macOS Binary | aivpn-client-macos | 3.2 MB | ✅ Готово |

---

## 🔐 Проверка Контрольных Сумм

```bash
# macOS
shasum -a 256 releases/aivpn-macos.dmg

# Windows
certutil -hashfile releases\aivpn-client.exe SHA256

# Android
sha256sum releases/aivpn-client.apk
```

---

**Дата сборки:** March 30, 2026  
**Версия:** 0.2.0  
**Статус:** ✅ Stable
