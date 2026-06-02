<div align="center">

# 👻 GhostSniff MEGA

**`WiFi & BLE Sniffer · ESP32 · Çift Kart Mimarisi`**

<br>

[![Live Demo](https://img.shields.io/badge/🌐_Canlı_Demo-GitHub_Pages-1f6feb?style=for-the-badge)](https://eren-oztk.github.io/GhostSniff-MEGA)
[![Language](https://img.shields.io/badge/C++-100%25-00599C?style=for-the-badge&logo=cplusplus)](https://github.com/Eren-Oztk/GhostSniff-MEGA)
[![Platform](https://img.shields.io/badge/ESP32-Deneyap_Kart-red?style=for-the-badge)](https://github.com/Eren-Oztk/GhostSniff-MEGA)

</div>

---

> ⚠ **Uyarı:** Bu araç yalnızca eğitim ve araştırma amaçlıdır.
> Yalnızca kendi cihazlarınızda ve ağlarınızda test edin.
> İzinsiz kullanım yasalara aykırıdır.

---

**Versiyon:** `v5.0`

**TR:** Çevre WiFi ağlarını ve Bluetooth cihazlarını sessizce tespit eden, Arduino MEGA ile çalışan çift kart ESP32 sniffer sistemi.

**EN:** A dual-board ESP32 sniffer system that silently detects nearby WiFi networks and Bluetooth devices, communicating with an Arduino MEGA master board over Serial2.

---

## Ne Yapar?

GhostSniff MEGA, Deneyap Kart (ESP32) üzerinde çalışan ve bir Arduino MEGA'ya bağlı olan kablosuz ağ izleme aracıdır. Promiscuous modda çalışarak çevresindeki WiFi beacon çerçevelerini, probe request'lerini ve BLE cihazlarını yakalar. Toplanan veriler Serial2 hattı üzerinden MEGA'ya aktarılır.

Ek olarak BLE Keyboard modunda bilgisayara kablosuz klavye olarak bağlanır; F1-F12, özel tuş kombinasyonları ve makrolar desteklenir.

---

## Nasıl Çalışır?

ESP32, `esp_wifi_set_promiscuous()` API'si ile WiFi kartını izleme moduna alır. Her beacon veya probe paketi IRAM'daki callback fonksiyonuna düşer. MAC adresi 30 saniyelik duplicate filtreden geçer, şifreleme türü (WPA3/WPA2/WPA/WEP/OPEN) ham paket baytlarından çözümlenir ve sonuç `Serial2.printf()` ile MEGA'ya iletilir.

BLE taraması, `BLEScan` API'si ile 3 saniyelik pencereler halinde gerçekleşir. BLE Keyboard modu aktifken cihaz Bluetooth HID klavye olarak bilgisayara bağlanır.

Mevcut mod `Preferences` (NVS flash) içinde kalıcı olarak saklanır; restart sonrası korunur.

---

## Çalışma Modları

| Mod | Açıklama |
|-----|----------|
| 1   | WiFi Beacon Sniffer — çevredeki AP'leri tespit eder (SSID, MAC, RSSI, şifreleme, kanal) |
| 2   | Probe Request Sniffer — cihazların aradığı ağları yakalar |
| 3   | BLE Scanner — Bluetooth cihazlarını listeler |
| 4   | BLE Keyboard — PC'ye kablosuz klavye olarak bağlanır |
| 5–9 | Genişletilmiş probe modu |
| 10  | Chat Modu |

---

## Donanım / Pin Bağlantıları

| Pin (Deneyap Kart) | Bağlantı |
|--------------------|----------|
| D8  | Serial2 RX (MEGA TX'e) |
| D4  | Serial2 TX (MEGA RX'e) |
| D9  | SD Kart CS |
| D13 | SD Kart MOSI |
| D14 | SD Kart SCK |
| D15 | SD Kart MISO |
| LED_BUILTIN | Durum LED'i |

> 📌 Bu firmware Deneyap Kart üzerinde test edilmiştir. Diğer ESP32 kartlarında pin numaraları farklılık gösterebilir.

---

## Kurulum

```bash
# 1. Arduino IDE'de ESP32 desteği ekle
# Board Manager → "esp32 by Espressif Systems"

# 2. Gerekli kütüphaneleri kur (Library Manager)
# Tümü aşağıdaki Bağımlılıklar tablosunda

# 3. Board: Deneyap Kart (veya uyumlu ESP32)

# 4. .ino dosyasını yükle
```

Serial2 hattını Arduino MEGA'ya bağla:
- ESP32 D8 (RX) ← MEGA TX pinime
- ESP32 D4 (TX) → MEGA RX pinine
- Her iki kart için ortak GND

---

## Bağımlılıklar

| Kütüphane | Sürüm | Kaynak |
|-----------|-------|--------|
| esp32 Arduino Core | ≥ 2.0 | Espressif Board Manager |
| BleKeyboard | 0.3.x | GitHub: T-vK/ESP32-BLE-Keyboard |
| Arduino SD | dahili | ESP32 core |
| ESP32 BLE Arduino | dahili | ESP32 core |

---

## Serial2 Protokolü

ESP32 → MEGA çıktı formatları:

```
WIFI,<MAC>,<RSSI>,<SSID>,<ENC>,<KANAL>
PROBE,<MAC>,<RSSI>,<HEDEF_SSID>
BLE,<MAC>,<RSSI>,<CİHAZ_ADI>
STATS:PKT=<n>,DEV=<n>,CH=<n>
KB:CONNECTED / KB:WAITING / KB:OK
```

MEGA → ESP32 komutları:

```
CMD:<1-10>    → Mod değiştir (restart ile)
CH:<1-13>     → Kanal ayarla
RESET         → Sayaçları sıfırla
KB:<komut>    → Klavye komutu (Mod 4)
```

---

## Bilinen Limitasyonlar

- 5 GHz WiFi yakalanmaz (ESP32 sadece 2.4 GHz)
- Şifreli paket içerikleri çözülemez
- Duplicate filtresi bellekte 50 MAC tutar; dolduğunda en eskisi silinir

---

## Lisans

MIT © 2026 Eren Özatak
