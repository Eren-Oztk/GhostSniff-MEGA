#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BleKeyboard.h>
#include <SD.h>
#include <SPI.h>

/*
 * ⚡ SIBER SNIFF MEGA v5.0 ⚡
 * 
 * TAMAMEN YENİDEN YAZILDI!
 * ✅ Tüm klavye fonksiyonları (F1-F12, özel tuşlar, makrolar)
 * ✅ Optimize edilmiş veri akışı
 * ✅ Düzgün Serial2 iletişimi
 */

// PIN TANIMLARI
#define RX_PIN D8
#define TX_PIN D4 
#define LED_PIN LED_BUILTIN
#define SD_CS D9
#define SD_MOSI D13
#define SD_SCK D14
#define SD_MISO D15

// GLOBAL
Preferences prefs;
int currentMode = 1;
int currentChannel = 1;
unsigned long lastLed = 0;
unsigned long lastStats = 0;
int packetCount = 0;
int uniqueCount = 0;

// BLE
BleKeyboard bleKb("ESP32-KB", "Deneyap", 100);
BLEScan* pBLEScan;

// SD
bool sdOK = false;

// PAKET YAPILAR
typedef struct { uint8_t mac[6]; } __attribute__((packed)) MacAddr;
typedef struct { 
  int16_t fctl; 
  int16_t duration; 
  MacAddr da; 
  MacAddr sa; 
  MacAddr bssid; 
  int16_t seqctl; 
  unsigned char payload[]; 
} __attribute__((packed)) WifiMgmtHdr;

// DUPLICATE FILTER
struct Seen {
  uint8_t mac[6];
  unsigned long time;
};
Seen seenAP[50];
int seenAPCount = 0;

bool isDuplicate(const uint8_t* mac) {
  unsigned long now = millis();
  for(int i=0; i<seenAPCount; i++) {
    if(now - seenAP[i].time < 30000) {
      bool match = true;
      for(int j=0; j<6; j++) {
        if(seenAP[i].mac[j] != mac[j]) { match = false; break; }
      }
      if(match) {
        seenAP[i].time = now;
        return true;
      }
    }
  }
  return false;
}

void addSeen(const uint8_t* mac) {
  if(seenAPCount >= 50) {
    int oldest = 0;
    for(int i=1; i<50; i++) {
      if(seenAP[i].time < seenAP[oldest].time) oldest = i;
    }
    memcpy(seenAP[oldest].mac, mac, 6);
    seenAP[oldest].time = millis();
  } else {
    memcpy(seenAP[seenAPCount].mac, mac, 6);
    seenAP[seenAPCount].time = millis();
    seenAPCount++;
  }
  uniqueCount++;
}

String getEnc(const uint8_t* p, int len, int off) {
  for(int i=off; i<len-2; i++) {
    if(p[i] == 0x30 && p[i+1] >= 0x14) {
      if(i+8 < len && p[i+8] == 0x08) return "WPA3";
      return "WPA2";
    }
  }
  for(int i=off; i<len-4; i++) {
    if(p[i] == 0xDD && p[i+2] == 0x00 && 
       p[i+3] == 0x50 && p[i+4] == 0xF2 && p[i+5] == 0x01) {
      return "WPA";
    }
  }
  if(p[34] & 0x10) return "WEP";
  return "OPEN";
}

void blinkLed() {
  if(millis() - lastLed > 100) {
    digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    lastLed = millis();
  }
}

// WIFI BEACON SNIFFER
void IRAM_ATTR wifi_sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const WifiMgmtHdr *wh = (WifiMgmtHdr*)pkt->payload;
  
  if(pkt->payload[0] == 0x80) { // BEACON
    if(isDuplicate(wh->bssid.mac)) return;
    
    int rssi = pkt->rx_ctrl.rssi; 
    int off = 36; 
    uint8_t len = pkt->payload[off + 1];
    
    String ssid = "";
    if(len == 0 || len > 32) {
      ssid = "<HIDDEN>";
    } else {
      for(int i=0; i<len; i++) {
        char c = (char)pkt->payload[off + 2 + i];
        if(c >= 32 && c <= 126) ssid += c;
        else ssid += '.';
      }
    }
    
    String enc = getEnc(pkt->payload, pkt->rx_ctrl.sig_len, off);
    
    int ch = currentChannel;
    for(int i=off; i<pkt->rx_ctrl.sig_len-2; i++) {
      if(pkt->payload[i] == 0x03 && pkt->payload[i+1] == 0x01) {
        ch = pkt->payload[i+2];
        break;
      }
    }
    
    Serial2.printf("WIFI,%02X:%02X:%02X:%02X:%02X:%02X,%d,%s,%s,%d\n",
             wh->bssid.mac[0], wh->bssid.mac[1], wh->bssid.mac[2],
             wh->bssid.mac[3], wh->bssid.mac[4], wh->bssid.mac[5], 
             rssi, ssid.c_str(), enc.c_str(), ch);
    
    addSeen(wh->bssid.mac);
    packetCount++;
  }
}

// PROBE SNIFFER
void IRAM_ATTR probe_sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const WifiMgmtHdr *wh = (WifiMgmtHdr*)pkt->payload;
  
  if(pkt->payload[0] == 0x40) { // PROBE
    int pos = 24; 
    int len = pkt->rx_ctrl.sig_len; 
    String target = "";
    
    while(pos < len-1) {
      if(pkt->payload[pos] == 0) {
        uint8_t tLen = pkt->payload[pos+1];
        if(tLen == 0) {
          target = "BROADCAST";
        } else if(tLen <= 32 && pos+2+tLen < len) {
          for(int i=0; i<tLen; i++) {
            char c = (char)pkt->payload[pos+2+i];
            if(c >= 32 && c <= 126) target += c;
            else target += '.';
          }
        }
        break;
      }
      if(pkt->payload[pos+1] == 0 || pos+2+pkt->payload[pos+1] >= len) break;
      pos += 2 + pkt->payload[pos+1];
    }
    
    if(target != "") {
      char mac[18];
      snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
               wh->sa.mac[0], wh->sa.mac[1], wh->sa.mac[2],
               wh->sa.mac[3], wh->sa.mac[4], wh->sa.mac[5]);
      
      Serial2.printf("PROBE,%s,%d,%s\n", mac, pkt->rx_ctrl.rssi, target.c_str());
      packetCount++;
    }
  }
}

// KLAVYE - TÜM FONKSİYONLAR!
void handleKey(String cmd) {
  if(!bleKb.isConnected()) {
    Serial2.println("KB:DISCONNECTED");
    return;
  }
  
  Serial.println("Key: " + cmd);
  
  if(cmd.startsWith("#")) {
    cmd = cmd.substring(1);
    
    // Fonksiyon tuşları
    if(cmd == "F1") bleKb.write(KEY_F1);
    else if(cmd == "F2") bleKb.write(KEY_F2);
    else if(cmd == "F3") bleKb.write(KEY_F3);
    else if(cmd == "F4") bleKb.write(KEY_F4);
    else if(cmd == "F5") bleKb.write(KEY_F5);
    else if(cmd == "F6") bleKb.write(KEY_F6);
    else if(cmd == "F7") bleKb.write(KEY_F7);
    else if(cmd == "F8") bleKb.write(KEY_F8);
    else if(cmd == "F9") bleKb.write(KEY_F9);
    else if(cmd == "F10") bleKb.write(KEY_F10);
    else if(cmd == "F11") bleKb.write(KEY_F11);
    else if(cmd == "F12") bleKb.write(KEY_F12);
    
    // Özel tuşlar
    else if(cmd == "ESC") bleKb.write(KEY_ESC);
    else if(cmd == "TAB") bleKb.write(KEY_TAB);
    else if(cmd == "ENTER") bleKb.write(KEY_RETURN);
    else if(cmd == "SPACE") bleKb.write(' ');
    else if(cmd == "BACKSPACE") bleKb.write(KEY_BACKSPACE);
    else if(cmd == "DELETE") bleKb.write(KEY_DELETE);
    else if(cmd == "INSERT") bleKb.write(KEY_INSERT);
    else if(cmd == "HOME") bleKb.write(KEY_HOME);
    else if(cmd == "END") bleKb.write(KEY_END);
    else if(cmd == "PAGEUP") bleKb.write(KEY_PAGE_UP);
    else if(cmd == "PAGEDOWN") bleKb.write(KEY_PAGE_DOWN);
    else if(cmd == "UP") bleKb.write(KEY_UP_ARROW);
    else if(cmd == "DOWN") bleKb.write(KEY_DOWN_ARROW);
    else if(cmd == "LEFT") bleKb.write(KEY_LEFT_ARROW);
    else if(cmd == "RIGHT") bleKb.write(KEY_RIGHT_ARROW);
    
    // Windows tuşları
    else if(cmd == "WIN") {
      bleKb.press(KEY_LEFT_GUI);
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "WIN_R") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('r');
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "WIN_E") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('e');
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "WIN_D") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('d');
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "WIN_L") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('l');
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "CTRL_ALT_DEL") {
      bleKb.press(KEY_LEFT_CTRL);
      bleKb.press(KEY_LEFT_ALT);
      bleKb.press(KEY_DELETE);
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "ALT_TAB") {
      bleKb.press(KEY_LEFT_ALT);
      bleKb.press(KEY_TAB);
      delay(100);
      bleKb.releaseAll();
    }
    else if(cmd == "ALT_F4") {
      bleKb.press(KEY_LEFT_ALT);
      bleKb.press(KEY_F4);
      delay(100);
      bleKb.releaseAll();
    }
    
    // Makrolar
    else if(cmd == "MACRO_CMD") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('r');
      delay(200);
      bleKb.releaseAll();
      delay(500);
      bleKb.print("cmd");
      delay(100);
      bleKb.write(KEY_RETURN);
    }
    else if(cmd == "MACRO_NOTEPAD") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('r');
      delay(200);
      bleKb.releaseAll();
      delay(500);
      bleKb.print("notepad");
      delay(100);
      bleKb.write(KEY_RETURN);
    }
    else if(cmd == "MACRO_CALC") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('r');
      delay(200);
      bleKb.releaseAll();
      delay(500);
      bleKb.print("calc");
      delay(100);
      bleKb.write(KEY_RETURN);
    }
    else if(cmd == "MACRO_CHROME") {
      bleKb.press(KEY_LEFT_GUI);
      bleKb.press('r');
      delay(200);
      bleKb.releaseAll();
      delay(500);
      bleKb.print("chrome");
      delay(100);
      bleKb.write(KEY_RETURN);
    }
  } else {
    // Normal metin
    bleKb.print(cmd);
  }
  
  Serial2.println("KB:OK");
}

void setup() {
  Serial.begin(115200);
  Serial2.begin(115200, SERIAL_8N1, RX_PIN, TX_PIN); 
  pinMode(LED_PIN, OUTPUT);
  
  delay(500);
  Serial.println("\n⚡ SIBER SNIFF v5.0 ⚡");
  
  // SD
  SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if(SD.begin(SD_CS)) {
    Serial.println("✅ SD OK");
    sdOK = true;
  }
  
  // Prefs
  prefs.begin("mega", false);
  currentMode = prefs.getInt("mode", 1);
  prefs.end();

  Serial.printf("Mode: %d\n", currentMode);
  Serial2.printf("STATUS:MODE=%d\n", currentMode);

  // MOD BAŞLAT
  if(currentMode == 1) {
    Serial.println("📡 WiFi Beacon");
    WiFi.mode(WIFI_STA); 
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer);
  } 
  else if(currentMode == 2) {
    Serial.println("🕵 Probe Request");
    WiFi.mode(WIFI_STA); 
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&probe_sniffer);
  }
  else if(currentMode == 3) {
    Serial.println("📱 BLE Scanner");
    BLEDevice::init(""); 
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setActiveScan(true); 
    pBLEScan->setInterval(100); 
    pBLEScan->setWindow(99);
  }
  else if(currentMode == 4) {
    Serial.println("⌨️ BLE Keyboard");
    bleKb.begin();
  }
  else if(currentMode >= 5 && currentMode <= 9) {
    Serial.printf("Mod %d aktif\n", currentMode);
    WiFi.mode(WIFI_STA); 
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&probe_sniffer);
  }
  else if(currentMode == 10) {
    Serial.println("💬 Chat Mode");
  }
  
  Serial.println("✅ READY\n");
}

unsigned long lastTime = 0;

void loop() {
  blinkLed();
  
  // STATS
  if(millis() - lastStats > 3000) {
    Serial2.printf("STATS:PKT=%d,DEV=%d,CH=%d\n", 
                   packetCount, uniqueCount, currentChannel);
    lastStats = millis();
  }
  
  // KOMUT
  if(Serial2.available()) {
    String data = Serial2.readStringUntil('\n'); 
    data.trim();
    
    if(data.length() == 0) return;
    
    Serial.println("CMD: " + data);
    
    // Mod değiştir
    if(data.startsWith("CMD:")) {
      int m = data.substring(4).toInt();
      if(m >= 1 && m <= 10) {
        Serial.printf("Mode: %d -> %d\n", currentMode, m);
        prefs.begin("mega", false); 
        prefs.putInt("mode", m); 
        prefs.end();
        delay(500);
        ESP.restart();
      }
    }
    // Kanal
    else if(data.startsWith("CH:")) {
      int ch = data.substring(3).toInt();
      if(ch >= 1 && ch <= 13) {
        currentChannel = ch;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial2.printf("CH:OK=%d\n", currentChannel);
      }
    }
    // Reset
    else if(data == "RESET") {
      seenAPCount = 0;
      packetCount = 0;
      uniqueCount = 0;
      Serial2.println("RESET:OK");
    }
    // Klavye
    else if(currentMode == 4 && data.startsWith("KB:")) {
      handleKey(data.substring(3));
    }
  }

  // MOD LOOP
  if(currentMode == 1 || currentMode == 2 || (currentMode >= 5 && currentMode <= 9)) {
    // Kanal değiştir
    if(millis() - lastTime > 500) {
      lastTime = millis(); 
      currentChannel = (currentChannel % 13) + 1;
      esp_wifi_set_promiscuous(true); 
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }
  }
  else if(currentMode == 3) {
    // BLE scan
    BLEScanResults devs = pBLEScan->start(3, false);
    for(int i=0; i<devs.getCount(); i++) {
      BLEAdvertisedDevice d = devs.getDevice(i);
      String mac = d.getAddress().toString().c_str();
      String name = d.getName().c_str(); 
      if(name == "") name = "(N/A)";
      
      Serial2.printf("BLE,%s,%d,%s\n", mac.c_str(), d.getRSSI(), name.c_str());
      packetCount++;
      delay(10);
    }
    pBLEScan->clearResults();
  }
  else if(currentMode == 4) {
    // KB status
    static unsigned long lastKb = 0;
    if(millis() - lastKb > 3000) {
      Serial2.printf("KB:%s\n", bleKb.isConnected() ? "CONNECTED" : "WAITING");
      lastKb = millis();
    }
  }
}
