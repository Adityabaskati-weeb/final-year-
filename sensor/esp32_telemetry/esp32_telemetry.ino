#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_system.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "DHT.h"

// Copy secrets.example.h to secrets.h and set the local values before uploading.
#include "secrets.h"

#define DHT_PIN 4
#define DHT_TYPE DHT11
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDRESS 0x3C
#define SDA_PIN 21
#define SCL_PIN 22
#define LED_PIN 15
#define BUZZER_PIN 19

DHT dht(DHT_PIN, DHT_TYPE);
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
unsigned long sequenceNumber = 0;
char bootId[33];

void showStatus(const char* status, float temperature, float humidity) {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("Updated IoT IDS");
  display.setCursor(0, 18);
  if (isnan(temperature)) display.print("Temp: --");
  else display.printf("Temp: %.1f C", temperature);
  display.setCursor(0, 32);
  if (isnan(humidity)) display.print("Humidity: --");
  else display.printf("Humidity: %.1f %%", humidity);
  display.setCursor(0, 50);
  display.print("Status: ");
  display.println(status);
  display.display();
}

bool connectWiFi(unsigned long timeoutMs = 15000) {
  if (WiFi.status() == WL_CONNECTED) return true;
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < timeoutMs) delay(300);
  return WiFi.status() == WL_CONNECTED;
}

void setup() {
  Serial.begin(115200);
  snprintf(bootId, sizeof(bootId), "%08lx%08lx%08lx%08lx",
           (unsigned long)esp_random(), (unsigned long)esp_random(),
           (unsigned long)esp_random(), (unsigned long)esp_random());
  dht.begin();
  Wire.begin(SDA_PIN, SCL_PIN);
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    Serial.println("OLED NOT FOUND");
    while (true) delay(100);
  }
  showStatus("CONNECTING", NAN, NAN);
  if (connectWiFi()) {
    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("WiFi connection timed out");
  }
}

void runAlert(float temperature, float humidity, const char* message) {
  for (int cycle = 0; cycle < 4; cycle++) {
    digitalWrite(LED_PIN, HIGH);
    digitalWrite(BUZZER_PIN, HIGH);
    showStatus(message, temperature, humidity);
    delay(180);
    digitalWrite(LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    delay(180);
  }
}

void loop() {
  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();
  if (isnan(temperature) || isnan(humidity)) {
    Serial.println("DHT11 ERROR");
    showStatus("SENSOR ERROR", NAN, NAN);
    delay(3000);
    return;
  }
  if (!connectWiFi()) {
    Serial.println("WiFi unavailable");
    showStatus("DISCONNECTED", temperature, humidity);
    digitalWrite(LED_PIN, LOW);
    delay(3000);
    return;
  }

  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(5000);
  http.begin(SERVER_URL);
  const char* responseHeaders[] = {"X-IoT-Security-Status"};
  http.collectHeaders(responseHeaders, 1);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-IoT-Token", TELEMETRY_TOKEN);
  String body = "{\"device_id\":\"" + String(DEVICE_ID) + "\",\"sequence\":" + String(sequenceNumber++) +
                ",\"temperature_c\":" + String(temperature, 2) +
                ",\"humidity_percent\":" + String(humidity, 2) +
                ",\"device_uptime_ms\":" + String(millis()) +
                ",\"boot_id\":\"" + String(bootId) + "\"}";
  int responseCode = http.POST(body);
  String status = "DISCONNECTED";
  bool securityAlert = false;
  if (responseCode == 202) {
    String response = http.header("X-IoT-Security-Status");
    securityAlert = response == "SECURITY_ALERT";
    status = securityAlert ? "SECURITY ALERT" :
             response == "NORMAL" ? "NORMAL" : "UNKNOWN";
  } else {
    Serial.printf("Telemetry HTTP error: %d\n", responseCode);
  }
  http.end();

  if (securityAlert) {
    runAlert(temperature, humidity, status.c_str());
  } else {
    digitalWrite(LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
  }
  showStatus(status.c_str(), temperature, humidity);
  Serial.printf("Temp %.1f C, humidity %.1f %%, telemetry: %s\n", temperature, humidity, status.c_str());
  delay(3000);
}
