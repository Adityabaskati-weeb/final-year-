# Demo and Sensor Setup

## Without hardware

Run `python run_demo.py`, open http://127.0.0.1:8020, stay on Synthetic demo. A virtual device produces three normal windows, then the selected generated attack pattern. Two qualifying malicious windows trigger a simulated block. Later synthetic packets are rejected by the simulator's admission gate. History records the sequence. No real packets are sent and no real firewall rules are added.

Open Devices for synthetic readings, Traffic for actual model outputs, Blocklist for simulated rule expiry/release, History for rejected packet counts and Models for the evaluation report. Select normal and rerun to check the benign case. Live network is a separate view; it must not show demo output as real detections.

## ESP32 reconnection

Preserved pins: DHT11 GPIO4; OLED SDA21/SCL22 address 0x3C; LED15; buzzer19. Use suitable resistors/drivers and common ground. A motor is not driven by this firmware; do not connect one directly to GPIO. MPU6050 readings are not implemented in the preserved sketch.

Libraries: DHT sensor library (and Adafruit Unified Sensor dependency), Adafruit GFX, Adafruit SSD1306; Espressif ESP32 board core. Copy secrets.example.h to secrets.h locally, set Wi-Fi, device ID and laptop LAN URL `http://LAPTOP_IP:8020/api/telemetry`. Match IOT_TELEMETRY_TOKEN in backend .env. Never commit secrets.h.

Start backend with `python -m uvicorn backend.main:create_app --factory --host 0.0.0.0 --port 8020`. Permit TCP8020 only from your sensor/private lab subnet. Register the **ESP32 IP**, not the laptop IP, in the Live network Devices tab. Device ID must match firmware. Source IP registration assumes no reverse proxy/NAT in this lab connection.

The endpoint returns 202 and X-IoT-Security-Status. UNKNOWN means telemetry was accepted without recent validated benign classification. SECURITY_ALERT requires a real-origin model detection for that device within 30 seconds. Synthetic demo events never activate hardware. Normal telemetry or loss of connection is not an attack. The OLED/LED/buzzer loop is preserved with bounded pulses; firmware has not been uploaded or physically verified in this implementation session.

## Physical acceptance still required

Check firmware compilation/upload, Wi-Fi, telemetry 202, correct IP identity, capture visibility, labelled independent-PCAP training, recent live predictions, alarm activation and recovery. An isolated laptop-only synthetic demo proves software integration, not these hardware results. For blocking third-party traffic to a sensor, add/test a gateway forwarding enforcement design before claiming prevention.
