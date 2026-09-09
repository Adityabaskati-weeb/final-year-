# Recorded Analysis and Physical Lab

## Recorded data

Run the download and training commands in README, then python run_project.py --build. Open http://127.0.0.1:8020 and select Recorded IoT-23, a capture and Analyze. Analysis is bounded to 500 records per run. This shows genuine historical dataset connections, not an attack on the connected sensor. The current model FAILED its held-out test; display that limitation during presentation.

## Live collector

Use a Linux host with Zeek installed at a point that can see your authorized lab traffic. For example, from a dedicated log directory:

```sh
sudo zeek -i YOUR_LAB_INTERFACE LogAscii::use_json=T
```

Check the actual generated JSON conn.log and packet visibility. Collector/interface permissions and deployment are environment-specific. On Windows, an ESP32 USB connection does not provide these network flows.

Either configure ZEEK_LOG_PATH to a locally readable live JSON conn.log, or configure the same secret ZEEK_INGEST_TOKEN on backend and forwarder:

```sh
python scripts/forward_zeek.py --server http://BACKEND_LAN_IP:8020 --log /path/to/conn.log
```

Use an isolated trusted lab or HTTPS transport; do not expose plain HTTP tokens to public networks. Configure a nonempty ADMIN_TOKEN before binding beyond loopback. Start the backend with --host 0.0.0.0 only when LAN access is needed and firewall access is appropriately restricted.

Register the ESP32's current Wi-Fi IP, select **Live Npcap** and explicitly start capture. Historical or unrelated-device records are rejected. The promoted local lab model returns `benign` for matching telemetry flows and `malicious` for the bounded private probe described in `docs/LAB_RUNBOOK.md`; its scope is only the registered device and matching extractor.

## Sensor

Preserved firmware is under sensor/. Keep your existing wiring and verify its telemetry URL/token against /docs. Do not flash guessed pins. USB can power/program the board; telemetry uses Wi-Fi. The OLED must not say ATTACK merely because the sensor is disconnected or a dashboard test was clicked.

The dashboard's **Hardware alarm test** is an explicit actuator check. It sends `LAB_TEST_ALERT` for a short, authenticated interval and should make the registered ESP32 show the test status and drive the LED/buzzer. This is a hardware test, not a model prediction. A model alert is separately visible in the live alert/detection tables; physical actuator response for that model alert still needs direct serial verification.

Remaining acceptance: healthy telemetry, visible genuine connections, labelled bounded lab scenarios, model validation on independent sessions, authenticated security-status delivery, OLED/LED/buzzer transitions and recovery. No attack was launched during this integration.
