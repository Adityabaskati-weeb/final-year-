import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck,
  Activity,
  Cpu,
  Ban,
  ScrollText,
  Play,
  Square,
  RefreshCw,
  Network,
  Unlock,
  Plus,
  AlertTriangle,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import "./style.css";

const time = (value) => new Date(value * 1000).toLocaleTimeString();
const label = (value) => String(value ?? "").replaceAll("_", " ");
const badge = (value) => (
  <span
    className={`badge ${["malicious", "blocked", "cleanup_required"].includes(value) ? "danger" : ["benign", "online"].includes(value) ? "good" : ""}`}
  >
    {label(value)}
  </span>
);
function App() {
  const [data, setData] = useState(null),
    [tab, setTab] = useState("Overview"),
    [connected, setConnected] = useState(false);
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [token, setToken] = useState("");
  const [credential, setCredential] = useState(""),
    [interfaces, setInterfaces] = useState([]),
    [iface, setIface] = useState("");
  const [scenario, setScenario] = useState("port_scan"),
    [scope, setScope] = useState("demo");
  async function api(path, body) {
    const response = await fetch("/api/" + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok)
      throw Error(
        typeof result.detail === "string"
          ? result.detail
          : JSON.stringify(result.detail),
      );
    return result;
  }
  async function action(path, body) {
    setBusy(true);
    setError("");
    try {
      await api(path, body);
      setData(await api("system/status"));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    let disposed = false,
      socket,
      retry;
    function connect() {
      socket = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/events`,
      );
      socket.onopen = () => socket.send(JSON.stringify({ token }));
      socket.onmessage = (e) => {
        if (!disposed) {
          setConnected(true);
          setData(JSON.parse(e.data));
        }
      };
      socket.onclose = () => {
        if (!disposed) {
          setConnected(false);
          retry = setTimeout(connect, 3000);
        }
      };
    }
    connect();
    api("interfaces")
      .then(setInterfaces)
      .catch((e) => setError(e.message));
    return () => {
      disposed = true;
      clearTimeout(retry);
      socket?.close();
    };
  }, [token]);
  const traffic = (data?.traffic || []).filter((r) => r.origin === scope),
    alerts = (data?.alerts || []).filter((r) => r.origin === scope);
  const blocks = (data?.blocks || []).filter(
    (r) => r.origin === scope && r.status !== "released",
  );
  const devices = (data?.devices || []).filter((r) => r.origin === scope);
  const events = (data?.events || []).filter(
    (r) => !r.origin || r.origin === scope,
  );
  const links = [
    ["Overview", Activity],
    ["Traffic", Network],
    ["Devices", Cpu],
    ["Blocklist", Ban],
    ["History", ScrollText],
    ["Models", ShieldCheck],
  ];
  const table = (headers, rows) => (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows
          ) : (
            <tr>
              <td colSpan={headers.length} className="empty">
                No records in this view
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
  const trafficTable = () =>
    table(
      [
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Packets/s",
        "Prediction",
        "Risk",
      ],
      traffic.map((r) => (
        <tr key={r.id}>
          <td>{time(r.timestamp)}</td>
          <td className="mono">{r.source_ip}</td>
          <td className="mono">{r.destination_ip}</td>
          <td>{r.protocol}</td>
          <td>{r.features.packets_per_second.toFixed(1)}</td>
          <td>{badge(r.prediction)}</td>
          <td>{r.prediction === "unknown" ? "N/A" : r.risk_score + "/100"}</td>
        </tr>
      )),
    );
  return (
    <div className="shell">
      <aside>
        <a className="brand" href="/">
          <ShieldCheck size={29} />
          <span>
            UPDATED IoT<small>Security operations</small>
          </span>
        </a>
        <nav>
          {links.map(([name, Icon]) => (
            <button
              key={name}
              className={tab === name ? "selected" : ""}
              onClick={() => setTab(name)}
            >
              <Icon size={18} />
              {name}
            </button>
          ))}
        </nav>
        <div className="aside-footer">
          <span className={`dot ${connected ? "online" : ""}`} />
          {connected ? "Backend connected" : "Backend disconnected"}
          <small>Source-window IDS / v1</small>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">INTRUSION DETECTION & RESPONSE</p>
            <h1>{tab}</h1>
          </div>
          <div className="header-status">
            <ShieldCheck size={17} />
            {data?.firewall_mode === "active"
              ? "Host firewall active"
              : "Firewall dry-run"}
          </div>
        </header>
        <div className="toolbar">
          <div className="segments">
            {["demo", "live"].map((s) => (
              <button
                key={s}
                aria-pressed={scope === s}
                onClick={() => setScope(s)}
              >
                {s === "demo" ? "Synthetic demo" : "Live network"}
              </button>
            ))}
          </div>
          <div className="controls">
            {scope === "demo" ? (
              <>
                <select
                  aria-label="Scenario"
                  value={scenario}
                  onChange={(e) => setScenario(e.target.value)}
                >
                  {[
                    "port_scan",
                    "connection_flood",
                    "udp_burst",
                    "connection_retry",
                    "normal",
                  ].map((s) => (
                    <option key={s} value={s}>
                      {label(s)}
                    </option>
                  ))}
                </select>
                <button
                  disabled={busy || !connected}
                  onClick={() =>
                    action(
                      "simulation/" + (data?.simulation ? "stop" : "start"),
                      { scenario },
                    )
                  }
                >
                  {data?.simulation ? <Square size={16} /> : <Play size={16} />}{" "}
                  {data?.simulation ? "Stop demo" : "Run demo"}
                </button>
              </>
            ) : (
              <>
                <select
                  aria-label="Capture interface"
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                >
                  <option value="">Capture interface</option>
                  {interfaces.map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.name}
                    </option>
                  ))}
                </select>
                <button
                  disabled={busy || !connected || (!iface && !data?.monitoring)}
                  onClick={() =>
                    action(
                      "monitoring/" + (data?.monitoring ? "stop" : "start"),
                      { interface: iface },
                    )
                  }
                >
                  {data?.monitoring ? <Square size={16} /> : <Play size={16} />}{" "}
                  {data?.monitoring ? "Stop capture" : "Start capture"}
                </button>
              </>
            )}
          </div>
        </div>
        <div className="notice">
          <AlertTriangle size={17} />
          {scope === "demo"
            ? "SYNTHETIC DEMO | In-memory packets. Blocks are simulated; no network attack or OS firewall change."
            : `LIVE NETWORK | ${data?.models?.live?.ready ? "Lab-trained model loaded. Host-only response scope." : "Observation only: no validated live model installed."}`}
        </div>
        {!connected && (
          <form
            className="auth"
            onSubmit={(e) => {
              e.preventDefault();
              setToken(credential);
            }}
          >
            <input
              type="password"
              placeholder="Admin token, if configured"
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              aria-label="Admin token"
            />
            <button type="submit">
              <RefreshCw size={16} />
              Reconnect
            </button>
          </form>
        )}
        {error && (
          <div role="alert" className="error">
            {error}
            <button aria-label="Dismiss error" onClick={() => setError("")}>
              ×
            </button>
          </div>
        )}
        {scope === "live" && data?.capture_error && (
          <div role="alert" className="error">
            Capture failed: {data.capture_error}
          </div>
        )}
        {tab === "Overview" && (
          <>
            <div className="stats">
              {[
                [
                  "Online devices",
                  devices.filter((d) => d.status === "online").length,
                ],
                ["Recent windows", traffic.length],
                [
                  "Recent detections",
                  traffic.filter((t) => t.prediction === "malicious").length,
                ],
                [
                  scope === "demo" ? "Simulated blocks" : "Active blocks",
                  blocks.filter((b) =>
                    ["blocked", "simulated_block"].includes(b.status),
                  ).length,
                ],
              ].map(([name, value]) => (
                <div key={name}>
                  <span>{name}</span>
                  <strong>{value}</strong>
                </div>
              ))}
            </div>
            <section>
              <div className="section-head">
                <h2>Traffic risk</h2>
                <span>Current server session · latest 200 windows</span>
              </div>
              <div className="chart">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={[...traffic]
                      .reverse()
                      .map((r) => ({
                        time: time(r.timestamp),
                        risk: r.prediction === "unknown" ? null : r.risk_score,
                      }))}
                  >
                    <CartesianGrid stroke="#303535" vertical={false} />
                    <XAxis
                      dataKey="time"
                      tick={{ fill: "#a4adaa", fontSize: 11 }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fill: "#a4adaa", fontSize: 11 }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#1a2020",
                        border: "1px solid #44504b",
                      }}
                    />
                    <Area
                      isAnimationActive={false}
                      type="monotone"
                      dataKey="risk"
                      stroke="#47cfb1"
                      fill="#47cfb1"
                      fillOpacity={0.12}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
            <section>
              <h2>Latest alerts</h2>
              {table(
                [
                  "Time",
                  "Source",
                  "Target",
                  "Classification",
                  "Confidence",
                  "Reason",
                ],
                alerts.slice(0, 8).map((r) => (
                  <tr key={r.id}>
                    <td>{time(r.timestamp)}</td>
                    <td>{r.source_ip}</td>
                    <td>{r.destination_ip}</td>
                    <td>{badge(r.attack_type)}</td>
                    <td>{(r.confidence * 100).toFixed(1)}%</td>
                    <td className="reason">{r.reasons?.[0]}</td>
                  </tr>
                )),
              )}
            </section>
          </>
        )}
        {tab === "Traffic" && (
          <section>
            <div className="section-head">
              <h2>Source windows</h2>
              <span>Capture drops: {data?.capture_dropped || 0}</span>
            </div>
            {trafficTable()}
          </section>
        )}
        {tab === "Devices" && (
          <section>
            <h2>Device registry</h2>
            {scope === "live" && (
              <form
                className="device-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  const body = Object.fromEntries(
                    new FormData(e.currentTarget),
                  );
                  action("devices", body);
                }}
              >
                {[
                  ["id", "esp32-lab-1"],
                  ["name", "Lab sensor"],
                  ["ip", "192.168.1.20"],
                  ["type", "ESP32"],
                ].map(([name, placeholder]) => (
                  <label key={name}>
                    {label(name)}
                    <input required name={name} placeholder={placeholder} />
                  </label>
                ))}
                <button disabled={busy}>
                  <Plus size={16} />
                  Register
                </button>
              </form>
            )}
            {table(
              [
                "Device",
                "IP address",
                "Type",
                "Status",
                "Last telemetry",
                "Temperature / Humidity",
                "Security / recent risk",
              ],
              devices.map((d) => {
                const reading = data.readings.find((r) => r.device_id === d.id);
                return (
                  <tr key={d.id}>
                    <td>
                      {d.name}
                      <small>{d.id}</small>
                    </td>
                    <td>{d.ip}</td>
                    <td>{d.type}</td>
                    <td>{badge(d.status)}</td>
                    <td>{d.last_seen ? time(d.last_seen) : "Not received"}</td>
                    <td>
                      {reading
                        ? `${reading.temperature_c ?? reading.temperature} °C / ${reading.humidity_percent ?? reading.humidity}%`
                        : "N/A"}
                    </td>
                    <td>
                      {badge(d.security_status || "unknown")}
                      <small>{d.current_risk == null ? "N/A" : `${d.current_risk}/100`}</small>
                    </td>
                  </tr>
                );
              }),
            )}
          </section>
        )}
        {tab === "Blocklist" && (
          <section>
            <h2>Response rules</h2>
            <form
              className="device-form"
              onSubmit={(e) => {
                e.preventDefault();
                action("firewall/block", {
                  ...Object.fromEntries(new FormData(e.currentTarget)),
                  origin: scope,
                });
              }}
            >
              <label>
                Source IP
                <input required name="ip" placeholder="Attacker IP" />
              </label>
              <label>
                Reason
                <input
                  required
                  name="reason"
                  maxLength="500"
                  placeholder="Manual response reason"
                />
              </label>
              <button disabled={busy}>
                <Ban size={16} />
                {scope === "demo" ? "Simulate block" : "Block source"}
              </button>
            </form>
            {table(
              [
                "Source",
                "State",
                "Classification",
                "Reason",
                "Expiry",
                "Action",
              ],
              blocks.map((b) => (
                <tr key={b.id}>
                  <td>{b.source_ip}</td>
                  <td>{badge(b.status)}</td>
                  <td>{label(b.attack_type)}</td>
                  <td className="reason">{b.error || b.reason}</td>
                  <td>{time(b.expires_at)}</td>
                  <td>
                    <button
                      disabled={busy}
                      title="Release this rule"
                      onClick={() => action("firewall/unblock", { id: b.id })}
                    >
                      <Unlock size={16} />
                      Unblock
                    </button>
                  </td>
                </tr>
              )),
            )}
          </section>
        )}
        {tab === "History" && (
          <section>
            <h2>Attack & response timeline</h2>
            <div className="timeline">
              {events.map((e) => (
                <div key={e.id}>
                  <span className="event-dot" />
                  <time>{time(e.timestamp)}</time>
                  <div>
                    <strong>{label(e.kind)}</strong>
                    <p>
                      {e.source_ip || e.device_id || e.scenario || ""}
                      {e.packets ? ` · ${e.packets} packets rejected` : ""}
                    </p>
                    {e.reason && <small>{e.reason}</small>}
                  </div>
                  {badge(e.origin || "system")}
                </div>
              ))}
              {!events.length && <p className="empty">No events recorded</p>}
            </div>
          </section>
        )}
        {tab === "Models" && (
          <section>
            <h2>Model readiness</h2>
            {["demo", "live"].map((k) => {
              const model = data?.models?.[k];
              const report = model?.report;
              return (
                <div className="model" key={k}>
                  <h3>
                    {k === "demo"
                      ? "Synthetic scenario classifier"
                      : "Live lab classifier"}{" "}
                    {badge(model?.ready ? "ready" : "unavailable")}
                  </h3>
                  <p>{model?.error || report?.scope}</p>
                  <small>
                    Schema: {model?.schema} · Random Forest · 13 features ·
                    five-second windows
                  </small>
                  {report && (
                    <div className="metrics">
                      {[
                        "binary_accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "f2",
                        "roc_auc",
                        "pr_auc_average_precision",
                        "inference_ms_p95",
                      ].map((key) => (
                        <div key={key}>
                          <span>{label(key)}</span>
                          <strong>{report[key].toFixed(3)}</strong>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </section>
        )}
        <footer>
          Updated IoT Work{" "}
          <span>
            Session {data?.run_id?.slice(0, 8) || "offline"} ·{" "}
            {data?.uptime || 0}s uptime
          </span>
        </footer>
      </main>
    </div>
  );
}
createRoot(document.getElementById("root")).render(<App />);
