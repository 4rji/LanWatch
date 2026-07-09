from __future__ import annotations

from datetime import datetime
from typing import Any

from flask import Flask, redirect, render_template_string, request, url_for

from lanwatch.config import Config
from lanwatch.database import DeviceDatabase
from lanwatch.models import DeviceRecord, ScanReport
from lanwatch.network import NetworkDetectionError
from lanwatch.runner import run_scan
from lanwatch.scanner import PermissionScanError, ScanError


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LanWatch</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #1d2733;
      --muted: #657487;
      --line: #d9e1ea;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --warn: #b45309;
      --danger: #b91c1c;
      --ok: #166534;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }
    header {
      background: #102033;
      color: #f8fafc;
      border-bottom: 1px solid #0b1725;
    }
    .wrap {
      width: min(1280px, calc(100% - 32px));
      margin: 0 auto;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 0;
    }
    h1 {
      margin: 0;
      font-size: 22px;
      font-weight: 700;
    }
    .meta {
      color: #cbd5e1;
      font-size: 13px;
    }
    main {
      padding: 22px 0 36px;
    }
    .actions {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 18px;
      flex-wrap: wrap;
    }
    button, .button {
      border: 1px solid var(--accent-strong);
      background: var(--accent);
      color: #ffffff;
      min-height: 36px;
      border-radius: 6px;
      padding: 8px 14px;
      font-weight: 650;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    button:hover, .button:hover {
      background: var(--accent-strong);
    }
    .button.secondary {
      background: var(--panel);
      color: var(--text);
      border-color: var(--line);
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(5, minmax(140px, 1fr));
      gap: 10px;
      margin-bottom: 22px;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 76px;
    }
    .metric span {
      color: var(--muted);
      display: block;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .02em;
    }
    .metric strong {
      display: block;
      margin-top: 6px;
      font-size: 28px;
      line-height: 1;
    }
    .notice {
      background: #fff7ed;
      border: 1px solid #fed7aa;
      color: #7c2d12;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 16px;
    }
    section {
      margin-top: 22px;
    }
    h2 {
      font-size: 15px;
      margin: 0 0 10px;
    }
    .table-wrap {
      overflow-x: auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 880px;
    }
    th, td {
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: middle;
      white-space: nowrap;
    }
    th {
      background: #eef3f8;
      color: #334155;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .02em;
    }
    tr:last-child td { border-bottom: 0; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      background: #eef3f8;
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: 2px 5px;
    }
    .status {
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 700;
      display: inline-block;
    }
    .new { background: #dcfce7; color: var(--ok); }
    .known { background: #e0f2fe; color: #075985; }
    .changed_ip { background: #fef3c7; color: var(--warn); }
    .offline { background: #fee2e2; color: var(--danger); }
    .empty {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      color: var(--muted);
    }
    .split {
      display: grid;
      grid-template-columns: minmax(0, 1.3fr) minmax(340px, .7fr);
      gap: 18px;
      align-items: start;
    }
    .toolbar {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    input {
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      min-width: 260px;
    }
    a { color: var(--accent-strong); font-weight: 650; }
    @media (max-width: 860px) {
      .summary, .split { grid-template-columns: 1fr; }
      .topbar { align-items: flex-start; flex-direction: column; }
      input { width: 100%; min-width: 0; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>LanWatch</h1>
        <div class="meta">
          {{ config_label }}
          {% if report %} · Last scan {{ report.scanned_at | dt }}{% endif %}
        </div>
      </div>
      <form action="{{ url_for('scan_now') }}" method="post">
        <button type="submit">Run Scan</button>
      </form>
    </div>
  </header>

  <main class="wrap">
    {% if error %}
      <div class="notice">{{ error }}</div>
    {% endif %}

    <div class="actions">
      <div class="toolbar">
        <a class="button secondary" href="{{ url_for('index') }}">Refresh</a>
      </div>
      <form class="toolbar" action="{{ url_for('index') }}" method="get">
        <input name="history" value="{{ selected_history or '' }}" placeholder="MAC or IP history">
        <button type="submit">History</button>
      </form>
    </div>

    <div class="summary">
      <div class="metric"><span>New</span><strong>{{ counts.new }}</strong></div>
      <div class="metric"><span>Changed IP</span><strong>{{ counts.changed }}</strong></div>
      <div class="metric"><span>Offline</span><strong>{{ counts.offline }}</strong></div>
      <div class="metric"><span>Known Active</span><strong>{{ counts.known }}</strong></div>
      <div class="metric"><span>Total Known</span><strong>{{ counts.total }}</strong></div>
    </div>

    <div class="split">
      <div>
        {{ device_section("New devices", report.new_devices if report else []) | safe }}
        {{ device_section("Changed IP", report.changed_ip_devices if report else []) | safe }}
        {{ device_section("Offline", report.offline_devices if report else []) | safe }}
        {{ device_section("Known active", report.known_active_devices if report else []) | safe }}

        <section>
          <h2>All known devices</h2>
          {{ devices_table(devices) | safe }}
        </section>
      </div>

      <div>
        <section>
          <h2>{% if selected_history %}History for {{ selected_history }}{% else %}Recent history{% endif %}</h2>
          {{ history_table(history_rows) | safe }}
        </section>
      </div>
    </div>
  </main>
</body>
</html>
"""


def create_app(config: Config) -> Flask:
    app = Flask(__name__)
    state: dict[str, Any] = {"report": None, "error": None}

    @app.template_filter("dt")
    def format_datetime(value: datetime | str | None) -> str:
        if value is None:
            return "-"
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    @app.context_processor
    def helpers() -> dict[str, Any]:
        return {
            "device_section": _device_section,
            "devices_table": _devices_table,
            "history_table": _history_table,
        }

    @app.get("/")
    def index():
        selected_history = request.args.get("history") or None
        devices = _list_devices(config)
        history_rows = _history(config, selected_history)
        report: ScanReport | None = state["report"]
        counts = _counts(report, devices)
        return render_template_string(
            PAGE,
            config_label=_config_label(config),
            counts=counts,
            devices=devices,
            error=state["error"],
            history_rows=history_rows,
            report=report,
            selected_history=selected_history,
        )

    @app.post("/scan")
    def scan_now():
        try:
            state["report"] = run_scan(config)
            state["error"] = None
        except PermissionScanError as exc:
            state["error"] = f"Permission required: {exc}"
        except NetworkDetectionError as exc:
            state["error"] = f"Network detection failed: {exc}"
        except ScanError as exc:
            state["error"] = f"Scan failed: {exc}"
        return redirect(url_for("index"))

    return app


def _list_devices(config: Config) -> list[DeviceRecord]:
    database = DeviceDatabase(config.database_path)
    try:
        return database.list_devices()
    finally:
        database.close()


def _history(config: Config, identifier: str | None):
    database = DeviceDatabase(config.database_path)
    try:
        if identifier:
            return database.history_for(identifier)
        return database.recent_history(20)
    finally:
        database.close()


def _counts(report: ScanReport | None, devices: list[DeviceRecord]) -> dict[str, int]:
    return {
        "new": len(report.new_devices) if report else 0,
        "changed": len(report.changed_ip_devices) if report else 0,
        "offline": len(report.offline_devices) if report else 0,
        "known": len(report.known_active_devices) if report else 0,
        "total": len(devices),
    }


def _config_label(config: Config) -> str:
    if config.subnets:
        target = ", ".join(config.subnets)
    elif config.subnet:
        target = config.subnet
    else:
        target = "auto subnet"

    interface = config.interface or "auto interface"
    return f"{target} · {interface} · {config.database_path}"


def _device_section(title: str, devices: list[DeviceRecord]) -> str:
    if not devices:
        return f"<section><h2>{title}</h2><div class=\"empty\">None</div></section>"
    return f"<section><h2>{title}</h2>{_devices_table(devices)}</section>"


def _devices_table(devices: list[DeviceRecord]) -> str:
    if not devices:
        return "<div class=\"empty\">No devices recorded yet.</div>"

    rows = []
    for device in devices:
        status = device.status.value
        rows.append(
            "<tr>"
            f"<td><span class=\"status {status}\">{status}</span></td>"
            f"<td>{_safe(device.ip_address)}</td>"
            f"<td><a href=\"/?history={device.mac_address}\"><code>{device.mac_address}</code></a></td>"
            f"<td>{_safe(device.hostname)}</td>"
            f"<td>{_safe(device.vendor)}</td>"
            f"<td>{_format_dt(device.first_seen)}</td>"
            f"<td>{_format_dt(device.last_seen)}</td>"
            "</tr>"
        )

    return (
        "<div class=\"table-wrap\"><table>"
        "<thead><tr><th>Status</th><th>IP</th><th>MAC</th><th>Hostname</th>"
        "<th>Vendor</th><th>First Seen</th><th>Last Seen</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _history_table(rows) -> str:
    rows = list(rows)
    if not rows:
        return "<div class=\"empty\">No history found.</div>"

    rendered = []
    for row in rows:
        status = row["status"]
        rendered.append(
            "<tr>"
            f"<td>{_format_iso(row['scanned_at'])}</td>"
            f"<td><a href=\"/?history={row['mac_address']}\"><code>{row['mac_address']}</code></a></td>"
            f"<td>{_safe(row['ip_address'])}</td>"
            f"<td>{_safe(row['previous_ip'])}</td>"
            f"<td><span class=\"status {status}\">{status}</span></td>"
            f"<td>{_safe(row['hostname'])}</td>"
            "</tr>"
        )

    return (
        "<div class=\"table-wrap\"><table>"
        "<thead><tr><th>Scanned</th><th>MAC</th><th>IP</th><th>Previous IP</th>"
        "<th>Status</th><th>Hostname</th></tr></thead>"
        f"<tbody>{''.join(rendered)}</tbody></table></div>"
    )


def _format_dt(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _format_iso(value: str) -> str:
    return _format_dt(datetime.fromisoformat(value))


def _safe(value: object | None) -> str:
    if value is None or value == "":
        return "-"
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
