# LanWatch

LanWatch is a local network watcher for discovering devices on your LAN and detecting changes over time. It scans the active IPv4 subnet with ARP, stores device state in SQLite, and reports new devices, changed IP addresses, offline devices, and known active devices.

## Features

- Auto-detects the active network interface and subnet.
- Supports config overrides for interface and subnet.
- Uses ARP discovery through Scapy, so it does not depend on `nmap`.
- Tracks devices by MAC address, not IP address.
- Stores current device state and scan history in SQLite.
- Shows vendor/OUI when a local OUI database or built-in fallback knows it.
- Resolves hostnames when reverse DNS is available.
- Saves every scan event to history.

## Requirements

- Python 3.10 or newer
- macOS or Linux
- Raw socket permissions for ARP scans, usually via `sudo`

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

For better default route detection, install the optional `netifaces` extra:

```bash
pip install -e ".[netifaces]"
```

After installation, the CLI command is:

```bash
lanwatch --help
```

The web dashboard uses Flask, which is installed as part of the normal dependencies.

## Configuration

Copy the example config if you want to override defaults:

```bash
cp config.example.yaml config.yaml
```

Example:

```yaml
scan_interval: 60
subnet: 192.168.1.0/24
interface: en0
offline_threshold: 0
database_path: lanwatch.db
scan_timeout: 2.0
```

To scan multiple subnets, use `subnets` instead of `subnet`:

```yaml
scan_interval: 60
subnets:
  - 192.168.1.0/24
  - 192.168.10.0/24
  - 10.0.0.0/24
interface: en0
offline_threshold: 0
database_path: lanwatch.db
scan_timeout: 2.0
```

Do not set `subnet` and `subnets` at the same time. LanWatch will reject that config so the scan target is unambiguous.

Config options:

- `scan_interval`: seconds between scans when using `watch`.
- `subnet`: optional subnet override, for example `192.168.1.0/24`.
- `subnets`: optional list of subnet overrides. Use this instead of `subnet` when scanning multiple networks.
- `interface`: optional interface override, for example `en0` or `eth0`.
- `offline_threshold`: seconds since `last_seen` before a missing device is reported as offline. The default `0` reports missing known devices as offline on the next scan.
- `database_path`: SQLite database path.
- `scan_timeout`: ARP scan timeout in seconds.

## Usage

Run one scan:

```bash
lanwatch scan
```

Keep scanning:

```bash
lanwatch watch --interval 30
```

List known devices:

```bash
lanwatch list
```

Show history for a MAC or IP:

```bash
lanwatch history aa:bb:cc:dd:ee:ff
lanwatch history 192.168.1.42
```

Forget a device and its history:

```bash
lanwatch forget aa:bb:cc:dd:ee:ff
```

Use a custom config file:

```bash
lanwatch scan --config ./config.yaml
```

Run the web dashboard on port 5000:

```bash
lanwatch serve
```

Open:

```text
http://127.0.0.1:5000
```

The dashboard shows the latest scan summary, new devices, changed IPs, offline devices, known devices, and recent history. Use the `Run Scan` button to execute a scan from the page.

To bind another host or port:

```bash
lanwatch serve --host 0.0.0.0 --port 5000
```

## How Detection Works

LanWatch identifies devices primarily by MAC address. If a MAC address appears for the first time, it is reported as `new`. If a known MAC address appears with a different IP address, it is reported as `changed_ip`. If a known MAC address is missing from the current scan, it is reported as `offline` but is not deleted.

## Permissions

ARP scanning uses raw sockets. On macOS and Linux this usually requires elevated privileges. For `scan`, `watch`, and `serve`, LanWatch automatically relaunches itself with `sudo` when needed, so the sudo password is requested once when the command starts. If `sudo` is not available or raw socket access is still denied, it exits with a clean message instead of a traceback.

## Notes

- Routers commonly block ICMP/ping discovery. LanWatch tries ARP discovery directly, which is the preferred method for a local subnet.
- Devices are identified primarily by MAC address. If the same MAC appears with a different IP, the scan marks it as `changed_ip`.
- Missing devices are marked `offline` but are not deleted.
- Every scan observation and offline event is saved in `scan_history`.
