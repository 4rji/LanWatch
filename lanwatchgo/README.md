# LanWatch Go

LanWatch Go is a dependency-free Go version of the LAN watcher. It scans all active local IPv4 interfaces automatically, adds any extra subnets from config or CLI flags, detects devices, stores state/history in JSON, and can show the results in the terminal or a small web dashboard.

## How It Discovers Devices

This version uses standard OS tools instead of raw packet libraries:

- It detects all active non-loopback IPv4 interfaces.
- It takes the current subnet from each interface.
- It pings each target IP to trigger neighbor/ARP cache updates.
- It reads the OS ARP/neighbor table with `arp -an` on macOS/BSD or `ip neigh` on Linux.
- If a MAC address is available, the device is tracked by MAC.
- If a remote/routed subnet only responds to ping and no MAC is visible, the device is tracked as IP-only.

ARP/MAC discovery usually works only in the same Layer 2 network or VLAN. For routed networks, ping can show that an IP is alive, but the real remote MAC is usually not visible.

## Build

```bash
cd lanwatchgo
go build -o lanwatchgo .
```

## Config

Copy and edit the example:

```bash
cp config.example.json config.json
```

Example:

```json
{
  "scan_interval": 60,
  "interfaces": [],
  "exclude_interfaces": [],
  "extra_subnets": [
    "10.10.65.0/24",
    "10.10.66.0/24"
  ],
  "state_path": "lanwatchgo-state.json",
  "ping_timeout_ms": 700,
  "concurrency": 128,
  "max_hosts_per_subnet": 4096
}
```

`extra_subnets` are added to the automatically detected interface subnets. Leave it empty if you only want the current local subnets:

```json
"extra_subnets": []
```

`interfaces` can be left empty to scan all active running interfaces. If a host has Docker, bridge, or other virtual interfaces and you want only the real LAN interface, set:

```json
"interfaces": ["enp0s3"]
```

or use the CLI flag:

```bash
./lanwatchgo scan --interface enp0s3
```

Interfaces that are down or have no carrier/running state are skipped automatically. Large auto-detected subnets are skipped with a warning instead of aborting the scan. Explicit `extra_subnets` are still protected by `max_hosts_per_subnet`.

## Usage

Create an initial baseline first. This records current devices as `known` so they do not appear as new in the dashboard:

```bash
./lanwatchgo baseline
```

If the dashboard already has old `new` events from before the baseline, use `Archive current new` in the web UI. That keeps the history but hides those already-reviewed devices from the “new devices in the last 10 minutes” panel.

Run one scan:

```bash
./lanwatchgo scan
```

Run one scan on a specific interface:

```bash
./lanwatchgo scan --interface enp0s3
```

Add more subnets without editing config:

```bash
./lanwatchgo scan --subnet 10.10.66.0/24 --subnet 10.10.67.0/24
```

Keep scanning:

```bash
./lanwatchgo watch
```

List known devices:

```bash
./lanwatchgo list
```

Show history for a MAC or IP:

```bash
./lanwatchgo history aa:bb:cc:dd:ee:ff
./lanwatchgo history 10.10.66.25
```

Forget a device:

```bash
./lanwatchgo forget aa:bb:cc:dd:ee:ff
./lanwatchgo forget 10.10.66.25
```

Show detected local interface subnets:

```bash
./lanwatchgo interfaces
./lanwatchgo interfaces --interface enp0s3
```

Run the web dashboard:

```bash
./lanwatchgo serve
```

`serve` is its own command. Do not put it after `scan`.

Open:

```text
http://127.0.0.1:5000
```

If port `5000` is already in use, choose another port:

```bash
./lanwatchgo serve 5991
```

To listen on all network interfaces:

```bash
./lanwatchgo serve 0.0.0.0 5991
```

The explicit flag version also works:

```bash
./lanwatchgo serve --host 0.0.0.0 --port 5991
```

Do not type square brackets like `[--host 127.0.0.1]`. In command docs, brackets only mean “optional”.

The dashboard includes:

- Summary counters for new devices in the last 10 minutes, active devices, changed IPs, offline devices, and total devices.
- A highlighted table at the top for devices first seen in the last 10 minutes.
- An `Archive current new` button to acknowledge the current new-device list without deleting history.
- Auto-scan controls with a configurable interval in seconds.
- A device menu directly below that table with tabs for known active devices, history, subnets, changed IP, offline, and all devices.
- One subnet tab per discovered subnet, based on the subnet stored for each device.

When running `serve`, scan activity is logged in the terminal where `go run . serve ...` is running. Logs include selected targets, ping sweep size, ARP/neighbor entries, observation count, scan summary, archive actions, and auto-scan start/stop/ticks.

## Notes

- This version does not require root for raw ARP sockets because it uses system `ping` plus the OS ARP/neighbor table.
- Routed subnets can be scanned with ping, but remote MAC/vendor data may be unavailable.
- Devices with MAC addresses can be marked `changed_ip`.
- IP-only devices are tracked by IP, so IP changes cannot be linked to the same physical device.
