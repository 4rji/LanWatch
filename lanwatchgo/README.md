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

## Usage

Run one scan:

```bash
./lanwatchgo scan
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
```

Run the web dashboard:

```bash
./lanwatchgo serve
```

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

## Notes

- This version does not require root for raw ARP sockets because it uses system `ping` plus the OS ARP/neighbor table.
- Routed subnets can be scanned with ping, but remote MAC/vendor data may be unavailable.
- Devices with MAC addresses can be marked `changed_ip`.
- IP-only devices are tracked by IP, so IP changes cannot be linked to the same physical device.
