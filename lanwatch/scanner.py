from __future__ import annotations

import ipaddress
import os
import queue
import socket
import threading

from lanwatch.models import DeviceObservation, normalize_mac
from lanwatch.vendor import VendorLookup


class ScanError(RuntimeError):
    pass


class PermissionScanError(ScanError):
    pass


def scan_subnet(
    subnet: ipaddress.IPv4Network,
    interface: str | None,
    timeout: float,
    vendor_lookup: VendorLookup | None = None,
) -> list[DeviceObservation]:
    vendor_lookup = vendor_lookup or VendorLookup()
    observations = _arp_scan(subnet, interface, timeout)

    enriched: list[DeviceObservation] = []
    for observation in observations:
        vendor = observation.vendor or vendor_lookup.lookup(observation.mac_address)
        hostname = observation.hostname or resolve_hostname(observation.ip_address)
        enriched.append(
            DeviceObservation(
                ip_address=observation.ip_address,
                mac_address=observation.mac_address,
                vendor=vendor,
                hostname=hostname,
            )
        )

    return sorted(enriched, key=lambda device: ipaddress.ip_address(device.ip_address))


def _arp_scan(
    subnet: ipaddress.IPv4Network,
    interface: str | None,
    timeout: float,
) -> list[DeviceObservation]:
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ScanError(
            "Scapy is required for ARP scanning. Install dependencies with: pip install -e ."
        ) from exc

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionScanError(
            "ARP scanning requires raw socket privileges. Run with sudo/admin rights, "
            "or run against an environment that grants packet capture permissions."
        )

    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))

    try:
        answered, _ = srp(packet, timeout=timeout, iface=interface, verbose=False)
    except PermissionError as exc:
        raise PermissionScanError(
            "ARP scan failed because raw socket access was denied. Try running with sudo."
        ) from exc
    except OSError as exc:
        message = str(exc).lower()
        if "permission" in message or "operation not permitted" in message:
            raise PermissionScanError(
                "ARP scan failed because raw socket access was denied. Try running with sudo."
            ) from exc
        raise ScanError(f"ARP scan failed: {exc}") from exc

    devices: dict[str, DeviceObservation] = {}
    for _, received in answered:
        mac = normalize_mac(received.hwsrc)
        devices[mac] = DeviceObservation(
            ip_address=received.psrc,
            mac_address=mac,
        )
    return list(devices.values())


def resolve_hostname(ip_address: str, timeout: float = 0.5) -> str | None:
    result_queue: queue.Queue[str | None] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except OSError:
            hostname = None
        try:
            result_queue.put_nowait(hostname)
        except queue.Full:
            pass

    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    try:
        return result_queue.get(timeout=timeout)
    except queue.Empty:
        return None
