from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class NetworkTarget:
    interface: str | None
    subnet: ipaddress.IPv4Network
    ip_address: str | None = None


class NetworkDetectionError(RuntimeError):
    pass


def detect_network(
    interface_override: str | None = None,
    subnet_override: str | None = None,
) -> NetworkTarget:
    if subnet_override:
        return NetworkTarget(interface_override, _parse_ipv4_network(subnet_override))

    if interface_override:
        return _network_for_interface(interface_override)

    default_interface = _default_interface_from_netifaces()
    if default_interface:
        return _network_for_interface(default_interface)

    local_ip = _local_ip_from_udp_probe()
    if local_ip:
        match = _network_for_ip(local_ip)
        if match:
            return match

    return _first_active_ipv4_network()


def detect_networks(
    interface_override: str | None = None,
    subnet_override: str | None = None,
    subnet_overrides: list[str] | None = None,
) -> list[NetworkTarget]:
    if subnet_override and subnet_overrides:
        raise NetworkDetectionError("Use either subnet or subnets, not both.")

    if subnet_overrides:
        return [
            NetworkTarget(interface_override, _parse_ipv4_network(subnet))
            for subnet in subnet_overrides
        ]

    return [detect_network(interface_override, subnet_override)]


def _parse_ipv4_network(value: str) -> ipaddress.IPv4Network:
    try:
        subnet = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise NetworkDetectionError(f"Invalid subnet: {value}") from exc

    if not isinstance(subnet, ipaddress.IPv4Network):
        raise NetworkDetectionError("Only IPv4 subnets are supported in this version.")
    return subnet


def _default_interface_from_netifaces() -> str | None:
    try:
        import netifaces  # type: ignore[import-not-found]
    except ImportError:
        return None

    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)
    if not default_gateway:
        return None
    return default_gateway[1]


def _network_for_interface(interface: str) -> NetworkTarget:
    addresses = psutil.net_if_addrs().get(interface)
    if not addresses:
        raise NetworkDetectionError(f"Interface not found: {interface}")

    for address in addresses:
        if address.family == socket.AF_INET and address.address and address.netmask:
            subnet = ipaddress.ip_network(
                f"{address.address}/{address.netmask}",
                strict=False,
            )
            return NetworkTarget(interface, subnet, address.address)

    raise NetworkDetectionError(f"No IPv4 address found for interface: {interface}")


def _network_for_ip(ip_address: str) -> NetworkTarget | None:
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            if address.address != ip_address or not address.netmask:
                continue
            subnet = ipaddress.ip_network(f"{address.address}/{address.netmask}", strict=False)
            return NetworkTarget(interface, subnet, address.address)
    return None


def _first_active_ipv4_network() -> NetworkTarget:
    stats = psutil.net_if_stats()
    for interface, addresses in psutil.net_if_addrs().items():
        interface_stats = stats.get(interface)
        if interface_stats and not interface_stats.isup:
            continue
        if interface.startswith(("lo", "utun", "awdl", "llw")):
            continue

        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            if address.address.startswith("127."):
                continue
            subnet = ipaddress.ip_network(f"{address.address}/{address.netmask}", strict=False)
            return NetworkTarget(interface, subnet, address.address)

    raise NetworkDetectionError(
        "Could not detect an active IPv4 network. Set interface or subnet in config.yaml."
    )


def _local_ip_from_udp_probe() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
