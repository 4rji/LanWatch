from __future__ import annotations

from lanwatch.config import Config
from lanwatch.database import DeviceDatabase
from lanwatch.models import DeviceObservation, ScanReport, normalize_mac
from lanwatch.network import NetworkTarget, detect_networks
from lanwatch.scanner import scan_subnet
from lanwatch.vendor import VendorLookup


def run_scan(config: Config) -> ScanReport:
    targets = detect_networks(config.interface, config.subnet, config.subnets)
    vendor_lookup = VendorLookup()
    observations_by_mac: dict[str, DeviceObservation] = {}

    for target in targets:
        observations = scan_subnet(
            target.subnet,
            target.interface,
            config.scan_timeout,
            vendor_lookup,
        )
        for observation in observations:
            observations_by_mac[normalize_mac(observation.mac_address)] = observation

    database = DeviceDatabase(config.database_path)
    try:
        return database.apply_scan(
            list(observations_by_mac.values()),
            ", ".join(str(target.subnet) for target in targets),
            _interface_label(targets),
            config.offline_threshold,
        )
    finally:
        database.close()


def _interface_label(targets: list[NetworkTarget]) -> str | None:
    interfaces = sorted({target.interface for target in targets if target.interface})
    if not interfaces:
        return None
    return ", ".join(interfaces)
