from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum


class DeviceStatus(StrEnum):
    NEW = "new"
    KNOWN = "known"
    CHANGED_IP = "changed_ip"
    OFFLINE = "offline"


@dataclass(frozen=True)
class DeviceObservation:
    ip_address: str
    mac_address: str
    vendor: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class DeviceRecord:
    mac_address: str
    ip_address: str | None
    vendor: str | None
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    status: DeviceStatus


@dataclass(frozen=True)
class ScanReport:
    scanned_at: datetime
    subnet: str
    interface: str | None
    new_devices: list[DeviceRecord]
    changed_ip_devices: list[DeviceRecord]
    offline_devices: list[DeviceRecord]
    known_active_devices: list[DeviceRecord]

    @property
    def total_active(self) -> int:
        return (
            len(self.new_devices)
            + len(self.changed_ip_devices)
            + len(self.known_active_devices)
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_mac(mac_address: str) -> str:
    return mac_address.strip().lower().replace("-", ":")
