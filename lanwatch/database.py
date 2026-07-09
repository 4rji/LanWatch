from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from lanwatch.models import (
    DeviceObservation,
    DeviceRecord,
    DeviceStatus,
    ScanReport,
    normalize_mac,
    utc_now,
)


class DeviceDatabase:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                current_ip TEXT,
                vendor TEXT,
                hostname TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                ip_address TEXT,
                vendor TEXT,
                hostname TEXT,
                status TEXT NOT NULL,
                previous_ip TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_mac
                ON scan_history(mac_address, scanned_at);
            CREATE INDEX IF NOT EXISTS idx_scan_history_ip
                ON scan_history(ip_address, scanned_at);
            """
        )
        self.connection.commit()

    def apply_scan(
        self,
        observations: list[DeviceObservation],
        subnet: str,
        interface: str | None,
        offline_threshold: int = 0,
    ) -> ScanReport:
        scanned_at = utc_now()
        previous = self._load_devices()
        seen_macs = {normalize_mac(device.mac_address) for device in observations}

        new_devices: list[DeviceRecord] = []
        changed_ip_devices: list[DeviceRecord] = []
        known_active_devices: list[DeviceRecord] = []
        offline_devices: list[DeviceRecord] = []

        with self.connection:
            for observation in observations:
                mac = normalize_mac(observation.mac_address)
                existing = previous.get(mac)

                if existing is None:
                    status = DeviceStatus.NEW
                    first_seen = scanned_at
                    previous_ip = None
                    target_list = new_devices
                elif existing.ip_address != observation.ip_address:
                    status = DeviceStatus.CHANGED_IP
                    first_seen = existing.first_seen
                    previous_ip = existing.ip_address
                    target_list = changed_ip_devices
                else:
                    status = DeviceStatus.KNOWN
                    first_seen = existing.first_seen
                    previous_ip = existing.ip_address
                    target_list = known_active_devices

                vendor = observation.vendor or (existing.vendor if existing else None)
                hostname = observation.hostname or (existing.hostname if existing else None)
                record = DeviceRecord(
                    mac_address=mac,
                    ip_address=observation.ip_address,
                    vendor=vendor,
                    hostname=hostname,
                    first_seen=first_seen,
                    last_seen=scanned_at,
                    status=status,
                )
                self._upsert_device(record)
                self._insert_history(record, scanned_at, previous_ip)
                target_list.append(record)

            for mac, existing in previous.items():
                if mac in seen_macs:
                    continue
                if not self._is_offline_due(existing, scanned_at, offline_threshold):
                    continue
                offline_record = DeviceRecord(
                    mac_address=existing.mac_address,
                    ip_address=existing.ip_address,
                    vendor=existing.vendor,
                    hostname=existing.hostname,
                    first_seen=existing.first_seen,
                    last_seen=existing.last_seen,
                    status=DeviceStatus.OFFLINE,
                )
                self._set_status(mac, DeviceStatus.OFFLINE)
                self._insert_history(offline_record, scanned_at, existing.ip_address)
                offline_devices.append(offline_record)

        return ScanReport(
            scanned_at=scanned_at,
            subnet=subnet,
            interface=interface,
            new_devices=new_devices,
            changed_ip_devices=changed_ip_devices,
            offline_devices=offline_devices,
            known_active_devices=known_active_devices,
        )

    def list_devices(self) -> list[DeviceRecord]:
        rows = self.connection.execute(
            """
            SELECT mac_address, current_ip, vendor, hostname, first_seen, last_seen, last_status
            FROM devices
            ORDER BY last_seen DESC, mac_address
            """
        ).fetchall()
        return [self._row_to_device(row) for row in rows]

    def history_for(self, identifier: str) -> list[sqlite3.Row]:
        normalized = normalize_mac(identifier)
        if ":" in normalized and len(normalized.split(":")) >= 3:
            rows = self.connection.execute(
                """
                SELECT scanned_at, mac_address, ip_address, vendor, hostname, status, previous_ip
                FROM scan_history
                WHERE mac_address = ?
                ORDER BY scanned_at DESC
                """,
                (normalized,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT scanned_at, mac_address, ip_address, vendor, hostname, status, previous_ip
                FROM scan_history
                WHERE ip_address = ? OR previous_ip = ?
                ORDER BY scanned_at DESC
                """,
                (identifier, identifier),
            ).fetchall()
        return rows

    def forget(self, identifier: str) -> int:
        mac = self._resolve_mac(identifier)
        if mac is None:
            return 0
        with self.connection:
            self.connection.execute("DELETE FROM scan_history WHERE mac_address = ?", (mac,))
            cursor = self.connection.execute("DELETE FROM devices WHERE mac_address = ?", (mac,))
        return cursor.rowcount

    def _resolve_mac(self, identifier: str) -> str | None:
        normalized = normalize_mac(identifier)
        row = self.connection.execute(
            "SELECT mac_address FROM devices WHERE mac_address = ?",
            (normalized,),
        ).fetchone()
        if row:
            return row["mac_address"]

        row = self.connection.execute(
            "SELECT mac_address FROM devices WHERE current_ip = ?",
            (identifier,),
        ).fetchone()
        return row["mac_address"] if row else None

    def _load_devices(self) -> dict[str, DeviceRecord]:
        return {device.mac_address: device for device in self.list_devices()}

    def _upsert_device(self, record: DeviceRecord) -> None:
        self.connection.execute(
            """
            INSERT INTO devices (
                mac_address, current_ip, vendor, hostname, first_seen, last_seen, last_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                current_ip = excluded.current_ip,
                vendor = COALESCE(excluded.vendor, devices.vendor),
                hostname = COALESCE(excluded.hostname, devices.hostname),
                last_seen = excluded.last_seen,
                last_status = excluded.last_status
            """,
            (
                record.mac_address,
                record.ip_address,
                record.vendor,
                record.hostname,
                _to_iso(record.first_seen),
                _to_iso(record.last_seen),
                record.status.value,
            ),
        )

    def _set_status(self, mac_address: str, status: DeviceStatus) -> None:
        self.connection.execute(
            "UPDATE devices SET last_status = ? WHERE mac_address = ?",
            (status.value, mac_address),
        )

    def _insert_history(
        self,
        record: DeviceRecord,
        scanned_at: datetime,
        previous_ip: str | None,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO scan_history (
                scanned_at, mac_address, ip_address, vendor, hostname, status, previous_ip
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _to_iso(scanned_at),
                record.mac_address,
                record.ip_address,
                record.vendor,
                record.hostname,
                record.status.value,
                previous_ip,
            ),
        )

    def _is_offline_due(
        self,
        record: DeviceRecord,
        scanned_at: datetime,
        offline_threshold: int,
    ) -> bool:
        if offline_threshold <= 0:
            return True
        return (scanned_at - record.last_seen).total_seconds() >= offline_threshold

    def _row_to_device(self, row: sqlite3.Row) -> DeviceRecord:
        return DeviceRecord(
            mac_address=row["mac_address"],
            ip_address=row["current_ip"],
            vendor=row["vendor"],
            hostname=row["hostname"],
            first_seen=_from_iso(row["first_seen"]),
            last_seen=_from_iso(row["last_seen"]),
            status=DeviceStatus(row["last_status"]),
        )


def _to_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _from_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed
