from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.table import Table

from lanwatch.models import DeviceRecord, ScanReport


def print_scan_report(console: Console, report: ScanReport) -> None:
    console.rule("[bold]LAN Watch Scan")
    console.print(
        f"[bold]Subnet:[/] {report.subnet}    "
        f"[bold]Interface:[/] {report.interface or 'auto'}    "
        f"[bold]Active:[/] {report.total_active}    "
        f"[bold]Scanned:[/] {_format_dt(report.scanned_at)}"
    )
    console.print()

    _print_device_section(console, "New devices", report.new_devices)
    _print_device_section(console, "Changed IP", report.changed_ip_devices)
    _print_device_section(console, "Offline", report.offline_devices)
    _print_device_section(console, "Known active", report.known_active_devices)


def print_device_list(console: Console, devices: Iterable[DeviceRecord]) -> None:
    table = _device_table("Known Devices")
    count = 0
    for device in devices:
        count += 1
        _add_device_row(table, device)
    if count == 0:
        console.print("[yellow]No devices recorded yet.[/]")
        return
    console.print(table)


def print_history(console: Console, rows: Iterable[object]) -> None:
    table = Table(title="Device History")
    table.add_column("Scanned")
    table.add_column("MAC")
    table.add_column("IP")
    table.add_column("Previous IP")
    table.add_column("Status")
    table.add_column("Hostname")
    table.add_column("Vendor")

    count = 0
    for row in rows:
        count += 1
        table.add_row(
            _format_iso(row["scanned_at"]),
            row["mac_address"],
            row["ip_address"] or "-",
            row["previous_ip"] or "-",
            row["status"],
            row["hostname"] or "-",
            row["vendor"] or "-",
        )

    if count == 0:
        console.print("[yellow]No history found.[/]")
        return
    console.print(table)


def _print_device_section(
    console: Console,
    title: str,
    devices: list[DeviceRecord],
) -> None:
    if not devices:
        console.print(f"[dim]{title}: none[/]")
        return

    table = _device_table(title)
    for device in devices:
        _add_device_row(table, device)
    console.print(table)


def _device_table(title: str) -> Table:
    table = Table(title=title)
    table.add_column("Status")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Vendor")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    return table


def _add_device_row(table: Table, device: DeviceRecord) -> None:
    table.add_row(
        device.status.value,
        device.ip_address or "-",
        device.mac_address,
        device.hostname or "-",
        device.vendor or "-",
        _format_dt(device.first_seen),
        _format_dt(device.last_seen),
    )


def _format_dt(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _format_iso(value: str) -> str:
    return _format_dt(datetime.fromisoformat(value))
