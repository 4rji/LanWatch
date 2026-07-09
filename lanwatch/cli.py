from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lanwatch.config import Config, load_config
from lanwatch.database import DeviceDatabase
from lanwatch.network import NetworkDetectionError, detect_network
from lanwatch.report import print_device_list, print_history, print_scan_report
from lanwatch.scanner import PermissionScanError, ScanError, scan_subnet
from lanwatch.vendor import VendorLookup


app = typer.Typer(help="LAN device discovery and change detection.")
console = Console()


ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to config.yaml."),
]


def _load(path: Path | None) -> Config:
    try:
        return load_config(path)
    except ValueError as exc:
        console.print(f"[red]Config error:[/] {exc}")
        raise typer.Exit(2) from exc


def _db(config: Config) -> DeviceDatabase:
    return DeviceDatabase(config.database_path)


def _run_scan(config: Config):
    try:
        target = detect_network(config.interface, config.subnet)
        observations = scan_subnet(
            target.subnet,
            target.interface,
            config.scan_timeout,
            VendorLookup(),
        )
    except NetworkDetectionError as exc:
        console.print(f"[red]Network detection failed:[/] {exc}")
        raise typer.Exit(2) from exc
    except PermissionScanError as exc:
        console.print(f"[yellow]Permission required:[/] {exc}")
        raise typer.Exit(1) from exc
    except ScanError as exc:
        console.print(f"[red]Scan failed:[/] {exc}")
        raise typer.Exit(1) from exc

    database = _db(config)
    try:
        return database.apply_scan(
            observations,
            str(target.subnet),
            target.interface,
            config.offline_threshold,
        )
    finally:
        database.close()


@app.command()
def scan(config: ConfigOption = None) -> None:
    """Run one LAN scan."""
    loaded = _load(config)
    report = _run_scan(loaded)
    print_scan_report(console, report)


@app.command()
def watch(
    config: ConfigOption = None,
    interval: Annotated[
        int | None,
        typer.Option("--interval", "-i", help="Override scan interval in seconds."),
    ] = None,
) -> None:
    """Keep scanning every N seconds."""
    loaded = _load(config)
    sleep_seconds = interval or loaded.scan_interval
    if sleep_seconds <= 0:
        console.print("[red]Scan interval must be greater than zero.[/]")
        raise typer.Exit(2)

    console.print(f"[bold]Watching LAN every {sleep_seconds} seconds. Press Ctrl+C to stop.[/]")
    try:
        while True:
            report = _run_scan(loaded)
            print_scan_report(console, report)
            time.sleep(sleep_seconds)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/]")


@app.command("list")
def list_devices(config: ConfigOption = None) -> None:
    """Show known devices."""
    loaded = _load(config)
    database = _db(loaded)
    try:
        print_device_list(console, database.list_devices())
    finally:
        database.close()


@app.command()
def history(
    identifier: Annotated[str, typer.Argument(help="MAC address or IP address.")],
    config: ConfigOption = None,
) -> None:
    """Show IP/status history for a MAC or IP."""
    loaded = _load(config)
    database = _db(loaded)
    try:
        print_history(console, database.history_for(identifier))
    finally:
        database.close()


@app.command()
def forget(
    identifier: Annotated[str, typer.Argument(help="MAC address or current IP address.")],
    config: ConfigOption = None,
) -> None:
    """Remove a device and its history from the database."""
    loaded = _load(config)
    database = _db(loaded)
    try:
        removed = database.forget(identifier)
    finally:
        database.close()

    if removed:
        console.print(f"[green]Forgot device:[/] {identifier}")
    else:
        console.print(f"[yellow]No matching device found:[/] {identifier}")


if __name__ == "__main__":
    app()
