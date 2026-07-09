from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass(frozen=True)
class Config:
    scan_interval: int = 60
    subnet: str | None = None
    subnets: list[str] | None = None
    interface: str | None = None
    offline_threshold: int = 0
    database_path: str = "lanwatch.db"
    scan_timeout: float = 2.0


def load_config(path: Path | None) -> Config:
    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return Config()

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must contain a YAML mapping: {config_path}")

    allowed = set(Config.__dataclass_fields__)
    unknown_keys = set(raw) - allowed
    if unknown_keys:
        keys = ", ".join(sorted(unknown_keys))
        raise ValueError(f"Unknown config option(s): {keys}")

    values: dict[str, Any] = {key: value for key, value in raw.items() if value is not None}
    if values.get("subnet") and values.get("subnets"):
        raise ValueError("Use either 'subnet' or 'subnets', not both.")

    subnets = values.get("subnets")
    if subnets is not None:
        if not isinstance(subnets, list) or not all(isinstance(item, str) for item in subnets):
            raise ValueError("'subnets' must be a list of subnet strings.")
        if not subnets:
            values.pop("subnets")

    return Config(**values)
