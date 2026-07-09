from __future__ import annotations

from pathlib import Path


COMMON_OUI_PATHS = (
    Path("/usr/share/misc/oui.txt"),
    Path("/usr/local/share/ieee-data/oui.txt"),
    Path("/var/lib/ieee-data/oui.txt"),
)


FALLBACK_VENDORS = {
    "00:00:0c": "Cisco Systems",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:95": "Apple",
    "00:14:22": "Dell",
    "00:16:cb": "Apple",
    "00:17:f2": "Apple",
    "00:19:e3": "Apple",
    "00:1b:63": "Apple",
    "00:1c:b3": "Apple",
    "00:1d:4f": "Apple",
    "00:1e:52": "Apple",
    "00:1f:f3": "Apple",
    "00:21:e9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6c": "Apple",
    "00:23:df": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4b": "Apple",
    "00:25:bc": "Apple",
    "00:26:08": "Apple",
    "00:26:bb": "Apple",
    "00:50:56": "VMware",
    "00:90:27": "Intel",
    "00:e0:4c": "Realtek",
    "08:00:27": "Oracle VirtualBox",
    "18:65:90": "Apple",
    "28:cf:e9": "Apple",
    "3c:5a:b4": "Google",
    "44:65:0d": "Amazon",
    "50:c7:bf": "TP-Link",
    "54:60:09": "Google",
    "58:55:ca": "Apple",
    "60:01:94": "Espressif",
    "64:16:66": "Nest Labs",
    "6c:72:20": "Apple",
    "74:e2:8c": "Microsoft",
    "78:4f:43": "Apple",
    "84:38:35": "Apple",
    "88:66:5a": "Apple",
    "90:72:40": "Apple",
    "98:01:a7": "Apple",
    "a4:83:e7": "Apple",
    "ac:bc:32": "Apple",
    "b8:27:eb": "Raspberry Pi",
    "b8:e8:56": "Apple",
    "bc:92:6b": "Apple",
    "c8:2a:14": "Apple",
    "d8:3a:dd": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e0:ac:cb": "Apple",
    "ec:2c:e2": "Apple",
    "f0:18:98": "Apple",
    "f4:f5:d8": "Google",
}


class VendorLookup:
    def __init__(self, oui_paths: tuple[Path, ...] = COMMON_OUI_PATHS) -> None:
        self._vendors = dict(FALLBACK_VENDORS)
        self._load_oui_files(oui_paths)

    def lookup(self, mac_address: str) -> str | None:
        oui = _oui(mac_address)
        return self._vendors.get(oui)

    def _load_oui_files(self, paths: tuple[Path, ...]) -> None:
        for path in paths:
            if not path.exists():
                continue
            try:
                self._load_oui_file(path)
            except OSError:
                continue

    def _load_oui_file(self, path: Path) -> None:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if "(hex)" not in line:
                    continue
                prefix, vendor = line.split("(hex)", maxsplit=1)
                normalized = prefix.strip().lower().replace("-", ":")
                if len(normalized) == 8:
                    self._vendors[normalized] = vendor.strip()


def _oui(mac_address: str) -> str:
    normalized = mac_address.strip().lower().replace("-", ":")
    return ":".join(normalized.split(":")[:3])
