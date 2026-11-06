"""Bluetooth SIG assigned numbers (company IDs, 16-bit UUIDs, appearance
categories). Tables are generated from Wireshark by tools/gen_assigned.sh."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=None)
def _table(name: str) -> dict[int, str]:
    out: dict[int, str] = {}
    try:
        text = resources.files("fang.data").joinpath(name).read_text("utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return out
    for line in text.splitlines():
        k, _, v = line.partition("\t")
        if k.isdigit():
            out[int(k)] = v
    return out


def company(cid: int) -> str:
    return _table("company_ids.tsv").get(cid, f"company 0x{cid:04x}")


def uuid16(u: int) -> str:
    return _table("uuid16.tsv").get(u, f"0x{u:04x}")


def appearance(value: int) -> str | None:
    if value is None:
        return None
    return _table("appearance.tsv").get(value >> 6)
