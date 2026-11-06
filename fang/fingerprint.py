"""Turn advertising data into a human description: what kind of device,
who made it, and whether it is a location tracker.

Tracker signatures (all observable passively in advertisements):
  * Apple Find My (company 0x004C, continuity type 0x12):
      - 2-byte payload  → "near owner" (an owner device is close by)
      - 25-byte payload → full public-key beacon = SEPARATED from its owner.
        This is the state anti-stalking apps (e.g. AirGuard) alert on.
    Both lengths were observed in this user's own captures.
  * Tile (service UUID 0xFEED / 0xFEEC), Chipolo (0xFE33),
    Samsung SmartThings Find (service data 0xFD5A — SmartTags but also
    Galaxy phones), Google Find My Device network (Eddystone service 0xFEAA
    with frame type 0x40 / 0x41; 0x41 = unwanted-tracking-protection mode).

Wording is deliberately cautious: a separated tracker near you is worth a
look, not proof that someone is tracking you (a friend's bag, a rental
car, a neighbour's keys all look the same).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import assigned
from .ble import AdInfo, random_addr_kind

APPLE = 0x004C
MICROSOFT = 0x0006

APPLE_TYPES = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods/Beats", 0x08: "Hey Siri",
    0x09: "AirPlay target", 0x0A: "AirPlay source", 0x0B: "Apple Watch",
    0x0C: "Handoff", 0x0D: "Wi-Fi settings", 0x0E: "Instant Hotspot",
    0x0F: "Nearby Action", 0x10: "Nearby Info", 0x12: "Find My",
}

TRACKER_UUIDS = {0xFEED: "Tile", 0xFEEC: "Tile", 0xFE33: "Chipolo"}


@dataclass(slots=True)
class Fingerprint:
    kind: str = ""                       # short human description
    vendor: str = ""
    tracker: str | None = None           # e.g. "Apple Find My"
    tracker_state: str | None = None     # "separated" / "near owner" / ...
    tags: list[str] = field(default_factory=list)

    @property
    def is_separated_tracker(self) -> bool:
        return self.tracker is not None and self.tracker_state in ("separated", "unwanted-tracking mode")


def apple_tlvs(payload: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i + 2 <= len(payload):
        t, ln = payload[i], payload[i + 1]
        if t not in APPLE_TYPES or i + 2 + ln > len(payload):
            break
        out.append((t, payload[i + 2:i + 2 + ln]))
        i += 2 + ln
    return out


def fingerprint(ad: AdInfo, addr: str | None = None, random: bool = False) -> Fingerprint:
    fp = Fingerprint()

    for cid, payload in ad.manufacturer:
        fp.vendor = fp.vendor or assigned.company(cid)
        if cid == APPLE:
            for t, v in apple_tlvs(payload):
                label = APPLE_TYPES[t]
                if label not in fp.tags:
                    fp.tags.append(label)
                if t == 0x12:
                    fp.tracker = "Apple Find My"
                    fp.tracker_state = "separated" if len(v) >= 25 else "near owner"
                elif t == 0x02 and len(v) >= 21:
                    uuid = v[:16].hex()
                    major = int.from_bytes(v[16:18], "big")
                    minor = int.from_bytes(v[18:20], "big")
                    fp.tags.append(f"iBeacon {uuid[:8]}… {major}/{minor}")
        elif cid == MICROSOFT and payload[:1] == b"\x01":
            fp.tags.append("Windows CDP beacon")
        elif cid == MICROSOFT and payload[:1] == b"\x03":
            fp.tags.append("Swift Pair")

    uuids = set(ad.uuid16) | set(ad.service_data)
    for u, name in TRACKER_UUIDS.items():
        if u in uuids:
            fp.tracker = name
            fp.tracker_state = fp.tracker_state or "present"
    if 0xFD5A in ad.service_data:
        fp.tracker = fp.tracker or "Samsung SmartThings Find"
        fp.tracker_state = fp.tracker_state or "present"
        fp.tags.append("SmartTag or Galaxy device")
    eddy = ad.service_data.get(0xFEAA)
    if eddy:
        frame = eddy[0]
        if frame in (0x40, 0x41):
            fp.tracker = "Google Find My Device"
            fp.tracker_state = "unwanted-tracking mode" if frame == 0x41 else "present"
        else:
            fp.tags.append({0x00: "Eddystone-UID", 0x10: "Eddystone-URL",
                            0x20: "Eddystone-TLM", 0x30: "Eddystone-EID"}.get(frame, "Eddystone"))
    if 0xFE2C in ad.service_data:
        fp.tags.append("Google Fast Pair")
    if 0xFD6F in uuids:
        fp.tags.append("Exposure Notification")

    if not fp.vendor and ad.service_data:
        fp.vendor = assigned.uuid16(next(iter(ad.service_data)))
    elif not fp.vendor and ad.uuid16:
        fp.vendor = assigned.uuid16(ad.uuid16[0])

    # kind: prefer name, then tracker, then appearance, then strongest tag
    app = assigned.appearance(ad.appearance) if ad.appearance is not None else None
    if fp.tracker:
        fp.kind = f"{fp.tracker} tracker" if fp.tracker != "Apple Find My" else "Find My device"
    elif "AirPods/Beats" in fp.tags:
        fp.kind = "AirPods/Beats"
    elif "Nearby Info" in fp.tags or "Handoff" in fp.tags:
        fp.kind = "Apple device"
    elif "Windows CDP beacon" in fp.tags:
        fp.kind = "Windows device"
    elif app:
        fp.kind = app
    elif fp.tags:
        fp.kind = fp.tags[0]
    if random and addr:
        fp.tags.append(f"{random_addr_kind(addr)} random addr")
    return fp
