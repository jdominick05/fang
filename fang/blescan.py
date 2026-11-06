"""BLE engine: turns raw Ubertooth packets into validated LE packets and a
live table of nearby devices, with advertising-channel management."""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field

from . import ble
from .ble import ADV_AA, ADV_CHANNELS, LePacket
from .device import STATUS_ERRORS, PktType, Ubertooth, UsbPacket, rssi_to_dbm
from .fingerprint import Fingerprint, fingerprint

WRAP = 1 << 32  # clk100ns wraps every ~429.5 s


class ClockMapper:
    """Map the device's 100 ns counter onto wall-clock time so packets in
    one USB read get distinct, accurate timestamps."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.anchor_host = None
        self.anchor_clk = 0
        self.last_clk = 0
        self.ext = 0

    def map(self, clk: int, host: float) -> float:
        if self.anchor_host is None:
            self.anchor_host, self.anchor_clk, self.last_clk, self.ext = host, clk, clk, 0
            return host
        if clk < self.last_clk:
            self.ext += WRAP
        self.last_clk = clk
        t = self.anchor_host + (clk + self.ext - self.anchor_clk) / 1e7
        if abs(t - host) > 0.5:      # lost sync (mode restart, long stall)
            self.anchor_host, self.anchor_clk, self.ext = host, clk, 0
            return host
        return t


@dataclass(slots=True)
class BleDevice:
    addr: str
    random: bool
    first_seen: float
    last_seen: float
    count: int = 0
    rssi: int = -127
    rssi_max: int = -127
    rssi_avg: float = 0.0
    name: str | None = None
    pdu_types: Counter = field(default_factory=Counter)
    channels: Counter = field(default_factory=Counter)
    fp: Fingerprint = field(default_factory=Fingerprint)
    adv_data: bytes = b""
    history: deque = field(default_factory=lambda: deque(maxlen=240))  # (t, rssi)

    @property
    def connectable(self) -> bool:
        return bool(self.pdu_types.get("ADV_IND") or self.pdu_types.get("ADV_DIRECT_IND"))

    def to_dict(self) -> dict:
        return {
            "addr": self.addr, "addr_type": "random" if self.random else "public",
            "first_seen": round(self.first_seen, 3), "last_seen": round(self.last_seen, 3),
            "count": self.count, "rssi": self.rssi, "rssi_max": self.rssi_max,
            "rssi_avg": round(self.rssi_avg, 1), "name": self.name,
            "kind": self.fp.kind, "vendor": self.fp.vendor, "tracker": self.fp.tracker,
            "tracker_state": self.fp.tracker_state, "tags": self.fp.tags,
            "pdu_types": dict(self.pdu_types), "adv_data": self.adv_data.hex(),
        }


@dataclass(slots=True)
class ChannelStats:
    good: int = 0
    bad: int = 0
    trunc: int = 0
    seconds: float = 0.0
    visit_good: int = 0        # good packets during the current/last visit
    last_rate: float = 0.0     # good packets/s measured on the last visit

    @property
    def quality(self) -> float:
        n = self.good + self.bad + self.trunc
        return self.good / n if n else 0.0


class BleScanner:
    """
    channels: list of advertising channel numbers (37/38/39).
    hop: "fixed" (first channel only), "rotate" (round-robin), or
         "auto" (survey all, then camp on the one with the most good packets).
    """

    def __init__(self, ut: Ubertooth, channels=(37, 38, 39), hop: str = "auto",
                 dwell: float = 3.0, camp: float = 20.0, follow: bool = False,
                 target: str | None = None, keep_bad: bool = False,
                 device_ttl: float | None = None):
        self.ut = ut
        self.channels = [c for c in channels if c in ADV_CHANNELS] or [37]
        self.hop = "fixed" if (follow or len(self.channels) == 1) else hop
        self.dwell, self.camp = dwell, camp
        self.follow, self.target = follow, target
        self.keep_bad = keep_bad
        self.device_ttl = device_ttl
        self.devices: dict[str, BleDevice] = {}
        self.chstats: dict[int, ChannelStats] = {c: ChannelStats() for c in ADV_CHANNELS}
        self.clock = ClockMapper()
        self.connections: dict[int, ble.ConnectParams] = {}   # AA -> params
        self.data_pkts = 0
        self.messages: deque = deque(maxlen=50)
        self.total_usb = 0
        self.dropped_status = 0
        self.started = time.time()
        self.live = not getattr(ut, "pkts", None)   # ReplayDevice has .pkts
        self.last_ts = 0.0
        self._ch_i = 0
        self._phase = "survey"
        self._phase_until = 0.0
        self._on_since = 0.0
        self.current = self.channels[0]

    # -------------------------------------------------- channel management
    def start(self):
        # Always set OR clear: the firmware keeps the target filter across
        # sessions, and a stale one silently drops every other advertiser
        # (measured: 35 devices → 1 after a previous `follow -t`).
        self.ut.btle_set_target(self.target)
        self._tune(self.channels[0])
        self._phase = "survey" if self.hop == "auto" else "rotate"
        self._phase_until = time.time() + self.dwell

    def _close_visit(self):
        """Book the time spent on the current channel and its packet rate."""
        if not self._on_since:
            return
        s = self.chstats[self.current]
        dt = time.time() - self._on_since
        s.seconds += dt
        if dt > 0.5:
            s.last_rate = s.visit_good / dt
        s.visit_good = 0
        self._on_since = 0.0

    def _tune(self, ch: int):
        self._close_visit()
        self.current = ch
        self.ut.start_btle(ADV_CHANNELS[ch], follow=self.follow)
        self.clock.reset()
        self._on_since = time.time()

    def _maybe_hop(self):
        if self.hop == "fixed":
            return
        now = time.time()
        if now < self._phase_until:
            return
        if self.hop == "auto" and self._phase == "survey" and self._ch_i + 1 >= len(self.channels):
            self._close_visit()   # so the last surveyed channel's rate counts
        if self.hop == "rotate":
            self._ch_i = (self._ch_i + 1) % len(self.channels)
            self._tune(self.channels[self._ch_i])
            self._phase_until = time.time() + self.dwell
            return
        # auto: survey each channel once, then camp on the best
        if self._phase == "survey":
            self._ch_i += 1
            if self._ch_i < len(self.channels):
                self._tune(self.channels[self._ch_i])
                self._phase_until = time.time() + self.dwell
            else:
                best = max(self.channels, key=lambda c: self.chstats[c].last_rate)
                self._phase = "camp"
                self._tune(best)
                self._phase_until = time.time() + self.camp
        else:
            self._phase, self._ch_i = "survey", 0
            self._tune(self.channels[0])
            self._phase_until = time.time() + self.dwell

    @property
    def hop_status(self) -> str:
        if self.hop == "fixed":
            return f"fixed ch{self.current}"
        if self.hop == "rotate":
            return f"rotating, on ch{self.current}"
        return f"auto: {'surveying' if self._phase == 'survey' else 'camping on'} ch{self.current}"

    # -------------------------------------------------------- processing
    def pump(self, timeout_ms: int = 50) -> list[LePacket]:
        """Read whatever the radio has and process it. Returns the new
        packets (CRC-valid only unless keep_bad)."""
        self._maybe_hop()
        out = []
        for up in self.ut.read_bulk(timeout_ms):
            self.total_usb += 1
            p = self.process(up)
            if p is not None and (p.crc_valid is not False or self.keep_bad):
                out.append(p)
        if self.device_ttl:
            cutoff = self.now() - self.device_ttl
            for a in [a for a, d in self.devices.items() if d.last_seen < cutoff]:
                del self.devices[a]
        return out

    def process(self, up: UsbPacket) -> LePacket | None:
        if up.status & STATUS_ERRORS:
            self.dropped_status += 1
        if up.pkt_type in (PktType.MESSAGE, PktType.LE_PROMISC):
            self.messages.append((up.host_time, up.pkt_type, up.data[:16].hex()))
            return None
        if up.pkt_type != PktType.LE:
            return None
        freq = 2402 + up.channel
        ch_idx = ble.freq_to_channel_index(freq)
        stats = self.chstats.get(ch_idx) if ch_idx in ADV_CHANNELS else None
        parts = ble.split_raw(up.data)
        if parts is None:
            if stats:
                stats.trunc += 1
            return None
        aa, pdu, crc = parts
        if aa == ADV_AA:
            valid = ble.crc_ok(pdu + crc)
        elif aa in self.connections:
            valid = ble.crc_ok(pdu + crc, self.connections[aa].crc_init)
        else:
            valid = None
        if stats:
            if valid:
                stats.good += 1
                stats.visit_good += 1
            else:
                stats.bad += 1
        ts = self.clock.map(up.clk100ns, up.host_time)
        self.last_ts = max(self.last_ts, ts)
        # le_phy.c re-asserts HGM on every RX strobe, so BLE is always high-gain.
        pkt = LePacket(aa, pdu, crc, valid, freq, rssi_to_dbm(up.rssi_max, True), ts)
        if aa != ADV_AA:
            self.data_pkts += 1
            return pkt
        ble.decode_adv(pkt)
        if not valid:
            return pkt
        if pkt.connect is not None:
            self.connections[pkt.connect.access_address] = pkt.connect
        self._update_device(pkt, ch_idx)
        return pkt

    def _update_device(self, pkt: LePacket, ch_idx: int | None):
        if not pkt.adv_addr:
            return
        # SCAN_REQ / CONNECT_IND name the advertiser but are sent by someone
        # else; don't let them skew its RSSI or counts.
        if pkt.pdu_type in (3, 5):
            return
        d = self.devices.get(pkt.adv_addr)
        if d is None:
            d = self.devices[pkt.adv_addr] = BleDevice(
                pkt.adv_addr, pkt.tx_random, pkt.timestamp, pkt.timestamp)
        d.last_seen = pkt.timestamp
        d.count += 1
        d.rssi = pkt.rssi_dbm
        d.rssi_max = max(d.rssi_max, pkt.rssi_dbm)
        d.rssi_avg = pkt.rssi_dbm if d.count == 1 else 0.9 * d.rssi_avg + 0.1 * pkt.rssi_dbm
        d.pdu_types[pkt.type_name] += 1
        if ch_idx is not None:
            d.channels[ch_idx] += 1
        d.history.append((pkt.timestamp, pkt.rssi_dbm))
        if pkt.adv_data:
            ad = ble.decode_ad(pkt.adv_data)
            if ad.name:
                d.name = ad.name
            # SCAN_RSP often only carries a name; keep the richer ADV fingerprint
            if pkt.pdu_type != 4 or not d.adv_data:
                d.adv_data = pkt.adv_data
                d.fp = fingerprint(ad, d.addr, d.random)

    # -------------------------------------------------------- summaries
    def now(self) -> float:
        """Wall clock when live; the recording's clock when replaying."""
        return time.time() if self.live else (self.last_ts or time.time())

    def trackers(self, within: float = 120.0) -> list[BleDevice]:
        return [d for d in self.active_devices(within) if d.fp.tracker]

    def active_devices(self, within: float = 30.0, min_count: int = 1) -> list[BleDevice]:
        cutoff = self.now() - within
        return [d for d in self.devices.values() if d.last_seen >= cutoff and d.count >= min_count]

    def totals(self) -> dict:
        g = sum(s.good for s in self.chstats.values())
        b = sum(s.bad for s in self.chstats.values())
        t = sum(s.trunc for s in self.chstats.values())
        return {"good": g, "bad": b, "trunc": t, "data": self.data_pkts,
                "usb": self.total_usb, "status_flags": self.dropped_status}
