"""Classic Bluetooth (BR/EDR) discovery: find piconets by their LAP (the
lower 24 bits of the master's BD_ADDR, carried in every packet's access
code). Uses libbtbb's syndrome-based access-code search via ctypes.

Improvement over stock ubertooth-rx: it searches only the first 400 symbols
of each 400-symbol USB packet, so access codes that straddle two packets are
missed. fang keeps the previous packet and searches across the boundary
when the two are contiguous (same channel, back-to-back timestamps).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import time
from collections import Counter
from dataclasses import dataclass, field

from .device import DMA_SIZE, STATUS_DISCARD, STATUS_ERRORS, PktType, Ubertooth, rssi_to_dbm

SYMS = DMA_SIZE * 8            # 400 symbols per USB packet
AC_LEN = 72
LAP_ANY = 0xFFFFFFFF
GIAC = 0x9E8B33                # General Inquiry Access Code
DIAC_RANGE = range(0x9E8B00, 0x9E8B40)

_TO_SYMS = bytes.maketrans(b"01", b"\x00\x01")


def unpack_symbols(data: bytes) -> bytes:
    """50 packed bytes (MSB first) → 400 bytes of 0x00/0x01."""
    return format(int.from_bytes(data[:DMA_SIZE], "big"), f"0{SYMS}b").encode().translate(_TO_SYMS)


class LibBtbb:
    def __init__(self, max_ac_errors: int = 2):
        path = ctypes.util.find_library("btbb") or "libbtbb.so.1"
        self.lib = lib = ctypes.CDLL(path)
        lib.btbb_init.argtypes = [ctypes.c_int]
        lib.btbb_init.restype = ctypes.c_int
        lib.btbb_find_ac.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32,
                                     ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        lib.btbb_find_ac.restype = ctypes.c_int
        lib.btbb_packet_get_lap.argtypes = [ctypes.c_void_p]
        lib.btbb_packet_get_lap.restype = ctypes.c_uint32
        lib.btbb_packet_get_ac_errors.argtypes = [ctypes.c_void_p]
        lib.btbb_packet_get_ac_errors.restype = ctypes.c_uint8
        lib.btbb_packet_unref.argtypes = [ctypes.c_void_p]
        lib.btbb_packet_unref.restype = None
        self.max_ac_errors = max_ac_errors
        if lib.btbb_init(max_ac_errors) < 0:
            raise RuntimeError("btbb_init failed")

    def find_ac(self, stream: bytes, search_len: int, lap: int = LAP_ANY):
        """Returns (offset, lap, ac_errors) or None."""
        pkt = ctypes.c_void_p()
        off = self.lib.btbb_find_ac(stream, search_len, lap, self.max_ac_errors,
                                    ctypes.byref(pkt))
        if off < 0 or not pkt.value:
            return None
        try:
            return off, self.lib.btbb_packet_get_lap(pkt), self.lib.btbb_packet_get_ac_errors(pkt)
        finally:
            self.lib.btbb_packet_unref(pkt)


@dataclass(slots=True)
class Piconet:
    lap: int
    first_seen: float
    last_seen: float
    count: int = 0
    clean: int = 0                         # hits with 0 access-code bit errors
    rssi: int = -127
    rssi_max: int = -127
    channels: Counter = field(default_factory=Counter)

    @property
    def label(self) -> str:
        if self.lap == GIAC:
            return "GIAC — someone is running device discovery (inquiry)"
        if self.lap in DIAC_RANGE:
            return "DIAC — dedicated inquiry"
        return ""

    @property
    def confident(self) -> bool:
        # A single noisy hit is often a false positive of the syndrome search.
        return self.clean >= 1 or self.count >= 3

    def to_dict(self) -> dict:
        return {"lap": f"{self.lap:06x}", "count": self.count, "clean": self.clean,
                "rssi": self.rssi, "rssi_max": self.rssi_max,
                "first_seen": round(self.first_seen, 3), "last_seen": round(self.last_seen, 3),
                "channels": sorted(self.channels), "label": self.label}


class ClassicScanner:
    def __init__(self, ut: Ubertooth, channel: int | None = None, max_ac_errors: int = 2):
        self.ut = ut
        self.mhz = 9999 if channel is None else 2402 + channel   # 9999 → sweep 0-78
        self.btbb = LibBtbb(max_ac_errors)
        self.piconets: dict[int, Piconet] = {}
        self.usb_pkts = 0
        self.overflows = 0
        self.hits = 0
        self.contiguous = 0
        self._pending = None      # (UsbPacket, symbols) awaiting its search

    def start(self):
        self.ut.start_br_rx(self.mhz)

    def _search(self, pkt, syms: bytes, nxt: bytes | None):
        """Search every access-code start position inside `pkt` exactly once:
        with the following packet's symbols appended when contiguous (so
        straddling codes are found), otherwise only where a full 72-symbol
        code still fits."""
        if nxt is not None:
            return self.btbb.find_ac(syms + nxt, SYMS)
        return self.btbb.find_ac(syms, SYMS - AC_LEN)

    def _record(self, pkt, hit, out):
        if hit is None:
            return
        _, lap, errs = hit
        self.hits += 1
        pn = self.piconets.get(lap)
        if pn is None:
            pn = self.piconets[lap] = Piconet(lap, pkt.host_time, pkt.host_time)
        pn.last_seen = pkt.host_time
        pn.count += 1
        pn.clean += errs == 0
        # BR rx runs with the front-end in high-gain mode (cc2400_rx()).
        pn.rssi = rssi_to_dbm(pkt.rssi_max, True)
        pn.rssi_max = max(pn.rssi_max, pn.rssi)
        pn.channels[pkt.channel] += 1
        out.append((pn, errs))

    def flush(self) -> list[tuple[Piconet, int]]:
        out = []
        if self._pending:
            pkt, syms = self._pending
            self._record(pkt, self._search(pkt, syms, None), out)
            self._pending = None
        return out

    def pump(self, timeout_ms: int = 50) -> list[tuple[Piconet, int]]:
        """Process available packets. Returns [(piconet, ac_errors)] hits."""
        out = []
        for p in self.ut.read_bulk(timeout_ms, max_packets=64):
            if p.pkt_type != PktType.BR:
                continue
            self.usb_pkts += 1
            if p.status & STATUS_ERRORS:     # 0x18 = CS/RSSI trigger: informational
                self.overflows += 1
            if p.status & STATUS_DISCARD or p.channel > 78:
                out += self.flush()
                continue
            syms = unpack_symbols(p.data)
            if self._pending:
                prev, prev_syms = self._pending
                contiguous = (prev.channel == p.channel and
                              3900 <= ((p.clk100ns - prev.clk100ns) & 0xFFFFFFFF) <= 4100)
                self.contiguous += contiguous
                self._record(prev, self._search(prev, prev_syms, syms if contiguous else None), out)
            self._pending = (p, syms)
        return out
