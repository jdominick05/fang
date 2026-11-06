"""2.4 GHz spectrum analyzer engine.

The firmware sweeps low..high in 1 MHz steps and ships 16 (freq, rssi)
samples per USB packet (~6600 samples/s, a full 79 MHz sweep every ~12 ms).
This engine assembles sweeps, keeps live/average/peak-hold traces and a
waterfall history, and scores Wi-Fi and BLE channels from them.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass

from .device import STATUS_ERRORS, PktType, Ubertooth, rssi_to_dbm

WIFI_CHANNELS = {n: 2412 + 5 * (n - 1) for n in range(1, 14)}   # center MHz
BLE_ADV = {37: 2402, 38: 2426, 39: 2480}

# Self-generated spurs: harmonics of the board's 16 MHz crystal. Measured on
# this unit: narrow lines ~22 dB above their neighbours in 85-94% of sweeps,
# same absolute level with HGM on or off (2480 = 155*16 is clean). They are
# drawn but masked out of all analysis so they don't fake "busy" channels.
SPUR_FREQS = (2416, 2432, 2448, 2464)


def mw(dbm: float) -> float:
    return 10 ** (dbm / 10)


def dbm(mw_val: float) -> float:
    return 10 * math.log10(mw_val) if mw_val > 0 else -150.0


@dataclass(slots=True)
class ChannelScore:
    name: str
    center: int
    power_dbm: float     # mean power over the channel, from the average trace
    busy: float          # fraction of recent samples > noise floor + 10 dB


class Spectrum:
    def __init__(self, ut: Ubertooth, low: int = 2402, high: int = 2480,
                 hgm: bool = True, avg_alpha: float = 0.08,
                 peak_decay_db_s: float = 3.0, waterfall_rows: int = 200):
        self.ut, self.low, self.high = ut, low, high
        self.want_hgm = hgm
        self.hgm = False            # actual state, confirmed by readback
        self.n = high - low + 1
        self.live = [-120.0] * self.n
        self.avg = [-120.0] * self.n
        self.peak = [-120.0] * self.n
        self.alpha = avg_alpha
        self.decay = peak_decay_db_s
        self.waterfall: deque[list[float]] = deque(maxlen=waterfall_rows)
        self._row = [-120.0] * self.n
        self._last_f = -1
        self._last_peak_t = time.time()
        self._busy_hits = [0] * self.n
        self._busy_total = [0] * self.n
        self.sweeps = 0
        self.samples = 0
        self.overflows = 0
        self._hgm_pending = False
        self.started = 0.0
        self.spur_idx = {f - low for f in SPUR_FREQS if low <= f <= high}
        self.mask_spurs = True

    def start(self):
        self.ut.start_specan(self.low, self.high)
        self._hgm_pending = True     # apply after first packet (see apply_hgm)
        self.started = time.time()

    def set_hgm(self, on: bool):
        self.want_hgm = on
        self._hgm_pending = True

    def _apply_hgm(self):
        # The firmware's specan() leaves HGM alone (its HGM_SET is commented
        # out) but mode entry may clear it, so set it once streaming and read
        # it back rather than trusting a sleep.
        self.ut.set_hgm(self.want_hgm)
        self.hgm = self.ut.get_hgm()
        self._hgm_pending = self.hgm != self.want_hgm

    def pump(self, timeout_ms: int = 50) -> int:
        """Read and integrate available samples; returns sweeps completed."""
        pkts = self.ut.read_bulk(timeout_ms, max_packets=64)
        if pkts and self._hgm_pending:
            self._apply_hgm()
        done = 0
        for p in pkts:
            if p.pkt_type != PktType.SPECAN:
                continue
            if p.status & STATUS_ERRORS:
                self.overflows += 1
            d = p.data
            for j in range(0, 48, 3):
                f = (d[j] << 8) | d[j + 1]
                i = f - self.low
                if not 0 <= i < self.n:
                    continue
                raw = d[j + 2] - 256 if d[j + 2] > 127 else d[j + 2]
                v = float(rssi_to_dbm(raw, self.hgm))
                if f < self._last_f:            # wrapped: sweep complete
                    self.waterfall.append(self._row)
                    self._row = [-120.0] * self.n
                    self.sweeps += 1
                    done += 1
                self._last_f = f
                self._row[i] = v
                self.live[i] = v
                self.avg[i] = v if self.samples < self.n else (
                    self.avg[i] + self.alpha * (v - self.avg[i]))
                if v > self.peak[i]:
                    self.peak[i] = v
                self.samples += 1
        now = time.time()
        dt = now - self._last_peak_t
        if dt > 0.1 and self.decay > 0:
            fall = self.decay * dt
            floor = self.avg
            self.peak = [max(floor[i], self.peak[i] - fall) for i in range(self.n)]
            self._last_peak_t = now
        if done:
            self._update_busy()
        return done

    def _clean(self, row: list[float]) -> list[float]:
        """Copy of a trace with spur bins replaced by their neighbours."""
        if not self.mask_spurs or not self.spur_idx:
            return row
        out = list(row)
        for i in self.spur_idx:
            nb = [row[j] for j in (i - 1, i + 1) if 0 <= j < self.n and j not in self.spur_idx]
            if nb:
                out[i] = sum(nb) / len(nb)
        return out

    def _update_busy(self):
        nf = self.noise_floor()
        row = self._clean(self.waterfall[-1])
        for i, v in enumerate(row):
            self._busy_total[i] += 1
            if v > nf + 10:
                self._busy_hits[i] += 1
        if self._busy_total[0] > 2000:     # keep it a recent-ish window
            self._busy_hits = [h // 2 for h in self._busy_hits]
            self._busy_total = [t // 2 for t in self._busy_total]

    # ------------------------------------------------------------ analysis
    def noise_floor(self) -> float:
        s = sorted(self._clean(self.avg))
        return s[max(0, len(s) // 10)]

    def freq_of(self, i: int) -> int:
        return self.low + i

    def _band(self, lo: int, hi: int) -> tuple[float, float]:
        idx = [f - self.low for f in range(lo, hi + 1) if self.low <= f <= self.high]
        if not idx:
            return -150.0, 0.0
        avg = self._clean(self.avg)
        p = dbm(sum(mw(avg[i]) for i in idx) / len(idx))
        hits = sum(self._busy_hits[i] for i in idx)
        tot = sum(self._busy_total[i] for i in idx)
        return p, (hits / tot if tot else 0.0)

    def wifi_scores(self) -> list[ChannelScore]:
        out = []
        for n, c in WIFI_CHANNELS.items():
            p, busy = self._band(c - 10, c + 10)
            out.append(ChannelScore(f"Wi-Fi {n}", c, p, busy))
        return out

    def ble_adv_scores(self) -> list[ChannelScore]:
        out = []
        for n, c in BLE_ADV.items():
            p, busy = self._band(c - 1, c + 1)
            out.append(ChannelScore(f"BLE {n}", c, p, busy))
        return out

    def best_wifi(self, candidates=(1, 6, 11)) -> ChannelScore:
        scores = {int(s.name.split()[1]): s for s in self.wifi_scores()}
        return min((scores[c] for c in candidates), key=lambda s: (s.busy, s.power_dbm))

    def peaks(self, n: int = 5, min_sep: int = 4) -> list[tuple[int, float]]:
        avg = self._clean(self.avg)
        order = sorted(range(self.n), key=lambda i: -avg[i])
        picked: list[int] = []
        for i in order:
            if all(abs(i - j) >= min_sep for j in picked):
                picked.append(i)
            if len(picked) == n:
                break
        return [(self.freq_of(i), avg[i]) for i in picked]
