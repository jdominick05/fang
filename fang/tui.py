"""Full-screen terminal UI (stdlib curses). One radio, four views:
  1 Spectrum  — live 2.4 GHz bars + peak hold + waterfall + channel advice
  2 BLE       — live device table with fingerprints; Enter for details
  3 Trackers  — Find My / Tile / SmartTag / Google FMDN, separated-state alerts
  4 Classic   — BR/EDR piconets (LAPs)
Switching between radio-mode groups (spectrum / BLE / classic) retunes the
Ubertooth; each engine keeps its accumulated state while you're away."""

from __future__ import annotations

import curses
import os
import time

from . import __version__, ble
from .blescan import BleDevice, BleScanner
from .classic import ClassicScanner
from .device import BOARD_NAMES
from .pcap import PcapWriter
from .spectrum import BLE_ADV, SPUR_FREQS, WIFI_CHANNELS, Spectrum

VIEWS = ["spectrum", "ble", "trackers", "classic"]
VIEW_TITLES = {"spectrum": "Spectrum", "ble": "BLE", "trackers": "Trackers", "classic": "Classic"}
SPARK = "▁▂▃▄▅▆▇█"
BARS = " ▁▂▃▄▅▆▇█"

GRAD_256 = [17, 18, 19, 20, 21, 27, 33, 39, 45, 51, 50, 49, 48, 47, 46, 82, 118,
            154, 190, 226, 220, 214, 208, 202, 196]


def ago(seconds: float) -> str:
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}"
    return f"{s // 3600}h{s % 3600 // 60:02d}"


def sparkline(values, lo=-100.0, hi=-35.0, width=24) -> str:
    vals = list(values)[-width:]
    out = []
    for v in vals:
        k = int((v - lo) / (hi - lo) * (len(SPARK) - 1))
        out.append(SPARK[max(0, min(len(SPARK) - 1, k))])
    return "".join(out)


class App:
    def __init__(self, ut, view: str = "spectrum", hgm: bool = True,
                 ble_kwargs: dict | None = None, classic_channel: int | None = None,
                 pcap_dir: str = ".", led: bool = False, info: dict | None = None):
        self.ut = ut
        self.view = view if view in VIEWS else "spectrum"
        self.hgm = hgm
        self.ble_kwargs = ble_kwargs or {}
        self.classic_channel = classic_channel
        self.pcap_dir = pcap_dir
        self.led = led
        self.info = info or {}
        self.spec: Spectrum | None = None
        self.ble: BleScanner | None = None
        self.classic: ClassicScanner | None = None
        self.active_group = None
        self.pcap: PcapWriter | None = None
        self.paused = False
        self.sel = 0
        self.sort = "rssi"
        self.show_stale = False
        self.detail: str | None = None
        self.help = False
        self.msg = ""
        self.msg_until = 0.0
        self._wf_acc = None
        self._rate = {"t": time.time(), "n": 0, "pps": 0.0}
        self._led_state = None

    # ------------------------------------------------------------ engines
    @staticmethod
    def group(view: str) -> str:
        return {"spectrum": "spectrum", "ble": "ble", "trackers": "ble", "classic": "classic"}[view]

    def activate(self):
        g = self.group(self.view)
        if g == self.active_group:
            return
        if g == "spectrum":
            if self.spec is None:
                self.spec = Spectrum(self.ut, hgm=self.hgm)
            self.spec.start()
        elif g == "ble":
            if self.ble is None:
                self.ble = BleScanner(self.ut, **self.ble_kwargs)
            self.ble.start()
        else:
            if self.classic is None:
                self.classic = ClassicScanner(self.ut, channel=self.classic_channel)
            self.classic.start()
        self.active_group = g

    def pump(self):
        g = self.active_group
        n = 0
        if g == "spectrum":
            n = self.spec.pump(30)
        elif g == "ble":
            pkts = self.ble.pump(30)
            n = len(pkts)
            if self.pcap:
                for p in pkts:
                    self.pcap.write(p)
            if self.led:
                self._update_led()
        elif g == "classic":
            n = len(self.classic.pump(30))
        self._rate["n"] += n

    def _update_led(self):
        on = any(d.fp.is_separated_tracker for d in self.ble.trackers(within=60))
        if on != self._led_state:
            try:
                self.ut.set_usr_led(on)
            except Exception:
                pass
            self._led_state = on

    def flash(self, msg: str, secs: float = 4.0):
        self.msg, self.msg_until = msg, time.time() + secs

    def toggle_pcap(self):
        if self.pcap:
            path, n = self.pcap.path, self.pcap.count
            self.pcap.close()
            self.pcap = None
            self.flash(f"saved {n} packets → {path}")
        else:
            os.makedirs(self.pcap_dir, exist_ok=True)
            path = os.path.join(self.pcap_dir, time.strftime("fang-ble-%Y%m%d-%H%M%S.pcap"))
            self.pcap = PcapWriter(path)
            self.flash(f"recording CRC-valid packets → {path}")

    # ------------------------------------------------------------ colors
    def init_colors(self):
        self.c = {}
        if not curses.has_colors():
            self.grad = [0]
            return
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        pairs = {
            "head": (curses.COLOR_BLACK, curses.COLOR_CYAN), "good": (curses.COLOR_GREEN, bg),
            "warn": (curses.COLOR_YELLOW, bg), "bad": (curses.COLOR_RED, bg),
            "dim": (curses.COLOR_BLUE, bg), "key": (curses.COLOR_CYAN, bg),
            "alert": (curses.COLOR_WHITE, curses.COLOR_RED), "ok": (curses.COLOR_BLACK, curses.COLOR_GREEN),
            "mag": (curses.COLOR_MAGENTA, bg),
        }
        for i, (name, (fg, b)) in enumerate(pairs.items(), start=1):
            curses.init_pair(i, fg, b)
            self.c[name] = curses.color_pair(i)
        base = len(pairs) + 1
        if curses.COLORS >= 256:
            cols = GRAD_256
        else:
            cols = [curses.COLOR_BLUE, curses.COLOR_CYAN, curses.COLOR_GREEN,
                    curses.COLOR_YELLOW, curses.COLOR_RED]
        self.grad = []
        for i, col in enumerate(cols):
            curses.init_pair(base + i, col, bg)
            self.grad.append(curses.color_pair(base + i))

    def col(self, name: str) -> int:
        return self.c.get(name, 0)

    def gcol(self, frac: float) -> int:
        k = int(max(0.0, min(0.999, frac)) * len(self.grad))
        return self.grad[k]

    # ------------------------------------------------------------ drawing
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        text = str(text)[: max(0, w - x - (1 if y == h - 1 else 0))]
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < 16 or w < 60:
            self.put(0, 0, f"terminal too small ({w}x{h}); need at least 60x16")
            self.scr.refresh()
            return
        self.draw_header(w)
        if self.help:
            self.draw_help(h, w)
        elif self.view == "spectrum":
            self.draw_spectrum(h, w)
        elif self.view == "ble":
            self.draw_ble(h, w)
        elif self.view == "trackers":
            self.draw_trackers(h, w)
        else:
            self.draw_classic(h, w)
        self.draw_footer(h, w)
        self.scr.refresh()

    def draw_header(self, w):
        tabs = []
        x = 0
        self.put(0, 0, " " * w, self.col("head"))
        title = f" fang {__version__} "
        self.put(0, x, title, self.col("head") | curses.A_BOLD)
        x += len(title)
        for i, v in enumerate(VIEWS, 1):
            label = f" {i} {VIEW_TITLES[v]} "
            attr = (curses.A_REVERSE | curses.A_BOLD) if v == self.view else self.col("head")
            self.put(0, x, label, attr)
            x += len(label)
        fw = self.info.get("firmware", "")
        right = f"{self.info.get('board', 'Ubertooth')} fw {fw} "
        if self.pcap:
            right = f"● REC {self.pcap.count} " + right
        if self.paused:
            right = "PAUSED " + right
        self.put(0, max(x + 1, w - len(right)), right, self.col("head"))

    def draw_footer(self, h, w):
        keys = {"spectrum": "g HGM  m spur-mask  p reset peaks",
                "ble": "↑↓ select  ⏎ details  s sort  a stale  r record pcap",
                "trackers": "↑↓ select  ⏎ details  r record pcap",
                "classic": "s sort"}[self.view]
        text = f" 1-4 views  {keys}  space pause  ? help  q quit"
        if self.msg and time.time() < self.msg_until:
            text = " " + self.msg
        self.put(h - 1, 0, text.ljust(w - 1), self.col("head"))

    def draw_help(self, h, w):
        lines = [
            "fang — receive-only Ubertooth One toolkit", "",
            "Views (each switch retunes the radio; data is kept):",
            "  1 Spectrum   live 2.4 GHz power, peak hold, waterfall, Wi-Fi/BLE channel scores",
            "  2 BLE        every advertiser, CRC-verified in software (no ghost devices)",
            "  3 Trackers   Apple Find My, Tile, Chipolo, SmartThings Find, Google FMDN",
            "  4 Classic    BR/EDR piconets by LAP (lower 24 bits of the master address)", "",
            "Spectrum:  g toggle front-end high-gain mode (HGM, ~12 dB more sensitive)",
            "           m toggle masking of the 16 MHz crystal spurs  p reset peak hold",
            "BLE:       s cycle sort (rssi/packets/last/first/name)  a show stale devices",
            "           r start/stop recording CRC-valid packets to a Wireshark pcap",
            "           ⏎ details for the selected device, Esc to close", "",
            "Levels are approximate dBm (uncalibrated; HGM gain step compensated).",
            "A 'separated' tracker is one away from its owner. Near you for a long time",
            "while you move around is worth checking — but it's often a friend's or",
            "a neighbour's. It is not proof of tracking.", "", "Press ? or Esc to close.",
        ]
        for i, line in enumerate(lines):
            self.put(2 + i, 2, line, curses.A_BOLD if i == 0 else 0)

    # --------------------------------------------------------- spectrum
    def draw_spectrum(self, h, w):
        s = self.spec
        if s is None:
            return
        lo_db = min(-115.0, s.noise_floor() - 4)
        hi_db = max(-40.0, max(s.peak) + 3)
        chart_h = max(6, (h - 10) // 2)
        wf_h = max(3, h - 10 - chart_h)
        top = 2
        plot_x = 6
        plot_w = w - plot_x - 1
        nb = s.n

        def bins_for(col):
            a = int(col * nb / plot_w)
            b = max(a + 1, int((col + 1) * nb / plot_w))
            return range(a, min(b, nb))

        clean_avg = s._clean(s.avg) if s.mask_spurs else s.avg
        # y-axis labels
        for r in range(0, chart_h, max(1, chart_h // 4)):
            db = hi_db - (hi_db - lo_db) * r / (chart_h - 1)
            self.put(top + r, 0, f"{db:5.0f}", self.col("dim"))
        for col in range(plot_w):
            idx = bins_for(col)
            if not idx:
                continue
            spur = any(i in s.spur_idx for i in idx)
            v_raw = max(s.avg[i] for i in idx)
            v = max(clean_avg[i] for i in idx)
            pk = max(s.peak[i] for i in idx)
            frac = (v - lo_db) / (hi_db - lo_db)
            eighths = int(max(0.0, min(1.0, frac)) * chart_h * 8)
            attr = self.gcol(frac)
            for r in range(chart_h):
                level = (chart_h - 1 - r) * 8
                fill = eighths - level
                if fill <= 0:
                    ch = " "
                elif fill >= 8:
                    ch = "█"
                else:
                    ch = BARS[fill]
                if ch != " ":
                    self.put(top + r, plot_x + col, ch, attr)
            # peak-hold marker
            pr = int((hi_db - pk) / (hi_db - lo_db) * (chart_h - 1))
            if 0 <= pr < chart_h:
                self.put(top + pr, plot_x + col, "▔", self.col("warn"))
            if spur:
                sr = int((hi_db - v_raw) / (hi_db - lo_db) * (chart_h - 1))
                if 0 <= sr < chart_h and s.mask_spurs:
                    self.put(top + sr, plot_x + col, "×", self.col("dim"))
        # frequency axis + markers
        ay = top + chart_h
        axis = [" "] * plot_w
        marks = [" "] * plot_w

        def col_of(f):
            return int((f - s.low + 0.5) * plot_w / nb)

        for f in range(2410, s.high + 1, 10):
            c = col_of(f)
            lab = str(f)
            if 0 <= c and c + len(lab) <= plot_w:
                for k, chx in enumerate(lab):
                    axis[c + k] = chx
        for n in (1, 6, 11):
            c = col_of(WIFI_CHANNELS[n])
            lab = f"W{n}"
            for k, chx in enumerate(lab):
                if 0 <= c + k < plot_w:
                    marks[c + k] = chx
        for n, f in BLE_ADV.items():
            c = min(plot_w - 2, col_of(f))
            for k, chx in enumerate(str(n)):
                if 0 <= c + k < plot_w:
                    marks[c + k] = chx
        for f in SPUR_FREQS:
            c = col_of(f)
            if 0 <= c < plot_w and marks[c] == " ":
                marks[c] = "×"
        self.put(ay, 0, " MHz", self.col("dim"))
        self.put(ay, plot_x, "".join(axis), self.col("dim"))
        self.put(ay + 1, plot_x, "".join(marks), self.col("key"))
        # waterfall: newest at top
        wy = ay + 2
        rows = list(s.waterfall)[-wf_h:][::-1]
        span = hi_db - lo_db
        for r, row in enumerate(rows):
            if s.mask_spurs:
                row = s._clean(row)
            line_y = wy + r
            for col in range(plot_w):
                idx = bins_for(col)
                if not idx:
                    continue
                v = max(row[i] for i in idx)
                frac = (v - lo_db) / span
                ch = " " if frac < 0.08 else ("░" if frac < 0.25 else ("▒" if frac < 0.45 else ("▓" if frac < 0.65 else "█")))
                if ch != " ":
                    self.put(line_y, plot_x + col, ch, self.gcol(frac))
        if rows:
            self.put(wy, 0, " now", self.col("dim"))
        # info panel
        iy = wy + wf_h
        el = max(0.001, time.time() - s.started)
        hgm_txt = "HGM on" if s.hgm else "HGM off"
        self.put(iy, 1, f"noise floor ≈{s.noise_floor():.0f} dBm   {hgm_txt}   "
                        f"{s.sweeps / el:.0f} sweeps/s   spurs {'masked ×' if s.mask_spurs else 'shown'}"
                        f"   overflows {s.overflows}", self.col("dim"))
        pk = "  ".join(f"{f} {v:.0f}" for f, v in s.peaks(4))
        self.put(iy + 1, 1, f"strongest: {pk}")
        best = s.best_wifi()
        ws = {int(x.name.split()[1]): x for x in s.wifi_scores()}
        wtxt = "   ".join(f"ch{n} {ws[n].busy:4.0%} busy" for n in (1, 6, 11))
        self.put(iy + 2, 1, f"Wi-Fi: {wtxt}   → least busy: ", 0)
        self.put(iy + 2, 1 + len(f"Wi-Fi: {wtxt}   → least busy: "), best.name, self.col("good") | curses.A_BOLD)
        btxt = "   ".join(f"{x.name} {x.busy:4.0%}" for x in s.ble_adv_scores())
        self.put(iy + 3, 1, f"BLE advertising channels busy: {btxt}", self.col("dim"))

    # -------------------------------------------------------------- BLE
    def ble_rows(self, trackers_only=False) -> list[BleDevice]:
        b = self.ble
        if b is None:
            return []
        within = 1e9 if self.show_stale else 60.0
        devs = b.trackers(within) if trackers_only else b.active_devices(within)
        key = {"rssi": lambda d: -d.rssi_avg, "packets": lambda d: -d.count,
               "last": lambda d: -d.last_seen, "first": lambda d: d.first_seen,
               "name": lambda d: (d.name or d.fp.kind or "~", d.addr)}[self.sort]
        return sorted(devs, key=key)

    def draw_ble_status(self, y, w):
        b = self.ble
        t = b.totals()
        n = t["good"] + t["bad"] + t["trunc"]
        q = t["good"] / n if n else 0
        chq = "  ".join(
            f"ch{c} {b.chstats[c].quality:3.0%}" for c in (37, 38, 39) if b.chstats[c].good + b.chstats[c].bad)
        self.put(y, 1, f"{b.hop_status}   {self._rate['pps']:.0f} valid pkt/s   CRC ok {q:.0%}   {chq}   "
                       f"{len(b.active_devices(60))} active / {len(b.devices)} seen")

    def draw_ble(self, h, w):
        if self.ble is None:
            return
        self.draw_ble_status(1, w)
        rows = self.ble_rows()
        if self.detail:
            self.draw_detail(h, w)
            return
        hdr = f"{'ADDRESS':17} T {'RSSI':>4} {'':10} {'MAX':>4} {'PKTS':>5} {'AGE':>5}  {'KIND':20} {'VENDOR':20} NAME"
        self.put(3, 1, hdr, curses.A_BOLD | curses.A_UNDERLINE)
        self._table(rows, 4, h - 2, w, self._ble_line)

    def _ble_line(self, d: BleDevice, y, w, selected):
        now = self.ble.now()
        bar_n = int(max(0, min(10, (d.rssi_avg + 100) / 6.5)))
        attr = curses.A_REVERSE if selected else 0
        t = "R" if d.random else "P"
        text = (f"{d.addr:17} {t} {d.rssi_avg:4.0f} {'':10} {d.rssi_max:4d} {d.count:5d} "
                f"{ago(now - d.last_seen):>5}  {(d.fp.kind or '-')[:20]:20} {(d.fp.vendor or '')[:20]:20} "
                f"{d.name or ''}")
        self.put(y, 1, text.ljust(w - 2), attr)
        self.put(y, 26, ("█" * bar_n).ljust(10), (self.gcol(bar_n / 10) if not selected else attr))
        if d.fp.is_separated_tracker:
            self.put(y, 1, d.addr, self.col("bad") | curses.A_BOLD | attr)

    def _table(self, rows, y0, y1, w, line_fn):
        visible = y1 - y0
        if not rows:
            self.put(y0, 1, "(nothing yet — listening…)", self.col("dim"))
            return
        self.sel = max(0, min(self.sel, len(rows) - 1))
        start = max(0, min(self.sel - visible // 2, len(rows) - visible))
        for i, d in enumerate(rows[start:start + visible]):
            line_fn(d, y0 + i, w, start + i == self.sel)
        self._rows = rows

    def draw_detail(self, h, w):
        d = self.ble.devices.get(self.detail)
        if d is None:
            self.detail = None
            return
        now = self.ble.now()
        y = 3
        L = []
        L.append((f"{d.addr}  ({'random ' + ble.random_addr_kind(d.addr) if d.random else 'public'} address)", curses.A_BOLD))
        L.append((f"kind: {d.fp.kind or '-'}    vendor: {d.fp.vendor or '-'}    name: {d.name or '-'}", 0))
        if d.fp.tracker:
            st = d.fp.tracker_state
            L.append((f"TRACKER: {d.fp.tracker} — {st}", self.col("bad" if d.fp.is_separated_tracker else "warn") | curses.A_BOLD))
        L.append((f"first seen {ago(now - d.first_seen)} ago, last {ago(now - d.last_seen)} ago, "
                  f"{d.count} packets", 0))
        L.append((f"RSSI now {d.rssi} dBm, avg {d.rssi_avg:.0f}, max {d.rssi_max}    "
                  f"{sparkline([r for _, r in d.history], width=min(60, w - 50))}", 0))
        L.append(("PDUs: " + ", ".join(f"{k}×{v}" for k, v in d.pdu_types.most_common()) +
                  "    channels: " + ", ".join(f"{k}×{v}" for k, v in sorted(d.channels.items())), 0))
        if d.fp.tags:
            L.append(("tags: " + ", ".join(d.fp.tags), 0))
        L.append(("", 0))
        L.append(("advertising data:", curses.A_BOLD))
        from . import assigned
        for t, v in ble.parse_ad(d.adv_data):
            desc = {0x01: "flags", 0x02: "uuid16 (partial)", 0x03: "uuid16", 0x06: "uuid128 (partial)",
                    0x07: "uuid128", 0x08: "short name", 0x09: "name", 0x0A: "tx power", 0x16: "service data",
                    0x19: "appearance", 0xFF: "manufacturer"}.get(t, f"type 0x{t:02x}")
            extra = ""
            if t == 0xFF and len(v) >= 2:
                extra = f" [{assigned.company(int.from_bytes(v[:2], 'little'))}]"
            elif t == 0x16 and len(v) >= 2:
                extra = f" [{assigned.uuid16(int.from_bytes(v[:2], 'little'))}]"
            elif t in (0x02, 0x03):
                extra = " [" + ", ".join(assigned.uuid16(int.from_bytes(v[j:j + 2], 'little'))
                                         for j in range(0, len(v) - 1, 2)) + "]"
            L.append((f"  {desc:18} {v.hex(' ')}{extra}", 0))
        L.append(("", 0))
        L.append(("Esc to go back", self.col("dim")))
        for i, (text, attr) in enumerate(L):
            if y + i < h - 1:
                self.put(y + i, 2, text, attr)

    # --------------------------------------------------------- trackers
    def draw_trackers(self, h, w):
        if self.ble is None:
            return
        self.draw_ble_status(1, w)
        if self.detail:
            self.draw_detail(h, w)
            return
        rows = self.ble_rows(trackers_only=True)
        sep = [d for d in rows if d.fp.is_separated_tracker and self.ble.now() - d.last_seen < 60]
        if sep:
            banner = f" {len(sep)} separated tracker(s) in range — away from their owner. Worth a look if one stays with you as you move. "
            self.put(3, 1, banner[: w - 2], self.col("alert") | curses.A_BOLD)
        else:
            self.put(3, 1, " No separated trackers in range. ", self.col("ok") | curses.A_BOLD)
        hdr = f"{'TRACKER':26} {'STATE':22} {'ADDRESS':17} {'RSSI':>4} {'SEEN FOR':>8} {'LAST':>5}  RSSI HISTORY"
        self.put(5, 1, hdr, curses.A_BOLD | curses.A_UNDERLINE)
        self._table(rows, 6, h - 5, w, self._tracker_line)
        tips = ["Addresses rotate (Find My: ~15 min near owner, ~daily when separated), so one tracker can",
                "appear as a few rows. Best test: walk/drive somewhere else and see if a separated one follows."]
        for i, t in enumerate(tips):
            self.put(h - 4 + i, 1, t, self.col("dim"))

    def _tracker_line(self, d: BleDevice, y, w, selected):
        now = self.ble.now()
        attr = curses.A_REVERSE if selected else 0
        state = d.fp.tracker_state or ""
        sattr = self.col("bad") | curses.A_BOLD if d.fp.is_separated_tracker else self.col("good")
        self.put(y, 1, f"{d.fp.tracker[:26]:26} ", attr)
        self.put(y, 28, f"{state[:22]:22} ", sattr | attr)
        self.put(y, 51, f"{d.addr:17} {d.rssi_avg:4.0f} {ago(d.last_seen - d.first_seen):>8} "
                        f"{ago(now - d.last_seen):>5}  {sparkline([r for _, r in d.history], width=max(8, w - 92))}", attr)

    # ---------------------------------------------------------- classic
    def draw_classic(self, h, w):
        c = self.classic
        if c is None:
            return
        mode = "sweeping all 79 channels" if self.classic_channel is None else f"fixed channel {self.classic_channel}"
        self.put(1, 1, f"{mode}   {c.usb_pkts} USB packets   {c.hits} access codes   "
                       f"{len(c.piconets)} piconets   overflows {c.overflows}")
        self.put(2, 1, "LAP = lower 24 bits of the piconet master's BD_ADDR. Low-confidence rows are single noisy hits.",
                 self.col("dim"))
        hdr = f"{'LAP':8} {'HITS':>5} {'CLEAN':>5} {'RSSI':>5} {'MAX':>5} {'CHANS':>5} {'FIRST':>6} {'LAST':>6}  NOTE"
        self.put(4, 1, hdr, curses.A_BOLD | curses.A_UNDERLINE)
        key = {"rssi": lambda p: -p.rssi, "packets": lambda p: -p.count, "last": lambda p: -p.last_seen,
               "first": lambda p: p.first_seen, "name": lambda p: p.lap}[self.sort]
        rows = sorted(c.piconets.values(), key=key)
        now = time.time()

        def line(p, y, w, selected):
            attr = (curses.A_REVERSE if selected else 0) | (0 if p.confident else self.col("dim"))
            note = p.label or ("" if p.confident else "low confidence")
            self.put(y, 1, f"{p.lap:06x}   {p.count:5d} {p.clean:5d} {p.rssi:5d} {p.rssi_max:5d} "
                           f"{len(p.channels):5d} {ago(now - p.first_seen):>6} {ago(now - p.last_seen):>6}  {note}".ljust(w - 2), attr)

        self._table(rows, 5, h - 1, w, line)

    # ------------------------------------------------------------ input
    def key(self, k) -> bool:
        if k in (ord("q"), ord("Q")):
            return False
        if k == 27:  # Esc
            self.detail = None
            self.help = False
            return True
        if k == ord("?"):
            self.help = not self.help
            return True
        if k in (ord("1"), ord("2"), ord("3"), ord("4")):
            self.view = VIEWS[k - ord("1")]
            self.detail = None
            self.sel = 0
            if not self.paused:
                self.activate()
            return True
        if k == ord(" "):
            self.paused = not self.paused
            if self.paused:
                self.ut.stop()
                self.active_group = None
                self.flash("paused (radio stopped)")
            else:
                self.activate()
            return True
        if k in (curses.KEY_UP, ord("k")):
            self.sel = max(0, self.sel - 1)
        elif k in (curses.KEY_DOWN, ord("j")):
            self.sel += 1
        elif k == curses.KEY_PPAGE:
            self.sel = max(0, self.sel - 10)
        elif k == curses.KEY_NPAGE:
            self.sel += 10
        elif k in (curses.KEY_ENTER, 10, 13) and self.view in ("ble", "trackers"):
            rows = getattr(self, "_rows", [])
            if rows and self.sel < len(rows) and isinstance(rows[self.sel], BleDevice):
                self.detail = rows[self.sel].addr
        elif k == ord("s"):
            order = ["rssi", "packets", "last", "first", "name"]
            self.sort = order[(order.index(self.sort) + 1) % len(order)]
            self.flash(f"sort: {self.sort}", 2)
        elif k == ord("a"):
            self.show_stale = not self.show_stale
            self.flash("showing all devices ever seen" if self.show_stale else "hiding devices silent > 60 s", 2)
        elif k == ord("r") and self.group(self.view) == "ble":
            self.toggle_pcap()
        elif k == ord("g") and self.spec is not None and self.view == "spectrum":
            self.spec.set_hgm(not self.spec.want_hgm)
            self.spec.peak = list(self.spec.avg)
            self.flash(f"front-end high-gain mode {'ON' if self.spec.want_hgm else 'OFF'}", 2)
        elif k == ord("m") and self.spec is not None:
            self.spec.mask_spurs = not self.spec.mask_spurs
        elif k == ord("p") and self.spec is not None:
            self.spec.peak = list(self.spec.avg)
        return True

    # ------------------------------------------------------------- loop
    def run(self, stdscr):
        self.scr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)
        self.init_colors()
        self.activate()
        last_draw = 0.0
        try:
            while True:
                if not self.paused and self.active_group:
                    self.pump()
                else:
                    time.sleep(0.03)
                now = time.time()
                if now - self._rate["t"] >= 1.0:
                    self._rate["pps"] = self._rate["n"] / (now - self._rate["t"])
                    self._rate["t"], self._rate["n"] = now, 0
                if now - last_draw >= 0.1:
                    self.draw()
                    last_draw = now
                k = stdscr.getch()
                while k != -1:
                    if not self.key(k):
                        return
                    k = stdscr.getch()
        finally:
            if self.pcap:
                self.pcap.close()
            if self.led and self._led_state:
                try:
                    self.ut.set_usr_led(False)
                except Exception:
                    pass


def run_tui(ut, **kwargs):
    app = App(ut, **kwargs)
    curses.wrapper(app.run)
    return app
