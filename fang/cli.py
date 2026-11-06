"""fang command line. Every mode has a full-screen view (default on a
terminal), a --text report, and --json (JSON lines) for scripting."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time

from . import __version__
from .device import (BOARD_NAMES, FLASH_HINT, ApiMismatch, RawRecorder,
                     ReplayDevice, Ubertooth, autosuspend_devices, autosuspend_fix,
                     list_devices)
from .usb import (LIBUSB_ERROR_IO, LIBUSB_ERROR_NO_DEVICE, LIBUSB_ERROR_TIMEOUT,
                  UsbError)


def _emit(obj):
    print(json.dumps(obj, separators=(",", ":")), flush=True)


class Stopper:
    """Ctrl-C / SIGTERM / --seconds all end a run cleanly."""

    def __init__(self, seconds: float | None):
        self.until = time.time() + seconds if seconds else None
        self.stop = False
        signal.signal(signal.SIGINT, self._sig)
        signal.signal(signal.SIGTERM, self._sig)

    def _sig(self, *_):
        self.stop = True

    def __bool__(self):
        return not self.stop and (self.until is None or time.time() < self.until)


def open_device(args):
    if getattr(args, "replay", None):
        return ReplayDevice(args.replay)
    if autosuspend_devices():
        print(f"fang: warning: {autosuspend_fix()}\n", file=sys.stderr)
    ut = Ubertooth(index=args.device)
    if getattr(args, "record", None):
        ut.recorder = RawRecorder(args.record, args.command or "")
    return ut


def device_info(ut) -> dict:
    if isinstance(ut, ReplayDevice):
        return {"board": "replay", "firmware": ut.mode_hint or "?"}
    v = ut.api_version
    return {
        "board": BOARD_NAMES.get(ut.board_id(), "unknown"),
        "firmware": ut.firmware_revision(),
        "api": f"{v >> 8}.{v & 0xFF:02x}",
        "compile_info": ut.compile_info(),
        "serial": ut.serial(),
        "part_number": f"0x{ut.part_number():08x}",
        "usb": f"bus {ut.bus} device {ut.address}",
        "usb_autosuspend": bool(autosuspend_devices()),
    }


def _is_tty() -> bool:
    return sys.stdout.isatty() and sys.stdin.isatty()


def _mode(args) -> str:
    if args.json:
        return "json"
    if args.text or not _is_tty():
        return "text"
    return "tui"


def _ble_kwargs(args) -> dict:
    chans = [int(c) for c in args.channels.split(",")] if args.channels else [37, 38, 39]
    return dict(channels=chans, hop=args.hop, dwell=args.dwell, camp=args.camp,
                follow=getattr(args, "follow", False), target=getattr(args, "target", None))


# ------------------------------------------------------------------ info
def cmd_info(args):
    devs = list_devices()
    if not devs:
        print("No Ubertooth found on USB.")
        return 1
    for i, d in enumerate(devs):
        v = d["bcdDevice"]
        print(f"[{i}] bus {d['bus']} device {d['address']}  API {v >> 8}.{v & 0xFF:02x}")
    try:
        with Ubertooth(index=args.device) as ut:
            info = device_info(ut)
            info.update({"leds": ut.leds(), "front_end_enabled": ut.get_pa_enabled(),
                         "high_gain_mode": ut.get_hgm(), "squelch": ut.get_squelch()})
    except ApiMismatch as e:
        print(e)
        return 2
    if info["usb_autosuspend"]:
        print(f"\n{autosuspend_fix()}\n", file=sys.stderr)
    if args.json:
        _emit(info)
        return 0
    w = max(len(k) for k in info)
    for k, v in info.items():
        print(f"  {k.replace('_', ' '):{w}}  {v}")
    return 0


# -------------------------------------------------------------- spectrum
def cmd_spectrum(args):
    from .spectrum import Spectrum
    mode = _mode(args)
    with open_device(args) as ut:
        if mode == "tui":
            from .tui import run_tui
            run_tui(ut, view="spectrum", hgm=not args.no_hgm, info=device_info(ut))
            return 0
        s = Spectrum(ut, low=args.low, high=args.high, hgm=not args.no_hgm)
        s.start()
        stop = Stopper(args.seconds or (None if mode == "json" else 5))
        last = time.time()
        while stop:
            s.pump()
            if mode == "json" and time.time() - last >= args.interval:
                last = time.time()
                _emit({"t": round(last, 3), "low": s.low, "hgm": s.hgm,
                       "noise_floor": round(s.noise_floor(), 1),
                       "avg": [round(v, 1) for v in s.avg], "peak": [round(v, 1) for v in s.peak],
                       "wifi_busy": {x.name: round(x.busy, 3) for x in s.wifi_scores()}})
            if getattr(ut, "done", False):
                break
        if mode == "text":
            _spectrum_report(s)
    return 0


def _spectrum_report(s):
    el = max(0.001, time.time() - s.started)
    print(f"2.4 GHz survey: {s.sweeps} sweeps in {el:.1f}s, front-end HGM {'on' if s.hgm else 'off'}, "
          f"16 MHz crystal spurs masked")
    print(f"noise floor ≈ {s.noise_floor():.0f} dBm (approximate)\n")
    print("strongest signals:")
    for f, v in s.peaks(5):
        print(f"  {f} MHz  {v:6.1f} dBm")
    print("\nWi-Fi channels (busy = % of time > 10 dB above the noise floor):")
    for x in s.wifi_scores():
        bar = "█" * int(x.busy * 40)
        print(f"  {x.name:9} {x.busy:5.1%} {bar}")
    best = s.best_wifi()
    print(f"\n→ least busy of the non-overlapping channels 1/6/11: {best.name}")
    print("\nBLE advertising channels:")
    for x in s.ble_adv_scores():
        print(f"  {x.name:7} {x.busy:5.1%} busy")


# ------------------------------------------------------------------ BLE
def cmd_scan(args, view="ble"):
    from .blescan import BleScanner
    from .pcap import PcapWriter
    mode = _mode(args)
    with open_device(args) as ut:
        if mode == "tui":
            from .tui import run_tui
            run_tui(ut, view=view, ble_kwargs=_ble_kwargs(args), pcap_dir=args.pcap_dir,
                    led=getattr(args, "led", False), info=device_info(ut))
            return 0
        sc = BleScanner(ut, keep_bad=args.keep_bad, **_ble_kwargs(args))
        pcap = PcapWriter(args.pcap) if args.pcap else None
        sc.start()
        default = None if (mode == "json" or view == "trackers") else 15
        stop = Stopper(args.seconds or default)
        seen_trackers: dict[str, str] = {}
        try:
            while stop:
                for p in sc.pump():
                    if pcap:
                        pcap.write(p, ref_aa=p.access_address)
                    if mode == "json":
                        d = sc.devices.get(p.adv_addr) if p.adv_addr else None
                        ev = {"t": round(p.timestamp, 6), "freq": p.freq, "rssi": p.rssi_dbm,
                              "aa": f"{p.access_address:08x}", "crc_ok": p.crc_valid,
                              "type": p.type_name, "addr": p.adv_addr, "target": p.target_addr,
                              "adv_data": p.adv_data.hex() or None}
                        if d is not None:
                            ev.update(kind=d.fp.kind, vendor=d.fp.vendor, name=d.name,
                                      tracker=d.fp.tracker, tracker_state=d.fp.tracker_state)
                        if p.connect:
                            c = p.connect
                            ev["connect"] = {"aa": f"{c.access_address:08x}", "crc_init": f"{c.crc_init:06x}",
                                             "interval_ms": c.interval_ms, "hop": c.hop,
                                             "channels": len(c.used_channels)}
                        _emit(ev)
                if view == "trackers" and mode == "text":
                    for d in sc.trackers(within=60):
                        key = f"{d.fp.tracker}|{d.fp.tracker_state}"
                        if seen_trackers.get(d.addr) != key:
                            seen_trackers[d.addr] = key
                            print(f"{time.strftime('%H:%M:%S')}  {d.fp.tracker:26} {d.fp.tracker_state:22} "
                                  f"{d.addr}  {d.rssi_avg:.0f} dBm", flush=True)
                    if getattr(args, "led", False):
                        on = any(d.fp.is_separated_tracker for d in sc.trackers(within=60))
                        ut.set_usr_led(on)
                if getattr(ut, "done", False):
                    break
        finally:
            if pcap:
                pcap.close()
            if getattr(args, "led", False) and not isinstance(ut, ReplayDevice):
                ut.set_usr_led(False)
        if mode == "text":
            _ble_report(sc, trackers_only=(view == "trackers"), min_count=args.min_packets)
            if pcap:
                print(f"\nwrote {pcap.count} packets to {args.pcap} (open with: wireshark {args.pcap})")
    return 0


def _ble_report(sc, trackers_only=False, min_count=2):
    t = sc.totals()
    n = t["good"] + t["bad"] + t["trunc"]
    print(f"\nBLE: {n} packets, {t['good']} CRC-valid ({t['good'] / n if n else 0:.0%}); "
          f"bad/garbled packets are discarded, not shown as devices")
    for c in (37, 38, 39):
        s = sc.chstats[c]
        if s.good + s.bad + s.trunc:
            print(f"  adv channel {c}: {s.quality:4.0%} clean  ({s.good} good / {s.bad + s.trunc} bad)")
    devs = sc.trackers(within=1e9) if trackers_only else sc.active_devices(within=1e9, min_count=min_count)
    devs.sort(key=lambda d: -d.rssi_avg)
    label = "trackers" if trackers_only else f"devices (≥{min_count} valid packets)"
    print(f"\n{len(devs)} {label}:\n")
    if not devs:
        return
    print(f"{'ADDRESS':17} T {'RSSI':>4} {'PKTS':>5}  {'KIND':22} {'VENDOR':24} NAME / TRACKER")
    for d in devs:
        extra = d.name or ""
        if d.fp.tracker:
            extra = f"{d.fp.tracker} ({d.fp.tracker_state}) {extra}"
        print(f"{d.addr:17} {'R' if d.random else 'P'} {d.rssi_avg:4.0f} {d.count:5d}  "
              f"{(d.fp.kind or '-')[:22]:22} {(d.fp.vendor or '')[:24]:24} {extra}")


def cmd_follow(args):
    """Follow BLE connections: the firmware latches onto a CONNECT_IND and
    hops with the connection. fang validates data-channel CRCs using the
    CRCInit learned from that CONNECT_IND."""
    from .blescan import BleScanner
    from .pcap import PcapWriter
    args.hop = "fixed"
    with open_device(args) as ut:
        sc = BleScanner(ut, follow=True, target=args.target, keep_bad=True,
                        channels=[int(args.channels.split(",")[0])] if args.channels else [37])
        pcap = PcapWriter(args.pcap) if args.pcap else None
        sc.start()
        print(f"listening for connections on ch{sc.current}"
              + (f" from {args.target}" if args.target else " (any device)")
              + " — Ctrl-C to stop", file=sys.stderr)
        stop = Stopper(args.seconds)
        per_conn = {}
        try:
            while stop:
                for p in sc.pump():
                    if pcap and (p.crc_valid or not p.is_adv):
                        ref = p.access_address
                        pcap.write(p, ref_aa=ref)
                    if p.connect and p.crc_valid:
                        c = p.connect
                        msg = {"event": "connect", "initiator": p.target_addr, "advertiser": p.adv_addr,
                               "aa": f"{c.access_address:08x}", "crc_init": f"{c.crc_init:06x}",
                               "interval_ms": c.interval_ms, "latency": c.latency,
                               "timeout_ms": c.timeout * 10, "hop": c.hop,
                               "channels_used": len(c.used_channels)}
                        if args.json:
                            _emit(msg)
                        else:
                            print(f"{time.strftime('%H:%M:%S')} CONNECT {p.target_addr} → {p.adv_addr}  "
                                  f"AA={c.access_address:08x} interval={c.interval_ms}ms hop={c.hop} "
                                  f"channels={len(c.used_channels)}/37", flush=True)
                    elif not p.is_adv:
                        st = per_conn.setdefault(p.access_address, [0, 0])
                        st[0] += 1
                        st[1] += bool(p.crc_valid)
                        if args.json:
                            _emit({"event": "data", "aa": f"{p.access_address:08x}", "freq": p.freq,
                                   "type": p.type_name, "len": len(p.pdu) - 2, "crc_ok": p.crc_valid,
                                   "rssi": p.rssi_dbm, "pdu": p.pdu.hex()})
                        elif args.verbose:
                            print(f"  {p.access_address:08x} {p.freq} {p.type_name:13} len={len(p.pdu) - 2:2d} "
                                  f"crc={'ok ' if p.crc_valid else 'BAD'} {p.pdu.hex()}", flush=True)
                if getattr(ut, "done", False):
                    break
        finally:
            if pcap:
                pcap.close()
        if not args.json:
            print(f"\n{len(sc.connections)} connection(s) seen")
            for aa, (n, ok) in per_conn.items():
                print(f"  AA {aa:08x}: {n} data packets, {ok} CRC-valid")
            if pcap:
                print(f"wrote {pcap.count} packets to {args.pcap}")
    return 0


# -------------------------------------------------------------- classic
def cmd_classic(args):
    from .classic import ClassicScanner
    mode = _mode(args)
    with open_device(args) as ut:
        if mode == "tui":
            from .tui import run_tui
            run_tui(ut, view="classic", classic_channel=args.channel, info=device_info(ut))
            return 0
        cs = ClassicScanner(ut, channel=args.channel, max_ac_errors=args.max_ac_errors)
        cs.start()
        stop = Stopper(args.seconds or (None if mode == "json" else 20))
        while stop:
            for pn, errs in cs.pump():
                if mode == "json":
                    _emit({"t": round(pn.last_seen, 3), "lap": f"{pn.lap:06x}", "ac_errors": errs,
                           "rssi": pn.rssi, "channel": max(pn.channels, key=pn.channels.get)})
            if getattr(ut, "done", False):
                break
        cs.flush()
        if mode == "text":
            rows = sorted(cs.piconets.values(), key=lambda p: -p.count)
            print(f"Classic BR/EDR survey: {cs.usb_pkts} packets, {cs.hits} access codes, "
                  f"{len(rows)} piconets (overflows: {cs.overflows})\n")
            print(f"{'LAP':8} {'HITS':>5} {'CLEAN':>5} {'RSSI':>5} {'CHANS':>5}  NOTE")
            for p in rows:
                note = p.label or ("" if p.confident else "low confidence (single noisy hit)")
                print(f"{p.lap:06x}   {p.count:5d} {p.clean:5d} {p.rssi:5d} {len(p.channels):5d}  {note}")
    return 0


# ----------------------------------------------------------------- misc
def cmd_tui(args):
    with open_device(args) as ut:
        from .tui import run_tui
        run_tui(ut, view=args.view, ble_kwargs=_ble_kwargs(args), pcap_dir=args.pcap_dir,
                led=args.led, info=device_info(ut))
    return 0


def cmd_blink(args):
    """Identify a unit: blink its LEDs."""
    with Ubertooth(index=args.device) as ut:
        if args.xmas:
            ut.xmas()
            print("LED light show running — Ctrl-C to stop")
            stop = Stopper(args.seconds or None)
            while stop:
                time.sleep(0.1)
            return 0
        for _ in range(args.times):
            ut.set_usr_led(True)
            ut.set_rx_led(True)
            time.sleep(0.25)
            ut.set_usr_led(False)
            ut.set_rx_led(False)
            time.sleep(0.25)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fang", description="Receive-only toolkit for the Ubertooth One: spectrum analyzer, "
                                 "BLE scanner/tracker detector, connection follower, Classic BT survey.")
    p.add_argument("--version", action="version", version=f"fang {__version__}")
    p.add_argument("-d", "--device", type=int, default=0, help="Ubertooth index (see 'fang info')")
    p.add_argument("--replay", metavar="FILE", help="replay a raw recording instead of using the radio")
    p.add_argument("--record", metavar="FILE", help="record raw USB packets for later --replay")
    sub = p.add_subparsers(dest="command")

    def outputs(sp, seconds_help):
        sp.add_argument("--text", action="store_true", help="print a report instead of the full-screen view")
        sp.add_argument("--json", action="store_true", help="stream JSON lines")
        sp.add_argument("-s", "--seconds", type=float, default=0, help=seconds_help)

    def ble_opts(sp):
        sp.add_argument("--channels", default=None, help="advertising channels, e.g. 37,38,39 (default all)")
        sp.add_argument("--hop", choices=["auto", "rotate", "fixed"], default="auto",
                        help="auto = survey all, then camp on the cleanest (default)")
        sp.add_argument("--dwell", type=float, default=3.0, help="seconds per channel when surveying/rotating")
        sp.add_argument("--camp", type=float, default=20.0, help="seconds on the best channel in auto mode")
        sp.add_argument("--pcap", metavar="FILE", help="write CRC-valid packets to a Wireshark pcap ('-' = stdout)")
        sp.add_argument("--pcap-dir", default=".", help="where the full-screen view's 'r' key saves pcaps")
        sp.add_argument("--keep-bad", action="store_true", help="also emit/write packets with bad CRC")
        sp.add_argument("--min-packets", type=int, default=2, help="text report: hide devices with fewer packets")

    sp = sub.add_parser("info", help="identify the Ubertooth and show hardware state")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("spectrum", help="2.4 GHz spectrum analyzer + Wi-Fi/BLE channel advice")
    outputs(sp, "run time (text default 5 s)")
    sp.add_argument("--low", type=int, default=2402)
    sp.add_argument("--high", type=int, default=2480)
    sp.add_argument("--no-hgm", action="store_true", help="leave the front-end in low-gain mode")
    sp.add_argument("--interval", type=float, default=1.0, help="JSON: seconds between snapshots")
    sp.set_defaults(func=cmd_spectrum)

    sp = sub.add_parser("scan", help="BLE advertisement scanner with device fingerprints")
    outputs(sp, "run time (text default 15 s)")
    ble_opts(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("trackers", help="watch for Find My / Tile / SmartTag / Google trackers")
    outputs(sp, "run time (text: until Ctrl-C)")
    ble_opts(sp)
    sp.add_argument("--led", action="store_true", help="light the Ubertooth's USR LED while a separated tracker is in range")
    sp.set_defaults(func=lambda a: cmd_scan(a, view="trackers"))

    sp = sub.add_parser("follow", help="follow BLE connections (your own devices) into a pcap")
    sp.add_argument("-t", "--target", metavar="MAC", help="only follow connections to this advertiser")
    sp.add_argument("--channels", default=None, help="advertising channel to listen on (default 37)")
    sp.add_argument("--pcap", metavar="FILE")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("-v", "--verbose", action="store_true", help="print every data packet")
    sp.add_argument("-s", "--seconds", type=float, default=0)
    sp.set_defaults(func=cmd_follow)

    sp = sub.add_parser("classic", help="Classic Bluetooth piconet (LAP) survey")
    outputs(sp, "run time (text default 20 s)")
    sp.add_argument("-c", "--channel", type=int, default=None, help="fixed BR channel 0-78 (default: sweep)")
    sp.add_argument("-e", "--max-ac-errors", type=int, default=2, choices=range(0, 5))
    sp.set_defaults(func=cmd_classic)

    sp = sub.add_parser("tui", help="full-screen interface (default)")
    sp.add_argument("--view", choices=["spectrum", "ble", "trackers", "classic"], default="spectrum")
    ble_opts(sp)
    sp.add_argument("--led", action="store_true")
    sp.set_defaults(func=cmd_tui)

    sp = sub.add_parser("blink", help="blink the LEDs to identify this unit")
    sp.add_argument("-n", "--times", type=int, default=6)
    sp.add_argument("--xmas", action="store_true", help="firmware LED light show")
    sp.add_argument("-s", "--seconds", type=float, default=0)
    sp.set_defaults(func=cmd_blink)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(argv)
    if not args.command:
        if not _is_tty():
            parser.print_help()
            return 0
        args = parser.parse_args(argv + ["tui"])
    try:
        return args.func(args) or 0
    except ApiMismatch as e:
        print(f"fang: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"fang: {e}", file=sys.stderr)
        return 1
    except UsbError as e:
        print(f"fang: USB error — {e}", file=sys.stderr)
        if autosuspend_devices():
            print(f"\n{autosuspend_fix()}", file=sys.stderr)
        elif e.code in (LIBUSB_ERROR_IO, LIBUSB_ERROR_NO_DEVICE, LIBUSB_ERROR_TIMEOUT):
            print("Unplug and replug the Ubertooth to reset it.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # Output piped into e.g. `head` that exited: silence the shutdown flush.
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
