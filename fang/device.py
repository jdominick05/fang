"""Ubertooth One device control — speaks the firmware's USB vendor protocol
directly (see firmware/bluetooth_rxtx/bluetooth_rxtx.c, API 1.07).

Transport notes, verified on hardware against the 2020-12-R1 firmware:
  * Every receive mode pushes packets out the bulk IN endpoint 0x82 —
    including BLE, whose modern PHY (le_phy.c) calls handle_usb(0) in its
    main loop. Bulk drained 981 BLE packets/3 s vs 867 for the stock tool's
    UBERTOOTH_POLL approach, and when both run, bulk wins every packet. So
    fang uses bulk everywhere; poll() is kept only as a fallback.
  * The LE PHY ignores SET_CHANNEL while sniffing (it only re-reads the
    advertising channel when it restarts), so changing advertising channel
    means stop + restart — see Ubertooth.start_btle().
  * The LE PHY never checks CRCs, so SET_CRC_VERIFY is a no-op there; fang
    verifies CRC24 in software (ble.py).
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from enum import IntEnum

from .usb import LIBUSB_ERROR_PIPE, LIBUSB_ERROR_TIMEOUT, UsbContext, UsbError

VENDOR_ID = 0x1D50
PID_UBERTOOTH_ONE = 0x6002
PID_UBERTOOTH_ZERO = 0x6000
REQUIRED_API = 0x0107
BULK_IN = 0x82
PKT_LEN = 64
DMA_SIZE = 50

# RSSI register → approximate dBm. NOT a lab calibration.
#  * -54 dB is the CC2400 datasheet offset; stock ubertooth-specan output
#    (front-end in low-gain mode) uses this.
#  * The CC2591 front-end's high-gain mode (HGM) adds gain. Measured on this
#    unit by toggling HGM during a live sweep: signal-dominated quantiles
#    (p90..p99.9) shift +19..+21 dB while the noise floor shifts only +7.
#    BLE/BR receive always runs with HGM on, so stock ubertooth-btle's
#    "rssi-54" overstates BLE signal levels by ~19 dB (it reported -15 dBm
#    for devices across the room). fang subtracts the gain step so all modes
#    share one scale.
RSSI_OFFSET = -54
HGM_GAIN_DB = 19


def rssi_to_dbm(raw: int, hgm: bool) -> int:
    return raw + RSSI_OFFSET - (HGM_GAIN_DB if hgm else 0)


class Cmd(IntEnum):
    PING = 0
    RX_SYMBOLS = 1
    GET_USRLED = 3
    SET_USRLED = 4
    GET_RXLED = 5
    SET_RXLED = 6
    GET_TXLED = 7
    SET_TXLED = 8
    GET_CHANNEL = 11
    SET_CHANNEL = 12
    RESET = 13
    GET_SERIAL = 14
    GET_PARTNUM = 15
    GET_PAEN = 16
    SET_PAEN = 17
    GET_HGM = 18
    SET_HGM = 19
    STOP = 21
    GET_MOD = 22
    SET_MOD = 23
    SPECAN = 27
    GET_PALEVEL = 28
    GET_REV_NUM = 33
    LED_SPECAN = 34
    GET_BOARD_ID = 35
    SET_SQUELCH = 36
    GET_SQUELCH = 37
    BTLE_SNIFFING = 42
    GET_ACCESS_ADDRESS = 43
    SET_ACCESS_ADDRESS = 44
    GET_CRC_VERIFY = 47
    SET_CRC_VERIFY = 48
    POLL = 49
    BTLE_PROMISC = 50
    GET_COMPILE_INFO = 55
    BTLE_SET_TARGET = 56
    CANCEL_FOLLOW = 70
    XMAS = 73
    # Deliberately absent: JAM_MODE (59), TX_SYMBOLS, BTLE_SLAVE, TX_GENERIC,
    # REPEATER. fang is a receive-only tool.


class Mod(IntEnum):
    BT_BASIC_RATE = 0
    BT_LOW_ENERGY = 1
    NONE = 3


class PktType(IntEnum):
    BR = 0
    LE = 1
    MESSAGE = 2
    KEEP_ALIVE = 3
    SPECAN = 4
    LE_PROMISC = 5


STATUS_DMA_OVERFLOW = 0x01
STATUS_DMA_ERROR = 0x02
STATUS_FIFO_OVERFLOW = 0x04
STATUS_DISCARD = 0x20
STATUS_ERRORS = STATUS_DMA_OVERFLOW | STATUS_DMA_ERROR | STATUS_FIFO_OVERFLOW

BOARD_NAMES = {0: "Ubertooth Zero", 1: "Ubertooth One", 2: "ToorCon 13 Badge"}

_PKT = struct.Struct("<BBBBIbbbB2x50s")
assert _PKT.size == PKT_LEN


@dataclass(slots=True)
class UsbPacket:
    pkt_type: int
    status: int
    channel: int        # BLE/specan: MHz above 2402; BR: channel 0-78
    clkn_high: int
    clk100ns: int       # device clock, 100 ns ticks, wraps at 2**32
    rssi_max: int
    rssi_min: int
    rssi_avg: int
    rssi_count: int
    data: bytes         # 50 bytes
    host_time: float    # time.time() when we received it
    raw: bytes = b""

    @classmethod
    def parse(cls, raw: bytes, host_time: float | None = None) -> "UsbPacket":
        f = _PKT.unpack(raw[:PKT_LEN])
        return cls(*f, host_time=time.time() if host_time is None else host_time,
                   raw=bytes(raw[:PKT_LEN]))


class ApiMismatch(RuntimeError):
    pass


FLASH_HINT = (
    "cp /usr/share/ubertooth/ubertooth-one-firmware-bin/bluetooth_rxtx.dfu /tmp/ && "
    "ubertooth-dfu -d /tmp/bluetooth_rxtx.dfu -r"
)


class Ubertooth:
    """One open Ubertooth. Always use as a context manager (or call close())
    so the radio is stopped and the interface released, even on Ctrl-C."""

    def __init__(self, index: int = 0, check_api: bool = True):
        self.usb = UsbContext()
        found = self.usb.find(VENDOR_ID, {PID_UBERTOOTH_ONE, PID_UBERTOOTH_ZERO})
        if not found:
            self.usb.close()
            raise FileNotFoundError("no Ubertooth found on USB (is it plugged in?)")
        if index >= len(found):
            self.usb.release_found(found)
            self.usb.close()
            raise FileNotFoundError(f"Ubertooth #{index} not found ({len(found)} present)")
        info = found[index]
        try:
            self.h = self.usb.open(info["dev"])
        finally:
            self.usb.release_found(found)
        self.bus, self.address = info["bus"], info["address"]
        self.api_version = info["bcdDevice"]
        try:
            self.h.claim(0)
        except UsbError:
            self.h.close()
            self.usb.close()
            raise
        if check_api and self.api_version < REQUIRED_API:
            v = self.api_version
            self.close()
            raise ApiMismatch(
                f"firmware API {v >> 8}.{v & 0xFF:02x} is too old (need 1.07). "
                f"Flash the bundled firmware:\n  {FLASH_HINT}")
        self._mode = "idle"
        self.recorder: "RawRecorder | None" = None
        self._target_set = False

    # ---- lifecycle -------------------------------------------------------
    def close(self):
        if getattr(self, "h", None) is None:
            return
        try:
            if self.h.h:
                self.stop()
                if self._target_set:      # don't leave a filter for the next tool
                    self.btle_set_target(None)
        except UsbError:
            pass
        if self.recorder:
            self.recorder.close()
            self.recorder = None
        self.h.close()
        self.h = None
        self.usb.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- low-level helpers ----------------------------------------------
    # The firmware services EP0 from a polled handler while streaming, so a
    # control request occasionally STALLs (LIBUSB_ERROR_PIPE). libubertooth
    # retries POLL for the same reason; fang retries every request briefly.
    def _retry(self, fn, *args):
        for attempt in range(5):
            try:
                return fn(*args)
            except UsbError as e:
                if e.code != LIBUSB_ERROR_PIPE or attempt == 4:
                    raise
                time.sleep(0.002 * (attempt + 1))

    def _out(self, cmd: Cmd, value: int = 0, index: int = 0, data: bytes = b"",
             timeout_ms: int = 1000):
        return self._retry(self.h.control_out, cmd, value, index, data, timeout_ms)

    def _in(self, cmd: Cmd, length: int, value: int = 0, timeout_ms: int = 1000) -> bytes:
        return self._retry(self.h.control_in, cmd, value, 0, length, timeout_ms)

    # ---- identification -------------------------------------------------
    def firmware_revision(self) -> str:
        d = self._in(Cmd.GET_REV_NUM, 255)
        if len(d) >= 3:
            n = d[2]
            return d[3:3 + n].decode(errors="replace")
        return "?"

    def compile_info(self) -> str:
        d = self._in(Cmd.GET_COMPILE_INFO, 255)
        return d[1:1 + d[0]].decode(errors="replace") if d else "?"

    def board_id(self) -> int:
        return self._in(Cmd.GET_BOARD_ID, 1)[0]

    def serial(self) -> str:
        d = self._in(Cmd.GET_SERIAL, 17)
        if not d or d[0] != 0:
            return "?"
        words = struct.unpack("<4I", d[1:17])
        return "".join(f"{w:08x}" for w in words)

    def part_number(self) -> int:
        d = self._in(Cmd.GET_PARTNUM, 5)
        if not d or d[0] != 0:
            return 0
        return int.from_bytes(d[1:5], "little")

    def ping(self) -> bool:
        try:
            self._in(Cmd.PING, 0)
            return True
        except UsbError:
            return False

    # ---- hardware knobs -------------------------------------------------
    def leds(self) -> dict:
        return {name: bool(self._in(cmd, 1)[0]) for name, cmd in
                (("usr", Cmd.GET_USRLED), ("rx", Cmd.GET_RXLED), ("tx", Cmd.GET_TXLED))}

    def set_usr_led(self, on: bool):
        self._out(Cmd.SET_USRLED, int(on))

    def set_rx_led(self, on: bool):
        self._out(Cmd.SET_RXLED, int(on))

    def get_hgm(self) -> bool:
        return bool(self._in(Cmd.GET_HGM, 1)[0])

    def set_hgm(self, on: bool):
        """CC2591 front-end LNA high-gain mode (better RX sensitivity)."""
        self._out(Cmd.SET_HGM, int(on))

    def get_pa_enabled(self) -> bool:
        return bool(self._in(Cmd.GET_PAEN, 1)[0])

    def set_pa_enabled(self, on: bool):
        """Powers the CC2591 front-end (needed for its LNA on receive too)."""
        self._out(Cmd.SET_PAEN, int(on))

    def get_squelch(self) -> int:
        return struct.unpack("b", self._in(Cmd.GET_SQUELCH, 1)[:1])[0]

    def set_squelch(self, level: int):
        """Carrier-sense threshold for BLE sync (raw RSSI units)."""
        self._out(Cmd.SET_SQUELCH, level & 0xFFFF)

    def get_modulation(self) -> int:
        return self._in(Cmd.GET_MOD, 1)[0]

    def set_modulation(self, mod: Mod):
        self._out(Cmd.SET_MOD, int(mod))

    def get_channel(self) -> int:
        d = self._in(Cmd.GET_CHANNEL, 2)
        return d[0] | (d[1] << 8)

    def set_channel(self, mhz: int):
        """Fixed frequency in MHz. A value above 2480 means 'sweep' (BR)."""
        self._out(Cmd.SET_CHANNEL, mhz)

    def get_crc_verify(self) -> bool:
        return bool(self._in(Cmd.GET_CRC_VERIFY, 1)[0])

    def set_crc_verify(self, on: bool):
        self._out(Cmd.SET_CRC_VERIFY, int(on))

    def xmas(self):
        """LED light show (harmless; firmware 'xmas' mode)."""
        self._out(Cmd.XMAS)
        self._mode = "xmas"

    # ---- modes ----------------------------------------------------------
    def stop(self):
        self._out(Cmd.STOP)
        self._mode = "idle"

    def drain(self, timeout_ms: int = 60):
        """Discard anything left in the device queue from a previous mode."""
        for _ in range(64):
            if not self.h.bulk_read(BULK_IN, PKT_LEN * 16, timeout_ms):
                break
        for _ in range(256):
            if self.poll() is None:
                break

    def prepare(self, mod: Mod | None, mhz: int | None):
        """Stock-tool mode hygiene: stop → drain → modulation → channel."""
        self.stop()
        time.sleep(0.02)
        self.drain()
        if mod is not None:
            self.set_modulation(mod)
        if mhz is not None:
            self.set_channel(mhz)

    def start_specan(self, low_mhz: int = 2402, high_mhz: int = 2480):
        self.prepare(None, None)
        self._out(Cmd.SPECAN, low_mhz, high_mhz)
        self._mode = "specan"

    def start_btle(self, adv_mhz: int = 2402, follow: bool = False):
        self.prepare(Mod.BT_LOW_ENERGY, adv_mhz)
        self._out(Cmd.BTLE_SNIFFING, int(follow))
        self._mode = "btle-follow" if follow else "btle"

    def start_btle_promisc(self, mhz: int):
        self.prepare(Mod.BT_LOW_ENERGY, mhz)
        self._out(Cmd.BTLE_PROMISC)
        self._mode = "btle-promisc"

    def btle_set_target(self, mac: str | None):
        """Restrict connection following to one advertiser (or clear)."""
        if not mac:
            self._out(Cmd.BTLE_SET_TARGET, data=bytes(7))
            self._target_set = False
            return
        b = bytes(int(x, 16) for x in mac.split(":"))
        if len(b) != 6:
            raise ValueError(f"bad MAC address: {mac}")
        self._out(Cmd.BTLE_SET_TARGET, data=b + bytes([48]))
        self._target_set = True

    def cancel_follow(self):
        self._out(Cmd.CANCEL_FOLLOW)

    def start_br_rx(self, mhz: int = 9999):
        """Classic BR symbol stream. 9999 (>2480) = sweep all 79 channels."""
        self.prepare(Mod.BT_BASIC_RATE, mhz)
        self._out(Cmd.RX_SYMBOLS)
        self._mode = "br"

    @property
    def mode(self) -> str:
        return self._mode

    # ---- receiving ------------------------------------------------------
    def poll(self) -> UsbPacket | None:
        """One packet via UBERTOOTH_POLL control transfer (BLE modes)."""
        for _ in range(3):  # stock tool retries stalls
            try:
                d = self._in(Cmd.POLL, PKT_LEN)
            except UsbError as e:
                if e.code in (LIBUSB_ERROR_PIPE, LIBUSB_ERROR_TIMEOUT):
                    continue
                raise
            if len(d) == PKT_LEN:
                return UsbPacket.parse(d)
            return None
        return None

    def read_bulk(self, timeout_ms: int = 100, max_packets: int = 32) -> list[UsbPacket]:
        """Packets from the bulk endpoint (specan / BR modes). Short reads
        (1-byte KEEP_ALIVE) are dropped."""
        raw = self.h.bulk_read(BULK_IN, PKT_LEN * max_packets, timeout_ms)
        now = time.time()
        out = []
        for i in range(0, len(raw) - PKT_LEN + 1, PKT_LEN):
            out.append(UsbPacket.parse(raw[i:i + PKT_LEN], now))
        if self.recorder and out:
            self.recorder.write(out)
        return out


RAW_MAGIC = b"FANGRAW1"
_REC = struct.Struct("<d")


class RawRecorder:
    """Records raw 64-byte USB packets (+ host timestamp) so any session can
    be replayed offline with ReplayDevice — for tests and bug reports."""

    def __init__(self, path: str, mode_hint: str = ""):
        self.f = open(path, "wb")
        hint = mode_hint.encode()[:255]
        self.f.write(RAW_MAGIC + bytes([len(hint)]) + hint)

    def write(self, pkts: list[UsbPacket]):
        self.f.write(b"".join(_REC.pack(p.host_time) + p.raw for p in pkts))

    def close(self):
        self.f.close()


class ReplayDevice:
    """Stands in for Ubertooth: serves recorded packets to the engines.
    Mode/knob commands are accepted and ignored."""

    api_version = REQUIRED_API

    def __init__(self, path: str, realtime: bool = False):
        with open(path, "rb") as f:
            data = f.read()
        if not data.startswith(RAW_MAGIC):
            raise ValueError(f"{path}: not a fang raw recording")
        n = data[len(RAW_MAGIC)]
        self.mode_hint = data[len(RAW_MAGIC) + 1:len(RAW_MAGIC) + 1 + n].decode()
        off = len(RAW_MAGIC) + 1 + n
        step = _REC.size + PKT_LEN
        self.pkts = []
        for i in range(off, len(data) - step + 1, step):
            (t,) = _REC.unpack_from(data, i)
            self.pkts.append(UsbPacket.parse(data[i + _REC.size:i + step], t))
        self.i = 0
        self.realtime = realtime
        self._t0 = None
        self._mode = "replay"
        self.recorder = None

    @property
    def done(self) -> bool:
        return self.i >= len(self.pkts)

    def read_bulk(self, timeout_ms: int = 100, max_packets: int = 32) -> list[UsbPacket]:
        if self.done:
            time.sleep(timeout_ms / 1000)
            return []
        out = self.pkts[self.i:self.i + max_packets]
        self.i += len(out)
        return out

    def __getattr__(self, name):
        # start_*, set_*, stop, prepare, btle_set_target, ... → no-ops
        if name.startswith(("start_", "set_", "btle_", "cancel_")) or name in ("stop", "prepare", "drain", "close"):
            return lambda *a, **k: None
        if name.startswith("get_"):
            return lambda *a, **k: True if name == "get_hgm" else 0
        raise AttributeError(name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


def autosuspend_devices() -> list[str]:
    """sysfs paths of attached Ubertooths whose USB runtime power management
    is 'auto'. The firmware frequently fails to resume from autosuspend and
    hangs (LIBUSB_ERROR_IO, then 'device not accepting address' until it is
    replugged) — observed repeatedly on a TLP-managed laptop."""
    import glob
    import os
    out = []
    for vid_file in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        d = os.path.dirname(vid_file)
        try:
            with open(vid_file) as f:
                if f.read().strip() != "1d50":
                    continue
            with open(os.path.join(d, "power", "control")) as f:
                if f.read().strip() == "auto":
                    out.append(d)
        except OSError:
            continue
    return out


def autosuspend_fix() -> str:
    import os
    import shutil
    contrib = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "contrib"))
    if shutil.which("tlp"):
        how = f"  sudo cp {contrib}/50-ubertooth.conf /etc/tlp.d/"
    else:
        how = (f"  sudo cp {contrib}/52-ubertooth-power.rules /etc/udev/rules.d/ && "
               "sudo udevadm control --reload")
    return ("USB autosuspend is enabled for the Ubertooth. Its firmware often fails to wake\n"
            "from it and hangs (LIBUSB_ERROR_IO; then it needs a replug). To fix, run:\n"
            f"{how}\nthen unplug and replug the Ubertooth.")


def list_devices() -> list[dict]:
    with UsbContext() as ctx:
        found = ctx.find(VENDOR_ID, {PID_UBERTOOTH_ONE, PID_UBERTOOTH_ZERO})
        ctx.release_found(found)
        for d in found:
            d.pop("dev", None)
        return found
