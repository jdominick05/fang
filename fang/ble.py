"""Bluetooth Low Energy link-layer decoding: CRC24, PDU headers,
advertising PDUs, AD structures, and CONNECT_IND parameters."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ADV_AA = 0x8E89BED6
ADV_CRC_INIT = 0x555555

ADV_CHANNELS = {37: 2402, 38: 2426, 39: 2480}

ADV_PDU_TYPES = {
    0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
    4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND", 7: "ADV_EXT_IND",
    8: "AUX_CONNECT_RSP",
}


# ---------------------------------------------------------------- CRC24
def _reverse24(x: int) -> int:
    r = 0
    for i in range(24):
        if x & (1 << i):
            r |= 1 << (23 - i)
    return r


def crc24(data: bytes, crc_init: int = ADV_CRC_INIT) -> int:
    """BLE CRC24 (poly x^24+x^10+x^9+x^6+x^4+x^3+x+1) over header+payload.
    Returns the value as it appears on air read little-endian from the 3
    CRC bytes. Bit-serial LFSR form, as in libbtbb's btle_calc_crc()."""
    state = _reverse24(crc_init)
    for byte in data:
        cur = byte
        for _ in range(8):
            nxt = (state ^ cur) & 1
            cur >>= 1
            state >>= 1
            if nxt:
                state |= 1 << 23
                state ^= 0x5A6000
    return state


def crc_ok(pdu_and_crc: bytes, crc_init: int = ADV_CRC_INIT) -> bool:
    if len(pdu_and_crc) < 5:
        return False
    body, wire = pdu_and_crc[:-3], pdu_and_crc[-3:]
    return crc24(body, crc_init) == int.from_bytes(wire, "little")


# ------------------------------------------------------------ channels
def freq_to_channel_index(mhz: int) -> int | None:
    if mhz == 2402:
        return 37
    if mhz == 2426:
        return 38
    if mhz == 2480:
        return 39
    if 2404 <= mhz <= 2424 and mhz % 2 == 0:
        return (mhz - 2404) // 2
    if 2428 <= mhz <= 2478 and mhz % 2 == 0:
        return (mhz - 2428) // 2 + 11
    return None


def channel_index_to_freq(idx: int) -> int:
    if idx in ADV_CHANNELS:
        return ADV_CHANNELS[idx]
    if 0 <= idx <= 10:
        return 2404 + 2 * idx
    if 11 <= idx <= 36:
        return 2428 + 2 * (idx - 11)
    raise ValueError(f"bad BLE channel index {idx}")


# ------------------------------------------------------------ addresses
def fmt_addr(le_bytes: bytes) -> str:
    """Over-the-air addresses are little-endian; display MSB first."""
    return ":".join(f"{b:02x}" for b in reversed(le_bytes))


def random_addr_kind(addr: str) -> str:
    top = int(addr[:2], 16) >> 6
    return {0b11: "static", 0b01: "resolvable", 0b00: "non-resolvable"}.get(top, "reserved")


# --------------------------------------------------------- AD structures
AD_FLAGS = 0x01
AD_UUID16_PARTIAL = 0x02
AD_UUID16_COMPLETE = 0x03
AD_UUID128_PARTIAL = 0x06
AD_UUID128_COMPLETE = 0x07
AD_NAME_SHORT = 0x08
AD_NAME_COMPLETE = 0x09
AD_TX_POWER = 0x0A
AD_SERVICE_DATA16 = 0x16
AD_APPEARANCE = 0x19
AD_MANUFACTURER = 0xFF


def parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    """Split AdvData into (type, value) pairs; stops at the first
    malformed length instead of raising."""
    out = []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0:
            break
        if i + 1 + ln > len(data):
            break
        out.append((data[i + 1], bytes(data[i + 2:i + 1 + ln])))
        i += 1 + ln
    return out


@dataclass(slots=True)
class AdInfo:
    flags: int | None = None
    name: str | None = None
    tx_power: int | None = None
    appearance: int | None = None
    uuid16: list[int] = field(default_factory=list)
    uuid128: list[str] = field(default_factory=list)
    service_data: dict[int, bytes] = field(default_factory=dict)
    manufacturer: list[tuple[int, bytes]] = field(default_factory=list)


def decode_ad(data: bytes) -> AdInfo:
    info = AdInfo()
    for t, v in parse_ad(data):
        if t == AD_FLAGS and v:
            info.flags = v[0]
        elif t in (AD_NAME_SHORT, AD_NAME_COMPLETE):
            name = v.decode("utf-8", errors="replace").strip("\x00")
            if t == AD_NAME_COMPLETE or not info.name:
                info.name = name
        elif t == AD_TX_POWER and v:
            info.tx_power = struct.unpack("b", v[:1])[0]
        elif t == AD_APPEARANCE and len(v) >= 2:
            info.appearance = int.from_bytes(v[:2], "little")
        elif t in (AD_UUID16_PARTIAL, AD_UUID16_COMPLETE):
            for j in range(0, len(v) - 1, 2):
                info.uuid16.append(int.from_bytes(v[j:j + 2], "little"))
        elif t in (AD_UUID128_PARTIAL, AD_UUID128_COMPLETE):
            for j in range(0, len(v) - 15, 16):
                u = v[j:j + 16][::-1].hex()
                info.uuid128.append(f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}")
        elif t == AD_SERVICE_DATA16 and len(v) >= 2:
            info.service_data[int.from_bytes(v[:2], "little")] = v[2:]
        elif t == AD_MANUFACTURER and len(v) >= 2:
            info.manufacturer.append((int.from_bytes(v[:2], "little"), v[2:]))
    return info


# ------------------------------------------------------------ LL packets
@dataclass(slots=True)
class ConnectParams:
    access_address: int
    crc_init: int
    win_size: int
    win_offset: int
    interval: int          # units of 1.25 ms
    latency: int
    timeout: int           # units of 10 ms
    channel_map: int       # 37-bit bitmap
    hop: int
    sca: int

    @property
    def interval_ms(self) -> float:
        return self.interval * 1.25

    @property
    def used_channels(self) -> list[int]:
        return [i for i in range(37) if self.channel_map >> i & 1]


@dataclass(slots=True)
class LePacket:
    """One received LE packet. `pdu` excludes AA and CRC."""
    access_address: int
    pdu: bytes
    crc: bytes
    crc_valid: bool | None     # None = unknown CRCInit (data channel)
    freq: int
    rssi_dbm: int
    timestamp: float
    # advertising-PDU fields (None on data channels)
    pdu_type: int | None = None
    tx_random: bool = False
    rx_random: bool = False
    adv_addr: str | None = None
    target_addr: str | None = None
    adv_data: bytes = b""
    connect: ConnectParams | None = None

    @property
    def is_adv(self) -> bool:
        return self.access_address == ADV_AA

    @property
    def type_name(self) -> str:
        if self.is_adv:
            return ADV_PDU_TYPES.get(self.pdu_type, f"ADV_TYPE_{self.pdu_type}")
        llid = self.pdu[0] & 0x03 if self.pdu else 0
        return {1: "LL_DATA_CONT", 2: "LL_DATA_START", 3: "LL_CONTROL"}.get(llid, "LL_RFU")


def split_raw(aa_and_rest: bytes) -> tuple[int, bytes, bytes] | None:
    """From AA(4)+header(2)+payload+CRC(3) bytes as delivered by the
    Ubertooth, carve out (aa, pdu, crc) using the header length field."""
    if len(aa_and_rest) < 4 + 2 + 3:
        return None
    aa = int.from_bytes(aa_and_rest[:4], "little")
    length = aa_and_rest[5]          # 8-bit length field (BT 5.x)
    end = 4 + 2 + length
    if end + 3 > len(aa_and_rest):   # truncated by the 50-byte USB payload
        return None
    return aa, bytes(aa_and_rest[4:end]), bytes(aa_and_rest[end:end + 3])


def decode_adv(pkt: LePacket) -> LePacket:
    """Fill in advertising fields from pkt.pdu (in place; returns pkt)."""
    p = pkt.pdu
    if len(p) < 2:
        return pkt
    h0 = p[0]
    pkt.pdu_type = h0 & 0x0F
    pkt.tx_random = bool(h0 & 0x40)
    pkt.rx_random = bool(h0 & 0x80)
    body = p[2:]
    t = pkt.pdu_type
    if t in (0, 2, 4, 6) and len(body) >= 6:          # ADV_IND/NONCONN/SCAN_RSP/SCAN_IND
        pkt.adv_addr = fmt_addr(body[:6])
        pkt.adv_data = body[6:]
    elif t == 1 and len(body) >= 12:                   # ADV_DIRECT_IND
        pkt.adv_addr = fmt_addr(body[:6])
        pkt.target_addr = fmt_addr(body[6:12])
    elif t == 3 and len(body) >= 12:                   # SCAN_REQ: ScanA, AdvA
        pkt.target_addr = fmt_addr(body[:6])
        pkt.adv_addr = fmt_addr(body[6:12])
    elif t == 5 and len(body) >= 34:                   # CONNECT_IND: InitA, AdvA, LLData
        pkt.target_addr = fmt_addr(body[:6])
        pkt.adv_addr = fmt_addr(body[6:12])
        ll = body[12:34]
        pkt.connect = ConnectParams(
            access_address=int.from_bytes(ll[0:4], "little"),
            crc_init=int.from_bytes(ll[4:7], "little"),
            win_size=ll[7],
            win_offset=int.from_bytes(ll[8:10], "little"),
            interval=int.from_bytes(ll[10:12], "little"),
            latency=int.from_bytes(ll[12:14], "little"),
            timeout=int.from_bytes(ll[14:16], "little"),
            channel_map=int.from_bytes(ll[16:21], "little"),
            hop=ll[21] & 0x1F,
            sca=ll[21] >> 5,
        )
    return pkt
