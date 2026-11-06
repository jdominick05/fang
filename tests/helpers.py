"""Synthetic Ubertooth USB packets, so engine tests run offline and the repo
never contains other people's captured traffic."""

import struct

from fang.ble import ADV_AA, ADV_CRC_INIT, crc24
from fang.device import RAW_MAGIC, ReplayDevice

PKT = struct.Struct("<BBBBIbbbB2x50s")


def usb_packet(pkt_type, data, channel=0, clk=0, rssi=-30, status=0):
    return PKT.pack(pkt_type, status, channel, 0, clk & 0xFFFFFFFF, rssi, rssi, rssi, 0,
                    data.ljust(50, b"\0")[:50])


def adv_pdu(pdu_type, addr: str, payload: bytes, random=True):
    a = bytes(int(x, 16) for x in reversed(addr.split(":")))
    body = a + payload
    return bytes([pdu_type | (0x40 if random else 0), len(body)]) + body


def le_packet(pdu: bytes, aa=ADV_AA, crc_init=ADV_CRC_INIT, freq=2402, rssi=-30,
              clk=0, corrupt=False):
    crc = crc24(pdu, crc_init).to_bytes(3, "little")
    if corrupt:
        pdu = pdu[:-1] + bytes([pdu[-1] ^ 0x10])
    return usb_packet(1, aa.to_bytes(4, "little") + pdu + crc, channel=freq - 2402, clk=clk, rssi=rssi)


def specan_packet(samples, clk=0):
    """samples: up to 16 (freq_mhz, raw_rssi) pairs."""
    data = b"".join(bytes([f >> 8, f & 0xFF, r & 0xFF]) for f, r in samples)
    return usb_packet(4, data, clk=clk)


def br_packet(symbols: bytes, channel=39, clk=0, rssi=-20):
    """symbols: 400 bytes of 0/1 → packed MSB-first like the firmware."""
    packed = bytes(int("".join(str(b) for b in symbols[i:i + 8]), 2) for i in range(0, 400, 8))
    return usb_packet(0, packed, channel=channel, clk=clk, rssi=rssi)


def replay_from(raw_packets, path, t0=1_700_000_000.0, dt=0.001):
    with open(path, "wb") as f:
        f.write(RAW_MAGIC + b"\x04test")
        for i, raw in enumerate(raw_packets):
            f.write(struct.pack("<d", t0 + i * dt) + raw)
    return ReplayDevice(path)


def ad(*structs):
    return b"".join(bytes([len(v) + 1, t]) + v for t, v in structs)
