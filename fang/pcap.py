"""pcap writer for LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256) — the format
Wireshark's btle_rf dissector decodes natively, with fang's own CRC verdict
recorded in the header flags."""

from __future__ import annotations

import struct
import sys
from typing import BinaryIO

from .ble import ADV_AA, LePacket

DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256

F_DEWHITENED = 0x0001
F_SIGNAL_VALID = 0x0002
F_REF_AA_VALID = 0x0010
F_CRC_CHECKED = 0x0400
F_CRC_VALID = 0x0800


class PcapWriter:
    def __init__(self, path: str):
        self.path = path
        if path == "-":
            self.f: BinaryIO = sys.stdout.buffer
            self._own = False
        else:
            self.f = open(path, "wb")
            self._own = True
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                 DLT_BLUETOOTH_LE_LL_WITH_PHDR))
        self.f.flush()
        self.count = 0

    def write(self, pkt: LePacket, ref_aa: int | None = None):
        flags = F_DEWHITENED | F_SIGNAL_VALID
        ref = ADV_AA if pkt.is_adv else (ref_aa or 0)
        if ref:
            flags |= F_REF_AA_VALID
        if pkt.crc_valid is not None:
            flags |= F_CRC_CHECKED | (F_CRC_VALID if pkt.crc_valid else 0)
        rf_channel = (pkt.freq - 2402) // 2
        phdr = struct.pack("<BbbBIH", rf_channel & 0xFF, max(-128, min(127, pkt.rssi_dbm)),
                           -128, 0, ref, flags)
        body = phdr + pkt.access_address.to_bytes(4, "little") + pkt.pdu + pkt.crc
        sec = int(pkt.timestamp)
        usec = int((pkt.timestamp - sec) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(body), len(body)) + body)
        self.f.flush()   # keep live pipes (wireshark -k -i -) responsive
        self.count += 1

    def close(self):
        if self._own:
            self.f.close()
