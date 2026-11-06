"""Engines driven by synthetic packets through the real replay path."""

import ctypes
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from fang.ble import crc24
from fang.blescan import BleScanner
from fang.classic import AC_LEN, ClassicScanner, LibBtbb
from fang.pcap import PcapWriter
from fang.spectrum import Spectrum
from tests.helpers import (ad, adv_pdu, br_packet, le_packet, replay_from,
                           specan_packet)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fang-test-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def path(self, name):
        return os.path.join(self.dir, name)


class BleEngine(Tmp):
    def packets(self):
        sep = adv_pdu(0, "c2:aa:00:fa:00:02", ad((0x01, b"\x06"), (0xFF, b"\x4c\x00\x12\x19\x10" + bytes(22) + b"\x01\x00")))
        named = adv_pdu(2, "c0:ff:ee:00:11:22", ad((0x09, b"Thermo")))
        out = []
        for i in range(5):
            out.append(le_packet(sep, rssi=-30 + i, clk=i * 20000))
            out.append(le_packet(named, rssi=-40, clk=i * 20000 + 5000))
        # corrupted copies must not create ghost devices
        out.append(le_packet(named, corrupt=True, clk=200000))
        out.append(le_packet(adv_pdu(0, "de:ad:be:ef:00:01", b""), corrupt=True, clk=210000))
        return out

    def test_devices_and_crc(self):
        rp = replay_from(self.packets(), self.path("ble.raw"))
        sc = BleScanner(rp, channels=[37])
        sc.start()
        got = []
        while not rp.done:
            got += sc.pump()
        self.assertEqual(sorted(sc.devices), ["c0:ff:ee:00:11:22", "c2:aa:00:fa:00:02"])
        self.assertEqual(sc.chstats[37].good, 10)
        self.assertEqual(sc.chstats[37].bad, 2)
        self.assertTrue(all(p.crc_valid for p in got))
        d = sc.devices["c2:aa:00:fa:00:02"]
        self.assertTrue(d.fp.is_separated_tracker)
        self.assertEqual(d.count, 5)
        self.assertEqual(sc.devices["c0:ff:ee:00:11:22"].name, "Thermo")
        self.assertEqual([x.addr for x in sc.trackers(within=1e9)], ["c2:aa:00:fa:00:02"])

    def test_data_channel_crc_after_connect_ind(self):
        aa, crc_init = 0x50654B2A, 0x13579B
        lldata = (aa.to_bytes(4, "little") + crc_init.to_bytes(3, "little") + b"\x02"
                  + (5).to_bytes(2, "little") + (24).to_bytes(2, "little") + bytes(2)
                  + (72).to_bytes(2, "little") + (0x1FFFFFFFFF).to_bytes(5, "little") + bytes([0x29]))
        body = bytes.fromhex("112233445566aabbccddeeff") + lldata
        connect = bytes([0x05 | 0x40, len(body)]) + body
        data_pdu = b"\x02\x07\x03\x00\x04\x00\x0a\x03\x00"     # L2CAP/ATT read req
        pkts = [le_packet(connect), le_packet(data_pdu, aa=aa, crc_init=crc_init, freq=2404),
                le_packet(data_pdu, aa=aa, crc_init=crc_init, freq=2404, corrupt=True)]
        rp = replay_from(pkts, self.path("conn.raw"))
        sc = BleScanner(rp, channels=[37], keep_bad=True)
        sc.start()
        got = []
        while not rp.done:
            got += sc.pump()
        self.assertIn(aa, sc.connections)
        data = [p for p in got if not p.is_adv]
        self.assertEqual([p.crc_valid for p in data], [True, False])

    def test_pcap_roundtrip(self):
        rp = replay_from(self.packets(), self.path("ble.raw"))
        sc = BleScanner(rp, channels=[37])
        sc.start()
        w = PcapWriter(self.path("out.pcap"))
        while not rp.done:
            for p in sc.pump():
                w.write(p)
        w.close()
        raw = open(self.path("out.pcap"), "rb").read()
        self.assertEqual(struct.unpack("<I", raw[20:24])[0], 256)
        self.assertEqual(w.count, 10)
        if shutil.which("tshark"):
            r = subprocess.run(["tshark", "-r", self.path("out.pcap"), "-T", "fields",
                                "-e", "btle_rf.flags.crc_valid", "-e", "btle.crc.incorrect",
                                "-e", "btle.advertising_address"], capture_output=True, text=True)
            lines = [l.split("\t") for l in r.stdout.strip().splitlines()]
            self.assertEqual(len(lines), 10)
            self.assertTrue(all(l[0] == "True" and l[1] == "" for l in lines))
            self.assertIn("c2:aa:00:fa:00:02", {l[2] for l in lines})


class SpectrumEngine(Tmp):
    def test_sweeps_spurs_and_wifi(self):
        pkts = []
        clk = 0
        for sweep in range(60):
            samples = []
            for f in range(2402, 2481):
                raw = -45
                if 2432 <= f <= 2442:      # a Wi-Fi channel 6 transmitter
                    raw = -10
                if f in (2416, 2448):      # crystal spur
                    raw = -20
                samples.append((f, raw))
            for i in range(0, len(samples), 16):
                pkts.append(specan_packet(samples[i:i + 16], clk=clk))
                clk += 100
        rp = replay_from(pkts, self.path("spec.raw"))
        s = Spectrum(rp, hgm=False)
        s.start()
        s._hgm_pending = False
        while not rp.done:
            s.pump()
        self.assertGreaterEqual(s.sweeps, 58)
        self.assertAlmostEqual(s.noise_floor(), -45 - 54, delta=1)
        best = s.best_wifi()
        self.assertNotEqual(best.name, "Wi-Fi 6")
        scores = {x.name: x for x in s.wifi_scores()}
        self.assertGreater(scores["Wi-Fi 6"].busy, 0.5)
        # spurs are masked out of analysis: peaks are the Wi-Fi signal only
        self.assertTrue(all(2432 <= f <= 2442 for f, _ in s.peaks(3)))
        i = 2416 - s.low
        self.assertAlmostEqual(s._clean(s.avg)[i], -45 - 54, delta=1)   # masked → neighbours
        s.mask_spurs = False
        self.assertAlmostEqual(s._clean(s.avg)[i], -20 - 54, delta=1)   # unmasked → raw spur


class ClassicEngine(Tmp):
    LAP = 0x9E8B33  # GIAC: a public, well-known access code

    def access_code(self):
        lib = ctypes.CDLL("libbtbb.so.1")
        lib.btbb_gen_syncword.restype = ctypes.c_uint64
        lib.btbb_gen_syncword.argtypes = [ctypes.c_int]
        sw = lib.btbb_gen_syncword(self.LAP)
        bits = [(sw >> i) & 1 for i in range(64)]           # LSB first on air
        pre = [1, 0, 1, 0] if bits[0] else [0, 1, 0, 1]
        trl = [0, 1, 0, 1] if bits[-1] else [1, 0, 1, 0]
        return pre + bits + trl

    def run_symbols(self, stream, contiguous=True):
        pkts = []
        for i in range(0, len(stream), 400):
            clk = i * 10 if contiguous else i * 50
            pkts.append(br_packet(bytes(stream[i:i + 400]), clk=clk))
        rp = replay_from(pkts, self.path("br.raw"))
        LibBtbb(2)
        cs = ClassicScanner(rp)
        cs.start()
        while not rp.done:
            cs.pump()
        cs.flush()
        return cs

    def filler(self, n):
        import random
        r = random.Random(7)
        return [r.randint(0, 1) for _ in range(n)]

    def test_finds_code_inside_packet(self):
        ac = self.access_code()
        stream = self.filler(100) + ac + self.filler(1200 - 100 - AC_LEN)
        cs = self.run_symbols(stream)
        self.assertIn(self.LAP, cs.piconets)
        self.assertEqual(cs.piconets[self.LAP].count, 1)

    def test_finds_code_straddling_two_packets(self):
        ac = self.access_code()
        start = 400 - 30                  # 30 symbols in packet 1, 42 in packet 2
        stream = self.filler(start) + ac + self.filler(1200 - start - AC_LEN)
        cs = self.run_symbols(stream)
        self.assertIn(self.LAP, cs.piconets, "straddling access code missed")
        self.assertEqual(cs.piconets[self.LAP].count, 1, "counted twice")

    def test_no_false_join_when_not_contiguous(self):
        ac = self.access_code()
        start = 400 - 30
        stream = self.filler(start) + ac + self.filler(1200 - start - AC_LEN)
        cs = self.run_symbols(stream, contiguous=False)
        self.assertNotIn(self.LAP, cs.piconets)


if __name__ == "__main__":
    unittest.main()
