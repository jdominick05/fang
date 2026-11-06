import unittest

from fang import ble
from tests.helpers import adv_pdu, ad

# Synthetic ADV_NONCONN_IND frames (AA + PDU + CRC). Wireshark's own CRC
# check (pcap written without fang's CRC flags) judged GOOD correct and BAD
# (one bit flipped in the name) incorrect. On a real 3181-packet capture,
# fang's CRC24 agreed with Wireshark on every packet both could judge.
GOOD = bytes.fromhex("d6be898e42230100fa00aac2020106110966616e672d746573742d766563746f7207ffffff01020304f3657e")
BAD = bytes.fromhex("d6be898e42230100fa00aac2020106110967616e672d746573742d766563746f7207ffffff01020304f3657e")


class Crc(unittest.TestCase):
    def test_real_vectors(self):
        aa, pdu, crc = ble.split_raw(GOOD)
        self.assertEqual(aa, ble.ADV_AA)
        self.assertTrue(ble.crc_ok(pdu + crc))
        aa, pdu, crc = ble.split_raw(BAD)
        self.assertFalse(ble.crc_ok(pdu + crc))

    def test_single_bit_flip_detected(self):
        aa, pdu, crc = ble.split_raw(GOOD)
        for i in range(len(pdu) * 8):
            flipped = bytearray(pdu)
            flipped[i // 8] ^= 1 << (i % 8)
            self.assertFalse(ble.crc_ok(bytes(flipped) + crc), f"bit {i}")

    def test_crc_init_matters(self):
        pdu = b"\x02\x05hello"
        c = ble.crc24(pdu, 0x123456).to_bytes(3, "little")
        self.assertTrue(ble.crc_ok(pdu + c, 0x123456))
        self.assertFalse(ble.crc_ok(pdu + c, ble.ADV_CRC_INIT))

    def test_truncated_returns_none(self):
        self.assertIsNone(ble.split_raw(GOOD[:20]))


class Channels(unittest.TestCase):
    def test_roundtrip(self):
        for idx in range(40):
            self.assertEqual(ble.freq_to_channel_index(ble.channel_index_to_freq(idx)), idx)

    def test_adv(self):
        self.assertEqual(ble.channel_index_to_freq(37), 2402)
        self.assertEqual(ble.channel_index_to_freq(38), 2426)
        self.assertEqual(ble.channel_index_to_freq(39), 2480)
        self.assertIsNone(ble.freq_to_channel_index(2403))


class Decode(unittest.TestCase):
    def test_adv_ind(self):
        payload = ad((0x01, b"\x06"), (0x09, b"Thermo"), (0x0A, b"\xf4"),
                     (0x03, b"\x0f\x18\x1a\x18"), (0xFF, b"\x4c\x00\x12\x02\x00\x01"))
        pdu = adv_pdu(0, "c0:ff:ee:00:11:22", payload)
        p = ble.decode_adv(ble.LePacket(ble.ADV_AA, pdu, b"", True, 2402, -50, 0))
        self.assertEqual(p.type_name, "ADV_IND")
        self.assertEqual(p.adv_addr, "c0:ff:ee:00:11:22")
        self.assertTrue(p.tx_random)
        info = ble.decode_ad(p.adv_data)
        self.assertEqual(info.name, "Thermo")
        self.assertEqual(info.tx_power, -12)
        self.assertEqual(info.uuid16, [0x180F, 0x181A])
        self.assertEqual(info.manufacturer[0][0], 0x004C)

    def test_malformed_ad_does_not_raise(self):
        self.assertEqual(ble.parse_ad(b"\x05\x09ab"), [])
        self.assertEqual(ble.parse_ad(b"\x02\x01\x06\x00\xff"), [(1, b"\x06")])

    def test_connect_ind(self):
        init = bytes.fromhex("112233445566")
        adva = bytes.fromhex("aabbccddeeff")
        lldata = ((0x50654B2A).to_bytes(4, "little") + (0xABCDEF).to_bytes(3, "little") + b"\x02"
                  + (5).to_bytes(2, "little") + (24).to_bytes(2, "little") + (0).to_bytes(2, "little")
                  + (72).to_bytes(2, "little") + (0x1FFFFFFFFF).to_bytes(5, "little") + bytes([0x29]))
        body = init + adva + lldata
        pdu = bytes([0x05 | 0x40, len(body)]) + body
        p = ble.decode_adv(ble.LePacket(ble.ADV_AA, pdu, b"", True, 2402, -50, 0))
        c = p.connect
        self.assertEqual(p.type_name, "CONNECT_IND")
        self.assertEqual(p.target_addr, "66:55:44:33:22:11")
        self.assertEqual(p.adv_addr, "ff:ee:dd:cc:bb:aa")
        self.assertEqual(c.access_address, 0x50654B2A)
        self.assertEqual(c.crc_init, 0xABCDEF)
        self.assertEqual(c.interval_ms, 30.0)
        self.assertEqual(c.hop, 9)
        self.assertEqual(len(c.used_channels), 37)


if __name__ == "__main__":
    unittest.main()
