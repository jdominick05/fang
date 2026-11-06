import unittest

from fang.ble import decode_ad
from fang.fingerprint import fingerprint
from tests.helpers import ad


def fp(*structs):
    return fingerprint(decode_ad(ad(*structs)))


class Trackers(unittest.TestCase):
    def test_find_my_near_owner(self):
        f = fp((0xFF, b"\x4c\x00\x12\x02\x00\x01"))
        self.assertEqual(f.tracker, "Apple Find My")
        self.assertEqual(f.tracker_state, "near owner")
        self.assertFalse(f.is_separated_tracker)

    def test_find_my_separated(self):
        f = fp((0xFF, b"\x4c\x00\x12\x19\x10" + bytes(22) + b"\x01\x00"))
        self.assertEqual(f.tracker_state, "separated")
        self.assertTrue(f.is_separated_tracker)

    def test_tile(self):
        f = fp((0x03, b"\xed\xfe"))
        self.assertEqual(f.tracker, "Tile")

    def test_smartthings(self):
        f = fp((0x16, b"\x5a\xfd" + bytes(8)))
        self.assertEqual(f.tracker, "Samsung SmartThings Find")

    def test_google_fmdn_unwanted_tracking(self):
        f = fp((0x16, b"\xaa\xfe\x41" + bytes(20)))
        self.assertEqual(f.tracker, "Google Find My Device")
        self.assertTrue(f.is_separated_tracker)

    def test_eddystone_url_is_not_a_tracker(self):
        f = fp((0x16, b"\xaa\xfe\x10\x00\x03example"))
        self.assertIsNone(f.tracker)
        self.assertIn("Eddystone-URL", f.tags)


class Kinds(unittest.TestCase):
    def test_windows(self):
        f = fp((0xFF, b"\x06\x00\x01\x09\x20\x02" + bytes(20)))
        self.assertEqual(f.kind, "Windows device")
        self.assertEqual(f.vendor, "Microsoft")

    def test_airpods(self):
        f = fp((0xFF, b"\x4c\x00\x07\x19" + bytes(25)))
        self.assertEqual(f.kind, "AirPods/Beats")

    def test_ibeacon(self):
        f = fp((0xFF, b"\x4c\x00\x02\x15" + bytes(range(16)) + b"\x00\x01\x00\x02\xc5"))
        self.assertTrue(any(t.startswith("iBeacon") for t in f.tags))

    def test_unknown_company_does_not_crash(self):
        f = fp((0xFF, b"\xfe\xff\x01\x02"))
        self.assertTrue(f.vendor)


if __name__ == "__main__":
    unittest.main()
