# fang

A receive-only toolkit for the [Ubertooth One](https://greatscottgadgets.com/ubertoothone/): a 2.4 GHz spectrum analyzer, BLE scanner, tracker detector, connection follower and Classic Bluetooth survey. It's a single program with a terminal UI. It talks to the radio directly over USB, using only the Python standard library.

## Install

Requires an Ubertooth One on firmware **2020-12-R1**, Python ≥ 3.10, `libusb-1.0`, and `libbtbb` (Classic mode only). Wireshark is optional.

```bash
git clone https://github.com/jdominick05/fang && cd fang
ln -s "$PWD/bin/fang" ~/.local/bin/fang
```

## Use

```bash
fang                     # terminal UI: 1 Spectrum  2 BLE  3 Trackers  4 Classic   (? for keys)
fang spectrum --text     # 2.4 GHz survey + least-busy Wi-Fi channel
fang scan --text         # nearby BLE devices with vendor/type
fang trackers --text     # Find My, Tile, Chipolo, SmartTag, Google trackers (--led lights the Ubertooth)
fang classic --text      # Classic Bluetooth piconets
fang follow -t MAC --pcap out.pcap   # follow your own device's BLE connection
fang info                # firmware and hardware state
```

Add `--json` for JSON lines, `--pcap FILE` for Wireshark, `-s N` to limit run time. `--record FILE` / `--replay FILE` save and re-analyse raw sessions.

## Improvements over the stock `ubertooth-*` tools

- **No ghost devices.** Every BLE packet gets a software CRC check; the stock tool shows corrupted packets as devices.
- **Picks the cleanest channel.** It measures all three advertising channels and listens on the best one.
- **Corrected signal levels.** RSSI accounts for the front-end's high-gain mode; the stock tools read about 19 dB high.
- **About 12 dB more sensitive spectrum view.** It enables the high-gain mode, and masks the Ubertooth's own 16 MHz crystal spurs.
- **Clears stale filters.** It resets the target filter that the firmware otherwise keeps between sessions.

## Notes

- Signal levels are approximate, not calibrated.
- A "separated" tracker is away from its owner. That's usually innocent; it only matters if one keeps following you to different places.
- It is receive-only by design: no jamming or transmit modes. Only capture connections between devices you own.

## Troubleshooting

**`LIBUSB_ERROR_IO`, or the Ubertooth stops enumerating until it's replugged:** USB autosuspend is on for it, and its firmware often fails to wake up. This is common on laptops running TLP or powertop. Fix it, then replug:

```bash
sudo cp contrib/50-ubertooth.conf /etc/tlp.d/                  # if you use TLP
sudo cp contrib/52-ubertooth-power.rules /etc/udev/rules.d/    # otherwise
```

`fang info` shows whether autosuspend is still on.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```
