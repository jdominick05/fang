"""Minimal ctypes binding to libusb-1.0 — just what an Ubertooth needs.

No third-party Python packages are required; libusb-1.0 is already a
dependency of the system ubertooth package.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from ctypes import (POINTER, Structure, byref, c_char_p, c_int, c_ssize_t,
                    c_ubyte, c_uint, c_uint8, c_uint16, c_void_p)

# libusb error codes we care about
LIBUSB_SUCCESS = 0
LIBUSB_ERROR_IO = -1
LIBUSB_ERROR_ACCESS = -3
LIBUSB_ERROR_NO_DEVICE = -4
LIBUSB_ERROR_NOT_FOUND = -5
LIBUSB_ERROR_BUSY = -6
LIBUSB_ERROR_TIMEOUT = -7
LIBUSB_ERROR_PIPE = -9

REQ_VENDOR_IN = 0xC0   # LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_IN
REQ_VENDOR_OUT = 0x40  # LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT

_FRIENDLY = {
    LIBUSB_ERROR_ACCESS: "permission denied — is your user in the 'uucp' group, "
                         "and did you replug after installing the udev rule?",
    LIBUSB_ERROR_BUSY: "device busy — another Ubertooth tool is probably running "
                       "(close ubertooth-btle / ubertooth-specan / other fang instances)",
    LIBUSB_ERROR_NO_DEVICE: "device disconnected",
    LIBUSB_ERROR_IO: "I/O error — the Ubertooth stopped responding (its firmware is hung)",
}


class DeviceDescriptor(Structure):
    _fields_ = [
        ("bLength", c_uint8), ("bDescriptorType", c_uint8),
        ("bcdUSB", c_uint16), ("bDeviceClass", c_uint8),
        ("bDeviceSubClass", c_uint8), ("bDeviceProtocol", c_uint8),
        ("bMaxPacketSize0", c_uint8), ("idVendor", c_uint16),
        ("idProduct", c_uint16), ("bcdDevice", c_uint16),
        ("iManufacturer", c_uint8), ("iProduct", c_uint8),
        ("iSerialNumber", c_uint8), ("bNumConfigurations", c_uint8),
    ]


class UsbError(OSError):
    def __init__(self, code: int, where: str = ""):
        self.code = code
        name = _lib().libusb_error_name(code).decode() if _LIB else str(code)
        msg = _FRIENDLY.get(code, name)
        super().__init__(code, f"{where}: {msg}" if where else msg)


_LIB = None


def _lib():
    global _LIB
    if _LIB is not None:
        return _LIB
    path = ctypes.util.find_library("usb-1.0") or "libusb-1.0.so.0"
    lib = ctypes.CDLL(path)
    # Pointers MUST be c_void_p, never the default int (truncates on 64-bit).
    lib.libusb_init.argtypes = [POINTER(c_void_p)]
    lib.libusb_init.restype = c_int
    lib.libusb_exit.argtypes = [c_void_p]
    lib.libusb_exit.restype = None
    lib.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
    lib.libusb_get_device_list.restype = c_ssize_t
    lib.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
    lib.libusb_free_device_list.restype = None
    lib.libusb_get_device_descriptor.argtypes = [c_void_p, POINTER(DeviceDescriptor)]
    lib.libusb_get_device_descriptor.restype = c_int
    lib.libusb_get_bus_number.argtypes = [c_void_p]
    lib.libusb_get_bus_number.restype = c_uint8
    lib.libusb_get_device_address.argtypes = [c_void_p]
    lib.libusb_get_device_address.restype = c_uint8
    lib.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
    lib.libusb_open.restype = c_int
    lib.libusb_close.argtypes = [c_void_p]
    lib.libusb_close.restype = None
    lib.libusb_ref_device.argtypes = [c_void_p]
    lib.libusb_ref_device.restype = c_void_p
    lib.libusb_unref_device.argtypes = [c_void_p]
    lib.libusb_unref_device.restype = None
    lib.libusb_claim_interface.argtypes = [c_void_p, c_int]
    lib.libusb_claim_interface.restype = c_int
    lib.libusb_release_interface.argtypes = [c_void_p, c_int]
    lib.libusb_release_interface.restype = c_int
    lib.libusb_control_transfer.argtypes = [c_void_p, c_uint8, c_uint8, c_uint16,
                                            c_uint16, POINTER(c_ubyte), c_uint16, c_uint]
    lib.libusb_control_transfer.restype = c_int
    lib.libusb_bulk_transfer.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_int,
                                         POINTER(c_int), c_uint]
    lib.libusb_bulk_transfer.restype = c_int
    lib.libusb_error_name.argtypes = [c_int]
    lib.libusb_error_name.restype = c_char_p
    _LIB = lib
    return lib


class UsbContext:
    """Owns a libusb context. Use as a context manager or call close()."""

    def __init__(self):
        self.lib = _lib()
        self.ctx = c_void_p()
        r = self.lib.libusb_init(byref(self.ctx))
        if r < 0:
            raise UsbError(r, "libusb_init")

    def find(self, vid: int, pids: set[int]) -> list[dict]:
        """List matching devices. Returned dicts hold a referenced device
        pointer under 'dev'; pass one to open() and unref the rest via
        release_found()."""
        lst = POINTER(c_void_p)()
        n = self.lib.libusb_get_device_list(self.ctx, byref(lst))
        if n < 0:
            raise UsbError(n, "get_device_list")
        found = []
        try:
            for i in range(n):
                dev = lst[i]
                desc = DeviceDescriptor()
                if self.lib.libusb_get_device_descriptor(dev, byref(desc)) < 0:
                    continue
                if desc.idVendor == vid and desc.idProduct in pids:
                    found.append({
                        "dev": self.lib.libusb_ref_device(dev),
                        "bus": self.lib.libusb_get_bus_number(dev),
                        "address": self.lib.libusb_get_device_address(dev),
                        "pid": desc.idProduct,
                        "bcdDevice": desc.bcdDevice,
                    })
        finally:
            self.lib.libusb_free_device_list(lst, 1)
        return found

    def release_found(self, found: list[dict]) -> None:
        for d in found:
            if d.get("dev"):
                self.lib.libusb_unref_device(d["dev"])
                d["dev"] = None

    def open(self, dev) -> "UsbHandle":
        h = c_void_p()
        r = self.lib.libusb_open(dev, byref(h))
        if r < 0:
            raise UsbError(r, "open")
        return UsbHandle(self.lib, h)

    def close(self):
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class UsbHandle:
    def __init__(self, lib, handle: c_void_p):
        self.lib = lib
        self.h = handle
        self.claimed: set[int] = set()

    def claim(self, iface: int = 0):
        r = self.lib.libusb_claim_interface(self.h, iface)
        if r < 0:
            raise UsbError(r, "claim_interface")
        self.claimed.add(iface)

    def control_in(self, request: int, value: int = 0, index: int = 0,
                   length: int = 64, timeout_ms: int = 1000) -> bytes:
        buf = (c_ubyte * max(length, 1))()
        r = self.lib.libusb_control_transfer(self.h, REQ_VENDOR_IN, request,
                                             value & 0xFFFF, index & 0xFFFF,
                                             buf, length, timeout_ms)
        if r < 0:
            raise UsbError(r, f"control_in(req={request})")
        return bytes(buf[:r])

    def control_out(self, request: int, value: int = 0, index: int = 0,
                    data: bytes = b"", timeout_ms: int = 1000) -> int:
        n = len(data)
        buf = (c_ubyte * max(n, 1)).from_buffer_copy(data or b"\0")
        r = self.lib.libusb_control_transfer(self.h, REQ_VENDOR_OUT, request,
                                             value & 0xFFFF, index & 0xFFFF,
                                             buf if n else None, n, timeout_ms)
        if r < 0:
            raise UsbError(r, f"control_out(req={request})")
        return r

    def bulk_read(self, endpoint: int, length: int, timeout_ms: int) -> bytes:
        """Read up to `length` bytes. A timeout is not an error: whatever
        arrived before it is returned (possibly b'')."""
        buf = (c_ubyte * length)()
        got = c_int(0)
        r = self.lib.libusb_bulk_transfer(self.h, endpoint, buf, length,
                                          byref(got), timeout_ms)
        if r < 0 and r != LIBUSB_ERROR_TIMEOUT:
            raise UsbError(r, "bulk_read")
        return bytes(buf[:got.value])

    def close(self):
        if not self.h:
            return
        for iface in list(self.claimed):
            self.lib.libusb_release_interface(self.h, iface)
        self.claimed.clear()
        self.lib.libusb_close(self.h)
        self.h = c_void_p()
