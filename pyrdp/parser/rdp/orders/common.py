#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Common stream reading utilities
"""
from io import BytesIO
from pyrdp.core.packing import Uint8, Int8, Uint16LE, Int16LE, Uint32LE


def read_encoded_uint16(s: BytesIO) -> int:
    """Read an encoded UINT16."""
    # 2.2.2.2.1.2.1.2
    b = Uint8.unpack(s)
    if b & 0x80:
        return (b & 0x7F) << 8 | Uint8.unpack(s)
    else:
        return b & 0x7F


def read_encoded_int16(s: BytesIO) -> int:
    # 2.2.2.2.1.2.1.3
    msb = Uint8.unpack(s)
    val = msb & 0x3F

    if msb & 0x80:
        lsb = Uint8.unpack(s)
        val = (val << 8) | lsb

    return -val if msb & 0x40 else val


def read_encoded_uint32(s: BytesIO) -> int:
    # 2.2.2.2.1.2.1.4
    b = Uint8.unpack(s)
    n = (b & 0xC0) >> 6
    if n == 0:
        return b & 0x3F
    elif n == 1:
        return (b & 0x3F) << 8 | Uint8.unpack(s)
    elif n == 2:
        return ((b & 0x3F) << 16 | Uint8.unpack(s) << 8 | Uint8.unpack(s))
    else:  # 3
        return ((b & 0x3F) << 24 |
                Uint8.unpack(s) << 16 |
                Uint8.unpack(s) << 8 |
                Uint8.unpack(s))


def read_color(s: BytesIO):
    """
    2.2.2.2.1.3.4.1.1 TS_COLORREF ->  rgb
    2.2.2.2.1.2.4.1   TS_COLOR_QUAD -> bgr
    """
    return Uint32LE.unpack(s) & 0x00FFFFFF


def read_utf16_str(s: BytesIO, size: int) -> [int]:
    return [Uint16LE.unpack(s) for _ in range(size)]  # Decode into str?


def read_glyph_bitmap(w: int, h: int, s: BytesIO) -> bytes:
    """Read and inflate a glyph bitmap."""

    # Glyph encoding is specified in section 2.2.2.2.1.2.6.1
    scanline = ((w + 7) // 8)
    size = scanline * h
    packed = s.read(size)
    pad = 4 - (size % 4)

    if pad < 4:  # Skip alignment padding.
        s.read(pad)

    # Convert to 1 byte per pixel format for debugging.
    # data = bytearray(w * h)
    # for y in range(h):
    #     line = y * w
    #     for x in range(w):
    #         bits = packed[scanline * y + (x // 8)]
    #         px = (bits >> (8 - (x % 8))) & 1
    #         data[line + x] = px
    # return data
    return packed


class Glyph:
    """
    TS_CACHE_GLYPH_DATA (2.2.2.2.1.2.5.1)
    """
    @staticmethod
    def parse(s: BytesIO) -> 'Glyph':
        self = Glyph()
        self.cacheIndex = Uint16LE.unpack(s)
        self.x = Uint16LE.unpack(s)
        self.y = Uint16LE.unpack(s)
        self.w = Uint16LE.unpack(s)
        self.h = Uint16LE.unpack(s)

        self.data = read_glyph_bitmap(self.w, self.h, s)

        return self


class GlyphV2:
    """
    TS_CACHE_GLYPH_DATA_REV2 (2.2.2.2.1.2.6.1)
    """
    @staticmethod
    def parse(s: BytesIO) -> Glyph:
        self = Glyph()

        self.cacheIndex = Uint8.unpack(s)

        self.x = read_encoded_int16(s)
        self.y = read_encoded_int16(s)
        self.w = read_encoded_uint16(s)
        self.h = read_encoded_uint16(s)

        self.data = read_glyph_bitmap(self.w, self.h, s)

        return self


BOUND_LEFT = 0x01
BOUND_TOP = 0x02
BOUND_RIGHT = 0x04
BOUND_BOTTOM = 0x08
BOUND_DELTA_LEFT = 0x10
BOUND_DELTA_TOP = 0x20
BOUND_DELTA_RIGHT = 0x40
BOUND_DELTA_BOTTOM = 0x80


class Bounds:
    """A bounding rectangle."""

    def __init__(self):
        self.left = 0
        self.top = 0
        self.bottom = 0
        self.right = 0

    def update(self, s: BytesIO):
        flags = Uint8.unpack(s)

        if flags & BOUND_LEFT:
            self.left = Int16LE.unpack(s)
        elif flags & BOUND_DELTA_LEFT:
            self.left += Int8.unpack(s)

        if flags & BOUND_TOP:
            self.top = Int16LE.unpack(s)
        elif flags & BOUND_DELTA_TOP:
            self.top += Int8.unpack(s)

        if flags & BOUND_RIGHT:
            self.right = Int16LE.unpack(s)
        elif flags & BOUND_DELTA_RIGHT:
            self.right += Int8.unpack(s)

        if flags & BOUND_BOTTOM:
            self.bottom = Int16LE.unpack(s)
        elif flags & BOUND_DELTA_BOTTOM:
            self.bottom += Int8.unpack(s)

    def __str__(self):
        return f'<Bounds {self.left}, {self.top}, {self.right - self.left}, {self.bottom - self.top}'
