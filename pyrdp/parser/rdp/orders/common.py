"""
Common String Reading Utilities
"""
from io import BytesIO
from pyrdp.core.packing import Uint8, Uint16LE, Uint32LE


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


def read_utf16_str(s: BytesIO, size: int) -> bytes:
    return bytes([Uint16LE.unpack(s) for _ in range(size)])  # Decode into str?


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
        self.cx = Uint16LE.unpack(s)
        self.cy = Uint16LE.unpack(s)

        # Calculate aj length (DWORD-aligned bitfield)
        cb = ((self.cx + 7) // 8) * self.cy
        cb += 4 - (cb % 4) if ((cb % 4) > 0) else 0
        self.aj = s.read(cb)

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
        self.cx = read_encoded_uint16(s)
        self.cy = read_encoded_uint16(s)

        # Calculate aj length (DWORD-aligned bitfield)

        cb = ((self.cx + 7) // 8) * self.cy
        cb += 4 - (cb % 4) if ((cb % 4) > 0) else 0
        self.aj = s.read(cb)

        return self
