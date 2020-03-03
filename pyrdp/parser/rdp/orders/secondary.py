#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Constants, state and parsing primitives for Secondary Drawing Orders.
"""
from io import BytesIO

from pyrdp.core.packing import Uint8, Uint16LE, Uint32LE
from pyrdp.enum.orders import Secondary
from pyrdp.enum.rdp import GeneralExtraFlag
from .common import read_color, read_utf16_str, read_encoded_uint16, read_encoded_uint32

CBR2_BPP = [0, 0, 0, 8, 16, 24, 32]
BPP_CBR2 = [0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
            0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]

CBR23_BPP = [0, 0, 0, 8, 16, 24, 32]
BPP_CBR23 = [0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
             0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]

BMF_BPP = [0, 1, 0, 8, 16, 24, 32, 0]
BPP_BMF = [0, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
           0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]

CBR2_HEIGHT_SAME_AS_WIDTH = 0x01
CBR2_PERSISTENT_KEY_PRESENT = 0x02
CBR2_NO_BITMAP_COMPRESSION_HDR = 0x08
CBR2_DO_NOT_CACHE = 0x10

BITMAP_CACHE_WAITING_LIST_INDEX = 0x7FFF
CG_GLYPH_UNICODE_PRESENT = 0x100

CACHED_BRUSH = 0x80


def decompress_brush(s: BytesIO, bpp: int) -> bytes:
    """
    Decompress brush data.

    The brush data is encoded in reverse order
    """
    bitmap = s.read(16)

    paletteBpp = (bpp + 1) // 8
    palette = s.read(paletteBpp*4)
    brush = bytes(paletteBpp * 64)  # 8x8 = 64 pixels

    i = 0
    for y in range(8):
        y = 8 - y
        for x in range(8):
            if x % 4 == 0:
                pixel = bitmap[i]
                i += 1

            # Encoded as 2-bit per pixel: 00112233.
            color = (pixel >> (3 - (x % 4)) * 2) & 0x3

            # Copy `paletteBpp` bytes into the brush.
            src = color * paletteBpp
            dst = (y * 8 + x) * paletteBpp
            brush[dst:dst+paletteBpp] = palette[src:src+paletteBpp]

    return brush


class CacheBitmapV1:
    @staticmethod
    def parse(s: BytesIO, orderType: int, flags: int) -> 'CacheBitmapV1':
        self = CacheBitmapV1()

        self.cacheId = Uint8.unpack(s)

        s.read(1)  # Padding

        self.width = Uint8.unpack(s)
        self.height = Uint8.unpack(s)
        self.bpp = Uint8.unpack(s)

        bitmapLength = Uint16LE.unpack(s)
        self.cacheIdx = Uint16LE.unpack(s)

        if orderType & Secondary.CACHE_BITMAP_COMPRESSED and \
           not flags & GeneralExtraFlag.NO_BITMAP_COMPRESSION_HDR:
            self.compression = s.read(8)
            bitmapLength -= 8

        self.data = s.read(bitmapLength)

        return self


class CacheColorTable:
    @staticmethod
    def parse(s: BytesIO) -> 'CacheColorTable':
        self = CacheColorTable()

        self.cacheIdx = Uint8.unpack(s)
        numberColors = Uint16LE.unpack(s)

        assert numberColors == 256
        self.colors = [read_color(s) for _ in range(numberColors)]

        return self


class CacheGlyph:
    @staticmethod
    def parse(s: BytesIO, flags: int, glyph) -> 'CacheGlyph':
        """
        Parse a CACHE_GLYPH order.

        :param s: The byte stream to parse
        :param flags: The UPDATE PDU controlFlags
        :param glyph: One of Glyph or GlyphV2 classes to select the parsing strategy
        """

        self = CacheGlyph()

        self.cacheId = Uint8.unpack(s)
        cGlyphs = Uint8.unpack(s)

        self.glyphs = [glyph.parse(s) for _ in range(cGlyphs)]

        if flags & CG_GLYPH_UNICODE_PRESENT and cGlyphs > 0:
            self.unicode = read_utf16_str(s, cGlyphs)

        return self


class CacheBitmapV2:
    def __init__(self):
        self.cacheId = 0
        self.cacheIndex = 0

        self.flags = 0
        self.bpp = 0
        self.key1 = self.key2 = 0
        self.height = self.width = 0

        self.cbCompFirstRowSize = 0
        self.cbCompMainBodySize = 0
        self.cbScanWidth = 0
        self.cbUncompressedSize = 0

    @staticmethod
    def parse(s: BytesIO, orderType: int, flags: int) -> 'CacheBitmapV2':
        self = CacheBitmapV2()

        self.cacheId = flags & 0x0003
        self.flags = (flags & 0xFF80) >> 7
        self.bpp = CBR2_BPP[(flags & 0x0078) >> 3]

        if self.flags & CBR2_PERSISTENT_KEY_PRESENT:
            self.key1 = Uint32LE.unpack(s)
            self.key2 = Uint32LE.unpack(s)

        if self.flags & CBR2_HEIGHT_SAME_AS_WIDTH:
            self.height = self.width = read_encoded_uint16(s)
        else:
            self.width = read_encoded_uint16(s)
            self.height = read_encoded_uint16(s)

        bitmapLength = read_encoded_uint32(s)
        self.cacheIndex = read_encoded_uint16(s)

        if self.flags & CBR2_DO_NOT_CACHE:
            self.cacheIndex = BITMAP_CACHE_WAITING_LIST_INDEX

        if orderType & Secondary.BITMAP_COMPRESSED_V2 and not \
           self.flags & CBR2_NO_BITMAP_COMPRESSION_HDR:
            # Parse compression header
            self.cbCompFirstRowSize = Uint16LE.unpack(s)
            self.cbCompMainBodySize = Uint16LE.unpack(s)
            self.cbScanWidth = Uint16LE.unpack(s)
            self.cbUncompressedSize = Uint16LE.unpack(s)

            bitmapLength = self.cbCompMainBodySize

        # Read bitmap data
        self.data = s.read(bitmapLength)

        return self

    def __str__(self):
        return (f'<CacheBitmapV2 Res={self.width}x{self.height}x{self.bpp} Len={len(self.data)}'
                f' CacheId={self.cacheId} CacheIndex={self.cacheIndex}>')


class CacheBrush:
    @staticmethod
    def parse(s: BytesIO) -> 'CacheBrush':
        self = CacheBrush()

        self.cacheIndex = Uint8.unpack(s)

        iBitmapFormat = Uint8.unpack(s)
        assert iBitmapFormat >= 0 and iBitmapFormat < len(BMF_BPP)

        self.bpp = BMF_BPP[iBitmapFormat]

        cx = self.width = Uint8.unpack(s)
        cy = self.height = Uint8.unpack(s)

        style = Uint8.unpack(s)
        assert style == 0  # (2.2.2.2.1.2.7 Appendix 4)

        iBytes = Uint8.unpack(s)

        compressed = False
        if cx == 8 and cy == 8 and self.bpp == 1:  # 8x8 mono bitmap
            self.data = s.read(8)[::-1]
        else:
            if self.bpp == 8 and iBytes == 20:
                compressed = True
            elif self.bpp == 16 and iBytes == 24:
                compressed = True
            elif self.bpp == 24 and iBytes == 32:
                compressed = True

            if compressed:
                self.data = decompress_brush(s, self.bpp)
            else:
                self.data = bytes(256)  # Preallocate
                scanline = (self.bpp // 8) * 8
                for i in range(7):
                    # TODO: Verify correctness
                    o = (7-i)*scanline
                    self.data[o:o+8] = s.read(scanline)

        return self


class CacheBitmapV3:
    @staticmethod
    def parse(s: BytesIO, flags: int) -> 'CacheBitmapV3':
        self = CacheBitmapV3()

        self.cacheId = flags & 0x00000003
        self.flags = (flags & 0x0000FF80) >> 7
        bitsPerPixelId = (flags & 0x00000078) >> 3

        # The spec says this should never be 0, but it is...
        self.bpp = CBR23_BPP[bitsPerPixelId]

        self.cacheIndex = Uint16LE.unpack(s)
        self.key1 = Uint32LE.unpack(s)
        self.key2 = Uint32LE.unpack(s)
        self.bpp = Uint8.unpack(s)

        compressed = Uint8.unpack(s)
        s.read(1)  # Reserved (1 bytes)

        self.codecId = Uint8.unpack(s)
        self.width = Uint16LE.unpack(s)
        self.height = Uint16LE.unpack(s)
        dataLen = Uint32LE.unpack(s)

        if compressed:  # TS_COMPRESSED_BITMAP_HEADER_EX present.
            s.read(24)  # Non-essential.

        self.data = s.read(dataLen)

        return self

    def __str__(self):
        return (f'<CacheBitmapV3 {self.width}x{self.height}x{self.bpp} Size={len(self.data)}'
                f' Cache={self.cacheId}:{self.cacheIndex} Codec={self.codecId}>')
