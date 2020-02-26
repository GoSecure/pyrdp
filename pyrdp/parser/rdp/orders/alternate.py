"""
Constants and state for Alternate Secondary Drawing Orders.
"""
from io import BytesIO

from pyrdp.core import Uint16LE, Uint8, Uint32LE
from .common import read_color

STREAM_BITMAP_END = 0x01
STREAM_BITMAP_COMPRESSED = 0x02
STREAM_BITMAP_V2 = 0x04


class CreateOffscreenBitmap:
    @staticmethod
    def parse(s: BytesIO) -> 'CreateOffscreenBitmap':
        self = CreateOffscreenBitmap()

        self.flags = Uint16LE.unpack(s)
        self.id = self.flags & 0x7FFF
        self.cx = Uint16LE.unpack(s)
        self.cy = Uint16LE.unpack(s)

        if self.flags & 0x8000 != 0:
            cIndices = Uint16LE.unpack(s)
            self.delete = [Uint16LE.unpack(s) for _ in range(cIndices)]
        else:
            self.delete = None

        return self


class SwitchSurface:
    @staticmethod
    def parse(s: BytesIO) -> 'SwitchSurface':
        self = SwitchSurface()

        self.id = Uint16LE.unpack(s)
        return id


class CreateNineGridBitmap:
    @staticmethod
    def parse(s: BytesIO) -> 'CreateNineGridBitmap':
        self = CreateNineGridBitmap()

        self.bpp = Uint8.unpack(s)
        self.id = Uint16LE.unpack(s)

        # NOTE: According to 2.2.2.2.1.3.4 There should be cx:16 and cy:16 here??

        self.flFlags = Uint32LE.unpack(s)
        self.ulLeftWidth = Uint16LE.unpack(s)
        self.ulRightWidth = Uint16LE.unpack(s)
        self.ulTopHeight = Uint16LE.unpack(s)
        self.ulBottomHeight = Uint16LE.unpack(s)
        self.rgb = read_color(s)  # FIXME: Bring this in

        return self


class StreamBitmapFirst:
    @staticmethod
    def parse(s: BytesIO) -> 'StreamBitmapFirst':
        self = StreamBitmapFirst()

        self.flags = Uint8.unpack(s)
        self.bpp = Uint8.unpack(s)
        self.type = Uint16LE.unpack(s)

        self.width = Uint16LE.unpack(s)
        self.height = Uint16LE.unpack(s)

        self.totalSize = 0
        if self.flags & STREAM_BITMAP_V2:
            self.totalSize = Uint32LE.unpack(s)
        else:
            self.totalSize = Uint16LE.unpack(s)

        blockSize = Uint16LE.unpack(s)
        self.data = s.read(blockSize)

        return self


class StreamBitmapNext:
    @staticmethod
    def parse(s: BytesIO) -> 'StreamBitmapNext':
        self = StreamBitmapNext()

        self.flags = Uint8.unpack(s)
        self.bitmapType = Uint16LE.unpack(s)

        blockSize = Uint16LE.unpack(s)
        self.data = s.read(blockSize)

        return self


class GdiPlusFirst:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusFirst':
        self = GdiPlusFirst()

        s.read(1)  # Padding

        cbSize = Uint16LE.unpack(s)
        self.totalSize = Uint32LE.unpack(s)
        self.totalEmfSize = Uint32LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class GdiPlusNext:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusNext':
        self = GdiPlusNext()

        s.read(1)  # Padding

        cbSize = Uint16LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class GdiPlusEnd:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusEnd':
        self = GdiPlusEnd()

        s.read(1)  # Padding

        cbSize = Uint16LE.unpack(s)
        self.totalSize = Uint32LE.unpack(s)
        self.totalEmfSize = Uint32LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class GdiPlusCacheFirst:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusCacheFirst':
        self = GdiPlusCacheFirst()

        self.flags = Uint8.unpack(s)
        self.cacheType = Uint16LE.unpack(s)
        self.cacheIdx = Uint16LE.unpack(s)

        cbSize = Uint16LE.unpack(s)
        self.totalSize = Uint32LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class GdiPlusCacheNext:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusCacheNext':
        self = GdiPlusCacheNext()

        self.flags = Uint8.unpack(s)
        self.cacheType = Uint16LE.unpack(s)
        self.cacheIdx = Uint16LE.unpack(s)

        cbSize = Uint16LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class GdiPlusCacheEnd:
    @staticmethod
    def parse(s: BytesIO) -> 'GdiPlusCacheEnd':
        self = GdiPlusCacheEnd()

        self.flags = Uint8.unpack(s)
        self.cacheType = Uint16LE.unpack(s)
        self.cacheIndex = Uint16LE.unpack(s)
        cbSize = Uint16LE.unpack(s)
        self.totalSize = Uint32LE.unpack(s)
        self.data = s.read(cbSize)

        return self


class FrameMarker:
    @staticmethod
    def parse(s: BytesIO) -> 'FrameMarker':
        self = FrameMarker()
        self.action = Uint32LE.unpack(s)

        return self

# class Window:
#     @staticmethod
#     def parse(s: BytesIO) -> 'Window':
#         self = Window()
#         # This is specified in MS-RDPERP for seamless applications.
#         return self


# class CompDeskFirst
#     @staticmethod
#     def parse(s: BytesIO) -> 'CompDeskFirst':
#         self = CompdeskFirst()
