#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Constants, state and parsing primitives for Primary Drawing Orders.
"""
from io import BytesIO

from pyrdp.enum.orders import DrawingOrderControlFlags as ControlFlags
from pyrdp.core.packing import Uint8, Int8, Int16LE, Uint16LE, Uint32LE
from .common import GlyphV2, Bounds
from .secondary import BMF_BPP, CACHED_BRUSH

# This follows the PrimaryDrawOrderType enum
ORDERTYPE_FIELDBYTES = [1, 2, 1, 0, 0, 0, 0, 1, 1, 2, 1, 1, 0, 2, 3, 1, 2, 2, 2, 2, 1, 2, 1, 0, 2, 1, 2, 3]

BACKMODE_TRANSPARENT = 0x01
BACKMODE_OPAQUE = 0x02


def read_field_flags(s: BytesIO, flags: int, orderType: int) -> int:
    """Reads encoded field flags."""

    # REFACTOR: This could be internal to the context class.
    assert orderType >= 0 and orderType < len(ORDERTYPE_FIELDBYTES)

    fieldBytes = ORDERTYPE_FIELDBYTES[orderType]
    assert fieldBytes != 0  # Should be a valid orderType

    if flags & ControlFlags.TS_ZERO_FIELD_BYTE_BIT0:
        fieldBytes -= 1

    if flags & ControlFlags.TS_ZERO_FIELD_BYTE_BIT1:
        if fieldBytes > 1:
            fieldBytes -= 2
        else:
            fieldBytes = 0

    fieldFlags = 0
    for i in range(fieldBytes):
        fieldFlags |= Uint8.unpack(s) << (i * 8)

    return fieldFlags


def read_coord(s: BytesIO, delta: bool, prev: int):
    if delta:
        return prev + Int8.unpack(s)
    else:
        return Int16LE.unpack(s)


def read_delta(s: BytesIO) -> int:
    msb = Uint8.unpack(s)
    val = msb | ~0x3F if msb & 0x40 else msb & 0x3F
    if msb & 0x80:
        val = (val << 8) | Uint8.unpack(s)
    return val


def read_rgb(s: BytesIO) -> int:
    """Read an RGB color encoded as 0xBBGGRR."""
    r = Uint8.unpack(s)
    g = Uint8.unpack(s)
    b = Uint8.unpack(s)
    return r | g << 8 | b << 16


def read_delta_points(s: BytesIO, n: int, x0: int, y0: int) -> [(int, int)]:
    """
    Read an array of delta encoded points.

    :param s: The data stream to parse the delta points from.
    :param n: The number of points that are encoded in the stream.
    :param x0: The initial value of x.
    :param y0: The initial value of y.

    A points is represented as an (x,y)-tuple.

    This function converts the deltas into absolute coordinates.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/6c7b2a52-103c-4a7d-a2a9-997416d4a475
    """

    zeroBitsLen = ((n + 3) // 4)
    zeroBits = s.read(zeroBitsLen)

    dx = x0
    dy = y0

    points = []
    for i in range(n):

        # Next zeroBits byte.
        if i % 4 == 0:
            flags = zeroBits[i // 4]

        x = (read_delta(s) + dx) if not flags & 0x80 else dx
        y = (read_delta(s) + dy) if not flags & 0x40 else dy
        flags <<= 2
        points.append((x, y))

        # Update previous point coords.
        dx = x
        dy = y

    return points


def read_delta_rectangles(s: BytesIO, n: int) -> [(int, int, int, int)]:
    """
    Read an array of delta encoded rectangles.

    :param s: The data stream to parse the rectangles from.
    :param n: The number of rectangles encoded in the stream.

    A rectangles is represented as a (left, top, width, height)-tuple.

    This function converts the deltas into absolute coordinates.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/b89f2058-b180-4da0-9bd1-aa694c87768c
    """

    zeroBitsSize = (n + 1) // 2
    zeroBits = s.read(zeroBitsSize)

    rectangles = []
    dl = dt = dw = dh = 0

    for i in range(n):
        if i % 2 == 0:
            flags = zeroBits[i // 2]

        left = read_delta(s) + dl if not flags & 0x80 else dl
        top = read_delta(s) + dt if not flags & 0x40 else dt
        width = read_delta(s) if not flags & 0x20 else dw
        height = read_delta(s) if not flags & 0x10 else dh
        flags <<= 4
        rectangles.append((left, top, width, height))

        # Update previous rectangle coords.
        dl = left
        dt = top
        dw = width
        dh = height
    return rectangles


class PrimaryContext:
    """Primary drawing order context."""

    def __init__(self):
        # The field flags for the current order.
        self.fieldFlags: int = 0

        # Whether coordinates are being sent as a delta.
        self.deltaCoords: bool = False

        # A cache of the previous order type received.
        self.orderType: int = None

        # The configured bounding rectangle
        self.bounds: Bounds = Bounds()
        self.bounded: bool = False

        # Track state for each drawing order.
        self.dstBlt = DstBlt(self)
        self.patBlt = PatBlt(self)
        self.scrBlt = ScrBlt(self)
        self.drawNineGrid = DrawNineGrid(self)
        self.multiDrawNineGrid = MultiDrawNineGrid(self)
        self.lineTo = LineTo(self)
        self.opaqueRect = OpaqueRect(self)
        self.saveBitmap = SaveBitmap(self)
        self.memBlt = MemBlt(self)
        self.mem3Blt = Mem3Blt(self)
        self.multiDstBlt = MultiDstBlt(self)
        self.multiPatBlt = MultiPatBlt(self)
        self.multiScrBlt = MultiScrBlt(self)
        self.multiOpaqueRect = MultiOpaqueRect(self)
        self.fastIndex = FastIndex(self)
        self.polygonSc = PolygonSc(self)
        self.polygonCb = PolygonCb(self)
        self.polyLine = PolyLine(self)
        self.fastGlyph = FastGlyph(self)
        self.ellipseSc = EllipseSc(self)
        self.ellipseCb = EllipseCb(self)
        self.glyphIndex = GlyphIndex(self)

    def update(self, s: BytesIO, flags: int):
        """
        Update the context when parsing a new primary order.

        This method should be called at the beginning of every new
        primary order to process contextual changes.

        :param s BytesIO: The raw byte stream
        :param flags int: The controlFlags received in the UPDATE PDU.

        :return: The orderType to act upon.
        """

        if flags & ControlFlags.TS_TYPE_CHANGE:
            self.orderType = Uint8.unpack(s)
        assert self.orderType is not None

        self.fieldFlags = read_field_flags(s, flags, self.orderType)

        # Process bounding rectangle updates
        if flags & ControlFlags.TS_BOUNDS:
            self.bounded = True
            if not flags & ControlFlags.TS_ZERO_BOUNDS_DELTAS:
                self.bounds.update(s)
        else:
            self.bounded = False

        self.deltaCoords = flags & ControlFlags.TS_DELTA_COORDS != 0

        return self.orderType

    def field(self, n: int):
        """Check whether field `n` is present in the message."""
        return self.fieldFlags & (1 << (n - 1)) != 0


class Brush:
    def __init__(self):
        self.x = self.y = 0
        self.style = 0
        self.hatch = 0
        self.data = None
        self.index = None
        self.bpp = 0

    def update(self, s: BytesIO, flags: int):
        if flags & 0b00001:
            self.x = Uint8.unpack(s)
        if flags & 0b00010:
            self.y = Uint8.unpack(s)
        if flags & 0b00100:
            self.style = Uint8.unpack(s)
        if flags & 0b01000:
            self.hatch = Uint8.unpack(s)
        if flags & 0b10000:
            self.data = (s.read(7) + bytes([self.hatch]))[::-1]

        if self.style & CACHED_BRUSH:
            self.index = self.hatch
            self.bpp = BMF_BPP[self.style & 0x07]
            if self.bpp == 0:
                self.bpp = 1

        return self


class DstBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.x = 0
        self.y = 0
        self.w = 0
        self.h = 0
        self.rop = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(2):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)
        if self.ctx.field(3):
            self.w = read_coord(s, self.ctx.deltaCoords, self.w)
        if self.ctx.field(4):
            self.h = read_coord(s, self.ctx.deltaCoords, self.h)
        if self.ctx.field(5):
            self.rop = Uint8.unpack(s)

        return self

    def __str__(self):
        return f'<DstBlt ({self.x}, {self.y}) {self.w}x{self.h} Rop={self.rop}>'


class PatBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.x = 0
        self.y = 0
        self.w = 0
        self.h = 0
        self.rop = 0
        self.bg = 0
        self.fg = 0
        self.brush = Brush()

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(2):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)
        if self.ctx.field(3):
            self.w = read_coord(s, self.ctx.deltaCoords, self.w)
        if self.ctx.field(4):
            self.h = read_coord(s, self.ctx.deltaCoords, self.h)
        if self.ctx.field(5):
            self.rop = Uint8.unpack(s)
        if self.ctx.field(6):
            self.bg = read_rgb(s)
        if self.ctx.field(7):
            self.fg = read_rgb(s)

        self.brush.update(s, self.ctx.fieldFlags >> 7)

        return self

    def __str__(self):
        return f'<PatBlt ({self.x}, {self.y}) {self.w}x{self.h} Rop={self.rop}>'


class ScrBlt:
    """
    2.2.2.2.1.1.2.7
    """

    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.nLeftRect = 0
        self.nTopRect = 0
        self.nWidth = 0
        self.nHeight = 0
        self.bRop = 0
        self.nXSrc = 0
        self.nYSrc = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.nLeftRect = read_coord(s, self.ctx.deltaCoords, self.nLeftRect)
        if self.ctx.field(2):
            self.nTopRect = read_coord(s, self.ctx.deltaCoords, self.nTopRect)
        if self.ctx.field(3):
            self.nWidth = read_coord(s, self.ctx.deltaCoords, self.nWidth)
        if self.ctx.field(4):
            self.nHeight = read_coord(s, self.ctx.deltaCoords, self.nHeight)
        if self.ctx.field(5):
            self.bRop = Uint8.unpack(s)
        if self.ctx.field(6):
            self.nXSrc = read_coord(s, self.ctx.deltaCoords, self.nXSrc)
        if self.ctx.field(7):
            self.nYSrc = read_coord(s, self.ctx.deltaCoords, self.nYSrc)

        return self

    def __str__(self):
        return (f'<ScrBlt Src=({self.nXSrc},{self.nYSrc}) OP={self.bRop}'
                f' Dst=({self.nLeftRect}, {self.nTopRect}, {self.nWidth}, {self.nHeight})')


class DrawNineGrid:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.srcLeft = 0
        self.srcTop = 0
        self.srcRight = 0
        self.srcBottom = 0
        self.bitmapId = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.srcLeft = read_coord(s, self.ctx.deltaCoords, self.srcLeft)
        if self.ctx.field(2):
            self.srcTop = read_coord(s, self.ctx.deltaCoords, self.srcTop)
        if self.ctx.field(3):
            self.srcRight = read_coord(s, self.ctx.deltaCoords, self.srcRight)
        if self.ctx.field(4):
            self.srcBottom = read_coord(s, self.ctx.deltaCoords, self.srcBottom)
        if self.ctx.field(5):
            self.bitmapId = Uint16LE.unpack(s)

        return self

    def __str__(self):
        return '<DrawNineGrid>'


class MultiDrawNineGrid:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.srcLeft = 0
        self.srcTop = 0
        self.srcRight = 0
        self.srcBottom = 0
        self.bitmapId = 0
        self.nDeltaEntries = 0
        self.cbData = 0
        self.rectangles = []

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.srcLeft = read_coord(s, self.ctx.deltaCoords, self.srcLeft)
        if self.ctx.field(2):
            self.srcTop = read_coord(s, self.ctx.deltaCoords, self.srcTop)
        if self.ctx.field(3):
            self.srcRight = read_coord(s, self.ctx.deltaCoords, self.srcRight)
        if self.ctx.field(4):
            self.srcBottom = read_coord(s, self.ctx.deltaCoords, self.srcBottom)
        if self.ctx.field(5):
            self.bitmapId = Uint16LE.unpack(s)
        if self.ctx.field(6):
            self.nDeltaEntries = Uint8.unpack(s)

        if self.ctx.field(7):
            self.cbData = Uint16LE.unpack(s)
            self.rectangles = read_delta_rectangles(s, self.nDeltaEntries)

        return self

    def __str__(self):
        return '<MultiDrawNineGrid>'


class LineTo:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.bgMode = 0
        self.x0 = 0
        self.y0 = 0
        self.x1 = 0
        self.y1 = 0
        self.bg = 0
        self.rop2 = 0
        self.penStyle = 0
        self.penWidth = 0
        self.penColor = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.bgMode = Uint16LE.unpack(s)
        if self.ctx.field(2):
            self.x0 = read_coord(s, self.ctx.deltaCoords, self.x0)
        if self.ctx.field(3):
            self.y0 = read_coord(s, self.ctx.deltaCoords, self.y0)
        if self.ctx.field(4):
            self.x1 = read_coord(s, self.ctx.deltaCoords, self.x1)
        if self.ctx.field(5):
            self.y1 = read_coord(s, self.ctx.deltaCoords, self.y1)
        if self.ctx.field(6):
            self.bg = read_rgb(s)
        if self.ctx.field(7):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(8):
            self.penStyle = Uint8.unpack(s)
        if self.ctx.field(9):
            self.penWidth = Uint8.unpack(s)
        if self.ctx.field(10):
            self.penColor = read_rgb(s)

        return self

    def __str__(self):
        return '<LineTo>'


class OpaqueRect:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.x = 0
        self.y = 0
        self.w = 0
        self.h = 0
        self.color = 0  # 0xBBGGRR

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(2):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)
        if self.ctx.field(3):
            self.w = read_coord(s, self.ctx.deltaCoords, self.w)
        if self.ctx.field(4):
            self.h = read_coord(s, self.ctx.deltaCoords, self.h)

        if self.ctx.field(5):
            r = Uint8.unpack(s)
            self.color = (self.color & 0x00FFFF00) | r
        if self.ctx.field(6):
            g = Uint8.unpack(s)
            self.color = (self.color & 0x00FF00FF) | (g << 8)
        if self.ctx.field(7):
            b = Uint8.unpack(s)
            self.color = (self.color & 0x0000FFFF) | (b << 16)

        return self

    def __str__(self):
        return f'<OpaqueRect ({self.x}, {self.y}) {self.w}x{self.h}) Color={self.color:06X}>'


class SaveBitmap:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.savedBitmapPosition = 0
        self.nLeftRect = 0
        self.nTopRect = 0
        self.nRightRect = 0
        self.nBottomRect = 0
        self.operation = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.savedBitmapPosition = Uint32LE.unpack(s)
        if self.ctx.field(2):
            self.nLeftRect = read_coord(s, self.ctx.deltaCoords, self.nLeftRect)
        if self.ctx.field(3):
            self.nTopRect = read_coord(s, self.ctx.deltaCoords, self.nTopRect)
        if self.ctx.field(4):
            self.nRightRect = read_coord(s, self.ctx.deltaCoords, self.nRightRect)
        if self.ctx.field(5):
            self.nBottomRect = read_coord(s, self.ctx.deltaCoords, self.nBottomRect)
        if self.ctx.field(6):
            self.operation = Uint8.unpack(s)

        return self

    def __str__(self):
        return '<SaveBitmap>'


class MemBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        # Blit rectangle.
        self.left = self.top = self.width = self.height = 0

        # Source buffer offsets.
        self.xSrc = self.ySrc = 0

        self.cacheIndex = 0
        self.cacheId = 0
        self.colorIndex = 0

    def update(self, s: BytesIO) -> 'MemBlt':
        ctx = self.ctx

        if ctx.field(1):
            self.cacheId = Uint16LE.unpack(s)
        if ctx.field(2):
            self.left = read_coord(s, ctx.deltaCoords, self.left)
        if ctx.field(3):
            self.top = read_coord(s, ctx.deltaCoords, self.top)
        if ctx.field(4):
            self.width = read_coord(s, ctx.deltaCoords, self.width)
        if ctx.field(5):
            self.height = read_coord(s, ctx.deltaCoords, self.height)
        if ctx.field(6):
            self.rop = Uint8.unpack(s)
        if ctx.field(7):
            self.xSrc = read_coord(s, ctx.deltaCoords, self.xSrc)
        if ctx.field(8):
            self.ySrc = read_coord(s, ctx.deltaCoords, self.ySrc)
        if ctx.field(9):
            self.cacheIndex = Uint16LE.unpack(s)

        self.colorIndex = self.cacheId >> 8
        self.cacheId = self.cacheId & 0xFF

        return self

    def __str__(self):
        return (f'<MemBlt ({self.xSrc},{self.ySrc}) OP={self.rop} L={self.left} T={self.top} W={self.width} H={self.height}'
                f' cacheIndex={self.cacheIndex} cacheId={self.cacheId} colorIdx={self.colorIndex}>')


class Mem3Blt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.brush = Brush()

        self.cacheId = 0
        self.left = 0
        self.top = 0
        self.width = 0
        self.height = 0
        self.rop = 0
        self.nXSrc = 0
        self.nYSrc = 0
        self.bg = 0
        self.fg = 0
        self.cacheIndex = 0
        self.colorIndex = 0
        self.cacheId = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.cacheId = Uint16LE.unpack(s)
        if self.ctx.field(2):
            self.left = read_coord(s, self.ctx.deltaCoords, self.left)
        if self.ctx.field(3):
            self.top = read_coord(s, self.ctx.deltaCoords, self.top)
        if self.ctx.field(4):
            self.width = read_coord(s, self.ctx.deltaCoords, self.width)
        if self.ctx.field(5):
            self.height = read_coord(s, self.ctx.deltaCoords, self.height)
        if self.ctx.field(6):
            self.rop = Uint8.unpack(s)
        if self.ctx.field(7):
            self.nXSrc = read_coord(s, self.ctx.deltaCoords, self.nXSrc)
        if self.ctx.field(8):
            self.nYSrc = read_coord(s, self.ctx.deltaCoords, self.nYSrc)
        if self.ctx.field(9):
            self.bg = read_rgb(s)
        if self.ctx.field(10):
            self.fg = read_rgb(s)

        self.brush.update(s, self.ctx.fieldFlags >> 10)

        if self.ctx.field(16):
            self.cacheIndex = Uint16LE.unpack(s)

        self.colorIndex = self.cacheId >> 8
        self.cacheId = self.cacheId & 0xFF

        return self

    def __str__(self):
        return '<Mem3Blt>'


class MultiDstBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.x = 0
        self.y = 0
        self.w = 0
        self.h = 0
        self.rop = 0
        self.numRectangles = 0
        self.cbData = 0
        self.rectangles = []

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(2):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)
        if self.ctx.field(3):
            self.w = read_coord(s, self.ctx.deltaCoords, self.w)
        if self.ctx.field(4):
            self.h = read_coord(s, self.ctx.deltaCoords, self.h)
        if self.ctx.field(5):
            self.rop = Uint8.unpack(s)
        if self.ctx.field(6):
            self.numRectangles = Uint8.unpack(s)

        if self.ctx.field(7):
            self.cbData = Uint16LE.unpack(s)
            self.rectangles = read_delta_rectangles(s, self.numRectangles)

        return self

    def __str__(self):
        return '<MultiDstBlt>'


class MultiPatBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.brush = Brush()

        self.x = 0
        self.y = 0
        self.w = 0
        self.h = 0
        self.rop = 0
        self.bg = 0
        self.fg = 0
        self.numRectangles = 0
        self.cbData = 0
        self.rectangles = []

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(2):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)
        if self.ctx.field(3):
            self.w = read_coord(s, self.ctx.deltaCoords, self.w)
        if self.ctx.field(4):
            self.h = read_coord(s, self.ctx.deltaCoords, self.h)
        if self.ctx.field(5):
            self.rop = Uint8.unpack(s)
        if self.ctx.field(6):
            self.bg = read_rgb(s)
        if self.ctx.field(7):
            self.fg = read_rgb(s)

        self.brush.update(s, self.ctx.fieldFlags >> 7)

        if self.ctx.field(13):
            self.numRectangles = Uint8.unpack(s)

        if self.ctx.field(14):
            self.cbData = Uint16LE.unpack(s)
            self.rectangles = read_delta_rectangles(s, self.numRectangles)

        return self

    def __str__(self):
        return '<MultiPatBlt>'


class MultiScrBlt:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.nLeftRect = 0
        self.nTopRect = 0
        self.nWidth = 0
        self.nHeight = 0
        self.bRop = 0
        self.nXSrc = 0
        self.nYSrc = 0
        self.numRectangles = 0
        self.cbData = 0
        self.rectangles = []

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.nLeftRect = read_coord(s, self.ctx.deltaCoords, self.nLeftRect)
        if self.ctx.field(2):
            self.nTopRect = read_coord(s, self.ctx.deltaCoords, self.nTopRect)
        if self.ctx.field(3):
            self.nWidth = read_coord(s, self.ctx.deltaCoords, self.nWidth)
        if self.ctx.field(4):
            self.nHeight = read_coord(s, self.ctx.deltaCoords, self.nHeight)
        if self.ctx.field(5):
            self.bRop = Uint8.unpack(s)
        if self.ctx.field(6):
            self.nXSrc = read_coord(s, self.ctx.deltaCoords, self.nXSrc)
        if self.ctx.field(7):
            self.nYSrc = read_coord(s, self.ctx.deltaCoords, self.nYSrc)
        if self.ctx.field(8):
            self.numRectangles = Uint8.unpack(s)

        if self.ctx.field(9):
            self.cbData = Uint16LE.unpack(s)
            self.rectangles = read_delta_rectangles(s, self.numRectangles)

        return self

    def __str__(self):
        return '<MultiScrBlt>'


class MultiOpaqueRect:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.nLeftRect = 0
        self.nTopRect = 0
        self.nWidth = 0
        self.nHeight = 0
        self.color = 0  # 0xBBGGRR
        self.numRectangles = 0
        self.cbData = 0
        self.rectangles = []

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.nLeftRect = read_coord(s, self.ctx.deltaCoords, self.nLeftRect)
        if self.ctx.field(2):
            self.nTopRect = read_coord(s, self.ctx.deltaCoords, self.nTopRect)
        if self.ctx.field(3):
            self.nWidth = read_coord(s, self.ctx.deltaCoords, self.nWidth)
        if self.ctx.field(4):
            self.nHeight = read_coord(s, self.ctx.deltaCoords, self.nHeight)

        if self.ctx.field(5):
            r = Uint8.unpack(s)
            self.color = (self.color & 0x00FFFF00) | r
        if self.ctx.field(6):
            g = Uint8.unpack(s)
            self.color = (self.color & 0x00FF00FF) | (g << 8)
        if self.ctx.field(7):
            b = Uint8.unpack(s)
            self.color = (self.color & 0x0000FFFF) | (b << 16)

        if self.ctx.field(8):
            self.numRectangles = Uint8.unpack(s)

        if self.ctx.field(9):
            self.cbData = Uint16LE.unpack(s)
            self.rectangles = read_delta_rectangles(s, self.numRectangles)

        return self

    def __str__(self):
        return f'<MultiOpaqueRect Color=#{self.color:06X}>'


class FastIndex:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.cacheId = 0
        self.ulCharInc = 0
        self.flAccel = 0
        self.bg = 0
        self.fg = 0
        self.bkLeft = 0
        self.bkTop = 0
        self.bkRight = 0
        self.bkBottom = 0
        self.opLeft = 0
        self.opTop = 0
        self.opRight = 0
        self.opBottom = 0
        self.x = 0
        self.y = 0

        self.data = b''

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.cacheId = Uint8.unpack(s)
        if self.ctx.field(2):
            self.ulCharInc = Uint8.unpack(s)
            self.flAccel = Uint8.unpack(s)
        if self.ctx.field(3):
            self.bg = read_rgb(s)
        if self.ctx.field(4):
            self.fg = read_rgb(s)
        if self.ctx.field(5):
            self.bkLeft = read_coord(s, self.ctx.deltaCoords, self.bkLeft)
        if self.ctx.field(6):
            self.bkTop = read_coord(s, self.ctx.deltaCoords, self.bkTop)
        if self.ctx.field(7):
            self.bkRight = read_coord(s, self.ctx.deltaCoords, self.bkRight)
        if self.ctx.field(8):
            self.bkBottom = read_coord(s, self.ctx.deltaCoords, self.bkBottom)
        if self.ctx.field(9):
            self.opLeft = read_coord(s, self.ctx.deltaCoords, self.opLeft)
        if self.ctx.field(10):
            self.opTop = read_coord(s, self.ctx.deltaCoords, self.opTop)
        if self.ctx.field(11):
            self.opRight = read_coord(s, self.ctx.deltaCoords, self.opRight)
        if self.ctx.field(12):
            self.opBottom = read_coord(s, self.ctx.deltaCoords, self.opBottom)
        if self.ctx.field(13):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(14):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)

        if self.ctx.field(15):
            cbData = Uint8.unpack(s)
            self.data = s.read(cbData)

        return self

    def __str__(self):
        return f'<FastIndex ({self.x}, {self.y}) Len={len(self.data)}>'


class PolygonSc:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.x0 = 0
        self.y0 = 0
        self.rop2 = 0
        self.fillMode = 0
        self.brushColor = 0
        self.cbData = 0
        self.numPoints = 0
        self.points = []

    def update(self, s: BytesIO):
        num = self.numPoints

        if self.ctx.field(1):
            self.x0 = read_coord(s, self.ctx.deltaCoords, self.x0)
        if self.ctx.field(2):
            self.y0 = read_coord(s, self.ctx.deltaCoords, self.y0)
        if self.ctx.field(3):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(4):
            self.fillMode = Uint8.unpack(s)
        if self.ctx.field(5):
            self.brushColor = read_rgb(s)

        if self.ctx.field(6):
            num = Uint8.unpack(s)

        if self.ctx.field(7):
            self.cbData = Uint8.unpack(s)
            self.numPoints = num
            self.points = read_delta_points(s, self.numPoints, self.x0, self.y0)

        return self

    def __str__(self):
        return '<PolygonSc>'


class PolygonCb:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.brush = Brush()

        self.x0 = 0
        self.y0 = 0
        self.rop2 = 0
        self.fillMode = 0
        self.bg = 0
        self.fg = 0
        self.cbData = 0
        self.numPoints = 0
        self.points = []
        self.bgMode = BACKMODE_OPAQUE

    def update(self, s: BytesIO):

        num = self.numPoints
        if self.ctx.field(1):
            self.x0 = read_coord(s, self.ctx.deltaCoords, self.x0)
        if self.ctx.field(2):
            self.y0 = read_coord(s, self.ctx.deltaCoords, self.y0)
        if self.ctx.field(3):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(4):
            self.fillMode = Uint8.unpack(s)
        if self.ctx.field(5):
            self.bg = read_rgb(s)
        if self.ctx.field(6):
            self.fg = read_rgb(s)

        self.brush.update(s, self.ctx.fieldFlags >> 6)

        if self.ctx.field(12):
            num = Uint8.unpack(s)

        if self.ctx.field(13):
            self.cbData = Uint8.unpack(s)
            self.numPoints = num
            self.points = read_delta_points(s, self.numPoints, self.x0, self.y0)

        self.bgMode = BACKMODE_TRANSPARENT if self.rop2 & 0x80 else BACKMODE_OPAQUE
        self.rop2 = self.rop2 & 0x1F

        return self

    def __str__(self):
        return '<PolygonCb>'


class PolyLine:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.x0 = 0
        self.y0 = 0
        self.rop2 = 0
        self.penColor = 0
        self.cbData = 0
        self.numPoints = 0
        self.points = []

    def update(self, s: BytesIO):
        num = self.numPoints
        if self.ctx.field(1):
            self.x0 = read_coord(s, self.ctx.deltaCoords, self.x0)
        if self.ctx.field(2):
            self.y0 = read_coord(s, self.ctx.deltaCoords, self.y0)
        if self.ctx.field(3):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(4):
            s.read(2)  # unused (brushCacheIndex)
        if self.ctx.field(5):
            self.penColor = read_rgb(s)
        if self.ctx.field(6):
            num = Uint8.unpack(s)

        if self.ctx.field(7):
            self.cbData = Uint8.unpack(s)
            self.numPoints = num
            self.points = read_delta_points(s, self.numPoints, self.x0, self.y0)

        return self

    def __str__(self):
        return '<PolyLine>'


class FastGlyph:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.cacheId = 0
        self.cacheIndex = 0
        self.glyph = None
        self.ulCharInc = 0
        self.flAccel = 0
        self.bg = 0
        self.fg = 0

        # Text background coords.
        self.bkLeft = 0
        self.bkTop = 0
        self.bkRight = 0
        self.bkBottom = 0

        # Opaque rectangle coords. (0 -> same as Bk*)
        self.opLeft = 0
        self.opTop = 0
        self.opRight = 0
        self.opBottom = 0

        # Position of the glyph.
        self.x = 0
        self.y = 0

    def update(self, s: BytesIO):
        if self.ctx.field(1):
            self.cacheId = Uint8.unpack(s)
        if self.ctx.field(2):
            self.ulCharInc = Uint8.unpack(s)
            self.flAccel = Uint8.unpack(s)
        if self.ctx.field(3):
            self.bg = read_rgb(s)
        if self.ctx.field(4):
            self.fg = read_rgb(s)
        if self.ctx.field(5):
            self.bkLeft = read_coord(s, self.ctx.deltaCoords, self.bkLeft)
        if self.ctx.field(6):
            self.bkTop = read_coord(s, self.ctx.deltaCoords, self.bkTop)
        if self.ctx.field(7):
            self.bkRight = read_coord(s, self.ctx.deltaCoords, self.bkRight)
        if self.ctx.field(8):
            self.bkBottom = read_coord(s, self.ctx.deltaCoords, self.bkBottom)
        if self.ctx.field(9):
            self.opLeft = read_coord(s, self.ctx.deltaCoords, self.opLeft)
        if self.ctx.field(10):
            self.opTop = read_coord(s, self.ctx.deltaCoords, self.opTop)
        if self.ctx.field(11):
            self.opRight = read_coord(s, self.ctx.deltaCoords, self.opRight)
        if self.ctx.field(12):
            self.opBottom = read_coord(s, self.ctx.deltaCoords, self.opBottom)
        if self.ctx.field(13):
            self.x = read_coord(s, self.ctx.deltaCoords, self.x)
        if self.ctx.field(14):
            self.y = read_coord(s, self.ctx.deltaCoords, self.y)

        if self.ctx.field(15):
            cbData = Uint8.unpack(s)

            if cbData > 1:
                # Read glyph data.
                self.glyph = GlyphV2.parse(s)
                self.cacheIndex = self.glyph.cacheIndex
                s.read(2)  # Padding / Unicode representation
            else:
                # Only a cache index.
                assert cbData == 1
                self.glyph = None  # Glyph must be retrieved from cacheIndex
                self.cacheIndex = Uint8.unpack(s)

        return self

    def __str__(self):
        return f'<FastGlyph Cache={self.cacheId}:{self.cacheIndex} New={self.glyph != None}>'


class EllipseSc:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.left = 0
        self.top = 0
        self.right = 0
        self.bottom = 0
        self.rop2 = 0
        self.fillMode = 0
        self.color = 0

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.left = read_coord(s, self.ctx.deltaCoords, self.left)
        if self.ctx.field(2):
            self.top = read_coord(s, self.ctx.deltaCoords, self.top)
        if self.ctx.field(3):
            self.right = read_coord(s, self.ctx.deltaCoords, self.right)
        if self.ctx.field(4):
            self.bottom = read_coord(s, self.ctx.deltaCoords, self.bottom)
        if self.ctx.field(5):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(6):
            self.fillMode = Uint8.unpack(s)
        if self.ctx.field(7):
            self.color = read_rgb(s)

        return self

    def __str__(self):
        return '<EllipseSc>'


class EllipseCb:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx
        self.brush = Brush()

        self.left = 0
        self.top = 0
        self.right = 0
        self.bottom = 0
        self.rop2 = 0
        self.fillMode = 0
        self.bg = 0
        self.fg = 0

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.left = read_coord(s, self.ctx.deltaCoords, self.left)
        if self.ctx.field(2):
            self.top = read_coord(s, self.ctx.deltaCoords, self.top)
        if self.ctx.field(3):
            self.right = read_coord(s, self.ctx.deltaCoords, self.right)
        if self.ctx.field(4):
            self.bottom = read_coord(s, self.ctx.deltaCoords, self.bottom)
        if self.ctx.field(5):
            self.rop2 = Uint8.unpack(s)
        if self.ctx.field(6):
            self.fillMode = Uint8.unpack(s)
        if self.ctx.field(7):
            self.bg = read_rgb(s)
        if self.ctx.field(8):
            self.fg = read_rgb(s)

        self.brush.update(s, self.ctx.fieldFlags >> 8)

        return self

    def __str__(self):
        return '<EllipseCb>'


class GlyphIndex:
    def __init__(self, ctx: PrimaryContext):
        self.ctx = ctx

        self.cacheId = 0
        self.flAccel = 0
        self.ulCharInc = 0
        self.fOpRedundant = 0
        self.bg = 0
        self.fg = 0
        self.bkLeft = 0
        self.bkTop = 0
        self.bkRight = 0
        self.bkBottom = 0
        self.opLeft = 0
        self.opTop = 0
        self.opRight = 0
        self.opBottom = 0

        self.brush = Brush()

        self.x = 0
        self.y = 0

        self.data = b''

    def update(self, s: BytesIO):

        if self.ctx.field(1):
            self.cacheId = Uint8.unpack(s)
        if self.ctx.field(2):
            self.flAccel = Uint8.unpack(s)
        if self.ctx.field(3):
            self.ulCharInc = Uint8.unpack(s)
        if self.ctx.field(4):
            self.fOpRedundant = Uint8.unpack(s)
        if self.ctx.field(5):
            self.bg = read_rgb(s)
        if self.ctx.field(6):
            self.fg = read_rgb(s)
        if self.ctx.field(7):
            self.bkLeft = Uint16LE.unpack(s)
        if self.ctx.field(8):
            self.bkTop = Uint16LE.unpack(s)
        if self.ctx.field(9):
            self.bkRight = Uint16LE.unpack(s)
        if self.ctx.field(10):
            self.bkBottom = Uint16LE.unpack(s)
        if self.ctx.field(11):
            self.opLeft = Uint16LE.unpack(s)
        if self.ctx.field(12):
            self.opTop = Uint16LE.unpack(s)
        if self.ctx.field(13):
            self.opRight = Uint16LE.unpack(s)
        if self.ctx.field(14):
            self.opBottom = Uint16LE.unpack(s)

        self.brush.update(s, self.ctx.fieldFlags >> 14)

        if self.ctx.field(20):
            self.x = Uint16LE.unpack(s)
        if self.ctx.field(21):
            self.y = Uint16LE.unpack(s)

        if self.ctx.field(22):
            cbData = Uint8.unpack(s)
            self.data = s.read(cbData)

        return self

    def __str__(self):
        return '<GlyphIndex>'
