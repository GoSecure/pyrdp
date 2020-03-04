#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
"""
Drawing Order Context.
"""

from pyrdp.parser.rdp.orders.alternate import CreateOffscreenBitmap, SwitchSurface, CreateNineGridBitmap, \
    StreamBitmapFirst, StreamBitmapNext, GdiPlusFirst, GdiPlusNext, GdiPlusEnd, GdiPlusCacheFirst, \
    GdiPlusCacheNext, GdiPlusCacheEnd, FrameMarker

from .common import Bounds
from pyrdp.enum import IntEnum


class BrushStyle(IntEnum):
    SOLID = 0x00
    NULL = 0x01
    HATCHED = 0x02
    PATTERN = 0x03


class HatchStyle(IntEnum):
    HORIZONTAL = 0x00
    VERTICAL = 0x01
    FDIAGONAL = 0x02
    BDIAGNOAL = 0x03
    CROSS = 0x04
    DIAGCROSS = 0x05


class GdiFrontend:
    """
    Interface for objects that implement GDI.

    This class provides abstract methods to be used by modules
    interested in listening and acting upon context updates.
    Its primary purpose is for the PyRDP player to render the
    remote desktop.

    NOTE: Unimplemented methods will act as No-Op.
    """
    # REFACTOR: Move to core, this isn't really relevant to the parser.

    def onBounds(self, b: Bounds):
        """
        Called by the parser to configure the bounding rectangle.
        """
        pass

    def dstBlt(self, state):
        pass

    def patBlt(self, state):
        pass

    def scrBlt(self, state):
        pass

    def drawNineGrid(self, state):
        pass

    def multiDrawNineGrid(self, state):
        pass

    def lineTo(self, state):
        pass

    def opaqueRect(self, state):
        pass

    def saveBitmap(self, state):
        pass

    def memBlt(self, state):
        pass

    def mem3Blt(self, state):
        pass

    def multiDstBlt(self, state):
        pass

    def multiPatBlt(self, state):
        pass

    def multiScrBlt(self, state):
        pass

    def multiOpaqueRect(self, state):
        pass

    def fastIndex(self, state):
        pass

    def polygonSc(self, state):
        pass

    def polygonCb(self, state):
        pass

    def polyLine(self, state):
        pass

    def fastGlyph(self, state):
        pass

    def ellipseSc(self, state):
        pass

    def ellipseCb(self, state):
        pass

    def glyphIndex(self, state):
        pass

    # Secondary Handlers
    def cacheBitmapV1(self, state):
        pass

    def cacheBitmapV2(self, state):
        pass

    def cacheBitmapV3(self, state):
        pass

    def cacheColorTable(self, state):
        pass

    def cacheGlyph(self, state):
        pass

    def cacheBrush(self, state):
        pass

    # Alternate Secondary Handlers
    def frameMarker(self, state: FrameMarker):
        pass

    def createOffscreenBitmap(self, state: CreateOffscreenBitmap):
        """
        Create an offscreen bitmap.
        """
        pass

    def switchSurface(self, state: SwitchSurface):
        """
        Switch drawing surface.
        """
        pass

    def createNineGridBitmap(self, state: CreateNineGridBitmap):
        """
        Create a Nine Grid bitmap.
        """
        pass

    def streamBitmapFirst(self, state: StreamBitmapFirst):
        pass

    def streamBitmapNext(self, state: StreamBitmapNext):
        pass

    def drawGdiPlusFirst(self, state: GdiPlusFirst):
        pass

    def drawGdiPlusNext(self, state: GdiPlusNext):
        pass

    def drawGdiPlusEnd(self, state: GdiPlusEnd):
        pass

    def drawGdiPlusCacheFirst(self, state: GdiPlusCacheFirst):
        pass

    def drawGdiPlusCacheNext(self, state: GdiPlusCacheNext):
        pass

    def drawGdiPlusCacheEnd(self, state: GdiPlusCacheEnd):
        pass
