#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
from pyrdp.logging import LOGGER_NAMES

from pyrdp.parser.rdp.orders import GdiFrontend

from pyrdp.parser.rdp.orders.alternate import CreateOffscreenBitmap, SwitchSurface, CreateNineGridBitmap, \
    StreamBitmapFirst, StreamBitmapNext, GdiPlusFirst, GdiPlusNext, GdiPlusEnd, GdiPlusCacheFirst, \
    GdiPlusCacheNext, GdiPlusCacheEnd, FrameMarker

from pyrdp.parser.rdp.orders.secondary import CacheBitmapV1, CacheBitmapV2, CacheBitmapV3, CacheColorTable, \
    CacheGlyph, CacheBrush

from pyrdp.parser.rdp.orders.primary import DstBlt, PatBlt, ScrBlt, DrawNineGrid, MultiDrawNineGrid, \
    LineTo, OpaqueRect, SaveBitmap, MemBlt, Mem3Blt, MultiDstBlt, MultiPatBlt, MultiScrBlt, MultiOpaqueRect, \
    FastIndex, PolygonSc, PolygonCb, PolyLine, FastGlyph, EllipseSc, EllipseCb, GlyphIndex

from pyrdp.ui import QRemoteDesktop, RDPBitmapToQtImage

from PySide2.QtGui import QImage, QPainter, QColor

LOG = logging.getLogger(LOGGER_NAMES.PLAYER + '.gdi')


class GdiQtFrontend(GdiFrontend):
    """
    A Qt Frontend for GDI drawing operations.

    This acts as a straight adapter from GDI to Qt as much as
    possible, but GDI specific operations that are not supported by Qt
    are implemented here.
    """

    def __init__(self, dc: QRemoteDesktop):
        self.dc = dc
        self._surface = QImage(dc.width(), dc.height(), QImage.Format_RGB32)
        self._old = None

        # For now this is a rudimentary cache implementation.
        self.bmpCache = {}

    def dstBlt(self, state: DstBlt):
        LOG.debug(state)

    def patBlt(self, state: PatBlt):
        LOG.debug(state)

    def scrBlt(self, state: ScrBlt):
        LOG.debug(state)
        # TODO: ROP3 operation
        p = QPainter(self._surface)
        p.drawImage(state.nLeftRect, state.nTopRect, self._old, state.nXSrc, state.nYSrc, state.nWidth, state.nHeight)
        p.setBrush(QColor.fromRgb(0xff, 0, 0, 0x20))

    def drawNineGrid(self, state: DrawNineGrid):
        LOG.debug(state)

    def multiDrawNineGrid(self, state: MultiDrawNineGrid):
        LOG.debug(state)

    def lineTo(self, state: LineTo):
        LOG.debug(state)

    def opaqueRect(self, state: OpaqueRect):
        LOG.debug(state)

    def saveBitmap(self, state: SaveBitmap):
        LOG.debug(state)

    def memBlt(self, state: MemBlt):
        LOG.debug(state)
        if state.cacheId not in self.bmpCache:  # Ignore cache miss?
            return

        cache = self.bmpCache[state.cacheId]
        if state.cacheIndex not in cache:  # Ignore cache miss?
            return

        bmp = cache[state.cacheIndex]

        # TODO: Check if NOHDR from general caps otherwise check COMPHDR
        img = RDPBitmapToQtImage(bmp.width, bmp.height,  bmp.bpp, True, bmp.data)

        p = QPainter(self._surface)

        ySrc = (bmp.height - state.height) - state.ySrc
        p.drawImage(state.left, state.top, img, state.xSrc, ySrc)

    def mem3Blt(self, state: Mem3Blt):
        LOG.debug(state)

    def multiDstBlt(self, state: MultiDstBlt):
        LOG.debug(state)

    def multiPatBlt(self, state: MultiPatBlt):
        LOG.debug(state)

    def multiScrBlt(self, state: MultiScrBlt):
        LOG.debug(state)

    def multiOpaqueRect(self, state: MultiOpaqueRect):
        LOG.debug(state)

    def fastIndex(self, state: FastIndex):
        LOG.debug(state)

    def polygonSc(self, state: PolygonSc):
        LOG.debug(state)

    def polygonCb(self, state: PolygonCb):
        LOG.debug(state)

    def polyLine(self, state: PolyLine):
        LOG.debug(state)

    def fastGlyph(self, state: FastGlyph):
        LOG.debug(state)

    def ellipseSc(self, state: EllipseSc):
        LOG.debug(state)

    def ellipseCb(self, state: EllipseCb):
        LOG.debug(state)

    def glyphIndex(self, state: GlyphIndex):
        LOG.debug(state)

    # Secondary Handlers
    def cacheBitmapV1(self, state: CacheBitmapV1):
        LOG.debug(state)

    def cacheBitmapV2(self, state: CacheBitmapV2):
        LOG.debug(state)
        cid = state.cacheId
        idx = state.cacheIndex

        # Create cache if needed.
        if cid not in self.bmpCache:
            self.bmpCache[cid] = {}

        cache = self.bmpCache[cid]
        cache[idx] = state

    def cacheBitmapV3(self, state: CacheBitmapV3):
        LOG.debug(state)
        cid = state.cacheId
        idx = state.cacheIndex

        # Create cache if needed.
        if cid not in self.bmpCache:
            self.bmpCache[cid] = {}

        cache = self.bmpCache[cid]
        cache[idx] = state

    def cacheColorTable(self, state: CacheColorTable):
        LOG.debug(state)

    def cacheGlyph(self, state: CacheGlyph):
        LOG.debug(state)

    def cacheBrush(self, state: CacheBrush):
        LOG.debug(state)

    # Alternate Secondary Handlers
    def frameMarker(self, state: FrameMarker):
        LOG.debug(state)
        if state.action == 0x01:  # END
            self.dc.notifyImage(0, 0, self._surface, self.dc.width(), self.dc.height())
        else:  # BEGIN
            self._old = self._surface
            self._surface = self._old.copy()

    def createOffscreenBitmap(self, state: CreateOffscreenBitmap):
        LOG.debug(state)

    def switchSurface(self, state: SwitchSurface):
        LOG.debug(state)

    def createNineGridBitmap(self, state: CreateNineGridBitmap):
        LOG.debug(state)

    def streamBitmapFirst(self, state: StreamBitmapFirst):
        LOG.debug(state)

    def streamBitmapNext(self, state: StreamBitmapNext):
        LOG.debug(state)

    def drawGdiPlusFirst(self, state: GdiPlusFirst):
        LOG.debug(state)

    def drawGdiPlusNext(self, state: GdiPlusNext):
        LOG.debug(state)

    def drawGdiPlusEnd(self, state: GdiPlusEnd):
        LOG.debug(state)

    def drawGdiPlusCacheFirst(self, state: GdiPlusCacheFirst):
        LOG.debug(state)

    def drawGdiPlusCacheNext(self, state: GdiPlusCacheNext):
        LOG.debug(state)

    def drawGdiPlusCacheEnd(self, state: GdiPlusCacheEnd):
        LOG.debug(state)
