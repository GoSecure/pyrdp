#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
import typing
from pyrdp.logging import LOGGER_NAMES

from pyrdp.parser.rdp.orders import GdiFrontend
from pyrdp.parser.rdp.orders.common import Bounds
from pyrdp.parser.rdp.orders.frontend import BrushStyle, HatchStyle
from pyrdp.parser.rdp.orders.alternate import CreateOffscreenBitmap, SwitchSurface, CreateNineGridBitmap, \
    StreamBitmapFirst, StreamBitmapNext, GdiPlusFirst, GdiPlusNext, GdiPlusEnd, GdiPlusCacheFirst, \
    GdiPlusCacheNext, GdiPlusCacheEnd, FrameMarker
from pyrdp.parser.rdp.orders.secondary import CacheBitmapV1, CacheBitmapV2, CacheBitmapV3, CacheColorTable, \
    CacheGlyph, CacheBrush
from pyrdp.parser.rdp.orders.primary import DstBlt, PatBlt, ScrBlt, DrawNineGrid, MultiDrawNineGrid, \
    LineTo, OpaqueRect, SaveBitmap, MemBlt, Mem3Blt, MultiDstBlt, MultiPatBlt, MultiScrBlt, MultiOpaqueRect, \
    FastIndex, PolygonSc, PolygonCb, PolyLine, FastGlyph, EllipseSc, EllipseCb, GlyphIndex, Brush, \
    BACKMODE_TRANSPARENT

from pyrdp.ui import QRemoteDesktop, RDPBitmapToQtImage

from .cache import BitmapCache, BrushCache, PaletteCache, GlyphCache, GlyphEntry
from .raster import set_rop3, set_rop2

from PySide2.QtCore import Qt, QPoint
from PySide2.QtGui import QImage, QPainter, QColor, QPixmap, QBrush, QPen, QPolygon

LOG = logging.getLogger(LOGGER_NAMES.PLAYER + '.gdi')

SCREEN_BITMAP_SURFACE = 0xFFFF
BITMAPCACHE_SCREEN_ID = 0xFF
SUBSTITUTE_SURFACE = -1

# Opaque Rectangle Encoding Flags.
OPRECT_BOTTOM_ABSENT = 0x01
OPRECT_RIGHT_ABSENT = 0x02
OPRECT_TOP_ABSENT = 0x04
OPRECT_LEFT_ABSENT = 0x08

GLYPH_SPECIAL_PROCESSING = -32768
GLYPH_FRAGMENT_USE = 0xFE
GLYPH_FRAGMENT_ADD = 0xFF

# Defined in 2.2.2.2.1.1.2.13 (GlyphIndex)
SO_VERTICAL = 0x01
SO_HORIZONTAL = 0x02
SO_CHAR_INC_EQUAL_BM_BASE = 0x20


def rgb_to_qcolor(color: int):
    """Convert an RDP color (0xRRGGBB) to a QColor."""
    bpp = 16
    # TODO: check BPP from capabilities
    if bpp in [24, 32]:
        return QColor(color)
    if bpp == 16:
        t = color & 0x1F
        t = (t << 3) + t // 4
        b = min(t, 255)

        t = (color >> 5) & 0x3F
        t = (t << 2) + t // 4 // 2
        g = min(t, 255)

        t = (color >> 11) & 0x1F
        t = (t << 3) + t // 4
        r = min(t, 255)

    elif bpp == 15:
        pass
    elif bpp == 8:  # TODO: Support palettized mode.
        pass
    return QColor.fromRgb(r, g, b)


class GdiQtFrontend(GdiFrontend):
    """
    A Qt Frontend for GDI drawing operations.

    This acts as a straight adapter from GDI to Qt as much as
    possible, but GDI specific operations that are not supported by Qt
    are implemented here.

    Some of the methods are not implemented and will simply ignore the
    order:

        - NineGrid-related orders
        - StreamBitmap orders
        - GDI+ orders

    Note that `CacheBitmapV3` is only used in 32 bits-per-pixel which
    PyRDP currently does not support due to RDP6.0 compression not
    being implemented yet.

    If you have a replay which contains any unsupported or untested
    order, do not hesitate to share it with the project maintainers so
    that support can be added as required.

    (Make sure that the trace does not contain any sensitive information)
    """

    def __init__(self, dc: QRemoteDesktop):
        self.dc = dc
        self._warned = False

        # Initialize caches.
        self.bitmaps = BitmapCache()
        self.brushes = BrushCache()
        self.palettes = PaletteCache()
        self.glyphs = GlyphCache()

        self.bounds = None

        screen = dc.screen
        fallback = QImage(dc.width(), dc.height(), QImage.Format_ARGB32_Premultiplied)
        fallback.fill(0)

        self.surfaces = {
            SCREEN_BITMAP_SURFACE: screen,
            SUBSTITUTE_SURFACE: fallback,
        }
        self.activeSurface = SCREEN_BITMAP_SURFACE

    @property
    def surface(self) -> QImage:
        """Get the currently active surface."""
        return self.surfaces[self.activeSurface]

    @property
    def screen(self) -> QImage:
        return self.surfaces[SCREEN_BITMAP_SURFACE]

    # Rendering Helpers.
    def _paint(self, dst: QImage):
        """Retrieve QPainter for the given surface."""
        p = QPainter(dst)
        p.setPen(Qt.NoPen)
        # Set the bounding rectangle if present.
        if self.bounds:
            x = self.bounds.left
            y = self.bounds.top
            w = self.bounds.right - x
            h = self.bounds.bottom - y

            p.setClipRect(x, y, w + 1, h + 1)
            p.setClipping(True)
        return p

    def _end(self, p: QPainter):
        p.end()

    def _brush(self, b: Brush, p: QPainter):
        """Configure the given brush."""
        brush = None

        if b.index is not None:  # This is a cached brush.
            brush = self.brushes.get(b.index)
        elif b.style == BrushStyle.PATTERN:
            pm = QPixmap.loadFromData(b.data, _fmt[b.bpp])
            brush = QBrush(pm)
        elif b.style == BrushStyle.HATCHED:
            brush = QBrush(_hs[b.hatch])
        else:
            brush = QBrush(_bs[b.style])

        p.setBrush(brush)
        p.setBrushOrigin(b.x, b.y)

    # Drawing API.
    def onBounds(self, bounds: Bounds):
        """Called on bounding rectangle updates."""
        self.bounds = bounds

    def dstBlt(self, state: DstBlt):
        """Destination-only blitting operation."""
        LOG.debug(state)
        p = self._paint(self.surface)
        set_rop3(state.rop, p)
        p.fillRect(state.x, state.y, state.w, state.h, Qt.SolidPattern)
        self._end(p)

    def multiDstBlt(self, state: MultiDstBlt):
        """Destination-only blitting operation."""
        LOG.debug(state)
        p = self._paint(self.surface)
        set_rop3(state.rop, p)

        for (x, y, w, h) in state.rectangles:
            p.fillRect(x, y, w, h, Qt.SolidPattern)
        self._end(p)

    def patBlt(self, state: PatBlt):
        LOG.debug(state)
        p = self._paint(self.surface)
        self._brush(state.brush, p)
        set_rop3(state.rop, p)

        p.brush().setColor(rgb_to_qcolor(state.fg))
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))

        p.drawRect(state.x, state.y, state.w, state.h)
        self._end(p)

    def multiPatBlt(self, state: MultiPatBlt):
        LOG.debug(state)
        p = self._paint(self.surface)
        self._brush(state.brush)
        set_rop3(state.rop, p)

        p.brush().setColor(rgb_to_qcolor(state.fg))
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))

        for (x, y, w, h) in state.rectangles:
            p.drawRect(x, y, w, h)
        self._end(p)

    def scrBlt(self, state: ScrBlt):
        LOG.debug(state)
        src = self.screen
        dst = self.surface
        if src == dst:  # Qt doesn't support drawing to the source surface
            src = dst.copy()

        p = self._paint(dst)
        set_rop3(state.bRop, p)

        p.drawImage(state.nLeftRect, state.nTopRect, src, state.nXSrc, state.nYSrc, state.nWidth, state.nHeight)
        self._end(p)

    def multiScrBlt(self, state: MultiScrBlt):
        LOG.debug(state)
        src = self.screen
        dst = self.surface
        if src == dst:  # Qt doesn't support drawing to the source surface
            src = dst.copy()

        p = self._paint(dst)
        set_rop3(state.bRop, p)

        p.drawImage(state.nLeftRect, state.nTopRect, src, state.nXSrc, state.nYSrc, state.nWidth, state.nHeight)

        # Doesn't seem to be necessary.
        # for (x, y, w, h) in state.rectangles:
        #     p.drawImage(x, y, src, state.nXSrc, state.nYSrc, w, h)
        self._end(p)

    def drawNineGrid(self, state: DrawNineGrid):
        LOG.debug(state)
        self._unimplemented()

    def multiDrawNineGrid(self, state: MultiDrawNineGrid):
        LOG.debug(state)
        self._unimplemented()

    def lineTo(self, state: LineTo):
        LOG.debug(state)
        p = self._paint(self.surface)
        set_rop2(state.rop2, p)
        p.setBackgroundMode(Qt.TransparentMode if state.bgMode == BACKMODE_TRANSPARENT else Qt.OpaqueMode)
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))
        p.setPen(QPen(rgb_to_qcolor(state.penColor)))

        p.drawLine(state.x0, state.y0, state.x1, state.y1)
        self._end(p)

    def opaqueRect(self, state: OpaqueRect):
        LOG.debug(state)
        p = self._paint(self.surface)
        p.fillRect(state.x, state.y, state.w, state.h, rgb_to_qcolor(state.color))
        self._end(p)

    def multiOpaqueRect(self, state: MultiOpaqueRect):
        LOG.debug(state)
        p = self._paint(self.surface)
        color = rgb_to_qcolor(state.color)

        for (x, y, w, h) in state.rectangles:
            p.fillRect(x, y, w, h, color)

        self._end(p)

    def saveBitmap(self, state: SaveBitmap):
        LOG.debug(state)
        self._unimplemented()

    def memBlt(self, state: MemBlt):
        LOG.debug(state)
        dst = self.surface
        p = self._paint(dst)
        set_rop3(state.rop, p)

        if state.cacheId == BITMAPCACHE_SCREEN_ID:
            # Use offscreen bitmap as a source.
            src = self.surfaces[state.cacheIndex]
            if src == dst:
                src = dst.copy()  # Can't paint to same surface.
        else:
            src = self.bitmaps.get(state.cacheId, state.cacheIndex)

            if src is None:
                return  # Ignore cache misses.

        p.drawImage(state.left, state.top, src, state.xSrc, state.ySrc, state.width, state.height)
        self._end(p)

    def mem3Blt(self, state: Mem3Blt):
        LOG.debug(state)
        if state.cacheId == BITMAPCACHE_SCREEN_ID:
            # Use offscreen bitmap as a source.
            src = self.surfaces[state.cacheIndex]
        else:
            src = self.bitmaps.get(state.cacheId, state.cacheIndex)

            if src is None:
                return  # Ignore cache misses.

        p = self._paint(self.surface)
        self._brush(state.brush, p)
        set_rop3(state.rop, p)
        p.brush().setColor(rgb_to_qcolor(state.fg))
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))

        p.drawImage(state.left, state.top, src, state.xSrc, state.ySrc, state.width, state.height)
        self._end(p)

    def fastIndex(self, state: FastIndex):
        LOG.debug(state)
        self._process_glyph(GlyphContext(state), state.data)

    def polygonSc(self, state: PolygonSc):
        LOG.debug(state)
        p = self._paint(self.surface)
        p.setBrush(QBrush(rgb_to_qcolor(state.brushColor)))
        set_rop2(state.rop2, p)

        polygon = QPolygon()
        polygon.append(QPoint(state.x0, state.y0))
        for (x, y) in state.points:
            polygon.append(QPoint(x, y))

        p.drawPolygon(polygon, _fill[state.fillMode])
        self._end(p)

    def polygonCb(self, state: PolygonCb):
        LOG.debug(state)
        p = self._paint(self.surface)
        self._brush(state.brush)
        p.brush().setColor(rgb_to_qcolor(state.fg))
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))
        set_rop2(state.rop2, p)

        # Handle background mode.
        if state.brush.style in [BrushStyle.PATTERN, BrushStyle.HATCHED]:
            p.setBackgroundMode(Qt.TransparentMode if state.bgMode == BACKMODE_TRANSPARENT else Qt.OpaqueMode)

        polygon = QPolygon()
        polygon.append(QPoint(state.x0, state.y0))
        for (x, y) in state.points:
            polygon.append(QPoint(x, y))

        p.drawPolygon(polygon, _fill[state.fillMode])
        self._end(p)

    def polyLine(self, state: PolyLine):
        LOG.debug(state)
        p = self._paint(self.surface)
        p.setPen(QPen(rgb_to_qcolor(state.penColor)))
        set_rop2(state.rop2, p)

        polygon = QPolygon()
        polygon.append(QPoint(state.x0, state.y0))
        for (x, y) in state.points:
            polygon.append(QPoint(x, y))

        p.drawPolyline(polygon)
        self._end(p)

    def fastGlyph(self, state: FastGlyph):
        LOG.debug(state)
        if state.glyph:
            glyph = GlyphEntry(state.glyph)
            self.glyphs.add(state.cacheId, state.cacheIndex, glyph)
        else:
            glyph = self.glyphs.get(state.cacheId, state.cacheIndex)

        if not glyph:
            return  # Ignore unknown glyph.

        self._process_glyph(GlyphContext(state), bytes([state.cacheIndex, 0]))

    def ellipseSc(self, state: EllipseSc):
        LOG.debug(state)
        p = self._paint(self.surface)
        set_rop2(state.rop2, p)
        p.setBrush(QBrush(rgb_to_qcolor(state.brushColor)))

        if not state.fillMode:
            # This probably doesn't have the expected behavior.
            p.setBackgroundMode(Qt.TransparentMode)

        w = state.right - state.left
        h = state.bottom - state.top
        p.drawEllipse(state.left, state.top, w, h)
        self._end(p)

    def ellipseCb(self, state: EllipseCb):
        LOG.debug(state)
        p = self._paint(self.surface)
        self._brush(state.brush)
        p.brush().setColor(rgb_to_qcolor(state.fg))
        p.setBackground(QBrush(rgb_to_qcolor(state.bg)))
        set_rop2(state.rop2, p)

        if not state.fillMode:
            # This probably doesn't have the expected behavior.
            p.setBackgroundMode(Qt.TransparentMode)

        w = state.right - state.left
        h = state.bottom - state.top
        p.drawEllipse(state.left, state.top, w, h)

    def glyphIndex(self, state: GlyphIndex):
        LOG.debug(state)
        self._process_glyph(GlyphContext(state), state.data)

    # Secondary Handlers
    def cacheBitmapV1(self, state: CacheBitmapV1):
        LOG.debug(state)
        bmp = RDPBitmapToQtImage(state.width, state.height,  state.bpp, True, state.data)
        self.bitmaps.add(state.cacheId, state.cacheIndex, bmp)

    def cacheBitmapV2(self, state: CacheBitmapV2):
        LOG.debug(state)
        bmp = RDPBitmapToQtImage(state.width, state.height,  state.bpp, True, state.data)
        self.bitmaps.add(state.cacheId, state.cacheIndex, bmp)

    def cacheBitmapV3(self, state: CacheBitmapV3):
        LOG.debug(state)
        bmp = RDPBitmapToQtImage(state.width, state.height,  state.bpp, True, state.data)
        self.bitmaps.add(state.cacheId, state.cacheIndex, bmp)

    def cacheColorTable(self, state: CacheColorTable):
        LOG.debug(state)
        self.palettes.add(state.cacheIndex, state.colors)

    def cacheGlyph(self, state: CacheGlyph):
        LOG.debug(state)
        for g in state.glyphs:
            glyph = GlyphEntry(g)
            self.glyphs.add(state.cacheId, g.cacheIndex, glyph)

    def cacheBrush(self, state: CacheBrush):  # FIXME: Maybe should not be expanding brush pixels too?
        LOG.debug(state)
        # There's probably a more efficient than using QImage
        i = QImage(state.data, state.width, state.height, _fmt[state.bpp])
        pm = QPixmap.fromImageInPlace(i)
        self.brushes.add(state.cacheIndex, QBrush(pm))

    # Alternate Secondary Handlers
    def frameMarker(self, state: FrameMarker):
        LOG.debug(state)
        if state.action == 0x01:  # END
            # self.dc.notifyImage(0, 0, self.screen, self.dc.width(), self.dc.height())
            self.dc.update()

    def createOffscreenBitmap(self, state: CreateOffscreenBitmap):
        LOG.debug(state)
        bmp = QImage(state.cx, state.cy, QImage.Format_ARGB32_Premultiplied)
        bmp.fill(0)

        self.surfaces[state.id] = bmp

        for d in state.delete:
            if d in self.surfaces:
                del self.surfaces[d]

    def switchSurface(self, state: SwitchSurface):
        LOG.debug(state)
        if state.id not in self.surfaces:
            # Appendix A - <5> Section 2.2.2.2.1.3.3
            LOG.warning('Request for uninitialized surface: %d', state.id)
            self.activeSurface = SUBSTITUTE_SURFACE
            return
        self.activeSurface = state.id

    def createNineGridBitmap(self, state: CreateNineGridBitmap):
        LOG.debug(state)
        self._unimplemented()

    def streamBitmapFirst(self, state: StreamBitmapFirst):
        LOG.debug(state)
        self._unimplemented()

    def streamBitmapNext(self, state: StreamBitmapNext):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusFirst(self, state: GdiPlusFirst):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusNext(self, state: GdiPlusNext):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusEnd(self, state: GdiPlusEnd):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusCacheFirst(self, state: GdiPlusCacheFirst):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusCacheNext(self, state: GdiPlusCacheNext):
        LOG.debug(state)
        self._unimplemented()

    def drawGdiPlusCacheEnd(self, state: GdiPlusCacheEnd):
        LOG.debug(state)
        self._unimplemented()

    def _process_glyph(self, ctx: 'GlyphContext', data: bytes):
        """Process glyph rendering instructions."""
        # 2.2.2.2.1.1.2.14
        p = self._paint(self.surface)

        cid = ctx.cacheId

        i = 0
        while i < len(data):
            instr = data[i]
            i += 1

            if instr == GLYPH_FRAGMENT_USE:
                fid = data[i]
                i += 1
                fragment = self.glyphs.getFragment(cid, fid)
                n = 0
                size = len(fragment)

                while n < size:
                    idx = fragment[n]
                    n += 1

                    glyph = self.glyphs.get(cid, idx)

                    n = ctx.offset(n, fragment)
                    ctx.draw(glyph, p)

                # Skip for now, seems to always be 0.
                if ctx.ulCharInc == 0 and not (ctx.flAccel & SO_CHAR_INC_EQUAL_BM_BASE):
                    i += 2 if data[i] == 0x80 else 1

            elif instr == GLYPH_FRAGMENT_ADD:
                fid = data[i]
                size = data[i + 1]
                fragment = data[(i - size - 1):size]
                i += 2
                self.glyphs.addFragment(cid, fid, fragment)
            else:
                glyph = self.glyphs.get(cid, instr)
                i = ctx.offset(i, data)
                ctx.draw(glyph, p)
        self._end(p)

    def _unimplemented(self):
        if not self._warned:
            LOG.warning('One or more unimplemented drawing orders called! Expect lossy rendering.')
            self._warned = True


class GlyphContext:
    """
    Glyph processing context.

    This is an internal class to store mutable glyph rendering state
    during the rendering operations.
    """

    def __init__(self,  source: typing.Union[GlyphIndex, FastIndex, FastGlyph]):
        self.cacheId = source.cacheId

        self.bg = source.bg
        self.fg = source.fg

        self.opLeft = source.opLeft
        self.opTop = source.opTop
        self.opRight = source.opRight
        self.opBottom = source.opBottom

        self.bkLeft = source.bkLeft
        self.bkTop = source.bkTop
        self.bkRight = source.bkRight
        self.bkBottom = source.bkBottom

        self.x = source.x
        self.y = source.y

        self.flAccel = source.flAccel
        self.ulCharInc = source.ulCharInc
        self.fOpRedundant = False

        if not isinstance(source, GlyphIndex):
            if self.opBottom == GLYPH_SPECIAL_PROCESSING:
                flags = self.opTop & 0x0F
                if flags & OPRECT_BOTTOM_ABSENT:
                    self.opBottom = source.bkBottom
                elif flags & OPRECT_RIGHT_ABSENT:
                    self.opRight = source.bkRight
                elif flags & OPRECT_TOP_ABSENT:
                    self.opTop = source.bkTop
                elif flags & OPRECT_LEFT_ABSENT:
                    self.opLeft = source.bkLeft

            if self.opLeft == 0:
                self.opLeft = source.bkLeft
            if self.opRight == 0:
                self.opRight == source.bkRight

            # Adjust x and y
            if self.x == GLYPH_SPECIAL_PROCESSING:
                self.x = source.bkLeft
            if self.y == GLYPH_SPECIAL_PROCESSING:
                self.y = source.bkTop
        else:
            self.fOpRedundant = source.fOpRedundant

        self.bkWidth = source.bkRight - source.bkLeft + 1 if source.bkRight > source.bkLeft else 0
        self.bkHeight = source.bkBottom - source.bkTop + 1 if source.bkBottom > source.bkTop else 0

        self.opWidth = self.opRight - self.opLeft + 1 if self.opRight > self.opLeft else 0
        self.opHeight = self.opBottom - self.opTop + 1 if self.opBottom > self.opTop else 0

    def offset(self, index: int, data: bytes) -> int:
        """Read the offset of the next glyph and return the new instruction index."""
        if self.ulCharInc == 0 and not (self.flAccel & SO_CHAR_INC_EQUAL_BM_BASE):
            offset = data[index]
            index += 1
            if offset & 0x80:  # 2 byte offset.
                offset = data[index]
                offset |= data[index + 1]
                index += 2
            if self.flAccel & SO_VERTICAL:
                self.y += offset
            if self.flAccel & SO_HORIZONTAL:
                self.x += offset
        return index

    def draw(self, glyph: GlyphEntry, p: QPainter):
        """Render a glyph using the given painter."""
        # Adjust the glyph coordinates to center it on origin
        x = self.x + glyph.x
        y = self.y + glyph.y

        if not self.fOpRedundant:
            p.fillRect(x, y, glyph.w, glyph.h, rgb_to_qcolor(self.fg))

        p.setBrush(QBrush(rgb_to_qcolor(self.bg), glyph.bitmap))
        p.setBrushOrigin(x, y)
        p.drawRect(x, y, glyph.w, glyph.h)

        if self.flAccel & SO_CHAR_INC_EQUAL_BM_BASE:
            self.x += glyph.w


# Map brush styles to Qt brush style
_bs = {
    BrushStyle.SOLID: Qt.SolidPattern,
    BrushStyle.NULL: Qt.NoBrush,
    BrushStyle.HATCHED: None,  # Must lookup in _hs.
    BrushStyle.PATTERN: Qt.TexturePattern,
}

_hs = {
    HatchStyle.HORIZONTAL: Qt.HorPattern,
    HatchStyle.VERTICAL: Qt.VerPattern,
    HatchStyle.FDIAGONAL: Qt.FDiagPattern,
    HatchStyle.BDIAGNOAL: Qt.BDiagPattern,
    HatchStyle.CROSS: Qt.CrossPattern,
    HatchStyle.DIAGCROSS: Qt.DiagCrossPattern,
}

# Pixel format lookup table.
_fmt = {
    1: QImage.Format_Mono,
    8: QImage.Format_Grayscale8,
    16: QImage.Format_RGB16,
    24: QImage.Format_RGB888,
    32: QImage.Format_RGB32,
}

# Polygon fill mode lookup table
_fill = [
    None,  # 0x00
    Qt.OddEvenFill,  # 0x01: ALTERNATE
    Qt.WindingFill   # 0x02: WINDING

]
