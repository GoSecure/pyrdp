#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
# Copyright (c) 2018-2023 GoSecure Inc.
#
# This file is part of PyRDP.
# This file was part of rdpy.
#
# PyRDP is licensed under the GPLv3 or later.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Qt specific code

QRemoteDesktop is a widget use for render in rdpy
"""

import rle
from io import BytesIO

from PySide6.QtCore import QEvent, QPoint, Qt, Signal
from PySide6.QtGui import QColor, QImage, QTransform, QPainter
from PySide6.QtWidgets import QWidget

from pyrdp.logging import log
from pyrdp.player.ImageHandler import ImageHandler


def RDPBitmapToQtImage(width: int, height: int, bitsPerPixel: int, isCompressed: bool, data: bytes):
    """
    Bitmap transformation to Qt object
    :param width: width of bitmap
    :param height: height of bitmap
    :param bitsPerPixel: number of bit per pixel
    :param isCompressed: use RLE compression
    :param data: bitmap data
    """
    image = None
    buf = None

    if bitsPerPixel == 15:
        if isCompressed:
            buf = rle.bitmap_decompress(data, width, height, 2)
            image = QImage(buf, width, height, QImage.Format_RGB555)
        else:
            buf = data
            image = QImage(buf, width, height, QImage.Format_RGB555).transformed(QTransform(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))

    elif bitsPerPixel == 16:
        if isCompressed:
            buf = rle.bitmap_decompress(data, width, height, 2)
            image = QImage(buf, width, height, QImage.Format_RGB16)
        else:
            buf = data
            image = QImage(buf, width, height, QImage.Format_RGB16).transformed(QTransform(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))

    elif bitsPerPixel == 24:
        if isCompressed:
            buf = rle.bitmap_decompress(data, width, height, 3)

            # This is a ugly patch because there is a bug in the 24bpp decompression in rle.c
            # where the red and the blue colors are inverted. Fixing this in python causes a performance
            # issue, but at least it shows the good colors.
            buf2 = BytesIO(buf)
            while buf2.tell() < len(buf2.getvalue()):
                pixel = buf2.read(3)
                buf[buf2.tell() - 3] = pixel[2]
                buf[buf2.tell() - 1] = pixel[0]

            image = QImage(buf, width, height, QImage.Format_RGB888)
        else:
            buf = data
            image = QImage(buf, width, height, QImage.Format_RGB888).transformed(QTransform(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))

    elif bitsPerPixel == 32:
        if isCompressed:
            buf = rle.bitmap_decompress(data, width, height, 4)
            image = QImage(buf, width, height, QImage.Format_RGB32)
        else:
            buf = data
            image = QImage(buf, width, height, QImage.Format_RGB32).transformed(QTransform(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    elif bitsPerPixel == 8:
        if isCompressed:
            _buf = rle.bitmap_decompress(data, width, height, 1)
            buf = convert8bppTo16bpp(_buf)
            image = QImage(buf, width, height, QImage.Format_RGB16)
        else:
            buf = convert8bppTo16bpp(data)
            image = QImage(buf, width, height, QImage.Format_RGB16).transformed(QTransform(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    else:
        log.error("Receive image in bad format")
        image = QImage(width, height, QImage.Format_RGB32)
    return (image, buf)


def convert8bppTo16bpp(buf: bytes):
    r"""
    WARNING: The actual 8bpp images work by using a color palette, which this method does not use.
    This method instead tries to transform indices into colors. This results in a weird looking image,
    but it can still be useful to see whats happening ¯\_(ツ)_/¯
    """
    buf2 = bytearray(len(buf) * 2)
    i = 0
    for pixel in buf:
        r = (pixel & 0b11000000) >> 6
        g = (pixel & 0b00111000) >> 3
        b = (pixel & 0b00000111) >> 0
        buf2[i] = (b << 3)
        buf2[i + 1] = (g << 0) | (r << 5)
        i += 2

    return buf2


class QRemoteDesktop(QWidget, ImageHandler):
    """
    Qt RDP display widget. It is the widget directly responsible to display the "screen" of the
    client in the RDP session being shown/replayed.
    """

    # This signal can be used by other objects to run code on the main thread. The argument is a callable.
    mainThreadHook = Signal(object)

    def __init__(self, width: int, height: int, parent: QWidget = None):
        """
        :param width: width of widget
        :param height: height of widget
        :param parent: parent widget
        """
        super().__init__(parent)

        self.ratio = 1
        """ Scale factor used to render the RDP session on the player."""

        self.sessionWidth = width
        self.sessionHeight = height

        self.scaleToWindow = False

        # Buffer image
        self._buffer: QImage = QImage(width, height, QImage.Format_ARGB32_Premultiplied)

        # Set correct size
        self.resize(width, height)
        # Bind mouse event
        self.setMouseTracking(True)
        self.mouseX = width // 2
        self.mouseY = height // 2

        self.mainThreadHook.connect(self.runOnMainThread)

    def notifyImage(self, x: int, y: int, qimage: QImage, width: int, height: int):
        """
        Draw an image on the buffer.
        :param x: x position of the new image
        :param y: y position of the new image
        :param qimage: new QImage
        :param width: width of the new image
        :param height: height of the new image
        """

        # Fill buffer image
        qp = QPainter(self._buffer)
        qp.drawImage(x, y, qimage, 0, 0, width, height)

        # Force update
        self.update()

    def resize(self, width: int, height: int):
        """
        Resize the image buffer. This is called when the clientData is parsed, which
        contains the screen size used for the connection.
        :param width: new width of the replay client's screen
        :param height: new height of the replay client's screen.
        """
        self._buffer = QImage(width, height, QImage.Format_ARGB32_Premultiplied)
        self.sessionWidth = width
        self.sessionHeight = height
        self._updateWidgetSize()

    def update(self):
        QWidget.update(self)

    @property
    def screen(self):
        return self._buffer

    def runOnMainThread(self, target: callable):
        target()

    def setMousePosition(self, x: int, y: int):
        self.mouseX = x
        self.mouseY = y
        self.update()

    def scale(self, scale):
        """
        Rescale the current widget to a percentage of the height of the RDP session.
        :param scale: Ex: 0.5 for 50% height and 50% width.
        """
        self.ratio = scale
        self._updateWidgetSize()

    def _updateWidgetSize(self):
        """
        Size the widget according to if we are scaled or not
        """
        if self.scaleToWindow:
            # resize widget to parent size: will hide scrollbars
            super().resize(self.parent().size())
        else:
            # resize widget to session size: will show scrollbars if required
            super().resize(self.sessionWidth, self.sessionHeight)

    def setScaleToWindow(self, status):
        self.scaleToWindow = status > 0

    def paintEvent(self, e: QEvent):
        """
        Call when Qt renderer engine estimate that is needed
        :param e: the event
        """
        ratio = self.ratio if self.scaleToWindow else 1
        qp = QPainter(self)
        qp.drawImage(0, 0, self._buffer.scaled(self.sessionWidth * ratio, self.sessionHeight * ratio, aspectMode=Qt.KeepAspectRatio))
        qp.setBrush(QColor.fromRgb(255, 255, 0, 180))
        qp.drawEllipse(QPoint(self.mouseX * ratio, self.mouseY * ratio), 5, 5)

    def clear(self):
        self._buffer = QImage(self._buffer.width(), self._buffer.height(), QImage.Format_ARGB32_Premultiplied)
        self.setMousePosition(self._buffer.width() // 2, self._buffer.height() // 2)
        self.repaint()
