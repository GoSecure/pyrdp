#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
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

from PyQt4 import QtGui, Qt, QtCore

import rle

from PyQt4.QtCore import QPoint
from PyQt4.QtGui import QColor

import rdpy.core.log as log


def RDPBitmapToQtImage(width, height, bitsPerPixel, isCompress, data):
    """
    @summary: Bitmap transformation to Qt object
    @param width: width of bitmap
    @param height: height of bitmap
    @param bitsPerPixel: number of bit per pixel
    @param isCompress: use RLE compression
    @param data: bitmap data
    """
    image = None
    #allocate
    
    if bitsPerPixel == 15:
        if isCompress:
            buf = bytearray(width * height * 2)
            rle.bitmap_decompress(buf, width, height, data, 2)
            image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB555)
        else:
            image = QtGui.QImage(data, width, height, QtGui.QImage.Format_RGB555).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    
    elif bitsPerPixel == 16:
        if isCompress:
            buf = bytearray(width * height * 2)
            rle.bitmap_decompress(buf, width, height, data, 2)
            image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB16)
        else:
            image = QtGui.QImage(data, width, height, QtGui.QImage.Format_RGB16).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    
    elif bitsPerPixel == 24:
        if isCompress:
            buf = bytearray(width * height * 3)
            rle.bitmap_decompress(buf, width, height, data, 3)
            image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB888)
        else:
            image = QtGui.QImage(data, width, height, QtGui.QImage.Format_RGB888).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
            
    elif bitsPerPixel == 32:
        if isCompress:
            buf = bytearray(width * height * 4)
            rle.bitmap_decompress(buf, width, height, data, 4)
            image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB32)
        else:
            image = QtGui.QImage(data, width, height, QtGui.QImage.Format_RGB32).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    else:
        log.error("Receive image in bad format")
        image = QtGui.QImage(width, height, QtGui.QImage.Format_RGB32)
    return image



class QRemoteDesktop(QtGui.QWidget):
    """
    @summary: Qt display widget
    """
    def __init__(self, width, height, adaptor):
        """
        @param adaptor: {QAdaptor}
        @param width: {int} width of widget
        @param height: {int} height of widget
        """
        super(QRemoteDesktop, self).__init__()
        #adaptor use to send
        self._adaptor = adaptor
        #set correct size
        self.resize(width, height)
        #bind mouse event
        self.setMouseTracking(True)
        #buffer image
        self._buffer = QtGui.QImage(width, height, QtGui.QImage.Format_RGB32)
        self.mouseX = width / 2
        self.mouseY = height / 2


    def notifyImage(self, x, y, qimage, width, height):
        """
        @summary: Function call from QAdaptor
        @param x: x position of new image
        @param y: y position of new image
        @param qimage: new QImage
        """
        #fill buffer image
        with QtGui.QPainter(self._buffer) as qp:
            qp.drawImage(x, y, qimage, 0, 0, width, height)
        #force update
        self.update()

    def setMousePosition(self, x, y):
        self.mouseX = x
        self.mouseY = y
        self.update()

    def resize(self, width, height):
        """
        @summary: override resize function
        @param width: {int} width of widget
        @param height: {int} height of widget
        """
        self._buffer = QtGui.QImage(width, height, QtGui.QImage.Format_RGB32)
        QtGui.QWidget.resize(self, width, height)
        
    def paintEvent(self, e):
        """
        @summary: Call when Qt renderer engine estimate that is needed
        @param e: QEvent
        """
        #draw in widget
        with QtGui.QPainter(self) as qp:
            qp.drawImage(0, 0, self._buffer)
            qp.setBrush(QColor.fromRgb(255, 255, 0, 180))
            qp.drawEllipse(QPoint(self.mouseX, self.mouseY), 5, 5)
        
    def mouseMoveEvent(self, event):
        """
        @summary: Call when mouse move
        @param event: QMouseEvent
        """
        self._adaptor.sendMouseEvent(event, False)
        
    def mousePressEvent(self, event):
        """
        @summary: Call when button mouse is pressed
        @param event: QMouseEvent
        """
        self._adaptor.sendMouseEvent(event, True)
        
    def mouseReleaseEvent(self, event):
        """
        @summary: Call when button mouse is released
        @param event: QMouseEvent
        """
        self._adaptor.sendMouseEvent(event, False)
        
    def keyPressEvent(self, event):
        """
        @summary: Call when button key is pressed
        @param event: QKeyEvent
        """
        self._adaptor.sendKeyEvent(event, True)
        
    def keyReleaseEvent(self, event):
        """
        @summary: Call when button key is released
        @param event: QKeyEvent
        """
        self._adaptor.sendKeyEvent(event, False)
        
    def wheelEvent(self, event):
        """
        @summary: Call on wheel event
        @param event:    QWheelEvent
        """
        self._adaptor.sendWheelEvent(event)
        
    def closeEvent(self, event):
        """
        @summary: Call when widget is closed
        @param event: QCloseEvent
        """
        self._adaptor.closeEvent(event)

    def clear(self):
        self._buffer = QtGui.QImage(self._buffer.width(), self._buffer.height(), QtGui.QImage.Format_RGB32)
        self.repaint()