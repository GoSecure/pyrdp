#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import BitmapFlags, CapabilityType
from pyrdp.pdu import BitmapUpdateData, PlayerPDU
from pyrdp.player.RenderingEventHandler import RenderingEventHandler
from pyrdp.ui import RDPBitmapToQtImage

import logging

import av
from PIL import ImageQt
from PySide2.QtGui import QImage, QPainter, QColor


class Mp4Sink:
    def __init__(self):
        self.screen: QImage = None

    def notifyImage(self, x: int, y: int, img: QImage, w: int, h: int):
        p = QPainter(self.screen)
        p.drawImage(x, y, img, 0, 0, w, h)

    def update(self):
        pass

    def resize(self, w: int, h: int):
        self.screen = QImage(w, h, QImage.Format_RGB888)


class Mp4EventHandler(RenderingEventHandler):

    def __init__(self, filename: str, fps=30):
        """Construct an event handler that outputs to an Mp4 file."""

        self.sink = Mp4Sink()
        self.filename = filename
        self.mp4 = f = av.open(filename, 'w')
        self.stream = f.add_stream('h264', rate=fps)
        self.stream.pix_fmt = 'yuv420p'
        self.scale = False
        self.mouse = (0, 0)
        self.fps = fps
        self.delta = 1000 // fps  # ms per frame
        self.log = logging.getLogger(__name__)
        self.log.info('Begin MP4 export to %s: %d FPS', filename)
        self.timestamp = self.prevTimestamp = None

        super().__init__(self.sink)

    def onPDUReceived(self, pdu: PlayerPDU):
        super().onPDUReceived(pdu)

        # Make sure the rendering surface has been created.
        if self.sink.screen is None:
            return

        ts = pdu.timestamp
        self.timestamp = ts

        if self.prevTimestamp is None:
            dt = self.delta
        else:
            dt = self.timestamp - self.prevTimestamp  # ms
        nframes = (dt // self.delta)
        if nframes > 0:
            for _ in range(nframes):
                self._writeFrame(self.surface)
            self.prevTimestamp = ts
            self.log.debug('Rendered %d still frame(s)', nframes)

    def cleanup(self):
        # Add one second worth of padding so that the video doesn't end too abruptly.
        for _ in range(self.fps):
            self._writeFrame(self.surface)

        self.log.info('Flushing to disk: %s', self.filename)
        for pkt in self.stream.encode():
            self.mp4.mux(pkt)
        self.log.info('Export completed.')

        self.mp4.close()

    def onMousePosition(self, x, y):
        self.mouse = (x, y)
        super().onMousePosition(x, y)

    def onCapabilities(self, caps):
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)
        self.sink.resize(w, h)

        if w % 2 != 0:
            self.scale = True
            w += 1
        if h % 2 != 0:
            self.scale = True
            h += 1

        self.stream.width = w
        self.stream.height = h

    def onBeginRender(self):
        pass

    def onFinishRender(self):
        # When the screen is updated, always write a frame.
        self.prevTimestamp = self.timestamp
        self._writeFrame(self.surface)

    def _writeFrame(self, surface: QImage):
        w = self.stream.width
        h = self.stream.height
        surface = self.sink.screen.scaled(w, h) if self.scale else self.sink.screen
        frame = av.VideoFrame.from_image(ImageQt.fromqimage(surface))

        # Draw the mouse pointer.
        # NOTE: We could render mouse clicks by changing the color of the brush.
        p = QPainter(surface)
        p.setBrush(QColor.fromRgb(255, 255, 0, 180))
        (x, y) = self.mouse
        p.drawEllipse(x, y, 5, 5)
        p.end()

        # Output frame.
        frame = av.VideoFrame.from_image(ImageQt.fromqimage(surface))
        for packet in self.stream.encode(frame):
            self.mp4.mux(packet)
