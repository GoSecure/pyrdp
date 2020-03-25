#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import BitmapFlags, CapabilityType
from pyrdp.pdu import BitmapUpdateData
from pyrdp.player.RenderingEventHandler import RenderingEventHandler
from pyrdp.ui import RDPBitmapToQtImage

import av
from PIL import ImageQt
from PySide2.QtGui import QImage, QPainter


FPS = 24


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

    def __init__(self, filename: str):
        """Construct an event handler that outputs to an Mp4 file."""

        self.sink = Mp4Sink()
        self.mp4 = f = av.open(filename, 'w')
        self.stream = f.add_stream('h264', rate=FPS)
        self.stream.pix_fmt = 'yuv420p'
        self.scale = False
        self.mouse = (0, 0)

        super().__init__(self.sink)

    def cleanup(self):
        # FIXME: Need to flush here to avoid hanging.
        self.mp4.close()

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
        # Write to the mp4 container.
        w = self.stream.width
        h = self.stream.height

        surface = self.sink.screen.scaled(w, h) if self.scale else self.sink.screen
        frame = av.VideoFrame.from_image(ImageQt.fromqimage(surface))

        for packet in self.stream.encode(frame):
            self.mp4.mux(packet)
            # TODO: Add progress callback.
