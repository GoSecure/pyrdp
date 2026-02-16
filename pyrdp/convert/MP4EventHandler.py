#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2023 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import CapabilityType
from pyrdp.pdu import PlayerPDU
from pyrdp.player.ImageHandler import ImageHandler
from pyrdp.player.RenderingEventHandler import RenderingEventHandler

import logging

import av
import qimage2ndarray
from PySide6.QtGui import QImage, QPainter, QColor


class MP4Image(ImageHandler):
    """A QRemoteDesktop Mock."""
    def __init__(self):
        self.buffer: QImage = None

    def notifyImage(self, x: int, y: int, img: QImage, width: int, height: int):
        p = QPainter(self.buffer)
        p.drawImage(x, y, img, 0, 0, width, height)

    def resize(self, width: int, height: int):
        self.buffer = QImage(width, height, QImage.Format_ARGB32_Premultiplied)

    def update(self):
        pass

    @property
    def screen(self) -> QImage:
        return self.buffer


class MP4EventHandler(RenderingEventHandler):

    def __init__(self, filename: str, fps=10, progress=None):
        """
        Construct an event handler that outputs to an Mp4 file.

        :param filename: The output file to write to.
        :param fps: The frame rate (10 recommended for forensic captures).
        :param progress: An optional callback (sig: `() -> ()`) whenever a frame is muxed.
        """
        self.filename = filename
        # faststart moves the moov atom to the front for seekable playback.
        self.mp4 = f = av.open(filename, 'w', options={'movflags': 'faststart'})
        self.stream = f.add_stream('h264', rate=fps)
        self.stream.pix_fmt = 'yuv420p'
        self.stream.options = {'preset': 'ultrafast'}
        self.stream.gop_size = fps * 5  # Keyframe every 5s for seeking
        self.progress = progress
        self.scale = False
        self.mouse = (0, 0)
        self.fps = fps
        self.delta = 1000 // fps  # ms per frame
        self.log = logging.getLogger(__name__)
        self.log.info('Begin MP4 export to %s: %d FPS', filename, fps)
        self.timestamp = self.prevTimestamp = None
        # PTS counter in stream time_base units for correct playback timing
        self.pts = 0
        # Track whether the surface has changed since the last encoded frame
        self.dirty = False

        super().__init__(MP4Image())

    def onPDUReceived(self, pdu: PlayerPDU):
        super().onPDUReceived(pdu)

        # Make sure the rendering surface has been created.
        if self.imageHandler.screen is None:
            return

        ts = pdu.timestamp
        self.timestamp = ts

        if self.prevTimestamp is None:
            # First PDU: encode if surface was rendered
            if self.dirty:
                self.writeFrame()
                self.dirty = False
            self.prevTimestamp = ts
            return

        dt = self.timestamp - self.prevTimestamp  # ms
        nframes = (dt // self.delta)

        if nframes > 0:
            # Frame boundary crossed. Encode one frame if surface changed,
            # then advance PTS to cover any remaining idle gap.
            if self.dirty:
                self.writeFrame()
                self.dirty = False
                nframes -= 1  # One frame was just encoded
            # Skip remaining frames (player holds last frame)
            self.pts += nframes
            self.prevTimestamp = ts

    def cleanup(self):
        # Flush any pending dirty frame
        if self.dirty:
            self.writeFrame()
            self.dirty = False

        # Add one second worth of padding so that the video doesn't end too abruptly.
        for _ in range(self.fps):
            self.writeFrame()

        self.log.info('Flushing to disk: %s', self.filename)
        for pkt in self.stream.encode():
            if self.progress:
                self.progress()
            self.mp4.mux(pkt)
        self.log.info('Export completed.')
        self.mp4.close()

    def onMousePosition(self, x, y):
        self.mouse = (x, y)
        super().onMousePosition(x, y)

    def onCapabilities(self, caps):
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)
        self.imageHandler.resize(w, h)

        if w % 2 != 0:
            self.scale = True
            w += 1
        if h % 2 != 0:
            self.scale = True
            h += 1

        self.stream.width = w
        self.stream.height = h

        super().onCapabilities(caps)

    def onFinishRender(self):
        # Mark surface as changed. The frame will be encoded at the next
        # frame boundary in onPDUReceived, batching multiple renders.
        self.dirty = True

    def writeFrame(self):
        w = self.stream.width
        h = self.stream.height
        surface = self.imageHandler.screen.scaled(w, h) if self.scale else self.imageHandler.screen.copy()

        # Draw the mouse pointer. Render mouse clicks?
        p = QPainter(surface)
        p.setBrush(QColor.fromRgb(255, 255, 0, 180))
        (x, y) = self.mouse
        p.drawEllipse(x, y, 5, 5)
        p.end()

        # Output frame with explicit PTS for correct playback timing.
        frame = av.VideoFrame.from_ndarray(qimage2ndarray.rgb_view(surface))
        frame.pts = self.pts
        self.pts += 1
        for packet in self.stream.encode(frame):
            if self.progress:
                self.progress()
            self.mp4.mux(packet)
