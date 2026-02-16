#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2023 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import CapabilityType, PlayerPDUType
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

    def __init__(self, filename: str, fps=10, progress=None, idle_skip=0):
        """
        Construct an event handler that outputs to an Mp4 file.

        :param filename: The output file to write to.
        :param fps: The frame rate (10 recommended for forensic captures).
        :param progress: An optional callback (sig: `() -> ()`) whenever a frame is muxed.
        :param idle_skip: Seconds of inactivity before compressing idle gaps (0 = disabled).
        """
        self.filename = filename
        # faststart moves the moov atom to the front for seekable playback.
        self.mp4 = f = av.open(filename, 'w', options={'movflags': 'faststart'})
        self.stream = f.add_stream('h264', rate=fps)
        self.stream.pix_fmt = 'yuv420p'
        self.stream.options = {'preset': 'ultrafast'}
        self.stream.gop_size = fps * 5  # Keyframe every 5s for seeking
        self.progress = progress
        self.padW = 0
        self.padH = 0
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
        # Idle skip: based on user input (keyboard/mouse), not screen changes
        self.idle_skip_ms = idle_skip * 1000 if idle_skip > 0 else 0
        self.total_skipped_ms = 0
        self.lastInputTimestamp = None
        self._in_idle = False
        self._idle_enter_ts = None
        self._last_idle_frame_ts = None

        super().__init__(MP4Image())

    def onPDUReceived(self, pdu: PlayerPDU):
        super().onPDUReceived(pdu)

        # Make sure the rendering surface has been created.
        if self.imageHandler.screen is None:
            return

        ts = pdu.timestamp
        self.timestamp = ts
        is_input = pdu.header == PlayerPDUType.FAST_PATH_INPUT

        # Track user input for idle detection
        if is_input:
            self.lastInputTimestamp = ts

        if self.prevTimestamp is None:
            # First PDU: assume active at start
            if self.lastInputTimestamp is None:
                self.lastInputTimestamp = ts
            if self.dirty:
                self.writeFrame()
                self.dirty = False
            self.prevTimestamp = ts
            return

        # Check input-idle state
        input_idle_ms = ts - self.lastInputTimestamp
        now_idle = self.idle_skip_ms > 0 and input_idle_ms > self.idle_skip_ms

        if now_idle and not self._in_idle:
            # Entering idle: encode last dirty frame, then freeze
            self._in_idle = True
            self._idle_enter_ts = ts
            self._last_idle_frame_ts = ts
            if self.dirty:
                self.writeFrame()
                self.dirty = False

        if self._in_idle and not now_idle:
            # Exiting idle (input resumed)
            self._in_idle = False
            self.total_skipped_ms += ts - self._idle_enter_ts
            self.pts += self.fps  # 1s pause in output
            self.prevTimestamp = ts
            return

        if self._in_idle:
            # During idle: encode 1 frame every 10s to capture screen state
            if self.dirty and (ts - self._last_idle_frame_ts) >= 10000:
                self.writeFrame()
                self.dirty = False
                self._last_idle_frame_ts = ts
            else:
                self.dirty = False
            self.prevTimestamp = ts
            return

        # Normal (non-idle) processing
        dt = ts - self.prevTimestamp  # ms
        nframes = (dt // self.delta)

        if nframes > 0:
            # Frame boundary crossed. Encode one frame if surface changed,
            # then advance PTS to cover any remaining idle gap.
            if self.dirty:
                self.writeFrame()
                self.dirty = False
                nframes -= 1  # One frame was just encoded

            # True gap (no PDUs at all): compress
            gap_threshold = int(self.idle_skip_ms / self.delta) if self.idle_skip_ms > 0 else 0
            if gap_threshold > 0 and nframes > gap_threshold:
                self.total_skipped_ms += nframes * self.delta
                nframes = self.fps  # Replace gap with 1s pause

            # Skip remaining frames (player holds last frame)
            self.pts += nframes
            self.prevTimestamp = ts

    def cleanup(self):
        # Close out idle state if capture ends while idle
        if self._in_idle and self._idle_enter_ts and self.timestamp:
            self.total_skipped_ms += self.timestamp - self._idle_enter_ts
            self._in_idle = False

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

        if self.total_skipped_ms > 0:
            skipped_s = self.total_skipped_ms / 1000
            m, s = divmod(int(skipped_s), 60)
            h, m = divmod(m, 60)
            self.log.info('Total idle time skipped: %dh %dm %ds (%.1fs)', h, m, s, skipped_s)

        self.log.info('Export completed.')
        self.mp4.close()

    def onMousePosition(self, x, y):
        self.mouse = (x, y)
        super().onMousePosition(x, y)

    def onCapabilities(self, caps):
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)

        # H264 requires even dimensions. Pad by 1px instead of scaling
        # every frame (scaling 2556x929 is ~6ms per frame).
        self.padW = w % 2
        self.padH = h % 2
        self.stream.width = w + self.padW
        self.stream.height = h + self.padH

        self.imageHandler.resize(w, h)
        super().onCapabilities(caps)

    def onFinishRender(self):
        # Mark surface as changed. The frame will be encoded at the next
        # frame boundary in onPDUReceived, batching multiple renders.
        self.dirty = True

    def writeFrame(self):
        w = self.stream.width
        h = self.stream.height

        if self.padW or self.padH:
            # Create even-sized surface and draw screen into it (avoids full scale)
            surface = QImage(w, h, QImage.Format_ARGB32_Premultiplied)
            p = QPainter(surface)
            p.drawImage(0, 0, self.imageHandler.screen)
        else:
            surface = self.imageHandler.screen.copy()
            p = QPainter(surface)

        # Draw the mouse pointer.
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
