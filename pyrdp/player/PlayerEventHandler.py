#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtCore import QObject
from PySide2.QtGui import QTextCursor
from PySide2.QtWidgets import QTextEdit

from pyrdp.pdu import PlayerPDU
from pyrdp.enum import CapabilityType
from pyrdp.ui import QRemoteDesktop
from pyrdp.player.RenderingEventHandler import RenderingEventHandler
from pyrdp.logging import log


class PlayerEventHandler(QObject, RenderingEventHandler):
    """
    Qt Rendering Sink.

    This class handles the video pipeline by rendering to a Qt widget.
    """

    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit):
        QObject.__init__(self)
        RenderingEventHandler.__init__(self, viewer)

        self.viewer = viewer
        self.text = text

    def onPDUReceived(self, pdu: PlayerPDU, isMainThread=False):
        # Ensure we are on the main thread.
        if not isMainThread:
            self.viewer.mainThreadHook.emit(lambda: self.onPDUReceived(pdu, True))
            return

        log.debug("Received %(pdu)s", {"pdu": pdu})

        # Call the parent PDU Received method.
        super().onPDUReceived(pdu)

    def onCapabilities(self, caps):
        # Set viewport's initial size.
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)
        self.viewer.resize(w, h)

        super().onCapabilities(caps)

    def onMousePosition(self, x: int, y: int):
        self.viewer.setMousePosition(x, y)

    def writeText(self, text: str):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText(text.rstrip("\x00"))

    def writeSeparator(self):
        self.writeText("\n--------------------\n")
