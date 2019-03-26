import logging
import time
from typing import Optional, Union

from PySide2.QtCore import Qt
from PySide2.QtGui import QMouseEvent, QWheelEvent
from PySide2.QtWidgets import QWidget

from pyrdp.enum import MouseButton
from pyrdp.layer import PlayerLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.pdu import PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU
from pyrdp.ui import QRemoteDesktop


class RDPMITMWidget(QRemoteDesktop):
    def __init__(self, width: int, height: int, layer: PlayerLayer, parent: Optional[QWidget] = None):
        super().__init__(width, height, parent = parent)
        self.layer = layer
        self.handleEvents = False
        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)

    def getTimetamp(self) -> int:
        return int(round(time.time() * 1000))

    def getMousePosition(self, event: Union[QMouseEvent, QWheelEvent]) -> (int, int):
        return max(event.x(), 0), max(event.y(), 0)

    def mouseMoveEvent(self, event: QMouseEvent):
        if not self.handleEvents:
            return

        x, y = self.getMousePosition(event)

        pdu = PlayerMouseMovePDU(self.getTimetamp(), x, y)
        self.layer.sendPDU(pdu)

    def mousePressEvent(self, event: QMouseEvent):
        self.handleMouseButton(event, True)

    def mouseReleaseEvent(self, event: QMouseEvent):
        self.handleMouseButton(event, False)

    def handleMouseButton(self, event: QMouseEvent, pressed: bool):
        x, y = self.getMousePosition(event)
        button = event.button()

        mapping = {
            Qt.MouseButton.LeftButton: MouseButton.LEFT_BUTTON,
            Qt.MouseButton.RightButton: MouseButton.RIGHT_BUTTON,
            Qt.MouseButton.MiddleButton: MouseButton.MIDDLE_BUTTON,
        }

        if button not in mapping:
            return

        pdu = PlayerMouseButtonPDU(self.getTimetamp(), x, y, mapping[button], pressed)
        self.layer.sendPDU(pdu)

    def wheelEvent(self, event: QWheelEvent):
        x, y = self.getMousePosition(event)
        delta = event.delta()
        horizontal = event.orientation() == Qt.Orientation.Horizontal

        event.setAccepted(True)

        pdu = PlayerMouseWheelPDU(self.getTimetamp(), x, y, delta, horizontal)
        self.layer.sendPDU(pdu)