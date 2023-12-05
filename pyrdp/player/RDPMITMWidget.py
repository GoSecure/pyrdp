#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import functools
import logging
import platform
import time
from typing import Optional, Union

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QKeyEvent, QMouseEvent, QWheelEvent
from PySide6.QtWidgets import QWidget

from pyrdp.enum import MouseButton
from pyrdp.layer import PlayerLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.pdu import PlayerBitmapPDU, PlayerForwardingStatePDU, PlayerKeyboardPDU, PlayerMouseButtonPDU, \
    PlayerMouseMovePDU, PlayerMouseWheelPDU, PlayerTextPDU
from pyrdp.player import keyboard
from pyrdp.player.keyboard import isRightControl
from pyrdp.player.QTimerSequencer import QTimerSequencer
from pyrdp.ui import QRemoteDesktop


class RDPMITMWidget(QRemoteDesktop):
    """
    RDP Widget that handles mouse and keyboard events and sends them to the MITM server.
    """

    KEY_SEQUENCE_DELAY = 0

    def __init__(self, width: int, height: int, layer: PlayerLayer, parent: Optional[QWidget] = None):
        super().__init__(width, height, parent = parent)
        self.layer = layer
        self.handleEvents = False
        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.installEventFilter(self)


    def getTimetamp(self) -> int:
        return int(round(time.time() * 1000))


    def getMousePosition(self, event: Union[QMouseEvent, QWheelEvent]) -> (int, int):
        pos = event.position()
        return max(pos.x(), 0), max(pos.y(), 0)

    def mouseMoveEvent(self, event: QMouseEvent):
        if not self.handleEvents or not self.hasFocus():
            return

        x, y = self.getMousePosition(event)

        pdu = PlayerMouseMovePDU(self.layer.getCurrentTimeStamp(), x, y)
        self.layer.sendPDU(pdu)

    def mousePressEvent(self, event: QMouseEvent):
        if self.handleEvents:
            self.handleMouseButton(event, True)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if self.handleEvents:
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

        pdu = PlayerMouseButtonPDU(self.layer.getCurrentTimeStamp(), x, y, mapping[button], pressed)
        self.layer.sendPDU(pdu)


    def wheelEvent(self, event: QWheelEvent):
        if not self.handleEvents:
            return

        x, y = self.getMousePosition(event)
        delta = event.delta()
        horizontal = event.orientation() == Qt.Orientation.Horizontal

        event.setAccepted(True)

        pdu = PlayerMouseWheelPDU(self.layer.getCurrentTimeStamp(), x, y, delta, horizontal)
        self.layer.sendPDU(pdu)


    # We need this to capture tab key events
    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if self.handleEvents and event.type() == QEvent.KeyPress:
            self.keyPressEvent(event)
            return True

        return QObject.eventFilter(self, obj, event)


    def keyPressEvent(self, event: QKeyEvent):
        if not isRightControl(event):
            if self.handleEvents:
                self.handleKeyEvent(event, False)
        else:
            self.clearFocus()

    def keyReleaseEvent(self, event: QKeyEvent):
        if self.handleEvents:
            self.handleKeyEvent(event, True)

    def handleKeyEvent(self, event: QKeyEvent, released: bool):
        # After some testing, it seems like scan codes on Linux are 8 higher than their Windows version.
        if platform.system() == "Linux":
            offset = -8
        else:
            offset = 0

        scanCode = keyboard.findScanCodeForEvent(event) or event.nativeScanCode() + offset
        pdu = PlayerKeyboardPDU(self.layer.getCurrentTimeStamp(), scanCode, released, event.key() in keyboard.EXTENDED_KEYS)
        self.layer.sendPDU(pdu)


    def sendKeySequence(self, keys: [Qt.Key]):
        self.setFocus()

        pressPDUs = []
        releasePDUs = []

        for key in keys:
            scanCode = keyboard.SCANCODE_MAPPING[key]
            isExtended = key in keyboard.EXTENDED_KEYS

            pressPDU = PlayerKeyboardPDU(self.layer.getCurrentTimeStamp(), scanCode, False, isExtended)
            pressPDUs.append(pressPDU)

            releasePDU = PlayerKeyboardPDU(self.layer.getCurrentTimeStamp(), scanCode, True, isExtended)
            releasePDUs.append(releasePDU)

        def press() -> int:
            for pdu in pressPDUs:
                self.layer.sendPDU(pdu)

            return RDPMITMWidget.KEY_SEQUENCE_DELAY

        def release():
            for pdu in releasePDUs:
                self.layer.sendPDU(pdu)

        sequencer = QTimerSequencer([press, release])
        sequencer.run()


    def sendText(self, text: str):
        self.setFocus()

        functions = []

        def pressCharacter(character: str) -> int:
            pdu = PlayerTextPDU(self.layer.getCurrentTimeStamp(), character, False)
            print(c)
            self.layer.sendPDU(pdu)
            return RDPMITMWidget.KEY_SEQUENCE_DELAY

        def releaseCharacter(character: str):
            pdu = PlayerTextPDU(self.layer.getCurrentTimeStamp(), character, True)
            self.layer.sendPDU(pdu)

        for c in text:
            press = functools.partial(pressCharacter, c)
            release = functools.partial(releaseCharacter, c)
            functions.append(press)
            functions.append(release)

        sequencer = QTimerSequencer(functions)
        sequencer.run()


    def setControlState(self, controlled: bool):
        self.handleEvents = controlled
        self.setForwardingState(not controlled)

        if not controlled:
            self.sendCurrentScreen()

    def setForwardingState(self, shouldForward: bool):
        self.layer.sendPDU(PlayerForwardingStatePDU(self.layer.getCurrentTimeStamp(), shouldForward, shouldForward))

    def sendCurrentScreen(self):
        width = self._buffer.width()
        height = self._buffer.height()
        pdu = PlayerBitmapPDU(self.layer.getCurrentTimeStamp(), width, height, self._buffer.bits())
        self.layer.sendPDU(pdu)
