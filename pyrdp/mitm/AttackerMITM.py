#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter

from pyrdp.enum import FastPathInputType, MouseButton, PlayerPDUType, PointerFlag
from pyrdp.layer import FastPathLayer, PlayerLayer
from pyrdp.pdu import FastPathInputEvent, FastPathMouseEvent, FastPathPDU, FastPathScanCodeEvent, FastPathUnicodeEvent, \
    PlayerKeyboardPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU, PlayerPDU, PlayerTextPDU
from pyrdp.recording import Recorder


class AttackerMITM:
    """
    MITM component for commands coming from the player. The job of this component is just to adapt the format of events
    received to the format expected by RDP.
    """

    def __init__(self, server: FastPathLayer, attacker: PlayerLayer, log: LoggerAdapter, recorder: Recorder):
        """
        :param server: fast-path layer for the server side
        :param attacker: player layer for the attacker side
        :param log: logger for this component
        :param recorder: recorder for this connection
        """

        self.server = server
        self.attacker = attacker
        self.log = log
        self.recorder = recorder

        self.attacker.createObserver(
            onPDUReceived = self.onPDUReceived,
        )

        self.handlers = {
            PlayerPDUType.MOUSE_MOVE: self.handleMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.handleMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.handleMouseWheel,
            PlayerPDUType.KEYBOARD: self.handleKeyboard,
            PlayerPDUType.TEXT: self.handleText,
        }


    def onPDUReceived(self, pdu: PlayerPDU):
        if pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)


    def sendInputEvents(self, events: [FastPathInputEvent]):
        pdu = FastPathPDU(0, events)
        self.recorder.record(pdu, PlayerPDUType.FAST_PATH_INPUT)
        self.server.sendPDU(pdu)


    def handleMouseMove(self, pdu: PlayerMouseMovePDU):
        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = PointerFlag.PTRFLAGS_MOVE
        x = pdu.x
        y = pdu.y

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleMouseButton(self, pdu: PlayerMouseButtonPDU):
        mapping = {
            MouseButton.LEFT_BUTTON: PointerFlag.PTRFLAGS_BUTTON1,
            MouseButton.RIGHT_BUTTON: PointerFlag.PTRFLAGS_BUTTON2,
            MouseButton.MIDDLE_BUTTON: PointerFlag.PTRFLAGS_BUTTON3,
        }

        if pdu.button not in mapping:
            return

        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = mapping[pdu.button] | (PointerFlag.PTRFLAGS_DOWN if pdu.pressed else 0)
        x = pdu.x
        y = pdu.y

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleMouseWheel(self, pdu: PlayerMouseWheelPDU):
        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = PointerFlag.PTRFLAGS_WHEEL
        x = pdu.x
        y = pdu.y

        if pdu.delta < 0:
            flags |= PointerFlag.PTRFLAGS_WHEEL_NEGATIVE

        if pdu.horizontal:
            flags |= PointerFlag.PTRFLAGS_HWHEEL

        flags |= abs(pdu.delta) & PointerFlag.WheelRotationMask

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleKeyboard(self, pdu: PlayerKeyboardPDU):
        event = FastPathScanCodeEvent(2 if pdu.extended else 0, pdu.code, pdu.released)
        self.sendInputEvents([event])


    def handleText(self, pdu: PlayerTextPDU):
        event = FastPathUnicodeEvent(pdu.character, pdu.released)
        self.sendInputEvents([event])