#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter

from pyrdp.enum import FastPathInputType, MouseButton, PlayerPDUType, PointerFlag
from pyrdp.layer import FastPathLayer, PlayerLayer
from pyrdp.pdu import FastPathMouseEvent, FastPathPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerPDU
from pyrdp.recording import Recorder


class AttackerMITM:
    """
    MITM component for commands coming from the player.
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
        }


    def onPDUReceived(self, pdu: PlayerPDU):
        if pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)


    def handleMouseMove(self, pdu: PlayerMouseMovePDU):
        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = PointerFlag.PTRFLAGS_MOVE
        x = pdu.x
        y = pdu.y
        event = FastPathMouseEvent(eventHeader, flags, x, y)

        pduHeader = 0
        pdu = FastPathPDU(pduHeader, [event])
        self.recorder.record(pdu, PlayerPDUType.FAST_PATH_INPUT)
        self.server.sendPDU(pdu)


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

        pduHeader = 0
        pdu = FastPathPDU(pduHeader, [event])
        self.recorder.record(pdu, PlayerPDUType.FAST_PATH_INPUT)
        self.server.sendPDU(pdu)