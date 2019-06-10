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
from pyrdp.mitm.BasePathMITM import BasePathMITM

class FastPathMITM(BasePathMITM):
    """
    MITM component for the fast-path layer.
    """

    def __init__(self, client: FastPathLayer, server: FastPathLayer, state: RDPMITMState):
        """
        :param client: fast-path layer for the client side
        :param server: fast-path layer for the server side
        :param state: the MITM state.
        """
        super().__init__(state, client, server)

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