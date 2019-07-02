#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.mitm.state import RDPMITMState
from pyrdp.player import keyboard
from pyrdp.enum import ScanCode
from pyrdp.pdu.pdu import PDU
from pyrdp.layer.layer import Layer


class BasePathMITM:
    """
    Base MITM component for the fast-path and slow-path layers.
    """

    def __init__(self, state: RDPMITMState, client: Layer, server: Layer):
        self.state = state
        self.client = client
        self.server = server

    def onClientPDUReceived(self, pdu: PDU):
        raise NotImplementedError("onClientPDUReceived must be overridden")

    def onServerPDUReceived(self, pdu: PDU):
        raise NotImplementedError("onServerPDUReceived must be overridden")

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