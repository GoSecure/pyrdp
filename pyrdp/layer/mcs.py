#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import IntermediateLayer, Layer
from pyrdp.parser import MCSParser
from pyrdp.pdu import MCSConnectInitialPDU, MCSDomainParams, PDU


class MCSLayer(Layer):
    """
    Layer to handle MCS-related traffic.
    It doesn't really make sense to assign a single 'next' layer to this
    (since MCS is channel-based), so traffic is never forwarded.
    """

    def __init__(self, parser = MCSParser()):
        super().__init__(parser)

    def sendConnectInitial(self, payload = b"", callingDomain = b"\x01", calledDomain = b"\x01", upward = True,
                           targetParams = MCSDomainParams.createTarget(34, 2), minParams = MCSDomainParams.createMinimum(), maxParams = MCSDomainParams.createMaximum()):
        pdu = MCSConnectInitialPDU(callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload)
        self.sendPDU(pdu)


class MCSClientConnectionLayer(IntermediateLayer):
    """
    A layer to make it more simple to send MCS Connect Initial PDUs. Every parameter other than the payload is saved
    in this layer.
    """

    def __init__(self, mcs):
        """
        :param mcs: the MCS layer.
        :type mcs: MCSLayer
        """
        super().__init__(None)
        self.mcs = mcs
        self.callingDomain = b"\x01"
        self.calledDomain = b"\x01"
        self.upward = True
        self.targetParams = MCSDomainParams.createTarget(34, 2)
        self.minParams = MCSDomainParams.createMinimum()
        self.maxParams = MCSDomainParams.createMaximum()

    def recv(self, pdu):
        self.pduReceived(pdu)

    def sendBytes(self, data):
        pdu = MCSConnectInitialPDU(self.callingDomain, self.calledDomain, self.upward, self.targetParams, self.minParams, self.maxParams, data)
        self.mcs.sendPDU(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True