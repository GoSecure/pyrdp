#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import Layer
from pyrdp.parser import MCSParser
from pyrdp.pdu import MCSConnectInitialPDU, MCSDomainParams, MCSPDU


class MCSLayer(Layer):
    """
    Layer to handle MCS-related traffic.
    It doesn't really make sense to assign a single 'next' layer to this
    (since MCS is channel-based), so traffic is never forwarded.
    """

    def __init__(self, parser = MCSParser()):
        Layer.__init__(self, parser, hasNext=False)

    def recv(self, data):
        """
        Receive MCS data
        :param data: raw MCS layer bytes
        :type data: bytes
        """
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, pdu: MCSPDU):
        """
        Send a MCS PDU
        :param pdu: PDU to send
        """
        self.previous.send(self.mainParser.write(pdu))


class MCSClientConnectionLayer(Layer):
    """
    A layer to make it more simple to send MCS Connect Initial PDUs. Every parameter other than the payload is saved
    in this layer.
    """

    def __init__(self, mcs):
        """
        :param mcs: the MCS layer.
        :type mcs: MCSLayer
        """
        Layer.__init__(self)
        self.mcs = mcs
        self.callingDomain = b"\x01"
        self.calledDomain = b"\x01"
        self.upward = True
        self.targetParams = MCSDomainParams.createTarget(34, 2)
        self.minParams = MCSDomainParams.createMinimum()
        self.maxParams = MCSDomainParams.createMaximum()

    def recv(self, pdu):
        self.pduReceived(pdu, True)

    def send(self, data):
        pdu = MCSConnectInitialPDU(self.callingDomain, self.calledDomain, self.upward, self.targetParams, self.minParams, self.maxParams, data)
        self.mcs.send(pdu)