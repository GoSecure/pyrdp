from rdpy.core.newlayer import Layer
from rdpy.parser.mcs import MCSParser
from rdpy.pdu.mcs import MCSConnectInitialPDU, MCSDomainParams


class MCSLayer(Layer):
    """
    Layer for handling MCS related traffic.
    It doesn't really make sense to assign a single 'next' layer to this, so traffic is never forwarded.
    """

    def __init__(self):
        Layer.__init__(self)
        self.parser = MCSParser()

    def recv(self, data):
        """
        Receive MCS data
        :param data: raw MCS layer bytes
        """
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, False)

    def send(self, pdu):
        """
        Send an MCS PDU
        :param pdu: PDU to send
        """
        self.previous.send(self.parser.write(pdu))


class MCSClientConnectionLayer(Layer):
    def __init__(self, mcs):
        Layer.__init__(self)
        self.mcs = mcs
        self.callingDomain = "\x01"
        self.calledDomain = "\x01"
        self.upward = True
        self.targetParams = MCSDomainParams.createTarget(34, 2)
        self.minParams = MCSDomainParams.createMinimum()
        self.maxParams = MCSDomainParams.createMaximum()

    def recv(self, pdu):
        self.pduReceived(pdu, True)

    def send(self, data):
        pdu = MCSConnectInitialPDU(self.callingDomain, self.calledDomain, self.upward, self.targetParams, self.minParams, self.maxParams, data)
        self.mcs.send(pdu)