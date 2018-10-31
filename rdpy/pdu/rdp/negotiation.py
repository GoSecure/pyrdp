from rdpy.enum.rdp import NegotiationProtocols
from rdpy.pdu.base_pdu import PDU
from rdpy.protocol.rdp.x224 import NegociationType


class RDPNegotiationResponsePDU(PDU):
    """
    Second PDU of the RDP connection sequence. Sent by the server.
    Important information is the chosen encryption method.
    """

    def __init__(self, flags, selectedProtocols):
        PDU.__init__(self)
        self.packetType = NegociationType.TYPE_RDP_NEG_RSP
        self.length = 8
        self.flags = flags
        self.selectedProtocols = selectedProtocols
        self.tlsSelected = self.selectedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSelected = self.selectedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSelected = self.selectedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0


class RDPNegotiationRequestPDU(PDU):
    """
    First PDU of the RDP connection sequence. Sent by the client.
    """

    def __init__(self, cookie, flags, requestedProtocols):
        PDU.__init__(self)
        self.cookie = cookie
        self.flags = flags
        self.packetType = NegociationType.TYPE_RDP_NEG_REQ
        self.requestedProtocols = requestedProtocols
        self.tlsSupported = self.requestedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSupported = self.requestedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSupported = self.requestedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0