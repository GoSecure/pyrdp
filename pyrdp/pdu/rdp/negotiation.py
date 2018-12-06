from pyrdp.enum import NegotiationProtocols, NegotiationType
from pyrdp.pdu.base_pdu import PDU


class RDPNegotiationRequestPDU(PDU):
    """
    First PDU of the RDP connection sequence. Sent by the client.
    """
    def __init__(self, cookie, flags, requestedProtocols, correlationFlags, correlationID, reserved):
        """
        :param cookie: mstshash identifier or routing token.
        :type cookie: bytes | None
        :param flags: request flags.
        :type flags: int | None
        :param requestedProtocols: transport protocols supported by the client.
        :type requestedProtocols: int | None
        :param correlationFlags: correlation info flags.
        :type correlationFlags: int | None
        :param correlationID: correlation info id.
        :type correlationID: bytes | None
        :param reserved: correlation info reserved data.
        :type reserved: bytes | None
        """
        PDU.__init__(self)
        self.cookie = cookie
        self.flags = flags
        self.packetType = NegotiationType.TYPE_RDP_NEG_REQ
        self.requestedProtocols = requestedProtocols
        self.tlsSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0
        self.correlationFlags = correlationFlags
        self.correlationID = correlationID
        self.reserved = reserved


class RDPNegotiationResponsePDU(PDU):
    """
    Second PDU of the RDP connection sequence. Sent by the server.
    Important information is the chosen encryption method.
    """
    def __init__(self, flags, selectedProtocols):
        """
        :param flags: response flags.
        :type flags: int | None
        :param selectedProtocols: transport protocol chosen by the server.
        :type selectedProtocols: int | None
        """
        PDU.__init__(self)
        self.packetType = NegotiationType.TYPE_RDP_NEG_RSP
        self.length = 8
        self.flags = flags
        self.selectedProtocols = selectedProtocols
        self.tlsSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0