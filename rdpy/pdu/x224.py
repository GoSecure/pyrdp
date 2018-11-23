from rdpy.enum.x224 import X224PDUType
from rdpy.pdu.base_pdu import PDU


class X224PDU(PDU):
    """
    X.224 (T.125) PDU base class. Every X.224 PDU has a length, a header (PDU type) and a payload.
    """

    def __init__(self, length, header, payload):
        """
        :type length: int
        :param header: The PDU type
        :type payload: bytes
        """

        PDU.__init__(self, payload)
        self.length = length
        self.header = header


class X224ConnectionRequestPDU(X224PDU):

    def __init__(self, credit, destination, source, options, payload):
        X224PDU.__init__(self, len(payload) + 6, X224PDUType.X224_TPDU_CONNECTION_REQUEST, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224ConnectionConfirmPDU(X224PDU):

    def __init__(self, credit, destination, source, options, payload):
        X224PDU.__init__(self, len(payload) + 6, X224PDUType.X224_TPDU_CONNECTION_CONFIRM, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224DisconnectRequestPDU(X224PDU):

    def __init__(self, destination, source, reason, payload):
        X224PDU.__init__(self, len(payload) + 6, X224PDUType.X224_TPDU_DISCONNECT_REQUEST, payload)
        self.destination = destination
        self.source = source
        self.reason = reason


class X224DataPDU(X224PDU):

    def __init__(self, roa, eot, payload):
        """
        @param roa: request of acknowledgement (this is False unless agreed upon during connection)
        @param eot: end of transmission (True if this is the last packet in a sequence)
        @param payload: the data payload
        """
        X224PDU.__init__(self, 2, X224PDUType.X224_TPDU_DATA, payload)
        self.roa = roa
        self.eot = eot


class X224ErrorPDU(X224PDU):

    def __init__(self, destination, cause, payload):
        X224PDU.__init__(self, len(payload) + 4, X224PDUType.X224_TPDU_ERROR, payload)
        self.destination = destination
        self.cause = cause
