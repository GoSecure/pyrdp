from rdpy.enum.x224 import X224Header


class X224PDU(object):
    """
    @summary: Base class for X224 PDUs
    """
    def __init__(self, length, header, payload):
        self.length = length
        self.header = header
        self.payload = payload


class X224ConnectionRequest(X224PDU):
    """
    @summary: X224 Connection Request PDU
    """
    def __init__(self, credit, destination, source, options, payload):
        super(X224ConnectionRequest, self).__init__(len(payload) + 6, X224Header.X224_TPDU_CONNECTION_REQUEST, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224ConnectionConfirm(X224PDU):
    """
    @summary: X224 Connection Confirm PDU
    """
    def __init__(self, credit, destination, source, options, payload):
        super(X224ConnectionConfirm, self).__init__(len(payload) + 6, X224Header.X224_TPDU_CONNECTION_CONFIRM, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224DisconnectRequest(X224PDU):
    """
    @summary: X224 Disconnect Request PDU
    """
    def __init__(self, destination, source, reason, payload):
        super(X224DisconnectRequest, self).__init__(len(payload) + 6, X224Header.X224_TPDU_DISCONNECT_REQUEST, payload)
        self.destination = destination
        self.source = source
        self.reason = reason


class X224Data(X224PDU):
    """
    @summary: X224 Data PDU
    """
    def __init__(self, roa, eot, payload):
        """
        @param roa: request of acknowledgement (this is False unless agreed upon during connection)
        @param eot: end of transmission (True if this is the last packet in a sequence)
        @param payload: the data payload
        """
        super(X224Data, self).__init__(2, X224Header.X224_TPDU_DATA, payload)
        self.roa = roa
        self.eot = eot


class X224Error(X224PDU):
    """
    @summary: X224 Error PDU
    """
    def __init__(self, destination, cause):
        super(X224Error, self).__init__(len(payload) + 4, X224Header.X224_TPDU_ERROR, payload)
        self.destination = destination
        self.cause = cause