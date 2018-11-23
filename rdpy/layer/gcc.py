from rdpy.core.layer import Layer
from rdpy.parser.gcc import GCCParser
from rdpy.pdu.gcc import GCCConferenceCreateRequestPDU


class GCCClientConnectionLayer(Layer):
    """
    GCC Layer for parsing GCC conference PDUs.
    """
    def __init__(self, conferenceName):
        """
        :param conferenceName: the conference name
        :type conferenceName: bytes
        """
        Layer.__init__(self)
        self.conferenceName = conferenceName
        self.parser = GCCParser()

    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.previous.send(self.parser.write(pdu))
