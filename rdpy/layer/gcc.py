from rdpy.layer.layer import Layer
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
        Layer.__init__(self, GCCParser(), hasNext=True)
        self.conferenceName = conferenceName

    def recv(self, data):
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.previous.send(self.mainParser.write(pdu))
