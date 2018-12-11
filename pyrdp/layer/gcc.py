from pyrdp.layer.layer import Layer
from pyrdp.parser import GCCParser
from pyrdp.pdu import GCCConferenceCreateRequestPDU


class GCCClientConnectionLayer(Layer):
    """
    GCC Layer for parsing GCC conference PDUs.
    """
    def __init__(self, conferenceName, parser = GCCParser()):
        """
        :param conferenceName: the conference name
        :type conferenceName: bytes
        """
        Layer.__init__(self, parser, hasNext=True)
        self.conferenceName = conferenceName

    def recv(self, data):
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.previous.send(self.mainParser.write(pdu))
