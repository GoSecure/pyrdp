from rdpy.core.newlayer import Layer
from rdpy.parser.tpkt import TPKTParser
from rdpy.pdu.tpkt import TPKTPDU


class TPKTLayer(Layer):
    """
    Layer to handle TPKT-wrapped traffic
    """

    def __init__(self):
        Layer.__init__(self)
        self.parser = TPKTParser()

    def recv(self, data):
        """
        Since there can be more than one TPKT message per TCP packet, parse
        a TPKT message, handle the packet then check if we have more messages left.
        Note that TPKT reassembly (when a TPKT message is in more than one TCP packet) is not tested to be working.
        :param data: The TCP packet's payload
        :type data: str
        """
        while len(data) > 0:
            pdu = self.parser.parse(data)
            self.pduReceived(pdu, True)
            data = data[pdu.length :]

    def send(self, data):
        """
        Wrap the data inside a TPKT message and send it to the previous layer (TCP).
        :param data: The data we wish to send in a TPKT message
        :type data: str
        """
        pdu = TPKTPDU(3, data)
        self.previous.send(self.parser.write(pdu))

    def startTLS(self, tlsContext):
        """
        Tell the previous layer (in our case the TCP layer) to do the TLS handshake to encrypt further communications.
        :param tlsContext: Twisted TLS Context object (like DefaultOpenSSLContextFactory)
        :type tlsContext: ServerTLSContext
        """
        self.previous.startTLS(tlsContext)
