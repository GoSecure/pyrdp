from twisted.internet.protocol import Protocol

from rdpy.core.newlayer import Layer
from rdpy.core.subject import ObservedBy
from rdpy.protocol.tcp.layer import TCPObserver


@ObservedBy(TCPObserver)
class TCPLayer(Protocol, Layer):
    """
    Twisted protocol class and first layer in a stack.
    ObservedBy: TCPObserver
    Never notifies observers about PDUs because there isn't really a TCP PDU type per se.
    TCP observers are notified when a connection is made.
    """
    def __init__(self):
        Layer.__init__(self)

    def connectionMade(self):
        """
        When the TCP handshake is completed, notify the observer.
        """
        self.observer.onConnection()

    def dataReceived(self, data):
        """
        When a PSH TCP packet is received, call the next layer to receive the data.
        :param data: The byte stream (without the TCP header)
        :type data: str
        """
        self.next.recv(data)

    def send(self, data):
        """
        Send a TCP packet (or more than one if needed)
        :param data: The data to send
        :type data: str
        """
        self.transport.write(data)

    def startTLS(self, tlsContext):
        """
        Tell Twisted to make the TLS handshake so that all further communications are encrypted.
        :param tlsContext: Twisted TLS Context object (like DefaultOpenSSLContextFactory)
        :type tlsContext: ServerTLSContext
        """
        self.transport.startTLS(tlsContext)