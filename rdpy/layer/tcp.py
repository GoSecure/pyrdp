import logging

from twisted.internet.protocol import Protocol, connectionDone

from rdpy.core import log
from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import ObservedBy


class TCPObserver(LayerObserver):
    def onConnection(self):
        """
        Called when a TCP connection is made.
        """
        pass

    def onDisconnection(self, reason):
        """
        Called when the TCP connection is lost.
        :param reason: reason for disconnection.
        """
        pass


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
        self.logSSLRequired = False

    def logSSLParameters(self):
        """
        Log the SSL parameters of the connection in a format suitable for decryption by Wireshark.
        """
        log.get_ssl_logger().info(self.transport.protocol._tlsConnection.client_random(),
                                  self.transport.protocol._tlsConnection.master_key())

    def connectionMade(self):
        """
        When the TCP handshake is completed, notify the observer.
        """
        if hasattr(self.transport, 'client'):
            self.observer.onConnection(self.transport.client)
        else:
            self.observer.onConnection()


    def connectionLost(self, reason=connectionDone):
        """
        :param reason: reason for disconnection.
        """
        self.observer.onDisconnection(reason)

    def disconnect(self):
        """
        Close the TCP connection.
        """
        self.transport.abortConnection()

    def dataReceived(self, data):
        """
        When a PSH TCP packet is received, call the next layer to receive the data.
        :param data: The byte stream (without the TCP header)
        :type data: str
        """
        try:
            if self.logSSLRequired:
                self.logSSLParameters()
                self.logSSLRequired = False

            self.next.recv(data)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logging.getLogger("rdpy.exceptions").exception(e)
            raise

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
        self.logSSLRequired = True
        self.transport.startTLS(tlsContext)