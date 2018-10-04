from abc import ABCMeta, abstractmethod

from twisted.internet.protocol import Protocol

from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import Subject

class TCPObserver(LayerObserver):
    __metaclass__ = ABCMeta

    @abstractmethod
    def connected(self):
        pass

class TCPLayer(Protocol, Layer):
    """
    Twisted protocol class and first layer in a stack.
    Never notifies observers about PDUs because there isn't really a TCP PDU type per say.
    TCP observers are notified when a connection is made.
    """
    def __init__(self):
        Layer.__init__(self)
    
    def connectionMade(self):
        self.observer.connected()

    def dataReceived(self, data):
        self.next.recv(data)
    
    def send(self, data):
        self.transport.write(data)
    
    def startTLS(self, ctx):
        self.transport.startTLS(ctx)