from abc import ABCMeta, abstractmethod

from twisted.internet.protocol import Protocol

from rdpy.core.layer import Layer
from rdpy.core.subject import Subject

class TCPObserver:
    __metaclass__ = ABCMeta

    @abstractmethod
    def connected(self):
        pass

class TCPLayer(Protocol, Layer, Subject):
    def __init__(self):
        super(TCPLayer, self).__init__()
        super(TCPLayer, self).__init__()
    
    def connectionMade(self):
        self.observer.connected()

    def dataReceived(self, data):
        self.next.recv(data)
    
    def send(self, data):
        self.transport.write(data)
    
    def startTLS(self, ctx):
        self.transport.startTLS(ctx)