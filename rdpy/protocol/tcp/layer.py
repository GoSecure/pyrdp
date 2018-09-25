from abc import ABCMeta, abstractmethod

from twisted.internet.protocol import Protocol

class TCPController:
    __metaclass__ = ABCMeta

    @abstractmethod
    def connected(self):
        pass

class TCPLayer(Protocol):
    def __init__(self, next, controller):
        self.controller = controller
        self.next = next
    
    def startedConnecting(self):
        self.controller.connected()

    def dataReceived(self, data):
        self.next.recv(data)
    
    def send(self, data):
        self.transport.write(data)
    
    def startTLS(self, ctx):
        self.transport.startTLS(ctx)