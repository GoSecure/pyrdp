from abc import ABCMeta, abstractmethod

from rdpy.core.newlayer import Layer
from rdpy.core.subject import Subject
from rdpy.protocol.rdp.pdu.connection import RDPClientConnectionParser, RDPServerConnectionParser

class RDPClientConnectionObserver:
    __metaclass__ = ABCMeta

    @abstractmethod
    def serverDataReceived(self, pdu):
        pass

class RDPClientConnectionLayer(Layer, Subject):
    def __init__(self):
        Layer.__init__(self)
        Subject.__init__(self)
        self.clientRDP = RDPClientConnectionParser()
        self.serverRDP = RDPServerConnectionParser()
    
    def recv(self, data):
        pdu = self.serverRDP.parse(data)
        self.pduReceived(pdu, True)
    
    def send(self, pdu):
        self.previous.send(self.clientRDP.write(pdu))