from abc import abstractmethod, ABCMeta

from rdpy.core import log
from rdpy.core.layer import Layer
from rdpy.core.subject import Subject

from pdu import MCSParser, MCSPDUType, MCSSendDataRequestPDU, MCSErectDomainRequestPDU, MCSDisconnectProviderUltimatumPDU, MCSAttachUserRequestPDU, MCSAttachUserConfirmPDU, MCSChannelJoinRequestPDU, MCSChannelJoinConfirmPDU
from router import MCSRouter

class MCSChannelLayer(Layer):
    """
    @summary: Layer for handling MCS traffic on a particular channel
    """

    def __init__(self, mcs, channelID):
        super(MCSChannelLayer, self).__init__(self)
        self.mcs = mcs
        self.channelID = channelID
        self.initiator = None
    
    def recv(self, pdu):
        self.initiator = pdu.initiator
        self.next.recv(pdu.payload)
    
    def send(self, data):
        pdu = MCSSendDataRequestPDU(self.initiator, self.channelID, 0x70, data)
        self.mcs.sendPDU(pdu)

class MCSLayer(Layer):
    """
    @summary: Layer for handling MCS related traffic
    """

    def __init__(self, router = MCSRouter()):
        super(MCSLayer, self).__init__(self)
        self.parser = MCSParser()
        self.router = router
        self.handlers = {
            MCSPDUType.CONNECT_INITIAL: self.router.connectInitial,
            MCSPDUType.CONNECT_RESPONSE: self.router.connectResponse,
            MCSPDUType.ERECT_DOMAIN_REQUEST: self.router.erectDomainRequest,
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: self.router.disconnectProviderUltimatum,
            MCSPDUType.ATTACH_USER_REQUEST: self.router.attachUserRequest,
            MCSPDUType.ATTACH_USER_CONFIRM: self.router.attachUserConfirm,
            MCSPDUType.CHANNEL_JOIN_REQUEST: self.router.channelJoinRequest,
            MCSPDUType.CHANNEL_JOIN_CONFIRM: self.router.channelJoinConfirm,
            MCSPDUType.SEND_DATA_REQUEST: self.router.sendDataRequest,
            MCSPDUType.SEND_DATA_INDICATION: self.router.sendDataIndication,
        }

        self.router.setMCSLayer(self)
    
    def recv(self, data):
        pdu = self.parser.parse(data)

        if pdu.header not in self.handlers:
            raise Exception("Unhandled PDU received")
        
        self.handlers[pdu.header](pdu)

    def sendPDU(self, pdu):
        self.previous.send(self.parser.write(pdu))