from rdpy.core.newlayer import Layer
from pdu import MCSParser, MCSPDUType

class MCSLayer(Layer):
    """
    Layer for handling MCS related traffic
    """

    def __init__(self, router):
        """
        :param router: MCSRouter object
        """

        super(MCSLayer, self).__init__()
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
        """
        Receive MCS data
        :param data: raw MCS layer bytes
        """
        pdu = self.parser.parse(data)

        if pdu.header not in self.handlers:
            raise Exception("Unhandled PDU received")
        
        self.handlers[pdu.header](pdu)

    def send(self, pdu):
        """
        Send an MCS PDU
        :param pdu: PDU to send
        """
        self.previous.send(self.parser.write(pdu))