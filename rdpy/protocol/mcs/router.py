from collections import defaultdict

from rdpy.core.newlayer import LayerStrictRoutedObserver
from pdu import MCSChannel, MCSConnectResponsePDU, MCSAttachUserConfirmPDU, MCSAttachUserRequestPDU, MCSChannelJoinConfirmPDU, MCSChannelJoinRequestPDU, MCSSendDataRequestPDU, MCSPDUType

def whenConnected(method):
    """
    Decorator used to check if a router has been connected before running a method
    """
    def wrapper(*args):
        router = args[0]
        if not router.connected:
            raise Exception("Not connected")
        
        method(*args)
    
    return wrapper

class MCSRouter(LayerStrictRoutedObserver):
    def __init__(self, mcs):
        LayerStrictRoutedObserver.__init__(self, {
            MCSPDUType.CONNECT_INITIAL: self.connectInitial,
            MCSPDUType.CONNECT_RESPONSE: self.connectResponse,
            MCSPDUType.ERECT_DOMAIN_REQUEST: self.erectDomainRequest,
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: self.disconnectProviderUltimatum,
            MCSPDUType.ATTACH_USER_REQUEST: self.attachUserRequest,
            MCSPDUType.ATTACH_USER_CONFIRM: self.attachUserConfirm,
            MCSPDUType.CHANNEL_JOIN_REQUEST: self.channelJoinRequest,
            MCSPDUType.CHANNEL_JOIN_CONFIRM: self.channelJoinConfirm,
            MCSPDUType.SEND_DATA_REQUEST: self.sendDataRequest,
            MCSPDUType.SEND_DATA_INDICATION: self.sendDataIndication,
        })

        self.connected = False
        self.mcs = mcs

    def connectInitial(self, pdu):
        raise Exception("Connect Initial is not handled")

    def connectResponse(self, pdu):
        raise Exception("Connect Response is not handled")
    
    def disconnectProviderUltimatum(self, pdu):
        raise Exception("Disconnect Provider Ultimatum is not handled")

    def erectDomainRequest(self, pdu):
        raise Exception("Erect Domain Request is not handled")

    def attachUserRequest(self, pdu):
        raise Exception("Attach User Request is not handled")
    
    def attachUserConfirm(self, pdu):
        raise Exception("Attach User Confirm is not handled")
    
    def channelJoinRequest(self, pdu):
        raise Exception("Channel Join Request is not handled")
    
    def channelJoinConfirm(self, pdu):
        raise Exception("Channel Join Confirm is not handled")
    
    def sendDataRequest(self, pdu):
        raise Exception("Send Data Request is not handled")
    
    def sendDataIndication(self, pdu):
        raise Exception("Send Data Indication is not handled")
