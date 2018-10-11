from rdpy.enum.mcs import MCSPDUType
from rdpy.core.newlayer import LayerStrictRoutedObserver


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
            MCSPDUType.CONNECT_INITIAL: "onConnectInitial",
            MCSPDUType.CONNECT_RESPONSE: "onConnectResponse",
            MCSPDUType.ERECT_DOMAIN_REQUEST: "onErectDomainRequest",
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: "disconnectProviderUltimatum",
            MCSPDUType.ATTACH_USER_REQUEST: "onAttachUserRequest",
            MCSPDUType.ATTACH_USER_CONFIRM: "onAttachUserConfirm",
            MCSPDUType.CHANNEL_JOIN_REQUEST: "onChannelJoinRequest",
            MCSPDUType.CHANNEL_JOIN_CONFIRM: "onChannelJoinConfirm",
            MCSPDUType.SEND_DATA_REQUEST: "onSendDataRequest",
            MCSPDUType.SEND_DATA_INDICATION: "onSendDataIndication",
        })

        self.connected = False
        self.mcs = mcs

    def onConnectInitial(self, pdu):
        raise Exception("Connect Initial is not handled")

    def onConnectResponse(self, pdu):
        raise Exception("Connect Response is not handled")
    
    def disconnectProviderUltimatum(self, pdu):
        raise Exception("Disconnect Provider Ultimatum is not handled")

    def onErectDomainRequest(self, pdu):
        raise Exception("Erect Domain Request is not handled")

    def onAttachUserRequest(self, pdu):
        raise Exception("Attach User Request is not handled")
    
    def onAttachUserConfirm(self, pdu):
        raise Exception("Attach User Confirm is not handled")
    
    def onChannelJoinRequest(self, pdu):
        raise Exception("Channel Join Request is not handled")
    
    def onChannelJoinConfirm(self, pdu):
        raise Exception("Channel Join Confirm is not handled")
    
    def onSendDataRequest(self, pdu):
        raise Exception("Send Data Request is not handled")
    
    def onSendDataIndication(self, pdu):
        raise Exception("Send Data Indication is not handled")
