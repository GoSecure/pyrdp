from pyrdp.enum.mcs import MCSPDUType
from pyrdp.layer.layer import LayerStrictRoutedObserver


class MCSRouter(LayerStrictRoutedObserver):
    """
    Base observer class for MCS layers. Simply routes PDU types to methods.
    """
    def __init__(self, mcs):
        LayerStrictRoutedObserver.__init__(self, {
            MCSPDUType.CONNECT_INITIAL: "onConnectInitial",
            MCSPDUType.CONNECT_RESPONSE: "onConnectResponse",
            MCSPDUType.ERECT_DOMAIN_REQUEST: "onErectDomainRequest",
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: "onDisconnectProviderUltimatum",
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
        raise NotImplementedError("Connect Initial is not handled")

    def onConnectResponse(self, pdu):
        raise NotImplementedError("Connect Response is not handled")
    
    def onDisconnectProviderUltimatum(self, pdu):
        raise NotImplementedError("Disconnect Provider Ultimatum is not handled")

    def onErectDomainRequest(self, pdu):
        raise NotImplementedError("Erect Domain Request is not handled")

    def onAttachUserRequest(self, pdu):
        raise NotImplementedError("Attach User Request is not handled")
    
    def onAttachUserConfirm(self, pdu):
        raise NotImplementedError("Attach User Confirm is not handled")
    
    def onChannelJoinRequest(self, pdu):
        raise NotImplementedError("Channel Join Request is not handled")
    
    def onChannelJoinConfirm(self, pdu):
        raise NotImplementedError("Channel Join Confirm is not handled")
    
    def onSendDataRequest(self, pdu):
        raise NotImplementedError("Send Data Request is not handled")
    
    def onSendDataIndication(self, pdu):
        raise NotImplementedError("Send Data Indication is not handled")
