from rdpy.core.newlayer import LayerStrictRoutedObserver
from rdpy.enum.x224 import X224PDUType


class X224Observer(LayerStrictRoutedObserver):
    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            X224PDUType.X224_TPDU_CONNECTION_REQUEST: "onConnectionRequest",
            X224PDUType.X224_TPDU_CONNECTION_CONFIRM: "onConnectionConfirm",
            X224PDUType.X224_TPDU_DISCONNECT_REQUEST: "onDisconnectRequest",
            X224PDUType.X224_TPDU_DATA: "onData",
            X224PDUType.X224_TPDU_ERROR: "onError"
        }, **kwargs)

    def onConnectionRequest(self, pdu):
        raise Exception("Unhandled X224 Connection Request PDU")

    def onConnectionConfirm(self, pdu):
        raise Exception("Unhandled X224 Connection Confirm PDU")
    
    def onDisconnectRequest(self, pdu):
        raise Exception("Unhandled X224 Disconnect Request PDU")
    
    def onData(self, pdu):
        pass

    def onError(self, pdu):
        raise Exception("Unhandled X224 Error PDU")


