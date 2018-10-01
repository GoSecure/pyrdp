from abc import ABCMeta, abstractmethod
from collections from defaultdict

from rdpy.core.layer import Layer
from layer import MCSChannelLayer, MCSUserLayer
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

class MCSRouter:
    def __init__(self):
        self.connected = False
        self.mcs = None
    
    def setMCSLayer(self, mcs):
        """
        Set the MCS layer used with the router
        :param mcs: the MCS layer
        """
        self.mcs = mcs

    def connectInitial(self, pdu):
        raise Exception("Connect Initial is not handled")

    def connectResponse(self, pdu):
        raise Exception("Connect Response is not handled")
    
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
