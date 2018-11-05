from rdpy.core import log
from rdpy.layer.rdp.data import RDPDataLayerObserver, RDPFastPathDataLayerObserver


class MITMChannelObserver:
    def __init__(self, layer, innerObserver, name = ""):
        self.layer = layer
        self.innerObserver = innerObserver
        self.name = name
        self.peer = None

        self.setDataHandler = self.innerObserver.setDataHandler
        self.setDefaultDataHandler = self.innerObserver.setDefaultDataHandler

    def setPeer(self, peer):
        self.peer = peer
        peer.peer = self

    def onPDUReceived(self, pdu):
        log.debug("%s: received %s" % (self.name, self.getEffectiveType(pdu)))
        self.innerObserver.onPDUReceived(pdu)
        self.peer.sendPDU(pdu)

    def onUnparsedData(self, data):
        log.debug("%s: received data" % self.name)
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        log.debug("%s: sending %s" % (self.name, self.getEffectiveType(pdu)))
        self.layer.sendPDU(pdu)

    def sendData(self, data):
        log.debug("%s: sending data, %s" % (self.name, data.encode('hex')))
        self.layer.sendData(data)

    def getEffectiveType(self, pdu):
        return NotImplementedError("getEffectiveType must be overridden")


class MITMSlowPathObserver(MITMChannelObserver):
    def __init__(self, layer, name = "", **kwargs):
        MITMChannelObserver.__init__(self, layer, RDPDataLayerObserver(**kwargs), name)

    def getEffectiveType(self, pdu):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                return pdu.errorInfo
            else:
                return pdu.header.subtype
        else:
            return pdu.header.type


class MITMFastPathObserver(MITMChannelObserver):
    def __init__(self, layer, name = ""):
        MITMChannelObserver.__init__(self, layer, RDPFastPathDataLayerObserver(), name)

    def getEffectiveType(self, pdu):
        return str(pdu)

    def onPDUReceived(self, pdu):
        if pdu.header == 3:
            return

        MITMChannelObserver.onPDUReceived(self, pdu)