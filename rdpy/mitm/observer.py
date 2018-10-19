from rdpy.core import log
from rdpy.layer.rdp.data import RDPDataLayerObserver


class MITMChannelObserver(RDPDataLayerObserver):
    def __init__(self, layer, name = ""):
        RDPDataLayerObserver.__init__(self)
        self.layer = layer
        self.name = name
        self.peer = None
        self.setUnparsedDataHandler(self.onDataReceived)

    def setPeer(self, peer):
        self.peer = peer

    def onPDUReceived(self, pdu):
        if hasattr(pdu.header, "subtype"):
            log.debug("%s: received %s" % (self.name, pdu.header.subtype))

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: received %s" % (self.name, pdu.header.type))

        RDPDataLayerObserver.onPDUReceived(self, pdu)
        self.peer.sendPDU(pdu)

    def onDataReceived(self, data):
        log.debug("%s: received data" % self.name)
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        if hasattr(pdu.header, "subtype"):
            log.debug("%s: sending %s" % (self.name, pdu.header.subtype))

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: sending %s" % (self.name, pdu.header.type))

        self.layer.sendPDU(pdu)

    def sendData(self, data):
        log.debug("%s: sending data, %s" % (self.name, data.encode('hex')))
        self.layer.sendData(data)