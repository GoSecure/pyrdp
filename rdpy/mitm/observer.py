from binascii import hexlify

from rdpy.core.observer import Observer
from rdpy.enum.core import ParserMode
from rdpy.layer.rdp.data import RDPDataLayerObserver, RDPFastPathDataLayerObserver


class MITMChannelObserver(Observer):
    def __init__(self, log, layer, innerObserver, **kwargs):
        """
        :type layer: rdpy.core.layer.Layer
        :type mode: ParserMode
        """
        Observer.__init__(self, **kwargs)
        self.log = log
        self.layer = layer
        self.innerObserver = innerObserver
        self.peer = None

        self.setDataHandler = self.innerObserver.setDataHandler
        self.setDefaultDataHandler = self.innerObserver.setDefaultDataHandler

    def onPDUReceived(self, pdu):
        self.log.debug("Received {}".format(str(self.getEffectiveType(pdu))))
        self.innerObserver.onPDUReceived(pdu)
        self.peer.sendPDU(pdu)

    def onUnparsedData(self, data):
        self.log.debug("Received unparsed data: {}".format(hexlify(data)))
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        self.log.debug("Sending {}".format(str(self.getEffectiveType(pdu))))
        self.layer.sendPDU(pdu)

    def sendData(self, data):
        self.log.debug("Sending data: {}".format(hexlify(data)))
        self.layer.sendData(data)

    def getEffectiveType(self, pdu):
        return NotImplementedError("getEffectiveType must be overridden")


class MITMSlowPathObserver(MITMChannelObserver):
    def __init__(self, log, layer, **kwargs):
        """
        :type layer: rdpy.core.layer.Layer
        """
        MITMChannelObserver.__init__(self, log, layer, RDPDataLayerObserver(**kwargs))

    def getEffectiveType(self, pdu):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                return pdu.errorInfo
            else:
                return pdu.header.subtype
        else:
            return pdu.header.type


class MITMFastPathObserver(MITMChannelObserver):
    def __init__(self, log, layer):
        """
        :type layer: rdpy.core.layer.Layer
        """
        MITMChannelObserver.__init__(self, log, layer, RDPFastPathDataLayerObserver())

    def getEffectiveType(self, pdu):
        return str(pdu)