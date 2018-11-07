from rdpy.core import log
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.layer.rdp.data import RDPDataLayerObserver, RDPFastPathDataLayerObserver
from rdpy.pdu.rdp.fastpath import RDPFastPathPDU


class MITMChannelObserver:
    def __init__(self, layer, innerObserver, recorder, name=""):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type name: str
        """
        self.recorder = recorder
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
        if isinstance(pdu, RDPFastPathPDU):
            self.recorder.record(pdu, RDPPlayerMessageType.OUTPUT if self.name == "Client" else RDPPlayerMessageType.INPUT)
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
    def __init__(self, layer, recorder, name="", **kwargs):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type name: str
        """
        MITMChannelObserver.__init__(self, layer, RDPDataLayerObserver(**kwargs), recorder, name)

    def getEffectiveType(self, pdu):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                return pdu.errorInfo
            else:
                return pdu.header.subtype
        else:
            return pdu.header.type


class MITMFastPathObserver(MITMChannelObserver):
    def __init__(self, layer, recorder, name=""):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type name: str
        """
        MITMChannelObserver.__init__(self, layer, RDPFastPathDataLayerObserver(), recorder, name)

    def getEffectiveType(self, pdu):
        return str(pdu)

    def onPDUReceived(self, pdu):
        if pdu.header == 3:
            return
        MITMChannelObserver.onPDUReceived(self, pdu)