import logging

from rdpy.core.observer import Observer
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.layer.rdp.data import RDPDataLayerObserver, RDPFastPathDataLayerObserver
from rdpy.pdu.rdp.data import RDPConfirmActivePDU
from rdpy.pdu.rdp.fastpath import RDPFastPathPDU


class MITMChannelObserver(Observer):
    def __init__(self, layer, innerObserver, recorder, mode, **kwargs):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type mode: ParserMode
        """
        Observer.__init__(self, **kwargs)
        self.mitm_log = logging.getLogger("mitm.{}".format("client" if mode == ParserMode.CLIENT else "server"))
        self.recorder = recorder
        self.layer = layer
        self.innerObserver = innerObserver
        self.mode = mode
        self.peer = None

        self.setDataHandler = self.innerObserver.setDataHandler
        self.setDefaultDataHandler = self.innerObserver.setDefaultDataHandler

    def setPeer(self, peer):
        self.peer = peer
        peer.peer = self

    def onPDUReceived(self, pdu):
        self.mitm_log.debug("Received {}".format(str(self.getEffectiveType(pdu))))
        if isinstance(pdu, RDPFastPathPDU):
            self.recorder.record(pdu, RDPPlayerMessageType.OUTPUT if self.mode == ParserMode.CLIENT else RDPPlayerMessageType.INPUT)
        elif isinstance(pdu, RDPConfirmActivePDU):
            self.recorder.record(pdu, RDPPlayerMessageType.CONFIRM_ACTIVE)

        self.innerObserver.onPDUReceived(pdu)
        self.peer.sendPDU(pdu)

    def onUnparsedData(self, data):
        self.mitm_log.debug("Received unparsed data: {}".format(data.encode('hex')))
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        self.mitm_log.debug("Sending {}".format(str(self.getEffectiveType(pdu))))
        self.layer.sendPDU(pdu)

    def sendData(self, data):
        self.mitm_log.debug("Sending data: {}".format(data.encode('hex')))
        self.layer.sendData(data)

    def getEffectiveType(self, pdu):
        return NotImplementedError("getEffectiveType must be overridden")


class MITMSlowPathObserver(MITMChannelObserver):
    def __init__(self, layer, recorder, mode, **kwargs):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type mode: ParserMode
        """
        MITMChannelObserver.__init__(self, layer, RDPDataLayerObserver(**kwargs), recorder, mode)

    def getEffectiveType(self, pdu):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                return pdu.errorInfo
            else:
                return pdu.header.subtype
        else:
            return pdu.header.type


class MITMFastPathObserver(MITMChannelObserver):
    def __init__(self, layer, recorder, mode):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type mode: ParserMode
        """
        MITMChannelObserver.__init__(self, layer, RDPFastPathDataLayerObserver(), recorder, mode)

    def getEffectiveType(self, pdu):
        return str(pdu)

    def onPDUReceived(self, pdu):
        if pdu.header == 3:
            return
        MITMChannelObserver.onPDUReceived(self, pdu)



class MITMVirtualChannelObserver(Observer):
    """
    Simple MITM observer that forwards all data straight to its peer without logging anything.
    """

    def __init__(self, layer, **kwargs):
        Observer.__init__(self, **kwargs)
        self.peer = None
        self.layer = layer

    def setPeer(self, peer):
        """
        Set this observer's peer observer.
        :param peer: other observer.
        :type peer: MITMVirtualChannelObserver
        """
        self.peer = peer
        peer.peer = self

    def onPDUReceived(self, pdu):
        """
        Called when a PDU on the observed layer is received.
        :param pdu: the PDU that was received.
        """
        if self.peer:
            self.peer.sendData(pdu.payload)

    def sendData(self, data):
        """
        Send data through the layer.
        :param data: data to send.
        :type data: str
        """
        self.layer.send(data)
