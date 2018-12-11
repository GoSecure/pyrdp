from pyrdp.core import ObservedBy
from pyrdp.enum import CapabilityType, SlowPathPDUType, VirtualChannelCompressionFlag
from pyrdp.exceptions import UnknownPDUTypeError
from pyrdp.layer.layer import Layer, LayerStrictRoutedObserver
from pyrdp.layer.rdp.data import RDPDataObserver
from pyrdp.logging import log
from pyrdp.parser import SlowPathParser
from pyrdp.pdu import ConfirmActivePDU, DemandActivePDU, SlowPathPDU


class SlowPathObserver(RDPDataObserver, LayerStrictRoutedObserver):
    """
    Observer for slow-path PDUs.
    """

    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            SlowPathPDUType.DEMAND_ACTIVE_PDU: "onDemandActive",
            SlowPathPDUType.CONFIRM_ACTIVE_PDU: "onConfirmActive",
            SlowPathPDUType.DEACTIVATE_ALL_PDU: "onDeactivateAll",
            SlowPathPDUType.DATA_PDU: "onData",
            SlowPathPDUType.SERVER_REDIR_PKT_PDU: "onServerRedirect",
        }, **kwargs)

        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def getPDUType(self, pdu: SlowPathPDU):
        return pdu.header.subtype

    def onPDUReceived(self, pdu: SlowPathPDU):
        if pdu.header.pduType in self.handlers:
            self.handlers[pdu.header.pduType](pdu)
        else:
            self.onUnknownHeader(pdu)

    def onData(self, pdu):
        """
        Called when a data PDU is received.
        :param pdu: the pdu.
        """
        self.dispatchPDU(pdu)

    def onDemandActive(self, pdu: DemandActivePDU):
        """
        Called when a Demand Active PDU is received.
        Disable Virtual channel compression (unsupported for now).
        """
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = VirtualChannelCompressionFlag.VCCAPS_NO_COMPR
        pass

    def onConfirmActive(self, pdu: ConfirmActivePDU):
        """
        Change the received ConfirmActivePDU to facilitate data interception.
        """
        pass

    def onDeactivateAll(self, pdu):
        """
        Called when a Deactive All PDU is received.
        :param pdu: the PDU.
        """
        pass

    def onServerRedirect(self, pdu):
        """
        Called when a Server Redirect PDU is received.
        :param pdu: the PDU.
        """
        pass

@ObservedBy(SlowPathObserver)
class SlowPathLayer(Layer):
    """
    Layer for slow-path PDUs.
    """

    def __init__(self, parser = SlowPathParser()):
        Layer.__init__(self, parser, hasNext=False)

    def recv(self, data):
        try:
            pdu = self.mainParser.parse(data)
        except UnknownPDUTypeError as e:
            log.debug(str(e))
            if self.observer:
                self.observer.onUnparsedData(data)
        else:
            self.pduReceived(pdu, self.hasNext)

    def sendPDU(self, pdu):
        data = self.mainParser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)
