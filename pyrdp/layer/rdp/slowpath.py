from pyrdp.core import ObservedBy
from pyrdp.enum import CapabilityType, RDPSlowPathPDUType, VirtualChannelCompressionFlag
from pyrdp.exceptions import UnknownPDUTypeError
from pyrdp.layer.layer import Layer, LayerStrictRoutedObserver
from pyrdp.logging import log
from pyrdp.parser import RDPDataParser
from pyrdp.pdu import PDU, RDPConfirmActivePDU, RDPDemandActivePDU
from pyrdp.pdu.rdp.data import RDPDataPDU

class RDPDataLayerObserver:
    """
    Base observer class for RDP data layers.
    A handler can be set for each data PDU type. A default handler can also be used.
    You can also set a handler for when data that could not be parsed was received.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def dispatchPDU(self, pdu: PDU):
        """
        Call the proper handler depending on the PDU's type.
        :param pdu: the PDU that was received.
        """
        type = self.getPDUType(pdu)

        if type in self.dataHandlers:
            self.dataHandlers[type](pdu)
        elif self.defaultDataHandler:
            self.defaultDataHandler(pdu)

    def onUnparsedData(self, data: bytes):
        """
        Called when data that could not be parsed was received.
        :type data: bytes
        """
        if self.unparsedDataHandler is not None:
            self.unparsedDataHandler(data)

    def setDataHandler(self, type, handler):
        """
        Set a handler for a particular data PDU type.
        :type type: RDPSlowPathPDUType
        :type handler: callable object
        """
        self.dataHandlers[type] = handler

    def setDefaultDataHandler(self, handler):
        """
        Set the default handler.
        The default handler is called when a Data PDU is received that is not associated with a handler.
        :type handler: callable object
        """
        self.defaultDataHandler = handler

    def setUnparsedDataHandler(self, handler):
        """
        Set the handler used when data that could not be parsed is received.
        :type handler: callable object
        """
        self.unparsedDataHandler = handler

    def getPDUType(self, pdu: PDU):
        """
        Get the PDU type for a given PDU.
        :param pdu: the PDU.
        """
        raise NotImplementedError("getPDUType must be overridden")


class SlowPathLayerObserver(RDPDataLayerObserver, LayerStrictRoutedObserver):
    """
    Layer for non fast-path data PDUs.
    """

    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            RDPSlowPathPDUType.DEMAND_ACTIVE_PDU: "onDemandActive",
            RDPSlowPathPDUType.CONFIRM_ACTIVE_PDU: "onConfirmActive",
            RDPSlowPathPDUType.DEACTIVATE_ALL_PDU: "onDeactivateAll",
            RDPSlowPathPDUType.DATA_PDU: "onData",
            RDPSlowPathPDUType.SERVER_REDIR_PKT_PDU: "onServerRedirect",
        }, **kwargs)

        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def getPDUType(self, pdu: RDPDataPDU):
        return pdu.header.subtype

    def onPDUReceived(self, pdu: RDPDataPDU):
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

    def onDemandActive(self, pdu: RDPDemandActivePDU):
        """
        Called when a Demand Active PDU is received.
        Disable Virtual channel compression.
        :type pdu: RDPDemandActivePDU
        """
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = VirtualChannelCompressionFlag.VCCAPS_NO_COMPR
        pass

    def onConfirmActive(self, pdu: RDPConfirmActivePDU):
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

@ObservedBy(SlowPathLayerObserver)
class SlowPathLayer(Layer):
    """
    Base for all RDP data layers.
    """

    def __init__(self, parser = RDPDataParser()):
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
