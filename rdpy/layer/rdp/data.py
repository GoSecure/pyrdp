from rdpy.core import log
from rdpy.core.newlayer import Layer, LayerStrictRoutedObserver, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPDataPDUType, RDPPlayerMessageType
from rdpy.exceptions import UnknownPDUTypeError
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.data import RDPDataParser
from rdpy.parser.rdp.virtual_channel.clipboard.clipboard import ClipboardParser
from rdpy.pdu.rdp.data import RDPDemandActivePDU


class RDPBaseDataLayerObserver:
    """
    Base observer class for RDP data layers.
    A handler can be set for each data PDU type. A default handler can also be used.
    You can also set a handler for when data that could not be parsed was received.
    """

    def __init__(self):
        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def dispatchPDU(self, pdu):
        """
        Call the proper handler depending on the PDU's type.
        :param pdu: the PDU that was received.
        """
        type = self.getPDUType(pdu)

        if type in self.dataHandlers:
            self.dataHandlers[type](pdu)
        elif self.defaultDataHandler:
            self.defaultDataHandler(pdu)

    def onUnparsedData(self, data):
        """
        Called when data that could not be parsed was received.
        :type data: str
        """
        if self.unparsedDataHandler is not None:
            self.unparsedDataHandler(data)

    def setDataHandler(self, type, handler):
        """
        Set a handler for a particular data PDU type.
        :type type: RDPDataPDUType
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

    def getPDUType(self, pdu):
        """
        Get the PDU type for a given PDU.
        :param pdu: the PDU.
        """
        raise NotImplementedError("getPDUType must be overridden")



class RDPDataLayerObserver(RDPBaseDataLayerObserver, LayerStrictRoutedObserver):
    """
    Layer for non fast-path data PDUs.
    """

    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            RDPDataPDUType.DEMAND_ACTIVE_PDU: "onDemandActive",
            RDPDataPDUType.CONFIRM_ACTIVE_PDU: "onConfirmActive",
            RDPDataPDUType.DEACTIVATE_ALL_PDU: "onDeactivateAll",
            RDPDataPDUType.DATA_PDU: "onData",
            RDPDataPDUType.SERVER_REDIR_PKT_PDU: "onServerRedirect",
        }, **kwargs)

        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def getPDUType(self, pdu):
        return pdu.header.subtype

    def onPDUReceived(self, pdu):
        if pdu.header.type in self.handlers:
            self.handlers[pdu.header.type](pdu)
        else:
            self.onUnknownHeader(self, pdu)

    def onData(self, pdu):
        """
        Called when a data PDU is received.
        :param pdu: the pdu.
        """
        self.dispatchPDU(pdu)

    def onDemandActive(self, pdu):
        """
        Called when a Demand Active PDU is received
        :type pdu: RDPDemandActivePDU
        """
        pass

    def onConfirmActive(self, pdu):
        """
        Change the received ConfirmActivePDU to facilitate data interception.
        :type pdu: rdpy.pdu.rdp.data.RDPConfirmActivePDU
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



class RDPFastPathDataLayerObserver(RDPBaseDataLayerObserver, LayerObserver):
    """
    Base observer class for fast-path PDUs.
    """

    def onPDUReceived(self, pdu):
        self.dispatchPDU(pdu)

    def getPDUType(self, pdu):
        # The PDU type is stored in the last 3 bits
        return pdu.header & 0b11100000


class RDPBaseDataLayer(Layer):
    """
    Base for all RDP data layers.
    """

    def __init__(self, dataParser):
        Layer.__init__(self)
        self.dataParser = dataParser
        self.clientInfoParser = RDPClientInfoParser()
        self.rdpDataParser = RDPDataParser()
        self.clipboardParser = ClipboardParser()

    def recv(self, data):
        try:
            pdu = self.dataParser.parse(data)
        except UnknownPDUTypeError as e:
            log.error(str(e))
            if self.observer:
                self.observer.onUnparsedData(data)
        else:
            self.pduReceived(pdu, False)

    def sendPDU(self, pdu, messageType=None):
        if messageType == RDPPlayerMessageType.CLIENT_INFO:
            data = self.clientInfoParser.write(pdu)
        elif messageType == RDPPlayerMessageType.CONFIRM_ACTIVE:
            data = self.rdpDataParser.write(pdu)
        elif messageType == RDPPlayerMessageType.CLIPBOARD_DATA:
            data = self.clipboardParser.write(pdu)
        else:
            data = self.dataParser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)

@ObservedBy(RDPDataLayerObserver)
class RDPDataLayer(RDPBaseDataLayer):
    def __init__(self):
        RDPBaseDataLayer.__init__(self, RDPDataParser())
