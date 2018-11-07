from rdpy.core import log
from rdpy.core.newlayer import Layer, LayerStrictRoutedObserver, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPDataPDUType, RDPPlayerMessageType
from rdpy.exceptions import UnknownPDUTypeError
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.data import RDPDataParser


class RDPBaseDataLayerObserver:
    def __init__(self):
        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def dispatchPDU(self, pdu):
        type = self.getPDUType(pdu)

        if type in self.dataHandlers:
            self.dataHandlers[type](pdu)
        elif self.defaultDataHandler:
            self.defaultDataHandler(pdu)

    def onUnparsedData(self, data):
        if self.unparsedDataHandler is not None:
            self.unparsedDataHandler(data)

    def setDataHandler(self, type, handler):
        self.dataHandlers[type] = handler

    def setDefaultDataHandler(self, handler):
        self.defaultDataHandler = handler

    def setUnparsedDataHandler(self, handler):
        self.unparsedDataHandler = handler

    def getPDUType(self, pdu):
        raise NotImplementedError("getPDUType must be overridden")



class RDPDataLayerObserver(RDPBaseDataLayerObserver, LayerStrictRoutedObserver):
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
        self.dispatchPDU(pdu)

    def onDemandActive(self, pdu):
        pass

    def onConfirmActive(self, pdu):
        pass

    def onDeactivateAll(self, pdu):
        pass

    def onServerRedirect(self, pdu):
        pass



class RDPFastPathDataLayerObserver(RDPBaseDataLayerObserver, LayerObserver):
    def onPDUReceived(self, pdu):
        self.dispatchPDU(pdu)

    def getPDUType(self, pdu):
        return pdu.header & 0b11100000


class RDPBaseDataLayer(Layer):
    def __init__(self, fastPathParser):
        Layer.__init__(self)
        self.fastPathParser = fastPathParser
        self.clientInfoParser = RDPClientInfoParser()

    def recv(self, data):
        try:
            pdu = self.fastPathParser.parse(data)
        except UnknownPDUTypeError as e:
            log.error(str(e))
            if self.observer:
                self.observer.onUnparsedData(data)
        else:
            self.pduReceived(pdu, False)

    def sendPDU(self, pdu, messageType=None):
        if messageType == RDPPlayerMessageType.CLIENT_INFO:
            data = self.clientInfoParser.write(pdu)
        else:
            data = self.fastPathParser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)

@ObservedBy(RDPDataLayerObserver)
class RDPDataLayer(RDPBaseDataLayer):
    def __init__(self):
        RDPBaseDataLayer.__init__(self, RDPDataParser())
