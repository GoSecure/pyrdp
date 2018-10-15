from twisted.internet import reactor

from rdpy.core import log
from rdpy.core.newlayer import Layer, LayerStrictRoutedObserver, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPDataPDUType, RDPDataPDUSubtype
from rdpy.parser.rdp import RDPDataParser
from rdpy.pdu.rdp.data import RDPShareControlHeader, RDPConfirmActivePDU

class RDPDataLayerObserver(LayerStrictRoutedObserver):
    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            RDPDataPDUType.PDUTYPE_DEMANDACTIVEPDU: "onDemandActive",
            RDPDataPDUType.PDUTYPE_CONFIRMACTIVEPDU: "onConfirmActive",
            RDPDataPDUType.PDUTYPE_DEACTIVATEALLPDU: "onDeactivateAll",
            RDPDataPDUType.PDUTYPE_DATAPDU: "onData",
            RDPDataPDUType.PDUTYPE_SERVER_REDIR_PKT: "onServerRedirect",
        }, **kwargs)

        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def onPDUReceived(self, pdu):
        if pdu.header.type in self.handlers:
            self.handlers[pdu.header.type](pdu)
        else:
            self.onUnknownHeader(self, pdu)

    def onData(self, pdu):
        if pdu.header.subtype in self.dataHandlers:
            self.dataHandlers[pdu.header.subtype](pdu)
        elif self.defaultDataHandler is not None:
            self.defaultDataHandler(pdu)

    def setDataHandler(self, subtype, handler):
        self.dataHandlers[subtype] = handler

    def setDefaultDataHandler(self, handler):
        self.defaultDataHandler = handler

    def setUnparsedDataHandler(self, handler):
        self.unparsedDataHandler = handler

    def onUnparsedData(self, data):
        if self.unparsedDataHandler is not None:
            self.unparsedDataHandler(data)

    def onDemandActive(self, pdu):
        raise Exception("Unhandled Demand Active PDU")

    def onConfirmActive(self, pdu):
        raise Exception("Unhandled Confirm Active PDU")

    def onDeactivateAll(self, pdu):
        raise Exception("Unhandled Deactivate All PDU")

    def onServerRedirect(self, pdu):
        raise Exception("Unhandled Server Redirect PDU")

@ObservedBy(RDPDataLayerObserver)
class RDPDataLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.parser = RDPDataParser()

    def recv(self, data):
        try:
            pdu = self.parser.parse(data)
        except Exception as e:
            log.error(str(e))
            self.observer.onUnparsedData(data)
        else:
            self.pduReceived(pdu, False)

    def sendPDU(self, pdu):
        self.previous.send(self.parser.write(pdu))