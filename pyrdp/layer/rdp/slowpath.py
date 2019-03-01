#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core import ObservedBy
from pyrdp.enum import SlowPathPDUType
from pyrdp.layer.layer import Layer, LayerStrictRoutedObserver
from pyrdp.parser import SlowPathParser
from pyrdp.pdu import ConfirmActivePDU, DemandActivePDU, SlowPathPDU


class SlowPathObserver(LayerStrictRoutedObserver):
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

    def getPDUType(self, pdu: SlowPathPDU):
        """
        Get the PDU type for a given PDU.
        :param pdu: the PDU.
        """
        return pdu.header.subtype

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

    def dispatchPDU(self, pdu: SlowPathPDU):
        """
        Call the proper handler depending on the PDU's type.
        :param pdu: the PDU that was received.
        """
        type = self.getPDUType(pdu)

        if type in self.dataHandlers:
            self.dataHandlers[type](pdu)
        elif self.defaultDataHandler:
            self.defaultDataHandler(pdu)

    def onDemandActive(self, pdu: DemandActivePDU):
        """
        Called when a Demand Active PDU is received.
        Disable Virtual channel compression (unsupported for now).
        """
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
        Layer.__init__(self, parser)

    def sendBytes(self, data):
        self.previous.sendBytes(data)
