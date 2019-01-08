#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core import ObservedBy
from pyrdp.enum import X224PDUType
from pyrdp.layer.layer import IntermediateLayer, LayerStrictRoutedObserver
from pyrdp.parser import X224Parser
from pyrdp.pdu import X224ConnectionConfirmPDU, X224ConnectionRequestPDU, X224DataPDU, X224DisconnectRequestPDU, \
    X224ErrorPDU, X224PDU


class X224Observer(LayerStrictRoutedObserver):
    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            X224PDUType.X224_TPDU_CONNECTION_REQUEST: "onConnectionRequest",
            X224PDUType.X224_TPDU_CONNECTION_CONFIRM: "onConnectionConfirm",
            X224PDUType.X224_TPDU_DISCONNECT_REQUEST: "onDisconnectRequest",
            X224PDUType.X224_TPDU_DATA: "onData",
            X224PDUType.X224_TPDU_ERROR: "onError"
        }, **kwargs)

    def onConnectionRequest(self, pdu: X224ConnectionRequestPDU):
        """
        Called when a Connection Request PDU is received.
        """
        pass

    def onConnectionConfirm(self, pdu: X224ConnectionConfirmPDU):
        """
        Called when a Connection Confirm PDU is received.
        """
        pass

    def onDisconnectRequest(self, pdu: X224DisconnectRequestPDU):
        """
        Called when a Disconnect Request PDU is received.
        """
        pass

    def onData(self, pdu: X224DataPDU):
        """
        Called when a Data PDU is received.
        """
        pass

    def onError(self, pdu: X224ErrorPDU):
        """
        Called when an Error PDU is received.
        """
        pass


@ObservedBy(X224Observer)
class X224Layer(IntermediateLayer):
    """
    Layer to handle X224-related traffic
    ObservedBy: X224Observer
    """

    def __init__(self, parser = X224Parser()):
        super().__init__(parser)

    def sendBytes(self, data: bytes, roa: bool = False, eot: bool = True):
        """
        Encapsulate the payload in a X.224 Data PDU and send it to the previous layer.
        :param data: bytes to send.
        :param eot: End of transmission.
        :param roa: Request of acknowledgement
        """

        pdu = X224DataPDU(roa, eot, data)
        self.previous.sendBytes(self.mainParser.write(pdu))

    def shouldForward(self, pdu: X224PDU) -> bool:
        return pdu.header == X224PDUType.X224_TPDU_DATA

    def sendConnectionRequest(self, payload: bytes, credit = 0, destination = 0, source = 0, options = 0):
        """
        :param payload: the connection request payload.
        :param credit: the PDU's credit property.
        :param destination: the PDU's destination property.
        :param source: the PDU's source property.
        :param options: the PDU's options property.
        """
        pdu = X224ConnectionRequestPDU(credit, destination, source, options, payload)
        self.sendPDU(pdu)

    def sendConnectionConfirm(self, payload: bytes, credit = 0, destination = 0, source = 0, options = 0):
        """
        :param payload: the connection confirm payload.
        :param credit: the PDU's credit property.
        :param destination: the PDU's destination property.
        :param source: the PDU's source property.
        :param options: the PDU's options property.
        """
        pdu = X224ConnectionConfirmPDU(credit, destination, source, options, payload)
        self.sendPDU(pdu)

    def sendDisconnectRequest(self, reason: int, destination = 0, source = 0, payload = b""):
        """
        :param payload: the PDU's payload bytes.
        :param reason: the disconnection reason.
        :param destination: the PDU's destination property.
        :param source: the PDU's source property.
        """

        pdu = X224DisconnectRequestPDU(destination, source, reason, payload)
        self.sendPDU(pdu)

    def sendError(self, cause: int, destination = 0):
        """
        :param cause: the error cause.
        :param destination: the PDU's destination property.
        """
        pdu = X224ErrorPDU(destination, cause)
        self.sendPDU(pdu)
