#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.core import ObservedBy
from pyrdp.enum import MCSPDUType
from pyrdp.layer.layer import IntermediateLayer, Layer, LayerStrictRoutedObserver
from pyrdp.parser import MCSParser
from pyrdp.pdu import MCSConnectInitialPDU, MCSDomainParams, PDU, MCSConnectResponsePDU, \
    MCSDisconnectProviderUltimatumPDU, MCSErectDomainRequestPDU, MCSAttachUserRequestPDU, MCSAttachUserConfirmPDU, \
    MCSChannelJoinRequestPDU, MCSChannelJoinConfirmPDU, MCSSendDataRequestPDU, MCSSendDataIndicationPDU


class MCSObserver(LayerStrictRoutedObserver):
    """
    Base observer class for MCS layers. Simply routes PDU types to methods.
    """
    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            MCSPDUType.CONNECT_INITIAL: "onConnectInitial",
            MCSPDUType.CONNECT_RESPONSE: "onConnectResponse",
            MCSPDUType.ERECT_DOMAIN_REQUEST: "onErectDomainRequest",
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: "onDisconnectProviderUltimatum",
            MCSPDUType.ATTACH_USER_REQUEST: "onAttachUserRequest",
            MCSPDUType.ATTACH_USER_CONFIRM: "onAttachUserConfirm",
            MCSPDUType.CHANNEL_JOIN_REQUEST: "onChannelJoinRequest",
            MCSPDUType.CHANNEL_JOIN_CONFIRM: "onChannelJoinConfirm",
            MCSPDUType.SEND_DATA_REQUEST: "onSendDataRequest",
            MCSPDUType.SEND_DATA_INDICATION: "onSendDataIndication",
        }, **kwargs)

    def onConnectInitial(self, pdu: MCSConnectInitialPDU):
        pass

    def onConnectResponse(self, pdu: MCSConnectResponsePDU):
        pass

    def onDisconnectProviderUltimatum(self, pdu: MCSDisconnectProviderUltimatumPDU):
        pass

    def onErectDomainRequest(self, pdu: MCSErectDomainRequestPDU):
        pass

    def onAttachUserRequest(self, pdu: MCSAttachUserRequestPDU):
        pass

    def onAttachUserConfirm(self, pdu: MCSAttachUserConfirmPDU):
        pass

    def onChannelJoinRequest(self, pdu: MCSChannelJoinRequestPDU):
        pass

    def onChannelJoinConfirm(self, pdu: MCSChannelJoinConfirmPDU):
        pass

    def onSendDataRequest(self, pdu: MCSSendDataRequestPDU):
        pass

    def onSendDataIndication(self, pdu: MCSSendDataIndicationPDU):
        pass


@ObservedBy(MCSObserver)
class MCSLayer(Layer):
    """
    Layer to handle MCS-related traffic.
    It doesn't really make sense to assign a single 'next' layer to this
    (since MCS is channel-based), so traffic is never forwarded.
    """

    def __init__(self, parser = MCSParser()):
        super().__init__(parser)

    def sendConnectInitial(self, payload = b"", callingDomain = b"\x01", calledDomain = b"\x01", upward = True,
                           targetParams = MCSDomainParams.createTarget(34, 2), minParams = MCSDomainParams.createMinimum(), maxParams = MCSDomainParams.createMaximum()):
        pdu = MCSConnectInitialPDU(callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload)
        self.sendPDU(pdu)


class MCSClientConnectionLayer(IntermediateLayer):
    """
    A layer to make it more simple to send MCS Connect Initial PDUs. Every parameter other than the payload is saved
    in this layer.
    """

    def __init__(self, mcs):
        """
        :param mcs: the MCS layer.
        :type mcs: MCSLayer
        """
        super().__init__(None)
        self.mcs = mcs
        self.callingDomain = b"\x01"
        self.calledDomain = b"\x01"
        self.upward = True
        self.targetParams = MCSDomainParams.createTarget(34, 2)
        self.minParams = MCSDomainParams.createMinimum()
        self.maxParams = MCSDomainParams.createMaximum()

    def recv(self, pdu):
        self.pduReceived(pdu)

    def sendBytes(self, data):
        pdu = MCSConnectInitialPDU(self.callingDomain, self.calledDomain, self.upward, self.targetParams, self.minParams, self.maxParams, data)
        self.mcs.sendPDU(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True