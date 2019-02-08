#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import CapabilityType, OrderFlag, VirtualChannelCompressionFlag
from pyrdp.layer import SlowPathLayer, SlowPathObserver
from pyrdp.pdu import Capability, ConfirmActivePDU, DemandActivePDU, SlowPathPDU


class SlowPathMITM:
    """
    MITM component for the slow-path layer.
    """

    def __init__(self, client: SlowPathLayer, server: SlowPathLayer):
        """
        :param client: slow-path layer for the client side
        :param server: slow-path layer for the server side
        """
        self.client = client
        self.server = server

        self.clientObserver = self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived,
            onUnparsedData = self.onClientUnparsedData,
            onConfirmActive = self.onConfirmActive
        )

        self.serverObserver = self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
            onUnparsedData=self.onServerUnparsedData,
            onDemandActive=self.onDemandActive,
        )

    def onClientPDUReceived(self, pdu: SlowPathPDU):
        SlowPathObserver.onPDUReceived(self.clientObserver, pdu)
        self.server.sendPDU(pdu)

    def onClientUnparsedData(self, data):
        self.server.sendBytes(data)

    def onServerPDUReceived(self, pdu: SlowPathPDU):
        SlowPathObserver.onPDUReceived(self.serverObserver, pdu)
        self.client.sendPDU(pdu)

    def onServerUnparsedData(self, data):
        self.client.sendBytes(data)

    def onConfirmActive(self, pdu: ConfirmActivePDU):
        """
        Disable drawing orders and other unimplemented features.
        :param pdu: the confirm active PDU
        """

        # Force RDP server to send bitmap events instead of order events.
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderFlags = OrderFlag.NEGOTIATEORDERSUPPORT | OrderFlag.ZEROBOUNDSDELTASSUPPORT
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderSupport = b"\x00" * 32

        # Disable virtual channel compression
        if CapabilityType.CAPSTYPE_VIRTUALCHANNEL in pdu.parsedCapabilitySets:
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = VirtualChannelCompressionFlag.VCCAPS_NO_COMPR

        # Override the bitmap cache capability set with null values.
        if CapabilityType.CAPSTYPE_BITMAPCACHE in pdu.parsedCapabilitySets:
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAPCACHE] = Capability(CapabilityType.CAPSTYPE_BITMAPCACHE, b"\x00" * 36)

        # Disable surface commands
        if CapabilityType.CAPSETTYPE_SURFACE_COMMANDS in pdu.parsedCapabilitySets:
            pdu.parsedCapabilitySets[CapabilityType.CAPSETTYPE_SURFACE_COMMANDS].cmdFlags = 0

    def onDemandActive(self, pdu: DemandActivePDU):
        """
        Disable virtual channel compression.
        :param pdu: the demand active PDU
        """

        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = VirtualChannelCompressionFlag.VCCAPS_NO_COMPR
