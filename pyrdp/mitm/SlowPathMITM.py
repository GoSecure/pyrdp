#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import CapabilityType, KeyboardFlag, OrderFlag, VirtualChannelCompressionFlag
from pyrdp.layer import SlowPathLayer, SlowPathObserver
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import Capability, ConfirmActivePDU, DemandActivePDU, InputPDU, KeyboardEvent, SlowPathPDU
from pyrdp.mitm.BasePathMITM import BasePathMITM

class SlowPathMITM(BasePathMITM):
    """
    MITM component for the slow-path layer.
    """

    def __init__(self, client: SlowPathLayer, server: SlowPathLayer, state: RDPMITMState):
        """
        :param client: slow-path layer for the client side
        :param server: slow-path layer for the server side
        """
        super().__init__(state, client, server)

        self.clientObserver = self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived,
            onConfirmActive = self.onConfirmActive
        )

        self.serverObserver = self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
            onDemandActive=self.onDemandActive,
        )

    def onClientPDUReceived(self, pdu: SlowPathPDU):
        SlowPathObserver.onPDUReceived(self.clientObserver, pdu)

        if self.state.forwardInput:
            self.server.sendPDU(pdu)

        if not self.state.loggedIn:
            if isinstance(pdu, InputPDU):
                for event in pdu.events:
                    if isinstance(event, KeyboardEvent):
                        self.onScanCode(event.keyCode, event.flags & KeyboardFlag.KBDFLAGS_DOWN == 0, event.flags & KeyboardFlag.KBDFLAGS_EXTENDED != 0)

    def onServerPDUReceived(self, pdu: SlowPathPDU):
        SlowPathObserver.onPDUReceived(self.serverObserver, pdu)

        if self.state.forwardOutput:
            self.client.sendPDU(pdu)

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
