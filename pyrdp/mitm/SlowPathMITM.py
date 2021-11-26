#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter

from pyrdp.enum import CapabilityType, KeyboardFlag, OrderFlag, VirtualChannelCompressionFlag, Order
from pyrdp.layer import SlowPathLayer, SlowPathObserver
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import Capability, ConfirmActivePDU, DemandActivePDU, InputPDU, KeyboardEvent, SlowPathPDU, MouseEvent
from pyrdp.mitm.BasePathMITM import BasePathMITM


class SlowPathMITM(BasePathMITM):
    """
    MITM component for the slow-path layer.
    """

    def __init__(self, client: SlowPathLayer, server: SlowPathLayer, state: RDPMITMState, statCounter: StatCounter, log: LoggerAdapter):
        """
        :param client: slow-path layer for the client side
        :param server: slow-path layer for the server side
        """
        super().__init__(state, client, server, statCounter, log)

        self.clientObserver = self.client.createObserver(
            onPDUReceived=self.onClientPDUReceived,
            onConfirmActive=self.onConfirmActive
        )

        self.serverObserver = self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
            onDemandActive=self.onDemandActive,
        )

    def onClientPDUReceived(self, pdu: SlowPathPDU):
        self.statCounter.increment(STAT.IO_INPUT_SLOWPATH)
        SlowPathObserver.onPDUReceived(self.clientObserver, pdu)

        if self.state.forwardInput:
            self.server.sendPDU(pdu)

        if not self.state.loggedIn:
            if isinstance(pdu, InputPDU):
                for event in pdu.events:
                    if isinstance(event, KeyboardEvent):
                        self.onScanCode(event.keyCode, event.flags & KeyboardFlag.KBDFLAGS_DOWN == 0,
                                        event.flags & KeyboardFlag.KBDFLAGS_EXTENDED != 0)
                    elif isinstance(event, MouseEvent):
                        self.onMouse(event.x, event.y, event.flags)

    def onServerPDUReceived(self, pdu: SlowPathPDU):
        self.statCounter.increment(STAT.IO_OUTPUT_SLOWPATH)
        SlowPathObserver.onPDUReceived(self.serverObserver, pdu)

        if self.state.forwardOutput:
            self.client.sendPDU(pdu)

    def onConfirmActive(self, pdu: ConfirmActivePDU):
        """
        Disable drawing orders and other unimplemented features.
        :param pdu: the confirm active PDU
        """

        if self.state.config.downgrade:

            # Disable surface commands
            if CapabilityType.CAPSETTYPE_SURFACE_COMMANDS in pdu.parsedCapabilitySets:
                pdu.parsedCapabilitySets[CapabilityType.CAPSETTYPE_SURFACE_COMMANDS].cmdFlags = 0

            # Disable GDI if not explicitly requested.
            if not self.state.config.useGdi:
                # Force RDP server to send bitmap events instead of order events.
                pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderFlags = \
                    OrderFlag.NEGOTIATEORDERSUPPORT | OrderFlag.ZEROBOUNDSDELTASSUPPORT
                pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderSupport = b"\x00" * 32

                # Override the bitmap cache capability set with null values.
                if CapabilityType.CAPSTYPE_BITMAPCACHE in pdu.parsedCapabilitySets:
                    pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAPCACHE] = Capability(
                        CapabilityType.CAPSTYPE_BITMAPCACHE, b"\x00" * 36)
            else:
                # Disable NineGrid support (Not implemented in Player)
                if CapabilityType.CAPSTYPE_ORDER in pdu.parsedCapabilitySets:
                    orders = pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER]
                    supported = bytearray(orders.orderSupport)
                    supported[Order.TS_NEG_DRAWNINEGRID_INDEX] = 0
                    orders.orderSupport = supported

                if CapabilityType.CAPSTYPE_DRAWNINEGRIDCACHE in pdu.parsedCapabilitySets:
                    pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_DRAWNINEGRIDCACHE].rawData = b"\x00"*8

        # Disable virtual channel compression
        if CapabilityType.CAPSTYPE_VIRTUALCHANNEL in pdu.parsedCapabilitySets:
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = \
                VirtualChannelCompressionFlag.VCCAPS_NO_COMPR

    def onDemandActive(self, pdu: DemandActivePDU):
        """
        Disable virtual channel compression.
        :param pdu: the demand active PDU
        """

        if CapabilityType.CAPSTYPE_ORDER in pdu.parsedCapabilitySets:
            orders = pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER]
            supported = bytearray(orders.orderSupport)
            supported[Order.TS_NEG_DRAWNINEGRID_INDEX] = 0
            orders.orderSupport = supported

        if CapabilityType.CAPSTYPE_VIRTUALCHANNEL in pdu.parsedCapabilitySets:
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = \
                VirtualChannelCompressionFlag.VCCAPS_NO_COMPR
