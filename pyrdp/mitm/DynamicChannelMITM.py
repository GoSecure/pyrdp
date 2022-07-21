#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import binascii
from logging import LoggerAdapter
from typing import Dict

from pyrdp.core import Subject
from pyrdp.layer.rdp.virtual_channel.dynamic_channel import DynamicChannelLayer
from pyrdp.logging.StatCounter import STAT, StatCounter
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu.rdp.virtual_channel.dynamic_channel import CreateRequestPDU, DataPDU, \
    DynamicChannelPDU


class DynamicChannelMITM(Subject):
    """
    MITM component for the dynamic virtual channels (drdynvc).
    """

    def __init__(self, client: DynamicChannelLayer, server: DynamicChannelLayer, log: LoggerAdapter,
                 statCounter: StatCounter, state: RDPMITMState):
        """
        :param client: DynamicChannel layer for the client side
        :param server: DynamicChannel layer for the server side
        :param log: logger for this component
        :param statCounter: Object to keep miscellaneous stats for the current connection
        :param state: the state of the PyRDP MITM connection.
        """
        super().__init__()

        self.client = client
        self.server = server
        self.state = state
        self.log = log
        self.statCounter = statCounter

        self.channels: Dict[int, str] = {}

        self.client.createObserver(
            onPDUReceived=self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
        )

    def onClientPDUReceived(self, pdu: DynamicChannelPDU):
        self.statCounter.increment(STAT.DYNAMIC_CHANNEL_CLIENT, STAT.DYNAMIC_CHANNEL)
        self.handlePDU(pdu, self.server)

    def onServerPDUReceived(self, pdu: DynamicChannelPDU):
        self.statCounter.increment(STAT.DYNAMIC_CHANNEL_SERVER, STAT.DYNAMIC_CHANNEL)
        self.handlePDU(pdu, self.client)

    def handlePDU(self, pdu: DynamicChannelPDU, destination: DynamicChannelLayer):
        """
        Handle the logic for a PDU and send the PDU to its destination.
        :param pdu: the PDU that was received
        :param destination: the destination layer
        """
        if isinstance(pdu, CreateRequestPDU):
            self.channels[pdu.channelId] = pdu.channelName
            self.log.info("Dynamic virtual channel creation received: ID: %(channelId)d Name: %(channelName)s", {"channelId": pdu.channelId, "channelName": pdu.channelName})
        elif isinstance(pdu, DataPDU):
            if pdu.channelId not in self.channels:
                self.log.error("Received a data PDU in an unkown channel: %(channelId)s", {"channelId": pdu.channelId})
            else:
                self.log.debug("Data PDU for channel %(channelName)s: %(data)s", {"data": binascii.hexlify(pdu.payload), "channelName": self.channels[pdu.channelId]})
        else:
            self.log.debug("Dynamic Channel PDU received: %(dynVcPdu)s", {"dynVcPdu": pdu})

        destination.sendPDU(pdu)
