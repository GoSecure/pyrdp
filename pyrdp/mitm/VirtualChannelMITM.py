#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import RawLayer
from pyrdp.pdu import PDU


class VirtualChannelMITM:
    """
    Generic MITM component for any virtual channel.
    """

    def __init__(self, client: RawLayer, server: RawLayer):
        """
        :param client: layer for the client side
        :param server: layer for the server side
        """

        self.client = client
        self.server = server

        self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived
        )

        self.server.createObserver(
            onPDUReceived = self.onServerPDUReceived
        )

    def onClientPDUReceived(self, pdu: PDU):
        """
        Forward the PDU to the server.
        :param pdu: the PDU that was received
        """

        self.server.sendPDU(pdu)

    def onServerPDUReceived(self, pdu: PDU):
        """
        Forward the PDU to the client.
        :param pdu: the PDU that was received
        """

        self.client.sendPDU(pdu)