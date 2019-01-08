#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core import Observer


class MITMVirtualChannelObserver(Observer):
    """
    Simple MITM observer that forwards all data straight to its peer without logging anything.
    """

    def __init__(self, layer, **kwargs):
        Observer.__init__(self, **kwargs)
        self.peer = None
        self.layer = layer

    def onPDUReceived(self, pdu):
        """
        Called when a PDU on the observed layer is received.
        :param pdu: the PDU that was received.
        """
        if self.peer:
            self.peer.sendData(pdu.payload)

    def sendData(self, data):
        """
        Send data through the layer.
        :param data: data to send.
        :type data: bytes
        """
        self.layer.sendBytes(data)
