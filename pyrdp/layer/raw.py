#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import Layer
from pyrdp.pdu import PDU


class RawLayer(Layer):
    """
    Simple layer that uses raw PDUs and always forwards data.
    """

    def recv(self, data):
        pdu = PDU(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        self.previous.send(data)