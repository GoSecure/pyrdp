#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.buffered import BufferedLayer
from pyrdp.parser import TPKTParser
from pyrdp.pdu import PDU, TPKTPDU


class TPKTLayer(BufferedLayer):
    """
    Layer for handling TPKT-related traffic.
    """

    def __init__(self, parser = TPKTParser()):
        BufferedLayer.__init__(self, parser)

    def sendBytes(self, data: bytes):
        pdu = TPKTPDU(data)
        self.sendPDU(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True