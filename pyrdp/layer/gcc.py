#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import IntermediateLayer
from pyrdp.parser import GCCParser
from pyrdp.pdu import GCCConferenceCreateRequestPDU, PDU


class GCCClientConnectionLayer(IntermediateLayer):
    """
    GCC Layer for parsing GCC conference PDUs.
    """
    def __init__(self, conferenceName: bytes, parser = GCCParser()):
        """
        :param conferenceName: the conference name
        """
        super().__init__(parser)
        self.conferenceName = conferenceName

    def sendBytes(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.sendPDU(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True
