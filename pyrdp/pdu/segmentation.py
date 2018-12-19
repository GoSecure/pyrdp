#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.pdu.pdu import PDU


class SegmentationPDU(PDU):
    def __init__(self, payload):
        """
        :type payload: bytes
        """
        PDU.__init__(self, payload)

    def getSegmentationType(self):
        raise NotImplementedError("getType must be overridden")

