#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import GCCPDUType
from pyrdp.pdu.pdu import PDU


class GCCPDU(PDU):
    """
    Base PDU class for GCC (T.124) PDUs. Every GCC PDU has a header and a payload.
    """

    def __init__(self, header: GCCPDUType, payload: bytes):
        """
        :param header: GCC PDU type.
        :param payload: GCC's payload (so probably some RDP connection data).
        """

        PDU.__init__(self, payload)
        self.header = header


class GCCConferenceCreateRequestPDU(GCCPDU):
    def __init__(self, conferenceName: str, payload: bytes):
        """
        :param conferenceName: the GCC conference name.
        :param payload: GCC's payload (so probably some RDP connection data).
        """
        GCCPDU.__init__(self, GCCPDUType.CREATE_CONFERENCE_REQUEST, payload)
        self.conferenceName = conferenceName


class GCCConferenceCreateResponsePDU(GCCPDU):
    def __init__(self, nodeID: int, tag: int, result: int, payload: bytes):
        """
        :param nodeID: GCC node ID.
        :param tag: GCC tag.
        :param result: response result.
        :param payload: GCC's payload (so probably some RDP connection data).
        """
        GCCPDU.__init__(self, GCCPDUType.CREATE_CONFERENCE_RESPONSE, payload)
        self.nodeID = nodeID
        self.tag = tag
        self.result = result
