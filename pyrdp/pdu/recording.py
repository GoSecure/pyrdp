#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import PlayerMessageType
from pyrdp.pdu.pdu import PDU


class PlayerMessagePDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, header: PlayerMessageType, timestamp: int, payload: bytes):
        self.header = header  # Uint8
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)
