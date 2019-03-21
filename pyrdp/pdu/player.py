#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import PlayerPDUType
from pyrdp.pdu.pdu import PDU


class PlayerPDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, header: PlayerPDUType, timestamp: int, payload: bytes):
        self.header = header  # Uint16LE
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)
