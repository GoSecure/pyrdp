#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.parser import Parser
from pyrdp.pdu import PDU
from pyrdp.pdu.tcp import TCPPDU


class TCPParser(Parser):
    def doParse(self, data: bytes) -> TCPPDU:
        return TCPPDU(data)

    def write(self, pdu: PDU) -> bytes:
        return pdu.payload