#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.parser import Parser
from pyrdp.pdu import PDU


class RawParser(Parser):
    """
    This parser transforms bytes into raw PDUs.
    This is mostly for convenience and to make everything fit together.
    The use case for this is for layers with PDUs that we're not really interested in parsing.
    """

    def parse(self, data: bytes) -> PDU:
        return PDU(data)

    def write(self, pdu: PDU) -> bytes:
        return pdu.payload