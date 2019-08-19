#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.pdu import PDU


class TCPPDU(PDU):
    """
    A TCP PDU (contains only the TCP payload).
    """
    def __init__(self, payload: bytes):
        super().__init__(payload)