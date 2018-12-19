#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class NegotiationRequestFlags(IntEnum):
    """
    Negotiation request flags.
    """
    CORRELATION_INFO_PRESENT = 8

class NegotiationType(IntEnum):
    """
    Negotiation data structure type.
    """
    TYPE_RDP_NEG_REQ = 0x01
    TYPE_RDP_NEG_RSP = 0x02
    TYPE_RDP_NEG_FAILURE = 0x03
    TYPE_RDP_CORRELATION_INFO = 0x06