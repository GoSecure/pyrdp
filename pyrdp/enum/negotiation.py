#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum, IntFlag


class NegotiationType(IntEnum):
    """
    Negotiation data structure type.
    """
    TYPE_RDP_NEG_REQ = 0x01
    TYPE_RDP_NEG_RSP = 0x02
    TYPE_RDP_NEG_FAILURE = 0x03
    TYPE_RDP_CORRELATION_INFO = 0x06


class NegotiationRequestFlags(IntEnum):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
    """
    NONE = 0x00
    RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
    REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
    CORRELATION_INFO_PRESENT = 0x08


class NegotiationResponseFlags(IntFlag):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
    """
    NONE = 0x00
    EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
    DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
    NEGRSP_FLAG_RESERVED = 0x04
    RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
    REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10

