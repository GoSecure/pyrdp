from enum import IntEnum


class MCSPDUType(IntEnum):
    """
    MCS PDU Headers
    """
    # Connection PDU headers
    CONNECT_INITIAL = 0x65
    CONNECT_RESPONSE = 0x66

    # Domain PDU headers
    ERECT_DOMAIN_REQUEST = 1
    DISCONNECT_PROVIDER_ULTIMATUM = 8
    ATTACH_USER_REQUEST = 10
    ATTACH_USER_CONFIRM = 11
    CHANNEL_JOIN_REQUEST = 14
    CHANNEL_JOIN_CONFIRM = 15
    SEND_DATA_REQUEST = 25
    SEND_DATA_INDICATION = 26


class MCSResult(IntEnum):
    """
    MCS Result enumeration.
    """
    RT_SUCCESSFUL = 0
    RT_UNSPECIFIED_FAILURE = 14
    RT_USER_REJECTED = 15


class MCSChannelID(IntEnum):
    """
    MCS Channel ID definitions.
    """
    USERCHANNEL_BASE = 1001