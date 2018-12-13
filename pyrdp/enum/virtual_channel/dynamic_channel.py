from enum import IntEnum


class CbId(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241267.aspx
    """
    ONE_BYTE = 0x00
    TWO_BYTE = 0x01
    FOUR_BYTES = 0x02
    INVALID = 0x03


class DynamicChannelCommand(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241267.aspx
    """
    CREATE = 0x01
    DATA_FIRST = 0x02
    DATA = 0x03
    CLOSE = 0x04
    CAPABILITY_REQUEST = 0x05
    DATA_FIRST_COMPRESSED = 0x06
    DATA_COMPRESSED = 0x07
    SOFT_SYNC_REQUEST = 0x08
    SOFT_SYNC_RESPONSE = 0x09
