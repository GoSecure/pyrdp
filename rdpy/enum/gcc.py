from enum import IntEnum


class GCCPDUType(IntEnum):
    """
    PDU types for GCC messages received in MCS Connect Initial PDUs.
    """
    CREATE_CONFERENCE_REQUEST = 0
    CREATE_CONFERENCE_RESPONSE = 0x14