from enum import IntEnum


class PlayerMessageType(IntEnum):
    """
    Types of events that we can encounter when replaying a RDP connection.
    """

    FAST_PATH_INPUT = 1  # Ex: scancode, mouse
    FAST_PATH_OUTPUT = 2  # Ex: image
    CLIENT_INFO = 3  # Creds on connection
    SLOW_PATH_PDU = 4  # For slow-path PDUs
    CONNECTION_CLOSE = 5  # To advertise the end of the connection
    CLIPBOARD_DATA = 6  # To collect clipboard data
    CLIENT_DATA = 7  # Contains the clientName