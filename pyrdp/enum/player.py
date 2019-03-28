from enum import IntEnum


class PlayerPDUType(IntEnum):
    """
    Types of events that we can encounter when replaying a RDP connection.
    """

    FAST_PATH_INPUT = 1  # Ex: scan codes, mouse, etc.
    FAST_PATH_OUTPUT = 2  # Ex: image
    CLIENT_INFO = 3  # Creds on connection
    SLOW_PATH_PDU = 4  # For slow-path PDUs
    CONNECTION_CLOSE = 5  # To advertise the end of the connection
    CLIPBOARD_DATA = 6  # To collect clipboard data
    CLIENT_DATA = 7  # Contains the clientName
    MOUSE_MOVE = 8  # Mouse move event from the player
    MOUSE_BUTTON = 9  # Mouse button event from the player
    MOUSE_WHEEL = 10  # Mouse wheel event from the player
    KEYBOARD = 11  # Keyboard event from the player
    TEXT = 12  # Text event from the player


class MouseButton(IntEnum):
    """
    Mouse button types
    """
    LEFT_BUTTON = 1
    RIGHT_BUTTON = 2
    MIDDLE_BUTTON = 3