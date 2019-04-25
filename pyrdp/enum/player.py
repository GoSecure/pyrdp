#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

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
    FORWARDING_STATE = 13  # Event from the player to change the state of I/O forwarding
    BITMAP = 14  # Bitmap event from the player
    DEVICE_MAPPING = 15  # Device mapping event notification
    DIRECTORY_LISTING_REQUEST = 16  # Directory listing request from the player
    DIRECTORY_LISTING_RESPONSE = 17  # Directory listing response to the player
    FILE_DOWNLOAD_REQUEST = 18  # File download request from the player
    FILE_DOWNLOAD_RESPONSE = 19  # File download response to the player
    FILE_DOWNLOAD_COMPLETE = 20  # File download completion notification to the player


class MouseButton(IntEnum):
    """
    Mouse button types
    """
    LEFT_BUTTON = 1
    RIGHT_BUTTON = 2
    MIDDLE_BUTTON = 3