#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import PlayerPDUType
from pyrdp.enum.player import MouseButton
from pyrdp.pdu.pdu import PDU


class PlayerPDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, header: PlayerPDUType, timestamp: int, payload: bytes):
        self.header = header  # Uint16LE
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)


class PlayerMouseMovePDU(PlayerPDU):
    """
    PDU definition for mouse move events coming from the player.
    """

    def __init__(self, timestamp: int, x: int, y: int):
        super().__init__(PlayerPDUType.MOUSE_MOVE, timestamp, b"")
        self.x = x
        self.y = y


class PlayerMouseButtonPDU(PlayerPDU):
    """
    PDU definition for mouse button events coming from the player.
    """

    def __init__(self, timestamp: int, x: int, y: int, button: MouseButton, pressed: bool):
        super().__init__(PlayerPDUType.MOUSE_BUTTON, timestamp, b"")
        self.x = x
        self.y = y
        self.button = button
        self.pressed = pressed