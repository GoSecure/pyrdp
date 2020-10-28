#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import CapabilityType, scancode
from pyrdp.pdu import PlayerPDU, FormatDataResponsePDU, FastPathUnicodeEvent
from pyrdp.player.BaseEventHandler import BaseEventHandler
from pyrdp.parser import ClientInfoParser, ClientConnectionParser, ClipboardParser
from pyrdp.core import decodeUTF16LE

import logging
import json

JSON_KEY_INFO = "info"
JSON_KEY_EVENTS = "events"


class JsonEventHandler(BaseEventHandler):
    """
    Playback event handler that converts events to JSON.

    The structure is as follows:

        {
            "info": {
                "date": <timestamp>,
                "host": "HOSTNAME",
                "width": 1920,
                "height: 1080,
                "username": "USERNAME",
                "password": "PASSWORD",
                "domain": "DOMAIN",
            },

            "events": [
                {
                    "timestamp": 10000,
                    "type": "clipboard" | "key" | "mouse" | "unicode",
                    "data":  { ... EventData ... }
                }
            ]
        }

    Event data is specific to the type of event.

    clipboard:

        {
            "mime": "text" | "blob",
            "file": "filename" | null,
            "content": "utf8-text" | [0x41, ...]
        }

    key and unicode:
        {
            "press": true | false, // Whether it's a key press or release
            "key": "a", // Key name
            "mods": ["alt", "ctrl", "shift", ...] // Modifiers
        }

    mouse:
        {
            "x": 100,
            "y": 100,
            "buttons": [
                "left": true | false, // If present, whether pressed or released.
                "right": true | false,
                "middle": true | false,
            ]
        }
    """

    def __init__(self, filename: str, progress=None):
        """
        Construct an event handler that outputs to a JSON file.

        :param filename: The output file to write to.
        """

        self.json = {JSON_KEY_INFO: {}, JSON_KEY_EVENTS: []}
        self.filename = filename
        self.timestamp = None
        self.mods = set()
        self.progress = progress
        super().__init__()

    def onPDUReceived(self, pdu: PlayerPDU):
        # Keep track of the timestamp for event notation.
        self.timestamp = pdu.timestamp
        super().onPDUReceived(pdu)
        if self.progress:
            self.progress()

    def cleanup(self):
        # self.log.info("Flushing to disk: %s", self.filename)
        with open(self.filename, "w") as o:
            json.dump(self.json, o)
        self.json = None

    def onClientInfo(self, pdu: PlayerPDU):
        parser = ClientInfoParser()
        clientInfoPDU = parser.parse(pdu.payload)
        info = self.json[JSON_KEY_INFO]

        info["date"] = pdu.timestamp
        info["username"] = clientInfoPDU.username.replace("\x00", "")
        info["password"] = clientInfoPDU.password.replace("\x00", "")
        info["domain"] = clientInfoPDU.domain.replace("\x00", "")

    def onClientData(self, pdu: PlayerPDU):
        parser = ClientConnectionParser()
        clientDataPDU = parser.parse(pdu.payload)
        clientName = clientDataPDU.coreData.clientName.strip("\x00")
        self.json[JSON_KEY_INFO]["host"] = clientName

    def onClipboardData(self, pdu: PlayerPDU):
        parser = ClipboardParser()
        pdu = parser.parse(pdu.payload)

        if not isinstance(pdu, FormatDataResponsePDU):
            # TODO: Handle file PDUs.
            return

        data = decodeUTF16LE(pdu.requestedFormatData)
        self.json[JSON_KEY_EVENTS].append(
            {
                "timestamp": self.timestamp,
                "type": "clipboard",
                "data": {"mime": "text/plain", "content": data},
            }
        )

    def onMousePosition(self, x, y):
        self.mouse = (x, y)
        self.json[JSON_KEY_EVENTS].append(
            {
                "timestamp": self.timestamp,
                "type": "mouse",
                "data": {"x": x, "y": y, "buttons": []},
            }
        )

    def onMouseButton(self, buttons, pos):
        pressed = []
        if 1 in buttons:
            pressed.append({"left": buttons[1] != 0})
        if 2 in buttons:
            pressed.append({"right": buttons[2] != 0})
        if 3 in buttons:
            pressed.append({"middle": buttons[3] != 0})

        (x, y) = pos

        self.json[JSON_KEY_EVENTS].append(
            {
                "timestamp": self.timestamp,
                "type": "mouse",
                "data": {"x": x, "y": y, "buttons": pressed},
            }
        )

    def onCapabilities(self, caps):
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)

        info = self.json[JSON_KEY_INFO]
        info["width"] = w
        info["height"] = h

        super().onCapabilities(caps)

    def onUnicode(self, event: FastPathUnicodeEvent):
        self.json[JSON_KEY_EVENTS].append(
            {
                "timestamp": event.timestamp,
                "type": "unicode",
                "data": {"press": not event.released, "key": event.text, "mods": []},
            }
        )

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        keyName = scancode.getKeyName(
            scanCode, isExtended, self.shiftPressed, self.capsLockOn
        )

        # Update the state that tracks capitalization.
        if scanCode in [0x2A, 0x36]:
            self.shiftPressed = not isReleased
        elif scanCode == 0x3A and not isReleased:
            self.capsLockOn = not self.capsLockOn

        # Keep track of active modifiers.
        if scancode.isModifier(scanCode):
            if isReleased:
                self.mods.discard(keyName)  # No-throw
            else:
                self.mods.add(keyName)

        # Add the event
        self.json[JSON_KEY_EVENTS].append(
            {
                "timestamp": self.timestamp,
                "type": "key",
                "data": {
                    "key": keyName,
                    "press": not isReleased,
                    "mods": list(self.mods),
                },
            }
        )

    def writeText(self, text):
        pass  # Don't do anything.
