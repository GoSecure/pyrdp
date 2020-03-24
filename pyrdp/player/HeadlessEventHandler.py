#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#


from io import TextIOBase
from sys import stdout

from pyrdp.logging import log
from pyrdp.enum import DeviceType, KeyboardFlag, ParserMode, PlayerPDUType, PointerFlag
from pyrdp.parser import BasicFastPathParser, ClientConnectionParser, ClientInfoParser, ClipboardParser, SlowPathParser
from pyrdp.pdu import FastPathScanCodeEvent, FastPathUnicodeEvent, FormatDataResponsePDU, InputPDU, KeyboardEvent, FastPathMouseEvent, MouseEvent, \
    PlayerDeviceMappingPDU, PlayerPDU
from pyrdp.enum.scancode import getKeyName, KBDFLAGS_EXTENDED
from pyrdp.core import decodeUTF16LE, Observer


class HeadlessEventHandler(Observer):
    """
    Handle events from a replay file without rendering to a surface.

    This event handler does not require any graphical dependencies.
    """

    def __init__(self, output: TextIOBase = stdout):
        super().__init__()
        self.output = output

        self.shiftPressed = False
        self.capsLockOn = False
        self.buffer = b""

        # Instantiate parsers.
        self.slowpath = SlowPathParser()
        # self.fastpath = FastPathOutputParser()
        self.clipboard = ClipboardParser()

        self.handlers = {
            PlayerPDUType.CLIENT_DATA: self.onClientData,
            PlayerPDUType.CLIENT_INFO: self.onClientInfo,
            PlayerPDUType.CONNECTION_CLOSE: self.onConnectionClose,
            PlayerPDUType.CLIPBOARD_DATA: self.onClipboardData,
            PlayerPDUType.SLOW_PATH_PDU: self.onSlowPathPDU,
            PlayerPDUType.FAST_PATH_INPUT: self.onFastPathInput,
            PlayerPDUType.DEVICE_MAPPING: self.onDeviceMapping,
        }

    def writeText(self, text: str):
        self.output.write(text.rstrip("\x00"))

    def writeSeparator(self):
        self.output.write("\n--------------------\n")

    def onPDUReceived(self, pdu: PlayerPDU, isMainThread=False):
        log.debug("Received %(pdu)s", {"pdu": pdu})
        if pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)

    def onClientData(self, pdu: PlayerPDU):
        parser = ClientConnectionParser()
        clientDataPDU = parser.parse(pdu.payload)
        clientName = clientDataPDU.coreData.clientName.strip("\x00")

        self.writeSeparator()
        self.writeText(f"HOST: {clientName}\n")
        self.writeSeparator()

    def onClientInfo(self, pdu: PlayerPDU):
        parser = ClientInfoParser()
        clientInfoPDU = parser.parse(pdu.payload)

        self.writeSeparator()

        self.writeText("USERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n".format(
            clientInfoPDU.username.replace("\x00", ""),
            clientInfoPDU.password.replace("\x00", ""),
            clientInfoPDU.domain.replace("\x00", "")
        ))

        self.writeSeparator()

    def onConnectionClose(self, _: PlayerPDU):
        self.writeText("\n<Connection closed>")

    def onClipboardData(self, pdu: PlayerPDU):
        parser = ClipboardParser()
        pdu = parser.parse(pdu.payload)

        if not isinstance(pdu, FormatDataResponsePDU):
            return

        clipboardData = decodeUTF16LE(pdu.requestedFormatData)

        self.writeSeparator()
        self.writeText(f"CLIPBOARD DATA: {clipboardData}")
        self.writeSeparator()

    def onSlowPathPDU(self, pdu: PlayerPDU):
        pdu = self.slowpath.parse(pdu.payload)

        if not isinstance(pdu, InputPDU):
            return
        for event in pdu.events:
            if isinstance(event, MouseEvent):
                self.onMousePosition(event.x, event.y)
            elif isinstance(event, KeyboardEvent):
                down = event.flags & KeyboardFlag.KBDFLAGS_DOWN == 0
                ext = event.flags & KeyboardFlag.KBDFLAGS_EXTENDED != 0
                self.onScanCode(event.keyCode, down, ext)

    def onFastPathInput(self, pdu: PlayerPDU):
        parser = BasicFastPathParser(ParserMode.SERVER)
        pdu = parser.parse(pdu.payload)

        for event in pdu.events:
            if isinstance(event, FastPathUnicodeEvent):
                if not event.released:
                    self.onUnicode(event)
            elif isinstance(event, FastPathMouseEvent):
                self.onMouse(event)
            elif isinstance(event, FastPathScanCodeEvent):
                ext = event.rawHeaderByte & KBDFLAGS_EXTENDED != 0
                self.onScanCode(event.scanCode, event.isReleased, ext)

    def onUnicode(self, event: FastPathUnicodeEvent):
        self.writeText(str(event.text))

    def onMouse(self, event: FastPathMouseEvent):
        if event.pointerFlags & PointerFlag.PTRFLAGS_DOWN:
            if event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON1:
                button = 'Left'
            elif event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON2:
                button = 'Right'
            elif event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON3:
                button = 'Middle'
            else:
                button = 'Unknown'
            self.writeText(f'\n<Click ({button}) @ ({event.mouseX}, {event.mouseY})>')
        self.onMousePosition(event.mouseX, event.mouseY)

    def onMousePosition(self, x: int, y: int):
        pass

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        keyName = getKeyName(scanCode, isExtended, self.shiftPressed, self.capsLockOn)

        if len(keyName) == 1:
            if not isReleased:
                self.writeText(keyName)
        else:
            self.writeText(f"\n<{keyName} {'released' if isReleased else 'pressed'}>")

        # Handle shift.
        if scanCode in [0x2A, 0x36]:
            self.shiftPressed = not isReleased

        # Caps lock
        elif scanCode == 0x3A and not isReleased:
            self.capsLockOn = not self.capsLockOn

    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        self.writeText(f"\n<{DeviceType.getPrettyName(pdu.deviceType)} mapped: {pdu.name}>")
