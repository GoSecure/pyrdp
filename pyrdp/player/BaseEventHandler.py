#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from typing import Optional, Tuple
from pyrdp.core import decodeUTF16LE, Observer
from pyrdp.enum import PlayerPDUType, CapabilityType, ParserMode, \
    FastPathFragmentation, \
    KeyboardFlag, PointerFlag, scancode, DeviceType
from pyrdp.pdu import ConfirmActivePDU, UpdatePDU, InputPDU, \
    FastPathOutputEvent, FastPathUnicodeEvent, FastPathScanCodeEvent, \
    FastPathMouseEvent, KeyboardEvent, MouseEvent, \
    PlayerPDU, PlayerDeviceMappingPDU, \
    FormatDataResponsePDU
from pyrdp.parser import ClientConnectionParser, ClientInfoParser, ClipboardParser, \
    SlowPathParser, BasicFastPathParser


class BaseEventHandler(Observer):
    """
    Base implementation for player event processing.
    """

    def __init__(self):
        super().__init__()

        # Input processing state.
        self.shiftPressed = False
        self.capsLockOn = False
        self.buffer = b""

        # Base level handlers.
        self.handlers = {
            PlayerPDUType.CLIENT_DATA: self.onClientData,
            PlayerPDUType.CLIENT_INFO: self.onClientInfo,
            PlayerPDUType.CONNECTION_CLOSE: self.onConnectionClose,
            PlayerPDUType.CLIPBOARD_DATA: self.onClipboardData,
            PlayerPDUType.SLOW_PATH_PDU: self.onSlowPathPDU,
            PlayerPDUType.FAST_PATH_OUTPUT: self.onFastPathFragment,
            PlayerPDUType.FAST_PATH_INPUT: self.onFastPathInput,
            PlayerPDUType.DEVICE_MAPPING: self.onDeviceMapping,
        }

    def writeText(self, text: str):
        pass

    def writeSeparator(self):
        pass

    def onCapabilities(self, caps: dict):
        """Handle capability set reported by the server."""
        bmp = caps[CapabilityType.CAPSTYPE_BITMAP]
        (w, h) = (bmp.desktopWidth, bmp.desktopHeight)
        self.writeText(f'<Resolution: {w}x{h}>')

    def cleanup(self):
        """
        Called when this handler is no longer needed.

        This callback can be used to perform any handler specific
        cleanup that is necessary after a data stream is done processing.

        For playback streams, this means that the replay file is over and will
        no longer be played back. (Essentially, the tab has been closed.)

        For live streams, this means that the connection has been terminated.
        """
        pass

    def onPDUReceived(self, pdu: PlayerPDU):
        if pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)

    def onClientData(self, pdu: PlayerPDU):
        """
        Prints the clientName on the screen
        """
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
        parser = SlowPathParser()
        pdu = parser.parse(pdu.payload)

        if isinstance(pdu, ConfirmActivePDU):
            self.onCapabilities(pdu.parsedCapabilitySets)

        elif isinstance(pdu, UpdatePDU):
            self.onSlowPathUpdate(pdu)

        elif isinstance(pdu, InputPDU):
            for event in pdu.events:
                if isinstance(event, MouseEvent):
                    self.onMousePosition(event.x, event.y)
                elif isinstance(event, KeyboardEvent):
                    self.onScanCode(event.keyCode,
                                    event.flags & KeyboardFlag.KBDFLAGS_DOWN == 0,
                                    event.flags & KeyboardFlag.KBDFLAGS_EXTENDED != 0)

    def onFastPathFragment(self, pdu: PlayerPDU):
        parser = BasicFastPathParser(ParserMode.CLIENT)
        pdu = parser.parse(pdu.payload)

        for event in pdu.events:
            reassembledEvent = self.reassembleEvent(event)

            if reassembledEvent is not None:
                self.onFastPathOutput(reassembledEvent)

    def onFastPathOutput(self, event: FastPathOutputEvent):
        pass

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
                self.onScanCode(event.scanCode, event.isReleased,
                                event.rawHeaderByte & scancode.KBDFLAGS_EXTENDED != 0)

    def onSlowPathUpdate(self, pdu: UpdatePDU):
        pass

    def onUnicode(self, event: FastPathUnicodeEvent):
        self.writeText(str(event.text))

    def onMouse(self, event: FastPathMouseEvent):
        self.onMousePosition(event.mouseX, event.mouseY)

        if event.pointerFlags & PointerFlag.PTRFLAGS_DOWN:
            self.onMouseButton({
                1: event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON1,
                2: event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON2,
                3: event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON3
            }, (event.mouseX, event.mouseY))

    def onMouseButton(self, buttons: dict, pos: Tuple[int, int]):
        """
        Called when mouse buttons have been pressed.

        :param buttons: A dictionary containing the state of MOUSE[1], MOUSE[2], MOUSE[3].
        :param pos: The (x,y) coordinates of the button press.

        The state is True if the button is pressed, False otherwise.
        """
        pass

    def onMousePosition(self, x: int, y: int):
        pass

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
        # This should probably be refactored so that the base layer does less
        # processing and lets more specific layers handle the keystrokes the way
        # they need.
        keyName = scancode.getKeyName(scanCode, isExtended, self.shiftPressed, self.capsLockOn)

        if len(keyName) == 1:
            if not isReleased:
                self.writeText(keyName)
        else:
            self.writeText(f"\n<{keyName} {'released' if isReleased else 'pressed'}>")

        # Left or right shift
        if scanCode in [0x2A, 0x36]:
            self.shiftPressed = not isReleased

        # Caps lock
        elif scanCode == 0x3A and not isReleased:
            self.capsLockOn = not self.capsLockOn

    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        self.writeText(f"\n<{DeviceType.getPrettyName(pdu.deviceType)} mapped: {pdu.name}>")

    def reassembleEvent(self, event: FastPathOutputEvent) -> Optional[FastPathOutputEvent]:
        """
        Handles FastPath event reassembly as described in
        https://msdn.microsoft.com/en-us/library/cc240622.aspx
        :param event: A potentially segmented fastpath output event
        :return: a FastPathBitmapEvent if a complete PDU has been reassembled, otherwise None. If the event is not
        fragmented, it is returned as is.
        """
        fragmentationFlag = FastPathFragmentation((event.header & 0b00110000) >> 4)

        if fragmentationFlag == FastPathFragmentation.FASTPATH_FRAGMENT_SINGLE:
            return event
        elif fragmentationFlag == FastPathFragmentation.FASTPATH_FRAGMENT_FIRST:
            self.buffer = event.payload
        elif fragmentationFlag == FastPathFragmentation.FASTPATH_FRAGMENT_NEXT:
            self.buffer += event.payload
        elif fragmentationFlag == FastPathFragmentation.FASTPATH_FRAGMENT_LAST:
            self.buffer += event.payload
            event.payload = self.buffer
            return event

        return None
