#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional, Union

from PySide2.QtGui import QTextCursor
from PySide2.QtWidgets import QTextEdit

from pyrdp.core import decodeUTF16LE, Observer
from pyrdp.enum import BitmapFlags, CapabilityType, DeviceType, FastPathFragmentation, KeyboardFlag, ParserMode, \
    PlayerPDUType, SlowPathUpdateType
from pyrdp.logging import log
from pyrdp.parser import BasicFastPathParser, BitmapParser, ClientConnectionParser, ClientInfoParser, ClipboardParser, \
    FastPathOutputParser, SlowPathParser
from pyrdp.pdu import BitmapUpdateData, ConfirmActivePDU, FastPathBitmapEvent, FastPathMouseEvent, FastPathOutputEvent, \
    FastPathScanCodeEvent, FastPathUnicodeEvent, FormatDataResponsePDU, InputPDU, KeyboardEvent, MouseEvent, \
    PlayerDeviceMappingPDU, PlayerPDU, UpdatePDU
from pyrdp.player import keyboard
from pyrdp.ui import QRemoteDesktop, RDPBitmapToQtImage


class PlayerEventHandler(Observer):
    """
    Class to handle events coming to the player.
    """

    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit):
        super().__init__()
        self.viewer = viewer
        self.text = text
        self.shiftPressed = False
        self.capsLockOn = False
        self.buffer = b""
        self.handlers = {
            PlayerPDUType.CLIENT_DATA: self.onClientData,
            PlayerPDUType.CLIENT_INFO: self.onClientInfo,
            PlayerPDUType.CONNECTION_CLOSE: self.onConnectionClose,
            PlayerPDUType.CLIPBOARD_DATA: self.onClipboardData,
            PlayerPDUType.SLOW_PATH_PDU: self.onSlowPathPDU,
            PlayerPDUType.FAST_PATH_OUTPUT: self.onFastPathOutput,
            PlayerPDUType.FAST_PATH_INPUT: self.onFastPathInput,
            PlayerPDUType.DEVICE_MAPPING: self.onDeviceMapping,
        }


    def writeText(self, text: str):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText(text)

    def writeSeparator(self):
        self.writeText("\n--------------------\n")


    def onPDUReceived(self, pdu: PlayerPDU, isMainThread = False):
        if not isMainThread:
            self.viewer.mainThreadHook.emit(lambda: self.onPDUReceived(pdu, True))
            return

        log.debug("Received %(pdu)s", {"pdu": pdu})

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
            bitmapCapability = pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP]
            self.viewer.resize(bitmapCapability.desktopWidth, bitmapCapability.desktopHeight)
        elif isinstance(pdu, UpdatePDU) and pdu.updateType == SlowPathUpdateType.SLOWPATH_UPDATETYPE_BITMAP:
            updates = BitmapParser().parseBitmapUpdateData(pdu.updateData)

            for bitmap in updates:
                self.handleBitmap(bitmap)
        elif isinstance(pdu, InputPDU):
            for event in pdu.events:
                if isinstance(event, MouseEvent):
                    self.onMousePosition(event.x, event.y)
                elif isinstance(event, KeyboardEvent):
                    self.onScanCode(event.keyCode, event.flags & KeyboardFlag.KBDFLAGS_DOWN == 0, event.flags & KeyboardFlag.KBDFLAGS_EXTENDED != 0)


    def onFastPathOutput(self, pdu: PlayerPDU):
        parser = BasicFastPathParser(ParserMode.CLIENT)
        pdu = parser.parse(pdu.payload)

        for event in pdu.events:
            reassembledEvent = self.reassembleEvent(event)

            if reassembledEvent is not None:
                if isinstance(reassembledEvent, FastPathBitmapEvent):
                    self.onFastPathBitmap(reassembledEvent)

    def reassembleEvent(self, event: FastPathOutputEvent) -> Optional[Union[FastPathBitmapEvent, FastPathOutputEvent]]:
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

            return FastPathOutputParser().parseBitmapEvent(event)

        return None

    def onFastPathBitmap(self, event: FastPathBitmapEvent):
        parser = FastPathOutputParser()
        parsedEvent = parser.parseBitmapEvent(event)

        for bitmapData in parsedEvent.bitmapUpdateData:
            self.handleBitmap(bitmapData)


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
                self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & keyboard.KBDFLAGS_EXTENDED != 0)


    def onUnicode(self, event: FastPathUnicodeEvent):
        self.writeText(str(event.text))


    def onMouse(self, event: FastPathMouseEvent):
        self.onMousePosition(event.mouseX, event.mouseY)

    def onMousePosition(self, x: int, y: int):
        self.viewer.setMousePosition(x, y)


    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
        keyName = keyboard.getKeyName(scanCode, isExtended, self.shiftPressed, self.capsLockOn)

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


    def handleBitmap(self, bitmapData: BitmapUpdateData):
        image = RDPBitmapToQtImage(
            bitmapData.width,
            bitmapData.heigth,
            bitmapData.bitsPerPixel,
            bitmapData.flags & BitmapFlags.BITMAP_COMPRESSION != 0,
            bitmapData.bitmapData
        )

        self.viewer.notifyImage(
            bitmapData.destLeft,
            bitmapData.destTop,
            image,
            bitmapData.destRight - bitmapData.destLeft + 1,
            bitmapData.destBottom - bitmapData.destTop + 1)


    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        self.writeText(f"\n<{DeviceType.getPrettyName(pdu.deviceType)} mapped: {pdu.name}>")