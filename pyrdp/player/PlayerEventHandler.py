#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtCore import QObject
from PySide2.QtGui import QTextCursor
from PySide2.QtWidgets import QTextEdit

from pyrdp.core import decodeUTF16LE, Observer
from pyrdp.enum import BitmapFlags, CapabilityType, DeviceType, FastPathFragmentation, KeyboardFlag, ParserMode, \
    PlayerPDUType, SlowPathUpdateType, scancode, PointerFlag
from pyrdp.logging import log
from pyrdp.parser import BasicFastPathParser, BitmapParser, ClientConnectionParser, ClientInfoParser, ClipboardParser, \
    FastPathOutputParser, SlowPathParser
from pyrdp.pdu import BitmapUpdateData, ConfirmActivePDU, FastPathBitmapEvent, FastPathOrdersEvent, FastPathMouseEvent, FastPathOutputEvent, \
    FastPathScanCodeEvent, FastPathUnicodeEvent, FormatDataResponsePDU, InputPDU, KeyboardEvent, MouseEvent, \
    PlayerDeviceMappingPDU, PlayerPDU, UpdatePDU
from pyrdp.ui import QRemoteDesktop, RDPBitmapToQtImage

from .gdi import GdiQtFrontend
from pyrdp.parser.rdp.orders import OrdersParser

from binascii import hexlify


class PlayerEventHandler(QObject, Observer):
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

        self.gdi: GdiQtFrontend = None
        self.orders: OrdersParser = None

    def writeText(self, text: str):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText(text.rstrip("\x00"))

    def writeSeparator(self):
        self.writeText("\n--------------------\n")

    def onPDUReceived(self, pdu: PlayerPDU, isMainThread=False):
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

            # Enable MS-RDPEGDI parsing and rendering.
            if CapabilityType.CAPSTYPE_ORDER in pdu.parsedCapabilitySets:
                self.gdi = GdiQtFrontend(self.viewer)
                self.orders = OrdersParser(self.gdi)
                self.orders.onCapabilities(pdu.parsedCapabilitySets)
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

        for fragment in pdu.events:
            event = self.mergeFragments(fragment)

            if event is not None:
                if isinstance(event, FastPathBitmapEvent):
                    self.onFastPathBitmap(event)
                elif isinstance(event, FastPathOrdersEvent):
                    if self.orders is None:
                        # TODO: Lazily instantiate drawing order parser here and process it anyway.
                        log.error('Received Unexpected Drawing Orders!')
                        return
                    self.onFastPathOrders(event)

    def mergeFragments(self, event: FastPathOutputEvent) -> FastPathOutputEvent:
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

        # Partial fragment, don't parse it yet.
        return None

    def onFastPathBitmap(self, event: FastPathBitmapEvent):
        parser = FastPathOutputParser()
        parsedEvent = parser.parseBitmapEvent(event)

        for bitmapData in parsedEvent.bitmapUpdateData:
            self.handleBitmap(bitmapData)

    def onFastPathOrders(self, event: FastPathOrdersEvent):
        try:
            self.orders.parse(event)
        except Exception as e:
            log.warn('Failed to parse a drawing order: ' + e)
            log.warn('Payload = ' + hexlify(event.payload))

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
                self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & scancode.KBDFLAGS_EXTENDED != 0)

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
        self.viewer.setMousePosition(x, y)

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
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
