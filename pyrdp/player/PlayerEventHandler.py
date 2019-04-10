#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional, Union

from PySide2.QtGui import QTextCursor
from PySide2.QtWidgets import QTextEdit

from pyrdp.core import decodeUTF16LE
from pyrdp.enum import BitmapFlags, CapabilityType, FastPathFragmentation, KeyboardFlag, ParserMode, SlowPathUpdateType
from pyrdp.layer import PlayerObserver
from pyrdp.logging import log
from pyrdp.parser import BasicFastPathParser, BitmapParser, ClientConnectionParser, ClientInfoParser, ClipboardParser, \
    FastPathOutputParser, SlowPathParser
from pyrdp.pdu import BitmapUpdateData, ConfirmActivePDU, FastPathBitmapEvent, FastPathMouseEvent, FastPathOrdersEvent, \
    FastPathOutputEvent, FastPathScanCodeEvent, FastPathUnicodeEvent, FormatDataResponsePDU, InputPDU, KeyboardEvent, \
    MouseEvent, PlayerPDU, UpdatePDU
from pyrdp.player import keyboard
from pyrdp.ui import QRemoteDesktop, RDPBitmapToQtImage


class PlayerEventHandler(PlayerObserver):
    """
    Class to manage the display of the RDP player when reading events.
    """

    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit):
        super().__init__()
        self.viewer = viewer
        self.text = text
        self.shiftPressed = False
        self.capsLockOn = False
        self.writeInCaps = False

        self.inputParser = BasicFastPathParser(ParserMode.SERVER)
        self.outputParser = BasicFastPathParser(ParserMode.CLIENT)
        self.clientInfoParser = ClientInfoParser()
        self.dataParser = SlowPathParser()
        self.clipboardParser = ClipboardParser()
        self.outputEventParser = FastPathOutputParser()
        self.clientConnectionParser = ClientConnectionParser()

        self.buffer = b""

    def onPDUReceived(self, pdu: PlayerPDU):
        parentMethod = super().onPDUReceived
        self.viewer.mainThreadHook.emit(lambda: parentMethod(pdu))

    def onConnectionClose(self, pdu: PlayerPDU):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText("\n<Connection closed>")

    def onOutput(self, pdu: PlayerPDU):
        pdu = self.outputParser.parse(pdu.payload)

        for event in pdu.events:
            reassembledEvent = self.reassembleEvent(event)
            if reassembledEvent is not None:
                if isinstance(reassembledEvent, FastPathOrdersEvent):
                    log.debug("Not handling orders event, not coded :)")
                elif isinstance(reassembledEvent, FastPathBitmapEvent):
                    log.debug("Handling bitmap event %(arg1)s", {"arg1": type(reassembledEvent)})
                    self.onBitmap(reassembledEvent)
                else:
                    log.debug("Can't handle output event: %(arg1)s", {"arg1": type(reassembledEvent)})
            else:
                log.debug("Reassembling output event...")

    def onInput(self, pdu: PlayerPDU):
        pdu = self.inputParser.parse(pdu.payload)

        for event in pdu.events:
            if isinstance(event, FastPathScanCodeEvent):
                log.debug("handling %(arg1)s", {"arg1": event})
                self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & 2 != 0)
            elif isinstance(event, FastPathUnicodeEvent):
                if not event.released:
                    self.onUnicode(event)
            elif isinstance(event, FastPathMouseEvent):
                self.onMouse(event)
            else:
                log.debug("Can't handle input event: %(arg1)s", {"arg1": event})


    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code.
        """
        log.debug("Reading scan code %(arg1)s", {"arg1": scanCode})
        keyName = keyboard.getKeyName(scanCode, isExtended, self.shiftPressed, self.capsLockOn)

        self.text.moveCursor(QTextCursor.End)

        if len(keyName) == 1:
            if not isReleased:
                self.text.insertPlainText(keyName)
        else:
            self.text.insertPlainText(f"\n<{keyName} {'released' if isReleased else 'pressed'}>")

        self.text.moveCursor(QTextCursor.End)

        # Left or right shift
        if scanCode in [0x2A, 0x36]:
            self.text.moveCursor(QTextCursor.End)
            self.shiftPressed = not isReleased

        # Caps lock
        elif scanCode == 0x3A and not isReleased:
            self.text.moveCursor(QTextCursor.End)
            self.capsLockOn = not self.capsLockOn


    def onUnicode(self, event: FastPathUnicodeEvent):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText(str(event.text))

    def onMouse(self, event: FastPathMouseEvent):
        self.onMousePosition(event.mouseX, event.mouseY)

    def onMousePosition(self, x: int, y: int):
        self.viewer.setMousePosition(x, y)

    def onBitmap(self, event: FastPathBitmapEvent):
        parsedEvent = self.outputEventParser.parseBitmapEvent(event)
        for bitmapData in parsedEvent.bitmapUpdateData:
            self.handleBitmap(bitmapData)

    def handleBitmap(self, bitmapData: BitmapUpdateData):
        image = RDPBitmapToQtImage(bitmapData.width, bitmapData.heigth, bitmapData.bitsPerPixel, bitmapData.flags & BitmapFlags.BITMAP_COMPRESSION != 0, bitmapData.bitmapData)
        self.viewer.notifyImage(bitmapData.destLeft, bitmapData.destTop, image,
                                bitmapData.destRight - bitmapData.destLeft + 1,
                                bitmapData.destBottom - bitmapData.destTop + 1)

    def onClientInfo(self, pdu: PlayerPDU):
        clientInfoPDU = self.clientInfoParser.parse(pdu.payload)
        self.text.insertPlainText("USERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n"
                                  .format(clientInfoPDU.username.replace("\0", ""),
                                          clientInfoPDU.password.replace("\0", ""),
                                          clientInfoPDU.domain.replace("\0", "")))
        self.text.insertPlainText("--------------------\n")

    def onSlowPathPDU(self, pdu: PlayerPDU):
        pdu = self.dataParser.parse(pdu.payload)

        if isinstance(pdu, ConfirmActivePDU):
            self.viewer.resize(pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopWidth,
                               pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopHeight)
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

    def onClipboardData(self, pdu: PlayerPDU):
        formatDataResponsePDU: FormatDataResponsePDU = self.clipboardParser.parse(pdu.payload)
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText("\n=============\n")
        self.text.insertPlainText("CLIPBOARD DATA: {}".format(decodeUTF16LE(formatDataResponsePDU.requestedFormatData)))
        self.text.insertPlainText("\n=============\n")

    def onClientData(self, pdu: PlayerPDU):
        """
        Prints the clientName on the screen
        """
        clientDataPDU = self.clientConnectionParser.parse(pdu.payload)
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText("--------------------\n")
        self.text.insertPlainText(f"HOST: {clientDataPDU.coreData.clientName.strip(chr(0))}\n")

    def reassembleEvent(self, event: FastPathOutputEvent) -> Optional[Union[FastPathBitmapEvent, FastPathOutputEvent]]:
        """
        Handles FastPath event reassembly as described in
        https://msdn.microsoft.com/en-us/library/cc240622.aspx
        :param event: A potentially segmented fastpath output event
        :return: a FastPathBitmapEvent if a complete PDU has been reassembled, otherwise None. If the event is not
        fragmented, returns the original event.
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
            return self.outputEventParser.parseBitmapEvent(event)

        return None
