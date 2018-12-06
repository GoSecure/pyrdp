from PyQt4 import QtGui
from PyQt4.QtGui import QTextCursor

from pyrdp.core.helpers import decodeUTF16LE
from pyrdp.core.scancode import scancodeToChar
from pyrdp.enum import BitmapFlags, CapabilityType, KeyboardFlag, ParserMode, SlowPathUpdateType
from pyrdp.layer import PlayerMessageObserver
from pyrdp.logging import log
from pyrdp.parser import ClipboardParser, RDPBasicFastPathParser, RDPClientInfoParser, RDPCommonParser, RDPDataParser, \
    RDPOutputEventParser
from pyrdp.pdu import BitmapUpdateData, FastPathBitmapEvent, FastPathMouseEvent, FastPathOrdersEvent, \
    FastPathScanCodeEvent, FormatDataResponsePDU, KeyboardEvent, MouseEvent, PDU, PlayerMessagePDU, RDPConfirmActivePDU, \
    RDPInputPDU, RDPUpdatePDU
from pyrdp.ui import RDPBitmapToQtImage


class PlayerMessageHandler(PlayerMessageObserver):
    """
    Class to manage the display of the RDP player when reading events.
    """

    def __init__(self, viewer, text):
        PlayerMessageObserver.__init__(self)
        self.viewer = viewer
        self.text = text
        self.writeInCaps = False

        self.inputParser = RDPBasicFastPathParser(ParserMode.SERVER)
        self.outputParser = RDPBasicFastPathParser(ParserMode.CLIENT)
        self.clientInfoParser = RDPClientInfoParser()
        self.dataParser = RDPDataParser()
        self.clipboardParser = ClipboardParser()
        self.outputEventParser = RDPOutputEventParser()

    def onConnectionClose(self, pdu):
        self.text.moveCursor(QTextCursor.End)
        self.text.insertPlainText("\n<Connection closed>")

    def onOutput(self, pdu):
        pdu = self.outputParser.parse(pdu.payload)

        for event in pdu.events:
            if isinstance(event, FastPathOrdersEvent):
                log.debug("Not handling orders event, not coded :)")
            elif isinstance(event, FastPathBitmapEvent):
                log.debug("Handling bitmap event {}".format(vars(event)))
                self.onBitmap(event)
            else:
                log.debug("Can't handle output event: {}".format(event))

    def onInput(self, pdu):
        pdu = self.inputParser.parse(pdu.payload)

        for event in pdu.events:
            if isinstance(event, FastPathScanCodeEvent):
                log.debug("handling {}".format(event))
                self.onScanCode(event.scancode, not event.isReleased)
            elif isinstance(event, FastPathMouseEvent):
                self.onMousePosition(event.mouseX, event.mouseY)
            else:
                log.debug("Can't handle input event: {}".format(event))

    def onScanCode(self, code: int, isPressed: bool):
        """
        Handle scan code.
        """
        log.debug("Reading scancode {}".format(code))

        if code in [0x2A, 0x36]:
            self.text.moveCursor(QTextCursor.End)
            self.text.insertPlainText("\n<LSHIFT PRESSED>" if isPressed else "\n<LSHIFT RELEASED>")
            self.writeInCaps = not self.writeInCaps
        elif code == 0x3A and isPressed:
            self.text.moveCursor(QTextCursor.End)
            self.text.insertPlainText("\n<CAPSLOCK>")
            self.writeInCaps = not self.writeInCaps
        elif isPressed:
            char = scancodeToChar(code)
            self.text.moveCursor(QtGui.QTextCursor.End)
            self.text.insertPlainText(char if self.writeInCaps else char.lower())

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

    def onClientInfo(self, pdu: PlayerMessagePDU):
        clientInfoPDU = self.clientInfoParser.parse(pdu.payload)
        self.text.insertPlainText("--------------------")
        self.text.insertPlainText("\nUSERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n"
                                  .format(clientInfoPDU.username.replace("\0", ""),
                                          clientInfoPDU.password.replace("\0", ""),
                                          clientInfoPDU.domain.replace("\0", "")))
        self.text.insertPlainText("--------------------\n")

    def onSlowPathPDU(self, pdu: PDU):
        pdu = self.dataParser.parse(pdu.payload)

        if isinstance(pdu, RDPConfirmActivePDU):
            self.viewer.resize(pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopWidth,
                               pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopHeight)
        elif isinstance(pdu, RDPUpdatePDU) and pdu.updateType == SlowPathUpdateType.SLOWPATH_UPDATETYPE_BITMAP:
            updates = RDPCommonParser().parseBitmapUpdateData(pdu.updateData)
            for bitmap in updates:
                self.handleBitmap(bitmap)
        elif isinstance(pdu, RDPInputPDU):
            for event in pdu.events:
                if isinstance(event, MouseEvent):
                    self.onMousePosition(event.x, event.y)
                elif isinstance(event, KeyboardEvent):
                    self.onScanCode(event.keyCode, event.flags & KeyboardFlag.KBDFLAGS_DOWN != 0)

    def onClipboardData(self, pdu: FormatDataResponsePDU):
        pdu = self.clipboardParser.parse(pdu.payload)
        self.text.insertPlainText("\n=============\n")
        self.text.insertPlainText("CLIPBOARD DATA: {}".format(decodeUTF16LE(pdu.requestedFormatData)))
        self.text.insertPlainText("\n=============\n")