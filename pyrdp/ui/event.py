from PyQt4 import QtGui
from PyQt4.QtGui import QTextCursor

from pyrdp.core.helper_methods import decodeUTF16LE
from pyrdp.core.logging import log
from pyrdp.core.scancode import scancodeToChar
from pyrdp.enum.core import ParserMode
from pyrdp.enum.rdp import CapabilityType, SlowPathUpdateType, BitmapFlags, KeyboardFlag
from pyrdp.layer.recording import RDPPlayerMessageObserver
from pyrdp.parser.rdp.client_info import RDPClientInfoParser
from pyrdp.parser.rdp.common import RDPCommonParser
from pyrdp.parser.rdp.data import RDPDataParser
from pyrdp.parser.rdp.fastpath import RDPOutputEventParser, RDPBasicFastPathParser
from pyrdp.parser.rdp.virtual_channel.clipboard import ClipboardParser
from pyrdp.pdu.base_pdu import PDU
from pyrdp.pdu.rdp.client_info import RDPClientInfoPDU
from pyrdp.pdu.rdp.common import BitmapUpdateData
from pyrdp.pdu.rdp.data import RDPConfirmActivePDU, RDPUpdatePDU, RDPInputPDU
from pyrdp.pdu.rdp.fastpath import FastPathEventScanCode, FastPathEventMouse, FastPathOrdersEvent, FastPathBitmapEvent
from pyrdp.pdu.rdp.input import KeyboardEvent, MouseEvent
from pyrdp.pdu.rdp.virtual_channel.clipboard import FormatDataResponsePDU
from pyrdp.ui.qt4 import RDPBitmapToQtImage


class RSSEventHandler(RDPPlayerMessageObserver):
    """
    Class to manage the display of the RDP player when reading events.
    """

    def __init__(self, viewer, text):
        RDPPlayerMessageObserver.__init__(self)
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
            if isinstance(event, FastPathEventScanCode):
                log.debug("handling {}".format(event))
                self.onScanCode(event.scancode, not event.isReleased)
            elif isinstance(event, FastPathEventMouse):
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

    def onClientInfo(self, pdu: RDPClientInfoPDU):
        pdu = self.clientInfoParser.parse(pdu.payload)
        self.text.insertPlainText("--------------------")
        self.text.insertPlainText("\nUSERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n"
                                  .format(pdu.username.replace("\0", ""),
                                  pdu.password.replace("\0", ""),
                                  pdu.domain.replace("\0", "")))
        self.text.insertPlainText("--------------------\n")

    def onSlowPathPDU(self, pdu: PDU):
        pdu = self.dataParser.parse(pdu.payload)

        if isinstance(pdu, RDPConfirmActivePDU):
            self.viewer.resize(pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopWidth,
                               pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopHeight)
        elif isinstance(pdu, RDPUpdatePDU) and pdu.updateType == SlowPathUpdateType.FASTPATH_UPDATETYPE_BITMAP:
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