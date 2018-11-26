from PyQt4 import QtGui
from PyQt4.QtGui import QTextCursor

from rdpy.core import log
from rdpy.core.scancode import scancodeToChar
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import CapabilityType, RDPDataPDUSubtype, SlowPathUpdateType
from rdpy.layer.recording import RDPPlayerMessageObserver
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.common import RDPCommonParser
from rdpy.parser.rdp.data import RDPDataParser
from rdpy.parser.rdp.fastpath import RDPOutputEventParser, RDPBasicFastPathParser
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser
from rdpy.pdu.rdp.common import BitmapUpdateData
from rdpy.pdu.rdp.data import RDPConfirmActivePDU, RDPUpdatePDU
from rdpy.pdu.rdp.fastpath import FastPathEventScanCode, FastPathEventMouse, FastPathOrdersEvent, FastPathBitmapEvent
from rdpy.ui.qt4 import RDPBitmapToQtImage


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
                log.debug("Handling bitmap event {}".format(event))
                self.onBitmap(event)
            else:
                log.debug("Cant handle output event: {}".format(event))

    def onInput(self, pdu):
        pdu = self.inputParser.parse(pdu.payload)

        for event in pdu.events:
            if isinstance(event, FastPathEventScanCode):
                log.debug("handling {}".format(event))
                self.onScancode(event)
            elif isinstance(event, FastPathEventMouse):
                log.debug("Not handling Mouse event since it has not yet been coded :)")
            else:
                log.debug("Cant handle input event: {}".format(event))

    def onScancode(self, event):
        """
        :type event: FastPathEventScanCode
        """
        log.debug("Reading scancode {}".format(event.scancode))
        code = event.scancode
        is_pressed = not event.isReleased
        if code in [0x2A, 0x36]:
            self.text.moveCursor(QTextCursor.End)
            self.text.insertPlainText("\n<LSHIFT PRESSED>" if is_pressed else "\n<LSHIFT RELEASED>")
            self.writeInCaps = not self.writeInCaps
        elif code == 0x3A and is_pressed:
            self.text.moveCursor(QTextCursor.End)
            self.text.insertPlainText("\n<CAPSLOCK>")
            self.writeInCaps = not self.writeInCaps
        elif is_pressed:
            char = scancodeToChar(code)
            self.text.moveCursor(QtGui.QTextCursor.End)
            self.text.insertPlainText(char if self.writeInCaps else char.lower())

    def onBitmap(self, event):
        """
        :type event: rdpy.pdu.rdp.fastpath.FastPathBitmapEvent
        """
        parsedEvent = self.outputEventParser.parseBitmapEvent(event)
        for bitmapData in parsedEvent.bitmapUpdateData:
            self.handleBitmap(bitmapData)

    def handleBitmap(self, bitmapData: BitmapUpdateData):
        image = RDPBitmapToQtImage(bitmapData.width, bitmapData.heigth, bitmapData.bitsPerPixel, True, bitmapData.bitmapData)
        self.viewer.notifyImage(bitmapData.destLeft, bitmapData.destTop, image,
                                bitmapData.destRight - bitmapData.destLeft + 1,
                                bitmapData.destBottom - bitmapData.destTop + 1)

    def onClientInfo(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.client_info.RDPClientInfoPDU
        """
        pdu = self.clientInfoParser.parse(pdu.payload)
        self.text.insertPlainText("--------------------")
        self.text.insertPlainText("\nUSERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n"
                                  .format(pdu.username.replace("\0", ""),
                                  pdu.password.replace("\0", ""),
                                  pdu.domain.replace("\0", "")))
        self.text.insertPlainText("--------------------\n")

    def onSlowPathPDU(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.data.RDPConfirmActivePDU
        """
        pdu = self.dataParser.parse(pdu.payload)

        if isinstance(pdu, RDPConfirmActivePDU):
            self.viewer.resize(pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopWidth,
                               pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopHeight)
        elif isinstance(pdu, RDPUpdatePDU) and pdu.updateType == SlowPathUpdateType.FASTPATH_UPDATETYPE_BITMAP:
            updates = RDPCommonParser().parseBitmapUpdateData(pdu.updateData)
            for bitmap in updates:
                self.handleBitmap(bitmap)

    def onClipboardData(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.virtual_channel.clipboard.FormatDataResponsePDU
        """
        pdu = self.clipboardParser.parse(pdu.payload)
        self.text.insertPlainText("\n=============\n")
        self.text.insertPlainText("CLIPBOARD DATA: {}".format(pdu.requestedFormatData.replace("\x00", "")))
        self.text.insertPlainText("\n=============\n")