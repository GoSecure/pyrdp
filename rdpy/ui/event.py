from PyQt4 import QtGui

from PyQt4.QtGui import QTextCursor

from rdpy.core import log
from rdpy.core.scancode import scancodeToChar
from rdpy.enum.rdp import RDPPlayerMessageType, CapabilityType
from rdpy.parser.rdp.fastpath import RDPOutputEventParser
from rdpy.pdu.rdp.fastpath import FastPathEventScanCode, FastPathEventMouse, FastPathOrdersEvent, FastPathBitmapEvent
from rdpy.ui.qt4 import RDPBitmapToQtImage


class RSSEventHandler:
    """
    Class to manage the display of the RDP player when reading events.
    """

    def __init__(self, viewer, text):
        self._viewer = viewer
        self._text = text
        self._write_in_caps = False
        self.rdpFastPathOutputEventParser = RDPOutputEventParser()

    def on_message_received(self, message):
        """
        For each event in the provided message, handle it, if it can be handled.
        :type message: rdpy.pdu.rdp.recording.RDPPlayerMessagePDU
        """
        if message.type == RDPPlayerMessageType.INPUT:
            self.handle_input_event(message.payload)
        elif message.type == RDPPlayerMessageType.OUTPUT:
            self.handle_output_event(message.payload)
        elif message.type == RDPPlayerMessageType.CLIENT_INFO:
            self.handle_client_info(message.payload)
        elif message.type == RDPPlayerMessageType.CONFIRM_ACTIVE:
            self.handle_resize(message.payload)
        else:
            log.error("Received wrong player message type: {}".format(message.type))

    def handle_output_event(self, payload):
        for event in payload.events:
            if isinstance(event, FastPathOrdersEvent):
                log.debug("Not handling orders event, not coded :)")
            elif isinstance(event, FastPathBitmapEvent):
                log.debug("Handling bitmap event {}".format(event))
                self.handle_image(event)
            else:
                log.debug("Cant handle output event: {}".format(event))

    def handle_input_event(self, payload):
        for event in payload.events:
            if isinstance(event, FastPathEventScanCode):
                log.debug("handling {}".format(event))
                self.handle_scancode(event)
            elif isinstance(event, FastPathEventMouse):
                log.debug("Not handling Mouse event since it has not yet been coded :)")
            else:
                log.debug("Cant handle input event: {}".format(event))

    def handle_scancode(self, event):
        log.debug("Reading scancode {}".format(event.scancode))
        code = event.scancode
        is_pressed = not event.isReleased
        if code in [0x2A, 0x36]:
            self._text.moveCursor(QTextCursor.End)
            self._text.insertPlainText("\n<LSHIFT PRESSED>" if is_pressed else "\n<LSHIFT RELEASED>")
            self._write_in_caps = not self._write_in_caps
        elif code == 0x3A and is_pressed:
            self._text.moveCursor(QTextCursor.End)
            self._text.insertPlainText("\n<CAPSLOCK>")
            self._write_in_caps = not self._write_in_caps
        elif is_pressed:
            char = scancodeToChar(code)
            self._text.moveCursor(QtGui.QTextCursor.End)
            self._text.insertPlainText(char if self._write_in_caps else char.lower())

    def handle_image(self, event):
        """
        :type event: rdpy.pdu.rdp.fastpath.FastPathBitmapEvent
        """
        parsedEvent = self.rdpFastPathOutputEventParser.parseBitmapEvent(event)
        for bitmapData in parsedEvent.bitmapUpdateData:
            image = RDPBitmapToQtImage(bitmapData.width, bitmapData.heigth, bitmapData.bitsPerPixel,
                                       True, bitmapData.bitmapStream)
            self._viewer.notifyImage(bitmapData.destLeft, bitmapData.destTop, image,
                                     bitmapData.destRight - bitmapData.destLeft + 1,
                                     bitmapData.destBottom - bitmapData.destTop + 1)
        pass

    def handle_client_info(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.client_info.RDPClientInfoPDU
        """
        self._text.insertPlainText("--------------------")
        self._text.insertPlainText("\nUSERNAME: {}\nPASSWORD: {}\nDOMAIN: {}\n"
                          .format(pdu.username.replace("\0", ""),
                                  pdu.password.replace("\0", ""),
                                  pdu.domain.replace("\0", "")))
        self._text.insertPlainText("--------------------\n")

    def handle_resize(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.data.RDPConfirmActivePDU
        """
        self._viewer.resize(pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopWidth,
                            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAP].desktopHeight)
