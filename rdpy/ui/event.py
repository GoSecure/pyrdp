from PyQt4 import QtGui

from rdpy.core import rss
from rdpy.core.scancode import scancodeToChar
from rdpy.ui.qt4 import RDPBitmapToQtImage

class RSSEventHandler:
    def __init__(self, viewer, text):
        self._viewer = viewer
        self._text = text
        self._write_in_caps = False
    
    def on_event_received(self, event):
        if event.type.value == rss.EventType.UPDATE:
            image = RDPBitmapToQtImage(event.event.width.value, event.event.height.value, event.event.bpp.value, event.event.format.value == rss.UpdateFormat.BMP, event.event.data.value);
            self._viewer.notifyImage(event.event.destLeft.value, event.event.destTop.value, image, event.event.destRight.value - event.event.destLeft.value + 1, event.event.destBottom.value - event.event.destTop.value + 1)

        elif event.type.value == rss.EventType.SCREEN:
            self._viewer.resize(event.event.width.value, event.event.height.value)

        elif event.type.value == rss.EventType.INFO:
            format_args = (event.event.domain.value, event.event.username.value, event.event.password.value, event.event.hostname.value)
            message = "Domain : %s\nUsername : %s\nPassword : %s\nHostname : %s\n" % format_args
            message = message.replace("\x00", "")
            self._text.append(message)
        elif event.type.value == rss.EventType.KEY_SCANCODE:
            code = event.event.code.value
            is_pressed = not event.event.isPressed.value
            if code in [0x2A, 0x36]:
                self._text.insertPlainText("\n<LSHIFT PRESSED>" if is_pressed else "\n<LSHIFT RELEASED>")
                self._write_in_caps = not self._write_in_caps
            elif code == 0x3A and is_pressed:
                self._text.insertPlainText("\n<CAPSLOCK>")
                self._write_in_caps = not self._write_in_caps
            elif is_pressed:
                self._text.moveCursor(QtGui.QTextCursor.End)
                char = scancodeToChar(code)
                self._text.insertPlainText(char if self._write_in_caps else char.lower())
        elif event.type.value == rss.EventType.CLOSE:
            pass