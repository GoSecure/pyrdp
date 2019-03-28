import functools
import logging
import time
from typing import Dict, List, Optional, Union

from PySide2.QtCore import QEvent, QObject, Qt
from PySide2.QtGui import QKeyEvent, QMouseEvent, QWheelEvent
from PySide2.QtWidgets import QWidget

from pyrdp.enum import MouseButton
from pyrdp.layer import PlayerLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.pdu import PlayerKeyboardPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU, PlayerTextPDU
from pyrdp.player.Sequencer import Sequencer
from pyrdp.ui import QRemoteDesktop


class RDPMITMWidget(QRemoteDesktop):
    """
    RDP Widget that handles mouse and keyboard events and sends them to the MITM server.
    """

    SCANCODE_MAPPING = {
        0x01: Qt.Key.Key_Escape,
        0x02: [Qt.Key.Key_1, Qt.Key.Key_Exclam],
        0x03: [Qt.Key.Key_2, Qt.Key.Key_At],
        0x04: [Qt.Key.Key_3, Qt.Key.Key_NumberSign],
        0x05: [Qt.Key.Key_4, Qt.Key.Key_Dollar],
        0x06: [Qt.Key.Key_5, Qt.Key.Key_Percent],
        0x07: [Qt.Key.Key_6, Qt.Key.Key_AsciiCircum],
        0x08: [Qt.Key.Key_7, Qt.Key.Key_Ampersand],
        0x09: [Qt.Key.Key_8, Qt.Key.Key_Asterisk],
        0x0A: [Qt.Key.Key_9, Qt.Key.Key_ParenLeft],
        0x0B: [Qt.Key.Key_0, Qt.Key.Key_ParenRight],
        0x0C: [Qt.Key.Key_Minus, Qt.Key.Key_Underscore],
        0x0D: [Qt.Key.Key_Equal, Qt.Key.Key_Plus],
        0x0E: Qt.Key.Key_Backspace,
        0x0F: Qt.Key.Key_Tab,
        0x10: Qt.Key.Key_Q,
        0x11: Qt.Key.Key_W,
        0x12: Qt.Key.Key_E,
        0x13: Qt.Key.Key_R,
        0x14: Qt.Key.Key_T,
        0x15: Qt.Key.Key_Y,
        0x16: Qt.Key.Key_U,
        0x17: Qt.Key.Key_I,
        0x18: Qt.Key.Key_O,
        0x19: Qt.Key.Key_P,
        0x1A: [Qt.Key.Key_BracketLeft, Qt.Key.Key_BraceLeft],
        0x1B: [Qt.Key.Key_BracketRight, Qt.Key.Key_BraceRight],
        0x1C: Qt.Key.Key_Return,
        0x1D: Qt.Key.Key_Control,
        0x1E: Qt.Key.Key_A,
        0x1F: Qt.Key.Key_S,
        0x20: Qt.Key.Key_D,
        0x21: Qt.Key.Key_F,
        0x22: Qt.Key.Key_G,
        0x23: Qt.Key.Key_H,
        0x24: Qt.Key.Key_J,
        0x25: Qt.Key.Key_K,
        0x26: Qt.Key.Key_L,
        0x27: [Qt.Key.Key_Semicolon, Qt.Key.Key_Colon],
        0x28: [Qt.Key.Key_Apostrophe, Qt.Key.Key_QuoteDbl],
        0x29: [Qt.Key.Key_QuoteLeft, Qt.Key.Key_AsciiTilde],
        0x2A: Qt.Key.Key_Shift,
        0x2B: [Qt.Key.Key_Backslash, Qt.Key.Key_Bar],
        0x2C: Qt.Key.Key_Z,
        0x2D: Qt.Key.Key_X,
        0x2E: Qt.Key.Key_C,
        0x2F: Qt.Key.Key_V,
        0x30: Qt.Key.Key_B,
        0x31: Qt.Key.Key_N,
        0x32: Qt.Key.Key_M,
        0x33: [Qt.Key.Key_Comma, Qt.Key.Key_Less],
        0x34: [Qt.Key.Key_Period, Qt.Key.Key_Greater],
        0x35: [Qt.Key.Key_Slash, Qt.Key.Key_Question],
        0x37: Qt.Key.Key_Print,
        0x38: [Qt.Key.Key_Alt, Qt.Key.Key_AltGr],
        0x39: Qt.Key.Key_Space,
        0x3A: Qt.Key.Key_CapsLock,
        0x3B: Qt.Key.Key_F1,
        0x3C: Qt.Key.Key_F2,
        0x3D: Qt.Key.Key_F3,
        0x3E: Qt.Key.Key_F4,
        0x3F: Qt.Key.Key_F5,
        0x40: Qt.Key.Key_F6,
        0x41: Qt.Key.Key_F7,
        0x42: Qt.Key.Key_F8,
        0x43: Qt.Key.Key_F9,
        0x44: Qt.Key.Key_F10,
        0x45: Qt.Key.Key_NumLock,
        0x46: Qt.Key.Key_ScrollLock,
        0x47: Qt.Key.Key_Home,
        0x48: Qt.Key.Key_Up,
        0x49: Qt.Key.Key_PageUp,
        0x4b: Qt.Key.Key_Left,
        0x4d: Qt.Key.Key_Right,
        0x4f: Qt.Key.Key_End,
        0x50: Qt.Key.Key_Down,
        0x51: Qt.Key.Key_PageDown,
        0x52: Qt.Key.Key_Insert,
        0x53: Qt.Key.Key_Delete,
        0x54: Qt.Key.Key_SysReq,
        0x57: Qt.Key.Key_F11,
        0x58: Qt.Key.Key_F12,
        0x5b: Qt.Key.Key_Meta,
        0x5F: Qt.Key.Key_Sleep,
        0x62: Qt.Key.Key_Zoom,
        0x63: Qt.Key.Key_Help,
        0x64: Qt.Key.Key_F13,
        0x65: Qt.Key.Key_F14,
        0x66: Qt.Key.Key_F15,
        0x67: Qt.Key.Key_F16,
        0x68: Qt.Key.Key_F17,
        0x69: Qt.Key.Key_F18,
        0x6A: Qt.Key.Key_F19,
        0x6B: Qt.Key.Key_F20,
        0x6C: Qt.Key.Key_F21,
        0x6D: Qt.Key.Key_F22,
        0x6E: Qt.Key.Key_F23,
        0x6F: Qt.Key.Key_F24,
        0x70: Qt.Key.Key_Hiragana,
        0x71: Qt.Key.Key_Kanji,
        0x72: Qt.Key.Key_Hangul,
    }

    SCANCODE_MAPPING_NUMPAD = {
        0x47: Qt.Key.Key_7,
        0x48: Qt.Key.Key_8,
        0x49: Qt.Key.Key_9,
        0x4A: Qt.Key.Key_Minus,
        0x4B: Qt.Key.Key_4,
        0x4C: Qt.Key.Key_5,
        0x4D: Qt.Key.Key_6,
        0x4E: Qt.Key.Key_Plus,
        0x4F: Qt.Key.Key_1,
        0x50: Qt.Key.Key_2,
        0x51: Qt.Key.Key_3,
        0x52: Qt.Key.Key_0,
        0x53: Qt.Key.Key_Period,
    }

    EXTENDED_KEYS = [Qt.Key.Key_Meta, Qt.Key.Key_AltGr]
    KEY_SEQUENCE_DELAY = 0


    def __init__(self, width: int, height: int, layer: PlayerLayer, parent: Optional[QWidget] = None):
        super().__init__(width, height, parent = parent)
        self.layer = layer
        self.handleEvents = False
        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.installEventFilter(self)


    def getTimetamp(self) -> int:
        return int(round(time.time() * 1000))


    def getMousePosition(self, event: Union[QMouseEvent, QWheelEvent]) -> (int, int):
        return max(event.x(), 0), max(event.y(), 0)

    def mouseMoveEvent(self, event: QMouseEvent):
        if not self.handleEvents or not self.hasFocus():
            return

        x, y = self.getMousePosition(event)

        pdu = PlayerMouseMovePDU(self.getTimetamp(), x, y)
        self.layer.sendPDU(pdu)

    def mousePressEvent(self, event: QMouseEvent):
        self.handleMouseButton(event, True)

    def mouseReleaseEvent(self, event: QMouseEvent):
        self.handleMouseButton(event, False)

    def handleMouseButton(self, event: QMouseEvent, pressed: bool):
        x, y = self.getMousePosition(event)
        button = event.button()

        mapping = {
            Qt.MouseButton.LeftButton: MouseButton.LEFT_BUTTON,
            Qt.MouseButton.RightButton: MouseButton.RIGHT_BUTTON,
            Qt.MouseButton.MiddleButton: MouseButton.MIDDLE_BUTTON,
        }

        if button not in mapping:
            return

        pdu = PlayerMouseButtonPDU(self.getTimetamp(), x, y, mapping[button], pressed)
        self.layer.sendPDU(pdu)

    def wheelEvent(self, event: QWheelEvent):
        x, y = self.getMousePosition(event)
        delta = event.delta()
        horizontal = event.orientation() == Qt.Orientation.Horizontal

        event.setAccepted(True)

        pdu = PlayerMouseWheelPDU(self.getTimetamp(), x, y, delta, horizontal)
        self.layer.sendPDU(pdu)


    # We need this to capture tab key events
    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.KeyPress:
            self.keyPressEvent(event)
            return True

        return QObject.eventFilter(self, obj, event)

    def findScanCodeForEvent(self, event: QKeyEvent) -> Optional[int]:
        if event.modifiers() & Qt.KeypadModifier != 0:
            mapping = RDPMITMWidget.SCANCODE_MAPPING_NUMPAD
        else:
            mapping = RDPMITMWidget.SCANCODE_MAPPING

        key = event.key()

        return self.findScanCodeForKey(key, mapping)

    def findScanCodeForKey(self, key: Qt.Key, mapping: Dict[int, Union[Qt.Key, List[Qt.Key]]]) -> Optional[int]:
        for k, v in mapping.items():
            if isinstance(v, list) and key in v:
                return k
            elif v == key:
                return k

        return None

    def isRightControl(self, event: QKeyEvent):
        return event.key() == Qt.Key.Key_Control and event.nativeScanCode() > 50

    def keyPressEvent(self, event: QKeyEvent):
        if not self.isRightControl(event):
            self.handleKeyEvent(event, False)
        else:
            self.clearFocus()

    def keyReleaseEvent(self, event: QKeyEvent):
        self.handleKeyEvent(event, True)

    def handleKeyEvent(self, event: QKeyEvent, released: bool):
        scanCode = self.findScanCodeForEvent(event)

        if scanCode is not None:
            event.setAccepted(True)

        pdu = PlayerKeyboardPDU(self.getTimetamp(), scanCode, released, event.key() in RDPMITMWidget.EXTENDED_KEYS)
        self.layer.sendPDU(pdu)

    def sendKeySequence(self, keys: [Qt.Key]):
        pressPDUs = []
        releasePDUs = []

        for key in keys:
            scanCode = self.findScanCodeForKey(key, RDPMITMWidget.SCANCODE_MAPPING)
            isExtended = key in RDPMITMWidget.EXTENDED_KEYS

            pdu = PlayerKeyboardPDU(self.getTimetamp(), scanCode, False, isExtended)
            pressPDUs.append(pdu)

            pdu = PlayerKeyboardPDU(self.getTimetamp(), scanCode, True, isExtended)
            releasePDUs.append(pdu)

        def press() -> int:
            for pdu in pressPDUs:
                self.layer.sendPDU(pdu)

            return RDPMITMWidget.KEY_SEQUENCE_DELAY

        def release():
            for pdu in releasePDUs:
                self.layer.sendPDU(pdu)

        sequencer = Sequencer([press, release])
        sequencer.run()

    def sendText(self, text: str):
        functions = []

        def pressCharacter(character: str):
            pdu = PlayerTextPDU(self.getTimetamp(), character, False)
            print(c)
            self.layer.sendPDU(pdu)
            return RDPMITMWidget.KEY_SEQUENCE_DELAY

        def releaseCharacter(character: str):
            pdu = PlayerTextPDU(self.getTimetamp(), character, True)
            self.layer.sendPDU(pdu)

        for c in text:
            press = functools.partial(pressCharacter, c)
            release = functools.partial(releaseCharacter, c)
            functions.append(press)
            functions.append(release)

        sequencer = Sequencer(functions)
        sequencer.run()