#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional

from PySide2.QtCore import Qt
from PySide2.QtGui import QKeyEvent

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/089d362b-31eb-4a1a-b6fa-92fe61bb5dbf
KBDFLAGS_EXTENDED = 2

SCANCODE_MAPPING = {
    Qt.Key.Key_Escape: 0x01,
    Qt.Key.Key_1: 0x02,
    Qt.Key.Key_Exclam: 0x02,
    Qt.Key.Key_2: 0x03,
    Qt.Key.Key_At: 0x03,
    Qt.Key.Key_3: 0x04,
    Qt.Key.Key_NumberSign: 0x04,
    Qt.Key.Key_4: 0x05,
    Qt.Key.Key_Dollar: 0x05,
    Qt.Key.Key_5: 0x06,
    Qt.Key.Key_Percent: 0x06,
    Qt.Key.Key_6: 0x07,
    Qt.Key.Key_AsciiCircum: 0x07,
    Qt.Key.Key_7: 0x08,
    Qt.Key.Key_Ampersand: 0x08,
    Qt.Key.Key_8: 0x09,
    Qt.Key.Key_Asterisk: 0x09,
    Qt.Key.Key_9: 0x0A,
    Qt.Key.Key_ParenLeft: 0x0A,
    Qt.Key.Key_0: 0x0B,
    Qt.Key.Key_ParenRight: 0x0B,
    Qt.Key.Key_Minus: 0x0C,
    Qt.Key.Key_Underscore: 0x0C,
    Qt.Key.Key_Equal: 0x0D,
    Qt.Key.Key_Plus: 0x0D,
    Qt.Key.Key_Backspace: 0x0E,
    Qt.Key.Key_Tab: 0x0F,
    Qt.Key.Key_Q: 0x10,
    Qt.Key.Key_W: 0x11,
    Qt.Key.Key_E: 0x12,
    Qt.Key.Key_R: 0x13,
    Qt.Key.Key_T: 0x14,
    Qt.Key.Key_Y: 0x15,
    Qt.Key.Key_U: 0x16,
    Qt.Key.Key_I: 0x17,
    Qt.Key.Key_O: 0x18,
    Qt.Key.Key_P: 0x19,
    Qt.Key.Key_BracketLeft: 0x1A,
    Qt.Key.Key_BraceLeft: 0x1A,
    Qt.Key.Key_BracketRight: 0x1B,
    Qt.Key.Key_BraceRight: 0x1B,
    Qt.Key.Key_Return: 0x1C,
    Qt.Key.Key_Control: 0x1D,
    Qt.Key.Key_A: 0x1E,
    Qt.Key.Key_S: 0x1F,
    Qt.Key.Key_D: 0x20,
    Qt.Key.Key_F: 0x21,
    Qt.Key.Key_G: 0x22,
    Qt.Key.Key_H: 0x23,
    Qt.Key.Key_J: 0x24,
    Qt.Key.Key_K: 0x25,
    Qt.Key.Key_L: 0x26,
    Qt.Key.Key_Semicolon: 0x27,
    Qt.Key.Key_Colon: 0x27,
    Qt.Key.Key_Apostrophe: 0x28,
    Qt.Key.Key_QuoteDbl: 0x28,
    Qt.Key.Key_QuoteLeft: 0x29,
    Qt.Key.Key_AsciiTilde: 0x29,
    Qt.Key.Key_Shift: 0x2A,
    Qt.Key.Key_Backslash: 0x2B,
    Qt.Key.Key_Bar: 0x2B,
    Qt.Key.Key_Z: 0x2C,
    Qt.Key.Key_X: 0x2D,
    Qt.Key.Key_C: 0x2E,
    Qt.Key.Key_V: 0x2F,
    Qt.Key.Key_B: 0x30,
    Qt.Key.Key_N: 0x31,
    Qt.Key.Key_M: 0x32,
    Qt.Key.Key_Comma: 0x33,
    Qt.Key.Key_Less: 0x33,
    Qt.Key.Key_Period: 0x34,
    Qt.Key.Key_Greater: 0x34,
    Qt.Key.Key_Slash: 0x35,
    Qt.Key.Key_Question: 0x35,
    Qt.Key.Key_Alt: 0x38,
    Qt.Key.Key_AltGr: 0x38,
    Qt.Key.Key_Space: 0x39,
    Qt.Key.Key_CapsLock: 0x3A,
    Qt.Key.Key_F1: 0x3B,
    Qt.Key.Key_F2: 0x3C,
    Qt.Key.Key_F3: 0x3D,
    Qt.Key.Key_F4: 0x3E,
    Qt.Key.Key_F5: 0x3F,
    Qt.Key.Key_F6: 0x40,
    Qt.Key.Key_F7: 0x41,
    Qt.Key.Key_F8: 0x42,
    Qt.Key.Key_F9: 0x43,
    Qt.Key.Key_F10: 0x44,
    Qt.Key.Key_NumLock: 0x45,
    Qt.Key.Key_ScrollLock: 0x46,
    Qt.Key.Key_Home: 0x47,
    Qt.Key.Key_Up: 0x48,
    Qt.Key.Key_PageUp: 0x49,
    Qt.Key.Key_Left: 0x4B,
    Qt.Key.Key_Right: 0x4D,
    Qt.Key.Key_End: 0x4F,
    Qt.Key.Key_Down: 0x50,
    Qt.Key.Key_PageDown: 0x51,
    Qt.Key.Key_Insert: 0x52,
    Qt.Key.Key_Delete: 0x53,
    Qt.Key.Key_SysReq: 0x54,
    Qt.Key.Key_F11: 0x57,
    Qt.Key.Key_F12: 0x58,
    Qt.Key.Key_Meta: 0x5B,
    Qt.Key.Key_Menu: 0x5D,
    Qt.Key.Key_Sleep: 0x5F,
    Qt.Key.Key_Zoom: 0x62,
    Qt.Key.Key_Help: 0x63,
    Qt.Key.Key_F13: 0x64,
    Qt.Key.Key_F14: 0x65,
    Qt.Key.Key_F15: 0x66,
    Qt.Key.Key_F16: 0x67,
    Qt.Key.Key_F17: 0x68,
    Qt.Key.Key_F18: 0x69,
    Qt.Key.Key_F19: 0x6A,
    Qt.Key.Key_F20: 0x6B,
    Qt.Key.Key_F21: 0x6C,
    Qt.Key.Key_F22: 0x6D,
    Qt.Key.Key_F23: 0x6E,
    Qt.Key.Key_F24: 0x6F,
    Qt.Key.Key_Hiragana: 0x70,
    Qt.Key.Key_Kanji: 0x71,
    Qt.Key.Key_Hangul: 0x72,
}

SCANCODE_MAPPING_NUMPAD = {
    Qt.Key.Key_Enter: 0x1C,
    Qt.Key.Key_Slash: 0x35,
    Qt.Key.Key_Asterisk: 0x37,
    Qt.Key.Key_7: 0x47,
    Qt.Key.Key_8: 0x48,
    Qt.Key.Key_9: 0x49,
    Qt.Key.Key_Minus: 0x4A,
    Qt.Key.Key_4: 0x4B,
    Qt.Key.Key_5: 0x4C,
    Qt.Key.Key_6: 0x4D,
    Qt.Key.Key_Plus: 0x4E,
    Qt.Key.Key_1: 0x4F,
    Qt.Key.Key_2: 0x50,
    Qt.Key.Key_3: 0x51,
    Qt.Key.Key_0: 0x52,
    Qt.Key.Key_Period: 0x53,
    Qt.Key.Key_Meta: 0x5C,
}

EXTENDED_KEYS = [
    Qt.Key.Key_Meta,
    Qt.Key.Key_AltGr,
    Qt.Key.Key_PageUp,
    Qt.Key.Key_PageDown,
    Qt.Key.Key_Insert,
    Qt.Key.Key_Delete,
    Qt.Key.Key_Home,
    Qt.Key.Key_End,
    Qt.Key.Key_Print,
    Qt.Key.Key_Left,
    Qt.Key.Key_Right,
    Qt.Key.Key_Up,
    Qt.Key.Key_Down,
    Qt.Key.Key_Menu,
]


def findScanCodeForEvent(event: QKeyEvent) -> Optional[int]:
    if event.modifiers() & Qt.KeypadModifier != 0:
        mapping = SCANCODE_MAPPING_NUMPAD
    else:
        mapping = SCANCODE_MAPPING

    key = event.key()
    return mapping.get(key, None)


def findKeyForScanCode(scanCode: int) -> Optional[Qt.Key]:
    # Right shift
    if scanCode == 0x36:
        return Qt.Key.Key_Shift

    # Right Windows
    elif scanCode == 0x5c:
        return Qt.Key.Key_Meta

    for mapping in [SCANCODE_MAPPING, SCANCODE_MAPPING_NUMPAD]:
        for k, v in mapping.items():
            if v == scanCode and k not in EXTENDED_KEYS:
                return k

    return None


def getKeyName(scanCode: int, isExtended: bool, shiftPressed: bool, capsLockOn: bool) -> str:
    if not isExtended:
        key = findKeyForScanCode(scanCode)
    elif scanCode == SCANCODE_MAPPING[Qt.Key.Key_Control]:
        key = Qt.Key.Key_Control
    # Numpad slash
    elif scanCode == 0x35:
        key = Qt.Key.Key_Slash
    else:
        key = None

        for extendedKey in EXTENDED_KEYS:
            if extendedKey in SCANCODE_MAPPING and SCANCODE_MAPPING[extendedKey] == scanCode:
                key = extendedKey
                break
            elif extendedKey in SCANCODE_MAPPING_NUMPAD and SCANCODE_MAPPING_NUMPAD[extendedKey] == scanCode:
                key = extendedKey
                break

        if key is None:
            return f"Unknown scan code {hex(scanCode)}"

    if key < 0x1000000:
        name = chr(key)

        if name.isalpha():
            return name.upper() if shiftPressed or capsLockOn else name.lower()
        else:
            key = shiftKey(key) if shiftPressed else key
            return chr(key)

    elif key == Qt.Key.Key_Meta:
        return "Windows"

    enumName = str(key)
    return " ".join(enumName.split("_")[1 :])


def shiftKey(key: Qt.Key) -> Qt.Key:
    if key in SCANCODE_MAPPING:
        code = SCANCODE_MAPPING[key]

        for k, v in SCANCODE_MAPPING.items():
            if v == code and k != key:
                return k

    return key


def isRightControl(event: QKeyEvent) -> bool:
    return event.key() == Qt.Key.Key_Control and event.nativeScanCode() > 50