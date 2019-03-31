# This file was adapted from scan code definitions in FreeRDP.
# https://github.com/FreeRDP/FreeRDP/blob/master/include/freerdp/scancode.h
#
# FreeRDP: A Remote Desktop Protocol Implementation
# RDP protocol "scancodes"
#
# Copyright 2009-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from collections import namedtuple

ScanCodeTuple = namedtuple("ScanCode", "code extended")

class ScanCode:
    """
    Enumeration for RDP scan codes. Values are a tuple of (scanCode: int, isExtended: bool).
    """

    UNKNOWN = ScanCodeTuple(0x00, False)           # Unknown key
    ESCAPE = ScanCodeTuple(0x01, False)            # VK_ESCAPE
    KEY_1 = ScanCodeTuple(0x02, False)             # VK_KEY_1
    KEY_2 = ScanCodeTuple(0x03, False)             # VK_KEY_2
    KEY_3 = ScanCodeTuple(0x04, False)             # VK_KEY_3
    KEY_4 = ScanCodeTuple(0x05, False)             # VK_KEY_4
    KEY_5 = ScanCodeTuple(0x06, False)             # VK_KEY_5
    KEY_6 = ScanCodeTuple(0x07, False)             # VK_KEY_6
    KEY_7 = ScanCodeTuple(0x08, False)             # VK_KEY_7
    KEY_8 = ScanCodeTuple(0x09, False)             # VK_KEY_8
    KEY_9 = ScanCodeTuple(0x0A, False)             # VK_KEY_9
    KEY_0 = ScanCodeTuple(0x0B, False)             # VK_KEY_0
    OEM_MINUS = ScanCodeTuple(0x0C, False)         # VK_OEM_MINUS
    OEM_PLUS = ScanCodeTuple(0x0D, False)          # VK_OEM_PLUS
    BACKSPACE = ScanCodeTuple(0x0E, False)         # VK_BACK Backspace
    TAB = ScanCodeTuple(0x0F, False)               # VK_TAB
    KEY_Q = ScanCodeTuple(0x10, False)             # VK_KEY_Q
    KEY_W = ScanCodeTuple(0x11, False)             # VK_KEY_W
    KEY_E = ScanCodeTuple(0x12, False)             # VK_KEY_E
    KEY_R = ScanCodeTuple(0x13, False)             # VK_KEY_R
    KEY_T = ScanCodeTuple(0x14, False)             # VK_KEY_T
    KEY_Y = ScanCodeTuple(0x15, False)             # VK_KEY_Y
    KEY_U = ScanCodeTuple(0x16, False)             # VK_KEY_U
    KEY_I = ScanCodeTuple(0x17, False)             # VK_KEY_I
    KEY_O = ScanCodeTuple(0x18, False)             # VK_KEY_O
    KEY_P = ScanCodeTuple(0x19, False)             # VK_KEY_P
    OEM_4 = ScanCodeTuple(0x1A, False)             # VK_OEM_4 '[' on US
    OEM_6 = ScanCodeTuple(0x1B, False)             # VK_OEM_6 ']' on US
    RETURN = ScanCodeTuple(0x1C, False)            # VK_RETURN Normal Enter
    LCONTROL = ScanCodeTuple(0x1D, False)          # VK_LCONTROL
    KEY_A = ScanCodeTuple(0x1E, False)             # VK_KEY_A
    KEY_S = ScanCodeTuple(0x1F, False)             # VK_KEY_S
    KEY_D = ScanCodeTuple(0x20, False)             # VK_KEY_D
    KEY_F = ScanCodeTuple(0x21, False)             # VK_KEY_F
    KEY_G = ScanCodeTuple(0x22, False)             # VK_KEY_G
    KEY_H = ScanCodeTuple(0x23, False)             # VK_KEY_H
    KEY_J = ScanCodeTuple(0x24, False)             # VK_KEY_J
    KEY_K = ScanCodeTuple(0x25, False)             # VK_KEY_K
    KEY_L = ScanCodeTuple(0x26, False)             # VK_KEY_L
    OEM_1 = ScanCodeTuple(0x27, False)             # VK_OEM_1 ';' on US
    OEM_7 = ScanCodeTuple(0x28, False)             # VK_OEM_7 "'" on US
    OEM_3 = ScanCodeTuple(0x29, False)             # VK_OEM_3 Top left, '`' on US, JP DBE_SBCSCHAR
    LSHIFT = ScanCodeTuple(0x2A, False)            # VK_LSHIFT
    OEM_5 = ScanCodeTuple(0x2B, False)             # VK_OEM_5 Next to Enter, '\' on US
    KEY_Z = ScanCodeTuple(0x2C, False)             # VK_KEY_Z
    KEY_X = ScanCodeTuple(0x2D, False)             # VK_KEY_X
    KEY_C = ScanCodeTuple(0x2E, False)             # VK_KEY_C
    KEY_V = ScanCodeTuple(0x2F, False)             # VK_KEY_V
    KEY_B = ScanCodeTuple(0x30, False)             # VK_KEY_B
    KEY_N = ScanCodeTuple(0x31, False)             # VK_KEY_N
    KEY_M = ScanCodeTuple(0x32, False)             # VK_KEY_M
    OEM_COMMA = ScanCodeTuple(0x33, False)         # VK_OEM_COMMA
    OEM_PERIOD = ScanCodeTuple(0x34, False)        # VK_OEM_PERIOD
    OEM_2 = ScanCodeTuple(0x35, False)             # VK_OEM_2 '/' on US
    RSHIFT = ScanCodeTuple(0x36, False)            # VK_RSHIFT
    MULTIPLY = ScanCodeTuple(0x37, False)          # VK_MULTIPLY Numerical
    LMENU = ScanCodeTuple(0x38, False)             # VK_LMENU Left 'Alt' key
    SPACE = ScanCodeTuple(0x39, False)             # VK_SPACE
    CAPSLOCK = ScanCodeTuple(0x3A, False)          # VK_CAPITAL 'Caps Lock', JP DBE_ALPHANUMERIC
    F1 = ScanCodeTuple(0x3B, False)                # VK_F1
    F2 = ScanCodeTuple(0x3C, False)                # VK_F2
    F3 = ScanCodeTuple(0x3D, False)                # VK_F3
    F4 = ScanCodeTuple(0x3E, False)                # VK_F4
    F5 = ScanCodeTuple(0x3F, False)                # VK_F5
    F6 = ScanCodeTuple(0x40, False)                # VK_F6
    F7 = ScanCodeTuple(0x41, False)                # VK_F7
    F8 = ScanCodeTuple(0x42, False)                # VK_F8
    F9 = ScanCodeTuple(0x43, False)                # VK_F9
    F10 = ScanCodeTuple(0x44, False)               # VK_F10
    NUMLOCK = ScanCodeTuple(0x45, False)           # VK_NUMLOCK Note: when this seems to appear in PKBDLLHOOKSTRUCT it means Pause which must be sent as Ctrl + NumLock
    SCROLLLOCK = ScanCodeTuple(0x46, False)        # VK_SCROLL 'Scroll Lock', JP OEM_SCROLL
    NUMPAD7 = ScanCodeTuple(0x47, False)           # VK_NUMPAD7
    NUMPAD8 = ScanCodeTuple(0x48, False)           # VK_NUMPAD8
    NUMPAD9 = ScanCodeTuple(0x49, False)           # VK_NUMPAD9
    SUBTRACT = ScanCodeTuple(0x4A, False)          # VK_SUBTRACT
    NUMPAD4 = ScanCodeTuple(0x4B, False)           # VK_NUMPAD4
    NUMPAD5 = ScanCodeTuple(0x4C, False)           # VK_NUMPAD5
    NUMPAD6 = ScanCodeTuple(0x4D, False)           # VK_NUMPAD6
    ADD = ScanCodeTuple(0x4E, False)               # VK_ADD
    NUMPAD1 = ScanCodeTuple(0x4F, False)           # VK_NUMPAD1
    NUMPAD2 = ScanCodeTuple(0x50, False)           # VK_NUMPAD2
    NUMPAD3 = ScanCodeTuple(0x51, False)           # VK_NUMPAD3
    NUMPAD0 = ScanCodeTuple(0x52, False)           # VK_NUMPAD0
    DECIMAL = ScanCodeTuple(0x53, False)           # VK_DECIMAL Numerical, '.' on US
    SYSREQ = ScanCodeTuple(0x54, False)            # Sys Req
    OEM_102 = ScanCodeTuple(0x56, False)           # VK_OEM_102 Lower left '\' on US
    F11 = ScanCodeTuple(0x57, False)               # VK_F11
    F12 = ScanCodeTuple(0x58, False)               # VK_F12
    SLEEP = ScanCodeTuple(0x5F, False)             # VK_SLEEP OEM_8 on FR (undocumented?)
    ZOOM = ScanCodeTuple(0x62, False)              # VK_ZOOM (undocumented?)
    HELP = ScanCodeTuple(0x63, False)              # VK_HELP (undocumented?)
    F13 = ScanCodeTuple(0x64, False)               # VK_F13 JP agree, should 0x7d according to ms894073
    F14 = ScanCodeTuple(0x65, False)               # VK_F14
    F15 = ScanCodeTuple(0x66, False)               # VK_F15
    F16 = ScanCodeTuple(0x67, False)               # VK_F16
    F17 = ScanCodeTuple(0x68, False)               # VK_F17
    F18 = ScanCodeTuple(0x69, False)               # VK_F18
    F19 = ScanCodeTuple(0x6A, False)               # VK_F19
    F20 = ScanCodeTuple(0x6B, False)               # VK_F20
    F21 = ScanCodeTuple(0x6C, False)               # VK_F21
    F22 = ScanCodeTuple(0x6D, False)               # VK_F22
    F23 = ScanCodeTuple(0x6E, False)               # VK_F23 JP agree
    F24 = ScanCodeTuple(0x6F, False)               # VK_F24 0x87 according to ms894073
    HIRAGANA = ScanCodeTuple(0x70, False)          # JP DBE_HIRAGANA
    HANJA_KANJI = ScanCodeTuple(0x71, False)       # VK_HANJA / VK_KANJI (undocumented?)
    KANA_HANGUL = ScanCodeTuple(0x72, False)       # VK_KANA / VK_HANGUL (undocumented?)
    ABNT_C1 = ScanCodeTuple(0x73, False)           # VK_ABNT_C1 JP OEM_102
    F24_JP = ScanCodeTuple(0x76, False)            # JP F24
    CONVERT_JP = ScanCodeTuple(0x79, False)        # JP VK_CONVERT
    NONCONVERT_JP = ScanCodeTuple(0x7B, False)     # JP VK_NONCONVERT
    TAB_JP = ScanCodeTuple(0x7C, False)            # JP TAB
    BACKSLASH_JP = ScanCodeTuple(0x7D, False)      # JP OEM_5 ('\')
    ABNT_C2 = ScanCodeTuple(0x7E, False)           # VK_ABNT_C2, JP
    HANJA = ScanCodeTuple(0x71, False)             # KR VK_HANJA
    HANGUL = ScanCodeTuple(0x72, False)            # KR VK_HANGUL
    RETURN_KP = ScanCodeTuple(0x1C, True)          # not RETURN Numerical Enter
    RCONTROL = ScanCodeTuple(0x1D, True)           # VK_RCONTROL
    DIVIDE = ScanCodeTuple(0x35, True)             # VK_DIVIDE Numerical
    PRINTSCREEN = ScanCodeTuple(0x37, True)        # VK_EXECUTE/VK_PRINT/VK_SNAPSHOT Print Screen
    RMENU = ScanCodeTuple(0x38, True)              # VK_RMENU Right 'Alt' / 'Alt Gr'
    PAUSE = ScanCodeTuple(0x46, True)              # VK_PAUSE Pause / Break (Slightly special handling)
    HOME = ScanCodeTuple(0x47, True)               # VK_HOME
    UP = ScanCodeTuple(0x48, True)                 # VK_UP
    PRIOR = ScanCodeTuple(0x49, True)              # VK_PRIOR 'Page Up'
    LEFT = ScanCodeTuple(0x4B, True)               # VK_LEFT
    RIGHT = ScanCodeTuple(0x4D, True)              # VK_RIGHT
    END = ScanCodeTuple(0x4F, True)                # VK_END
    DOWN = ScanCodeTuple(0x50, True)               # VK_DOWN
    NEXT = ScanCodeTuple(0x51, True)               # VK_NEXT 'Page Down'
    INSERT = ScanCodeTuple(0x52, True)             # VK_INSERT
    DELETE = ScanCodeTuple(0x53, True)             # VK_DELETE
    NULL = ScanCodeTuple(0x54, True)               # <00>
    HELP2 = ScanCodeTuple(0x56, True)              # Help - documented, different from VK_HELP
    LWIN = ScanCodeTuple(0x5B, True)               # VK_LWIN
    RWIN = ScanCodeTuple(0x5C, True)               # VK_RWIN
    APPS = ScanCodeTuple(0x5D, True)               # VK_APPS Application
    POWER_JP = ScanCodeTuple(0x5E, True)           # JP POWER
    SLEEP_JP = ScanCodeTuple(0x5F, True)           # JP SLEEP
    NUMLOCK_EXTENDED = ScanCodeTuple(0x45, True)   # should be NUMLOCK
    RSHIFT_EXTENDED = ScanCodeTuple(0x36, True)    # should be RSHIFT
    VOLUME_MUTE = ScanCodeTuple(0x20, True)        # VK_VOLUME_MUTE
    VOLUME_DOWN = ScanCodeTuple(0x2E, True)        # VK_VOLUME_DOWN
    VOLUME_UP = ScanCodeTuple(0x30, True)          # VK_VOLUME_UP
    MEDIA_NEXT_TRACK = ScanCodeTuple(0x19, True)   # VK_MEDIA_NEXT_TRACK
    MEDIA_PREV_TRACK = ScanCodeTuple(0x10, True)   # VK_MEDIA_PREV_TRACK
    MEDIA_STOP = ScanCodeTuple(0x24, True)         # VK_MEDIA_MEDIA_STOP
    MEDIA_PLAY_PAUSE = ScanCodeTuple(0x22, True)   # VK_MEDIA_MEDIA_PLAY_PAUSE
    BROWSER_BACK = ScanCodeTuple(0x6A, True)       # VK_BROWSER_BACK
    BROWSER_FORWARD = ScanCodeTuple(0x69, True)    # VK_BROWSER_FORWARD
    BROWSER_REFRESH = ScanCodeTuple(0x67, True)    # VK_BROWSER_REFRESH
    BROWSER_STOP = ScanCodeTuple(0x68, True)       # VK_BROWSER_STOP
    BROWSER_SEARCH = ScanCodeTuple(0x65, True)     # VK_BROWSER_SEARCH
    BROWSER_FAVORITES = ScanCodeTuple(0x66, True)  # VK_BROWSER_FAVORITES
    BROWSER_HOME = ScanCodeTuple(0x32, True)       # VK_BROWSER_HOME
    LAUNCH_MAIL = ScanCodeTuple(0x6C, True)        # VK_LAUNCH_MAIL