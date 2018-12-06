from pyrdp.enum import InputEventType
from pyrdp.pdu.base_pdu import PDU


class SlowPathInput(PDU):
    def __init__(self, eventTime, messageType):
        super().__init__()
        self.eventTime = eventTime
        self.messageType = messageType


class SynchronizeEvent(SlowPathInput):
    def __init__(self, eventTime, flags):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_SYNC)
        self.flags = flags


class UnusedEvent(SlowPathInput):
    def __init__(self, eventTime):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_UNUSED)


class KeyboardEvent(SlowPathInput):
    def __init__(self, eventTime, flags, keyCode):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_SCANCODE)
        self.flags = flags
        self.keyCode = keyCode


class UnicodeKeyboardEvent(SlowPathInput):
    def __init__(self, eventTime, flags, keyCode):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_UNICODE)
        self.flags = flags
        self.keyCode = keyCode


class MouseEvent(SlowPathInput):
    def __init__(self, eventTime, flags, x, y):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_MOUSE)
        self.flags = flags
        self.x = x
        self.y = y


class ExtendedMouseEvent(SlowPathInput):
    def __init__(self, eventTime, flags, x, y):
        SlowPathInput.__init__(self, eventTime, InputEventType.INPUT_EVENT_MOUSEX)
        self.flags = flags
        self.x = x
        self.y = y