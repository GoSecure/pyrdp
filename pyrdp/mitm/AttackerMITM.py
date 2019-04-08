#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter
from typing import Dict

from pyrdp.enum import FastPathInputType, FastPathOutputType, MouseButton, PlayerPDUType, PointerFlag, ScanCodeTuple
from pyrdp.layer import FastPathLayer, PlayerLayer
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITMObserver
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import BitmapParser
from pyrdp.pdu import BitmapUpdateData, DeviceAnnounce, FastPathBitmapEvent, FastPathInputEvent, FastPathMouseEvent, \
    FastPathOutputEvent, FastPathPDU, FastPathScanCodeEvent, FastPathUnicodeEvent, PlayerBitmapPDU, \
    PlayerForwardingStatePDU, PlayerKeyboardPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU, \
    PlayerPDU, PlayerTextPDU


class AttackerMITM(DeviceRedirectionMITMObserver):
    """
    MITM component for commands coming from the player. The job of this component is just to adapt the format of events
    received to the format expected by RDP.
    """

    def __init__(self, client: FastPathLayer, server: FastPathLayer, attacker: PlayerLayer, log: LoggerAdapter, state: RDPMITMState, recorder: MITMRecorder):
        """
        :param client: fast-path layer for the client side
        :param server: fast-path layer for the server side
        :param attacker: player layer for the attacker side
        :param log: logger for this component
        :param log: state of the MITM
        :param recorder: recorder for this connection
        """
        super().__init__()

        self.client = client
        self.server = server
        self.attacker = attacker
        self.log = log
        self.state = state
        self.recorder = recorder
        self.devices: Dict[int, DeviceAnnounce] = {}

        self.attacker.createObserver(
            onPDUReceived = self.onPDUReceived,
        )

        self.handlers = {
            PlayerPDUType.MOUSE_MOVE: self.handleMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.handleMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.handleMouseWheel,
            PlayerPDUType.KEYBOARD: self.handleKeyboard,
            PlayerPDUType.TEXT: self.handleText,
            PlayerPDUType.FORWARDING_STATE: self.handleForwardingState,
            PlayerPDUType.BITMAP: self.handleBitmap,
        }


    def onPDUReceived(self, pdu: PlayerPDU):
        if pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)


    def sendInputEvents(self, events: [FastPathInputEvent]):
        pdu = FastPathPDU(0, events)
        self.recorder.record(pdu, PlayerPDUType.FAST_PATH_INPUT, True)
        self.server.sendPDU(pdu)

    def sendOutputEvents(self, events: [FastPathOutputEvent]):
        pdu = FastPathPDU(0, events)
        self.client.sendPDU(pdu)

    def sendKeys(self, keys: [ScanCodeTuple]):
        for released in [False, True]:
            for key in keys:
                self.handleKeyboard(PlayerKeyboardPDU(0, key.code, released, key.extended))

    def sendText(self, text: str):
        for c in text:
            for released in [False, True]:
                self.handleText(PlayerTextPDU(0, c, released))


    def handleMouseMove(self, pdu: PlayerMouseMovePDU):
        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = PointerFlag.PTRFLAGS_MOVE
        x = pdu.x
        y = pdu.y

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleMouseButton(self, pdu: PlayerMouseButtonPDU):
        mapping = {
            MouseButton.LEFT_BUTTON: PointerFlag.PTRFLAGS_BUTTON1,
            MouseButton.RIGHT_BUTTON: PointerFlag.PTRFLAGS_BUTTON2,
            MouseButton.MIDDLE_BUTTON: PointerFlag.PTRFLAGS_BUTTON3,
        }

        if pdu.button not in mapping:
            return

        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = mapping[pdu.button] | (PointerFlag.PTRFLAGS_DOWN if pdu.pressed else 0)
        x = pdu.x
        y = pdu.y

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleMouseWheel(self, pdu: PlayerMouseWheelPDU):
        eventHeader = FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE << 5
        flags = PointerFlag.PTRFLAGS_WHEEL
        x = pdu.x
        y = pdu.y

        if pdu.delta < 0:
            flags |= PointerFlag.PTRFLAGS_WHEEL_NEGATIVE

        if pdu.horizontal:
            flags |= PointerFlag.PTRFLAGS_HWHEEL

        flags |= abs(pdu.delta) & PointerFlag.WheelRotationMask

        event = FastPathMouseEvent(eventHeader, flags, x, y)
        self.sendInputEvents([event])


    def handleKeyboard(self, pdu: PlayerKeyboardPDU):
        event = FastPathScanCodeEvent(2 if pdu.extended else 0, pdu.code, pdu.released)
        self.sendInputEvents([event])

    def handleText(self, pdu: PlayerTextPDU):
        event = FastPathUnicodeEvent(pdu.character, pdu.released)
        self.sendInputEvents([event])


    def handleForwardingState(self, pdu: PlayerForwardingStatePDU):
        self.state.forwardInput = pdu.forwardInput
        self.state.forwardOutput = pdu.forwardOutput


    def handleBitmap(self, pdu: PlayerBitmapPDU):
        bpp = 32
        flags = 0

        # RDP expects bitmap data in bottom-up, left-to-right
        # See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/84a3d4d2-5523-4e49-9a48-33952c559485
        for y in range(pdu.height):
            pixels = pdu.pixels[y * pdu.width * 4 : (y + 1) * pdu.width * 4]
            bitmap = BitmapUpdateData(0, y, pdu.width, y + 1, pdu.width, 1, bpp, flags, pixels)
            bitmapData = BitmapParser().writeBitmapUpdateData([bitmap])
            event = FastPathBitmapEvent(FastPathOutputType.FASTPATH_UPDATETYPE_BITMAP, None, [], bitmapData)
            self.sendOutputEvents([event])


    def onDeviceAnnounce(self, device: DeviceAnnounce):
        self.devices[device.deviceID] = device