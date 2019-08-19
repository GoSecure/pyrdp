#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import PlayerPDUType
from pyrdp.layer import FastPathObserver, SlowPathObserver
from pyrdp.pdu import ConfirmActivePDU, InputPDU, UpdatePDU
from pyrdp.pdu.rdp.fastpath import FastPathPDU
from pyrdp.recording.recorder import Recorder


class RecordingFastPathObserver(FastPathObserver):
    def __init__(self, recorder: Recorder, messageType: PlayerPDUType):
        self.recorder = recorder
        self.messageType = messageType
        FastPathObserver.__init__(self)

    def onPDUReceived(self, pdu: FastPathPDU):
        self.recorder.record(pdu, self.messageType)
        FastPathObserver.onPDUReceived(self, pdu)


class RecordingSlowPathObserver(SlowPathObserver):
    def __init__(self, recorder: Recorder):
        SlowPathObserver.__init__(self)
        self.recorder = recorder

    def onPDUReceived(self, pdu):
        if isinstance(pdu, (ConfirmActivePDU, UpdatePDU, InputPDU)):
            self.recorder.record(pdu, PlayerPDUType.SLOW_PATH_PDU)
        SlowPathObserver.onPDUReceived(self, pdu)
