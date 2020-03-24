#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import List, Optional

from pyrdp.enum import PlayerPDUType
from pyrdp.layer import LayerChainItem
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import PDU, InputPDU
from pyrdp.recording import Recorder


class MITMRecorder(Recorder):
    """
    Recorder subclass that avoids recording input events when input forwarding is disabled.
    """

    def __init__(self, transports: List[LayerChainItem], state: RDPMITMState):
        super().__init__(transports)
        self.state = state

    def record(self, pdu: Optional[PDU], messageType: PlayerPDUType, forceRecording: bool = False):
        """
        Record a PDU. The forceRecording param is mostly useful for recording forged PDUs (e.g: input coming from the attacker).
        :param pdu: the PDU to record.
        :param messageType: the message type.
        :param forceRecording: when set to True, records the PDU even if forwarding is disabled. Defaults to False.
        """

        if self.state.forwardInput or forceRecording or (messageType != PlayerPDUType.FAST_PATH_INPUT and not isinstance(pdu, InputPDU)):
            super().record(pdu, messageType)