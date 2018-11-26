from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.layer.rdp.data import RDPFastPathDataLayerObserver, RDPDataLayerObserver
from rdpy.pdu.rdp.data import RDPConfirmActivePDU, RDPInputPDU, RDPUpdatePDU
from rdpy.recording.recorder import Recorder


class RecordingFastPathObserver(RDPFastPathDataLayerObserver):
    def __init__(self, recorder: Recorder, messageType: RDPPlayerMessageType):
        self.recorder = recorder
        self.messageType = messageType
        RDPFastPathDataLayerObserver.__init__(self)

    def onPDUReceived(self, pdu):
        self.recorder.record(pdu, self.messageType)
        RDPFastPathDataLayerObserver.__init__(self)

class RecordingSlowPathObserver(RDPDataLayerObserver):
    def __init__(self, recorder: Recorder):
        RDPDataLayerObserver.__init__(self)
        self.recorder = recorder

    def onPDUReceived(self, pdu):
        if isinstance(pdu, (RDPConfirmActivePDU, RDPUpdatePDU, RDPInputPDU)):
            self.recorder.record(pdu, RDPPlayerMessageType.SLOW_PATH_PDU)