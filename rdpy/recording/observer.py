from rdpy.enum.rdp import RDPPlayerMessageType

from rdpy.recording.recorder import Recorder

from rdpy.layer.rdp.data import RDPFastPathDataLayerObserver


class RecordingFastPathObserver(RDPFastPathDataLayerObserver):
    def __init__(self, recorder, messageType):
        """
        :type recorder: Recorder
        :type messageType: RDPPlayerMessageType
        """
        self.recorder = recorder
        self.messageType = messageType
        RDPFastPathDataLayerObserver.__init__(self)

    def onPDUReceived(self, pdu):
        self.recorder.record(pdu, self.messageType)
        RDPFastPathDataLayerObserver.__init__(self)