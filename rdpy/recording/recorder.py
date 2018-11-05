from rdpy.core import log

from rdpy.core.newlayer import Layer
from rdpy.layer.tpkt import TPKTLayer

from rdpy.parser.rdp.fastpath import RDPInputEventParser
from rdpy.pdu.rdp.fastpath import FastPathEventScanCode


class Recorder(Layer):
    """
    Base class to implement a recorder for RDP events.
    """

    def __init__(self):
        super(Recorder, self).__init__()
        self.tpktLayer = TPKTLayer()
        self.setNext(self.tpktLayer)
        self.rdpInputEventParser = RDPInputEventParser()

    def record(self, pdu):
        """
        Encapsulate pdu in a TPKT packet, then record the provided pdu_data
        """

        if isinstance(pdu, FastPathEventScanCode):
            raw_data = self.rdpInputEventParser.write(pdu, write_timestamp=True)
            self.tpktLayer.send(raw_data)

    def send(self, data):
        """
        Method to override to record the event.
        """
        raise RuntimeError("Record.send() method not implemented")


class FileRecorder(Recorder):
    """
    Recorder that save RDP events to a file for later replay.
    """

    def __init__(self):
        super(FileRecorder, self).__init__()
        self.file_descriptor = open("hahatest.bin", "wb")

    def send(self, data):
        """
        Save data to the file.
        :type data: str
        """
        log.debug("writing {} to {}".format(data, self.file_descriptor))
        self.file_descriptor.write(data)
