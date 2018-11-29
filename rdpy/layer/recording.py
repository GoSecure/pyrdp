import time
from io import BytesIO

from rdpy.core.layer import Layer, LayerRoutedObserver
from rdpy.core.observer import Observer
from rdpy.core.packing import Uint8, Uint64LE
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.pdu.rdp.recording import RDPPlayerMessagePDU

class RDPPlayerMessageObserver(LayerRoutedObserver):
    def __init__(self, **kwargs):
        LayerRoutedObserver.__init__(self, {
            RDPPlayerMessageType.CONNECTION_CLOSE: "onConnectionClose",
            RDPPlayerMessageType.CLIENT_INFO: "onClientInfo",
            RDPPlayerMessageType.SLOW_PATH_PDU: "onSlowPathPDU",
            RDPPlayerMessageType.FAST_PATH_INPUT: "onInput",
            RDPPlayerMessageType.FAST_PATH_OUTPUT: "onOutput",
            RDPPlayerMessageType.CLIPBOARD_DATA: "onClipboardData",
        }, **kwargs)

    def onConnectionClose(self, pdu):
        pass

    def onClientInfo(self, pdu):
        pass

    def onSlowPathPDU(self, pdu):
        pass

    def onInput(self, pdu):
        pass

    def onOutput(self, pdu):
        pass

    def onClipboardData(self, pdu):
        pass

@ObservedBy(RDPPlayerMessageObserver)
class RDPPlayerMessageLayer(Layer):
    """
    Layer to manage the encapsulation of Player metadata such as event timestamp and
    event type/origin (input, output).
    """

    def __init__(self):
        Layer.__init__(self)

    def recv(self, data):
        """
        Parses data to make a RDPPlayerMessagePDU and calls the observer with it.
        :type data: bytes
        """
        type = Uint8.unpack(data[0])
        timestamp = Uint64LE.unpack(data[1 : 9])
        payload = data[9 :]
        pdu = RDPPlayerMessagePDU(type, timestamp, payload)
        self.pduReceived(pdu, False)

    def sendMessage(self, data, messageType):
        """
        :type data: bytes
        :type messageType: RDPPlayerMessageType
        """
        timestamp = self.getCurrentTimeStamp()

        stream = BytesIO()
        Uint8.pack(messageType, stream)
        Uint64LE.pack(timestamp, stream)
        stream.write(data)
        self.previous.send(stream.getvalue())

    def getCurrentTimeStamp(self) -> int:
        """
        Returns the current timestamp when writing a PDU.
        """
        return int(round(time.time() * 1000))

