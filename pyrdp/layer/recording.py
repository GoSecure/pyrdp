from io import BytesIO

from pyrdp.core.packing import Uint8, Uint64LE
from pyrdp.core.subject import ObservedBy
from pyrdp.enum.rdp import RDPPlayerMessageType
from pyrdp.layer.layer import Layer, LayerRoutedObserver
from pyrdp.pdu.rdp.recording import RDPPlayerMessagePDU


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

    def recv(self, data: bytes):
        """
        Parses data to make a RDPPlayerMessagePDU and calls the observer with it.
        """
        stream = BytesIO(data)
        type = RDPPlayerMessageType(Uint8.unpack(stream))
        timestamp = Uint64LE.unpack(stream)
        payload = stream.read()
        pdu = RDPPlayerMessagePDU(type, timestamp, payload)
        self.pduReceived(pdu, forward=False)

    def sendMessage(self, data: bytes, messageType: RDPPlayerMessageType, timeStamp: int):
        stream = BytesIO()
        Uint8.pack(messageType, stream)
        Uint64LE.pack(timeStamp, stream)
        stream.write(data)
        self.previous.send(stream.getvalue())

