import time
from io import BytesIO

from rdpy.core.layer import Layer, LayerRoutedObserver
from rdpy.core.observer import Observer
from rdpy.core.packing import Uint8, Uint64LE
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.pdu.rdp.recording import RDPPlayerMessagePDU

class RDPPlayerMessageObserver(LayerRoutedObserver):
    def __index__(self, **kwargs):
        LayerRoutedObserver.__init__(self, {
            RDPPlayerMessageType.CONNECTION_CLOSE: "onConnectionClose",
            RDPPlayerMessageType.CLIENT_INFO: "onClientInfo",
            RDPPlayerMessageType.CONFIRM_ACTIVE: "onConfirmActive",
            RDPPlayerMessageType.INPUT: "onInput",
            RDPPlayerMessageType.OUTPUT: "onOutput",
            RDPPlayerMessageType.CLIPBOARD_DATA: "onClipboardData",
        }, **kwargs)

    def onConnectionClose(self, pdu):
        pass

    def onClientInfo(self, pdu):
        pass

    def onConfirmActive(self, pdu):
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
        timestamp = int(round(time.time() * 1000))

        stream = BytesIO()
        Uint8.pack(messageType, stream)
        Uint64LE.pack(timestamp, stream)
        stream.write(data)
        self.previous.send(stream.getvalue())

