import time
from StringIO import StringIO

from rdpy.core.newlayer import Layer
from rdpy.core.packing import Uint8, Uint64LE
from rdpy.pdu.rdp.recording import RDPPlayerMessagePDU


class RDPPlayerMessageTypeLayer(Layer):
    """
    Layer to manage the encapsulation of Player metadata such as event timestamp and
    event type/origin (input, output).
    """

    def __init__(self):
        super(RDPPlayerMessageTypeLayer, self).__init__()
        self.messageType = None

    def recv(self, data):
        """
        Parses data to make a RDPPlayerMessagePDU and calls the observer with it.
        :type data: str
        """
        self.pduReceived(RDPPlayerMessagePDU(Uint8.unpack(data[0]), Uint64LE.unpack(data[1:9]), data[9:]), False)

    def send(self, payload):
        """
        Encapsulates the provided payload into a binary representation of a RDPPlayerMessagePDU and send it to
        the upper layer (should be tpkt).
        :type payload: str
        """
        stream = StringIO()
        Uint8.pack(self.messageType, stream)  # Message type
        Uint64LE.pack(int(round(time.time() * 1000)), stream)  # timestamp
        stream.write(payload)  # payload
        self.previous.send(stream.getvalue())

    def setMessageType(self, newType):
        self.messageType = newType
