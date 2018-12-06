from io import BytesIO

from pyrdp.core.packing import Uint8, Uint16BE
from pyrdp.exceptions import ParsingError
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import TPKTPDU


class TPKTParser(SegmentationParser):
    """
    Parser for TPKT traffic to read and write TPKT messages
    """
    def isCompletePDU(self, data):
        """
        Check if the PDU is fully contained in data.
        :param data: the data.
        :type data: bytes
        :return: bool
        """
        if len(data) < 4:
            return False

        length = self.getPDULength(data)
        return len(data) >= length

    def isTPKTPDU(self, data):
        """
        Check if the PDU in data is a TPKT PDU.
        :param data: the data.
        :type data: bytes
        :return: bool
        """
        return Uint8.unpack(data[0]) == 3

    def getPDULength(self, data):
        """
        Get the length of the PDU contained in data.
        :param data: the PDU data.
        :type data: bytes
        :return: int
        """
        return Uint16BE.unpack(data[2 : 4])

    def getPDULengthWithSocket(self, socket):
        """
        Same as getPDULength, but using a network socket.
        :type socket: socket.socket
        """
        data = socket.recv(3)
        return data, Uint16BE.unpack(data[1:])

    def parse(self, data):
        """
        Read the byte stream and return a TPKTPDU
        :type data: bytes
        :return: TPKTPDU
        """

        version = Uint8.unpack(data[0 : 1])
        padding = Uint8.unpack(data[1 : 2])  # Unused value
        length = Uint16BE.unpack(data[2 : 4])
        payload = data[4 : length]

        if len(payload) != length - 4:
            raise ParsingError("Payload is too short for TPKT length field")

        return TPKTPDU(payload)

    def write(self, pdu):
        """
        Encode a TPKTPDU into bytes to send on the network.
        :type pdu: TPKTPDU
        :return: str
        """

        stream = BytesIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(b"\x00")
        stream.write(Uint16BE.pack(len(pdu.payload) + 4))
        stream.write(pdu.payload)

        return stream.getvalue()
