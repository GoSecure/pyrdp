from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16BE
from rdpy.exceptions import ParsingError
from rdpy.pdu.tpkt import TPKTPDU


class TPKTParser:
    """
    Parser for TPKT traffic to read and write TPKT messages
    """
    def isCompletePDU(self, data):
        if len(data) < 4:
            return False

        length = self.getPDULength(data)
        return len(data) >= length

    def isTPKTPDU(self, data):
        return Uint8.unpack(data[0]) == 3

    def getPDULength(self, data):
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
        :type data: str
        :return: TPKTPDU
        """

        version = Uint8.unpack(data[0 : 1])
        padding = Uint8.unpack(data[1 : 2])  # Unused value
        length = Uint16BE.unpack(data[2 : 4])
        payload = data[4 : length]

        if len(payload) != length - 4:
            raise ParsingError("Payload is too short for TPKT length field")

        return TPKTPDU(version, payload)

    def write(self, pdu):
        """
        Encode a TPKTPDU into bytes to send on the network.
        :type pdu: TPKTPDU
        :return: str
        """

        stream = StringIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint8.pack(pdu.padding))
        stream.write(Uint16BE.pack(pdu.length))
        stream.write(pdu.payload)

        return stream.getvalue()
