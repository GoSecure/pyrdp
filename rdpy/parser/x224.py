from io import BytesIO

from rdpy.core.packing import Uint8, Uint16BE, Uint16LE
from rdpy.enum.x224 import X224PDUType
from rdpy.exceptions import ParsingError, UnknownPDUTypeError
from rdpy.parser.parser import Parser
from rdpy.pdu.x224 import X224ConnectionConfirmPDU, X224ConnectionRequestPDU, X224DisconnectRequestPDU, X224DataPDU, \
    X224ErrorPDU


class X224Parser(Parser):
    """
    Parser to read and write X224 (COTP) PDUs.
    """

    def __init__(self):
        self.parsers = {
            X224PDUType.X224_TPDU_CONNECTION_REQUEST: self.parseConnectionRequest,
            X224PDUType.X224_TPDU_CONNECTION_CONFIRM: self.parseConnectionConfirm,
            X224PDUType.X224_TPDU_DISCONNECT_REQUEST: self.parseDisconnectRequest,
            X224PDUType.X224_TPDU_DATA: self.parseData,
            X224PDUType.X224_TPDU_ERROR: self.parseError,
        }

        self.writers = {
            X224PDUType.X224_TPDU_CONNECTION_REQUEST: self.writeConnectionRequest,
            X224PDUType.X224_TPDU_CONNECTION_CONFIRM: self.writeConnectionConfirm,
            X224PDUType.X224_TPDU_DISCONNECT_REQUEST: self.writeDisconnectRequest,
            X224PDUType.X224_TPDU_DATA: self.writeData,
            X224PDUType.X224_TPDU_ERROR: self.writeError,
        }

    def parse(self, data):
        """
        Read the byte stream and return a corresponding X224PDU
        :type data: bytes
        :return: rdpy.pdu.x224.X224PDU
        """
        length = Uint8.unpack(data[0])
        header = Uint8.unpack(data[1]) >> 4

        if header in list(X224PDUType):
            header = X224PDUType(header)

        if length < 2:
            raise ParsingError("Invalid X224 length indicator: indicator = %d, expected at least 2 bytes" % length)
        if len(data) < length:
            raise ParsingError("Invalid X224 length indicator: indicator = %d, length = %d" % (length, len(data)))

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown X224 PDU type: %s" % (header if header in X224PDUType else hex(header)), header)

        return self.parsers[header](data, length)

    def parseConnectionPDU(self, data, length, name):
        """
        Parse the provided data to extract common information contained in Connection Request,
        Connection Confirm and Disconnect Request PDUs.
        :type data: bytes
        :param length: Length of the Connection PDU
        :param name: For debugging purposes: the name of the connection PDU (like "Connection Request")
        :return: A tuple of the information we find in both connection PDUs:
                (source, destination, options, payload)
        """

        if length < 6:
            raise ParsingError("Invalid X244 %s length indicator: indicator = %d, expected at least 6 bytes" % (name, 6))

        destination = Uint16BE.unpack(data[2 : 4])
        source = Uint16BE.unpack(data[4 : 6])
        options = Uint8.unpack(data[6])
        payload = data[7 :]

        if len(payload) != length - 6:
            raise ParsingError("Invalid X224 %s payload length: expected = %d, length = %d" % (name, length - 6, len(payload)))

        return source, destination, options, payload

    def parseConnectionRequest(self, data, length):
        """
        Parse a ConnectionRequest PDU from the raw bytes
        :type data: bytes
        :param length: The length in bytes of the Connection Request PDU.
        :return: X224ConnectionRequestPDU
        """
        credit = Uint8.unpack(data[1]) & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Request")
        return X224ConnectionRequestPDU(credit, destination, source, options, payload)

    def parseConnectionConfirm(self, data, length):
        """
        Parse a ConnectionConfirm PDU from the raw bytes
        :type data: bytes
        :param length: The length in bytes of the Connection Confirm PDU.
        :return: X224ConnectionConfirmPDU
        """
        credit = Uint8.unpack(data[1]) & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Confirm")
        return X224ConnectionConfirmPDU(credit, destination, source, options, payload)

    def parseDisconnectRequest(self, data, length):
        """
        Parse a DisconnectRequest PDU from the raw bytes
        :type data: bytes
        :param length: The length in bytes of the Disconnect Request PDU.
        :return: X224DisconnectRequestPDU
        """
        destination, source, reason, payload = self.parseConnectionPDU(data, length, "Disconnect Request")
        return X224DisconnectRequestPDU(destination, source, reason, payload)

    def parseData(self, data, length):
        """
        Parse a Data PDU from the raw bytes
        :type data: bytes
        :param length: The length in bytes of the Data PDU.
        :return: X224DataPDU
        """

        if length != 2:
            raise ParsingError("Invalid X224 Data PDU length indicator: expected = 2, indicator = %d" % length)

        code = Uint8.unpack(data[1]) & 0xf
        sequence = Uint8.unpack(data[2])
        payload = data[3 :]

        return X224DataPDU(code & 1 == 1, sequence & 0x80 == 0x80, payload)

    def parseError(self, data, length):
        """
        Parse a Error PDU from the raw bytes
        :type data: bytes
        :param length: The length in bytes of the Error PDU.
        :return: X224ErrorPDU
        """

        if length < 4:
            raise ParsingError("Invalid X224 Error PDU length indicator: indicator = %d, expected at least 4 bytes")

        destination = Uint16BE.unpack(data[2 : 4])
        cause = Uint8.unpack(data[4])
        payload = data[5 :]

        if len(payload) != length - 4:
            raise ParsingError("Invalid X224 Error PDU payload length: expected = %d, length = %d" % (length - 4, len(payload)))

        return X224ErrorPDU(destination, cause, payload)

    def write(self, pdu):
        """
        Encode the provided X224 pdu into a byte stream.
        :type pdu: rdpy.pdu.x224.X224PDU
        :return: str The byte stream to send to the previous layer
        """

        stream = BytesIO()
        stream.write(Uint8.pack(pdu.length))

        if pdu.header not in self.writers:
            raise UnknownPDUTypeError("Trying to write unknown X224 PDU type: %s" % (pdu.header if pdu.header in X224PDUType else hex(pdu.header)), pdu.header)

        self.writers[pdu.header](stream, pdu)
        stream.write(pdu.payload)
        return stream.getvalue()

    def writeConnectionPDU(self, stream, header, destination, source, options):
        """
        Write a connection PDU (connectionRequest/connectionConfirm/disconnectRequest) in the provided byte stream.
        :type stream: BytesIO
        :type header: X224PDUType
        :type destination: int
        :type source: int
        :type options: int
        """
        stream.write(Uint8.pack(header))
        stream.write(Uint16BE.pack(destination))
        stream.write(Uint16BE.pack(source))
        stream.write(Uint8.pack(options))

    def writeConnectionRequest(self, stream, pdu):
        """
        Write a connection request PDU onto the provided stream
        :type stream: BytesIO
        :type pdu: X224ConnectionRequestPDU
        """
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)

    def writeConnectionConfirm(self, stream, pdu):
        """
        Write a connection confirm PDU onto the provided stream
        :type stream: BytesIO
        :type pdu: X224ConnectionConfirmPDU
        """
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)

    def writeDisconnectRequest(self, stream, pdu):
        """
        Write a disconnect request PDU onto the provided stream
        :type stream: BytesIO
        :type pdu: X224DisconnectRequestPDU
        """
        self.writeConnectionPDU(stream, pdu.header, pdu.destination, pdu.source, pdu.reason)

    def writeData(self, stream, pdu):
        """
        Write a Data PDU onto the provided stream
        :type stream: BytesIO
        :type pdu: X224DataPDU
        """
        header = (pdu.header << 4) | int(pdu.roa)
        stream.write(Uint8.pack(header))
        stream.write(Uint8.pack(int(pdu.eot) << 7))

    def writeError(self, stream, pdu):
        """
        Write an error PDU onto the provided stream
        :type stream: BytesIO
        :type pdu: X224ErrorPDU
        """
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint16LE.pack(pdu.destination))
        stream.write(Uint8.pack(pdu.cause))
