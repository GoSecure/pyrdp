from pyrdp.pdu.base_pdu import PDU


class Parser:

    def __init__(self):
        pass

    def parse(self, data: bytes) -> PDU:
        """
        Decode a PDU from bytes.
        :param data: PDU data.
        :return: an instance of a PDU class.
        """
        raise NotImplementedError("Parse is not implemented")

    def write(self, pdu: PDU) -> bytes:
        """
        Encode a PDU to bytes.
        :param pdu: instance of a PDU class.
        """
        raise NotImplementedError("Write is not implemented")
