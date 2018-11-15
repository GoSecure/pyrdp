class Parser:
    def parse(self, data):
        """
        Decode a PDU from bytes.
        :param data: PDU data.
        :type data: str
        :return: an instance of a PDU class.
        """
        raise NotImplementedError("Parse is not implemented")

    def write(self, pdu):
        """
        Encode a PDU to bytes.
        :param pdu: instance of a PDU class.
        :return: str
        """
        raise NotImplementedError("Write is not implemented")