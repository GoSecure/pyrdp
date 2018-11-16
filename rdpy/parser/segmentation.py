from rdpy.parser.parser import Parser


class SegmentationParser(Parser):
    def isCompletePDU(self, data):
        """
        Check if a stream of data contains a complete PDU.
        :param data: the data.
        :type data: str
        :return: True if the data contains a complete PDU.
        """
        raise NotImplementedError("isCompletePDU must be overridden")

    def getPDULength(self, data):
        """
        Get the length of data required for the PDU contained in a stream of data.
        :param data: the data.
        :type data: str
        :return: length required.
        """
        raise NotImplementedError("getPDULength must be overridden")