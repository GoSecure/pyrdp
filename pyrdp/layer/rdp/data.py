from pyrdp.pdu import PDU


class RDPDataObserver:
    """
    Base observer class for RDP data observers (slow-path and fast-path).
    A handler can be set for each data PDU type. A default handler can also be used.
    You can also set a handler for when data that could not be parsed was received.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.dataHandlers = {}
        self.defaultDataHandler = None
        self.unparsedDataHandler = None

    def dispatchPDU(self, pdu: PDU):
        """
        Call the proper handler depending on the PDU's type.
        :param pdu: the PDU that was received.
        """
        type = self.getPDUType(pdu)

        if type in self.dataHandlers:
            self.dataHandlers[type](pdu)
        elif self.defaultDataHandler:
            self.defaultDataHandler(pdu)

    def onUnparsedData(self, data: bytes):
        """
        Called when data that could not be parsed was received.
        :type data: bytes
        """
        if self.unparsedDataHandler is not None:
            self.unparsedDataHandler(data)

    def setDataHandler(self, type, handler):
        """
        Set a handler for a particular data PDU type.
        :type type: RDPSlowPathPDUType
        :type handler: callable object
        """
        self.dataHandlers[type] = handler

    def setDefaultDataHandler(self, handler):
        """
        Set the default handler.
        The default handler is called when a Data PDU is received that is not associated with a handler.
        :type handler: callable object
        """
        self.defaultDataHandler = handler

    def setUnparsedDataHandler(self, handler):
        """
        Set the handler used when data that could not be parsed is received.
        :type handler: callable object
        """
        self.unparsedDataHandler = handler

    def getPDUType(self, pdu: PDU):
        """
        Get the PDU type for a given PDU.
        :param pdu: the PDU.
        """
        raise NotImplementedError("getPDUType must be overridden")