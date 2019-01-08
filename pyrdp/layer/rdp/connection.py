#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import Layer
from pyrdp.parser import ClientConnectionParser, ServerConnectionParser
from pyrdp.pdu.rdp.connection import ClientDataPDU


class ClientConnectionLayer(Layer):
    """
    Layer for client RDP connection data. Sends Client PDUs and receives Server PDUs.
    """
    def __init__(self, sendParser = ClientConnectionParser(), recvParser = ServerConnectionParser()):
        """
        :param sendParser: parser to use when sending client PDUs.
        :param recvParser: parser to use when receiving server PDUs.
        """
        # RED FLAG: Shouldn't be passing None to this.
        super().__init__(None)
        self.sendParser = sendParser
        self.recvParser = recvParser

    def recv(self, data):
        pdu = self.recvParser.parse(data)
        self.pduReceived(pdu)

    def sendPDU(self, pdu: ClientDataPDU):
        self.previous.sendBytes(self.sendParser.write(pdu))
