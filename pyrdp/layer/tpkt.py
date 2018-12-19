#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.buffered import BufferedLayer
from pyrdp.parser import SegmentationParser, TPKTParser
from pyrdp.pdu import TPKTPDU


class TPKTLayer(BufferedLayer):
    def __init__(self, parser = TPKTParser()):
        """
        :type parser: SegmentationParser
        """
        BufferedLayer.__init__(self, parser)

    def send(self, data):
        pdu = TPKTPDU(data)
        self.sendPDU(pdu)