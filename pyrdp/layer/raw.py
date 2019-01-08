#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import IntermediateLayer
from pyrdp.parser.RawParser import RawParser
from pyrdp.pdu import PDU


class RawLayer(IntermediateLayer):
    """
    Simple layer that uses raw PDUs and always forwards data.
    """

    def __init__(self):
        super().__init__(RawParser())

    def shouldForward(self, pdu: PDU) -> bool:
        return True