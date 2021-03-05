#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.layer import Layer


class VoidLayer(Layer):
    """
    Layer that doesn't actually send or receive anything.
    Basically this helps us avoid writing a bunch of `if [...]: layer.sendPDU` in the code.
    """

    def __init__(self, parser = None):
        super().__init__(parser)

    def sendPDU(self, pdu):
        return
