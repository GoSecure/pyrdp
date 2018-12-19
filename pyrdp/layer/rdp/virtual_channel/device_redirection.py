#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import Layer
from pyrdp.parser import DeviceRedirectionParser


class DeviceRedirectionLayer(Layer):
    """
    Layer to receive and send DeviceRedirection channel (rdpdr) packets.
    """

    def __init__(self, parser = DeviceRedirectionParser()):
        super().__init__(parser, hasNext=False)
