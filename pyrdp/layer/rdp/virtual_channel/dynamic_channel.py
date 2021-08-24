#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import Layer
from pyrdp.parser.rdp.virtual_channel.dynamic_channel import DynamicChannelParser


class DynamicChannelLayer(Layer):
    """
    Layer to receive and send DynamicChannel channel (drdynvc) packets.
    """

    def __init__(self, parser: DynamicChannelParser):
        super().__init__(parser)
