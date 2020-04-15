#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import AsyncIOTCPLayer, LayerChainItem, PlayerLayer, TwistedTCPLayer
from pyrdp.mitm import MITMConfig


class TwistedPlayerLayerSet:
    def __init__(self, config: MITMConfig):
        self.tcp = TwistedTCPLayer(config)
        self.player = PlayerLayer()
        LayerChainItem.chain(self.tcp, self.player)


class AsyncIOPlayerLayerSet:
    def __init__(self):
        self.tcp = AsyncIOTCPLayer()
        self.player = PlayerLayer()
        LayerChainItem.chain(self.tcp, self.player)
