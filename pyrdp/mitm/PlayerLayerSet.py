#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer import AsyncIOTCPLayer, LayerChainItem, PlayerLayer, TwistedTCPLayer


class TwistedPlayerLayerSet:
    def __init__(self):
        self.tcp = TwistedTCPLayer()
        self.player = PlayerLayer()
        LayerChainItem.chain(self.tcp, self.player)


class AsyncIOPlayerLayerSet:
    def __init__(self):
        self.tcp = AsyncIOTCPLayer()
        self.player = PlayerLayer()
        LayerChainItem.chain(self.tcp, self.player)