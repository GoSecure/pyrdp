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