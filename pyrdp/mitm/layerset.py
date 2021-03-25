#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import SegmentationPDUType
from pyrdp.layer import FastPathLayer, LayerChainItem, MCSLayer, SecurityLayer, SegmentationLayer, SlowPathLayer, \
    TPKTLayer, TwistedTCPLayer, X224Layer


class RDPLayerSet:
    """
    Class that handles initialization of regular (non-virtual channel) RDP layers.
    """

    def __init__(self):
        self.tcp = TwistedTCPLayer()
        self.segmentation = SegmentationLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = MCSLayer()
        self.security: SecurityLayer = None
        self.slowPath = SlowPathLayer()
        self.fastPath: FastPathLayer = None

        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
        LayerChainItem.chain(self.tpkt, self.x224, self.mcs)

    def replaceTCP(self):
        self.tcp = TwistedTCPLayer()
        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
