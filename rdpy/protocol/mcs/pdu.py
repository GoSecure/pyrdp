from StringIO import StringIO

from rdpy.core import ber, per
from rdpy.core.error import InvalidValue, InvalidSize
from rdpy.core.packing import Uint8, Uint16BE
from rdpy.enum.mcs import MCSPDUType, MCSChannelID

class MCSDomainParams:
    def __init__(self, maxChannelIDs, maxUserIDs, maxTokenIDs, numPriorities, minThroughput, maxHeight, maxMCSPDUSize, protocolVersion):
        self.maxChannelIDs = maxChannelIDs
        self.maxUserIDs = maxUserIDs
        self.maxTokenIDs = maxTokenIDs
        self.numPriorities = numPriorities
        self.minThroughput = minThroughput
        self.maxHeight = maxHeight
        self.maxMCSPDUSize = maxMCSPDUSize
        self.protocolVersion = protocolVersion
    
    @staticmethod
    def createTarget(maxChannelIDs, maxUserIDs):
        return MCSDomainParams(maxChannelIDs, maxUserIDs, 0, 1, 0, 1, 65535, 2)

    @staticmethod
    def createMinimum():
        return MCSDomainParams(1, 1, 1, 1, 0, 1, 1056, 2)

    @staticmethod
    def createMaximum():
        return MCSDomainParams(65535, 64535, 65535, 1, 0, 1, 65535, 2)


