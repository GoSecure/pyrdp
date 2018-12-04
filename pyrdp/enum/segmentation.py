from enum import IntEnum


class SegmentationPDUType(IntEnum):
    FAST_PATH = 0
    TPKT = 3
    MASK = 3