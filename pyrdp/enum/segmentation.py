#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class SegmentationPDUType(IntEnum):
    FAST_PATH = 0
    TPKT = 3
    MASK = 3