#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class GCCPDUType(IntEnum):
    """
    PDU types for GCC messages received in MCS Connect Initial PDUs.
    """
    CREATE_CONFERENCE_REQUEST = 0
    CREATE_CONFERENCE_RESPONSE = 0x14