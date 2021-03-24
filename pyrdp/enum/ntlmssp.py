#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class NTLMSSPMessageType(IntEnum):
    NEGOTIATE_MESSAGE = 1
    CHALLENGE_MESSAGE = 2
    AUTHENTICATE_MESSAGE = 3
