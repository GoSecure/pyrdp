#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class ParserMode(IntEnum):
    """
    Mode used by some parsers (Client or Server).
    """
    CLIENT = 0
    SERVER = 1